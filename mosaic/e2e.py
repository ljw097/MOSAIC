"""종단 간(E2E) 암호 계층: 클라이언트 ↔ MOSAIC 네이티브 서비스(.mosaic).

일반 인터넷 접속에서는 마름모의 오른쪽 꼭짓점이 출구 노드라는 제3자다. 네이티브 서비스에서는
그 꼭짓점이 **목적지 자신**이고, 출구는 아예 존재하지 않는다. 조각이 마지막으로 거치는 서비스 측
게이트웨이가 조각을 모두 모아 SSMS를 풀더라도 손에 남는 것은 이 계층의 암호문뿐이다.

핸드셰이크 (첫 메시지에 포함, 하이브리드 포스트-양자)
  ss1 = X25519(e_c, S_svc),  (ss2, ct) = ML-KEM-768.Encaps(K_svc)
  k_up ‖ k_down = HKDF(ss1 ‖ ss2, "MOSAIC e2e v1" ‖ conn ‖ e_c ‖ H(ct) ‖ S_svc)

메시지 (조각들이 다시 모인 뒤의 평문)
  INIT : 0xE1 ‖ conn(16) ‖ nonce(12) ‖ e_c(32) ‖ ct(1088) ‖ AEAD(k_up, cell)
  UP   : 0xE2 ‖ conn(16) ‖ nonce(12) ‖ AEAD(k_up, cell)
  DOWN : 0xE3 ‖ conn(16) ‖ nonce(12) ‖ AEAD(k_down, cell)
  AD = type ‖ conn. nonce는 무작위 (Poisson 지연 때문에 메시지 순서가 뒤바뀌므로 카운터를 쓰지 않는다).
"""
from __future__ import annotations

import base64
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import crypto as C

T_INIT, T_UP, T_DOWN = 0xE1, 0xE2, 0xE3
INIT_MAX_AGE = 600          # INIT 타임스탬프 허용 범위(초). 녹화된 INIT을 나중에 재전송해 요청을 반복시키는 공격 방지
_HDR = struct.Struct(">B16s12s")
OVERHEAD = _HDR.size + 16                                   # 45
INIT_EXTRA = 32 + C.MLKEM_CT_LEN                            # 1120
INIT_OVERHEAD = OVERHEAD + INIT_EXTRA + 8


class E2EError(Exception):
    pass


def service_address(identity_pk: bytes) -> str:
    """자기 인증 주소: 서비스 신원 공개키 해시의 base32. 주소만 알면 키를 바꿔치기할 수 없다."""
    return base64.b32encode(C.h(b"mosaic-service", identity_pk, n=20)).decode().lower() + ".mosaic"


def _keys(ss1: bytes, ss2: bytes, conn: bytes, e_pk: bytes, ct: bytes, svc_pk: bytes) -> tuple[bytes, bytes]:
    okm = C.hkdf(ss1 + ss2, b"MOSAIC e2e v1" + conn + e_pk + C.h(ct) + svc_pk, 64)
    return okm[:32], okm[32:]


def _seal(key: bytes, t: int, conn: bytes, pt: bytes, extra: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    hdr = _HDR.pack(t, conn, nonce)
    return hdr + extra + ChaCha20Poly1305(key).encrypt(nonce, pt, hdr[:17])


def _open(key: bytes, msg: bytes, extra_len: int = 0) -> bytes:
    t, conn, nonce = _HDR.unpack_from(msg)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, msg[_HDR.size + extra_len:], msg[:17])
    except Exception as e:      # noqa: BLE001
        raise E2EError("e2e authentication failed") from e


def peek(msg: bytes) -> tuple[int, bytes] | None:
    if len(msg) < _HDR.size or msg[0] not in (T_INIT, T_UP, T_DOWN):
        return None
    return msg[0], msg[1:17]


class ClientSession:
    """클라이언트 측. 첫 seal()은 INIT, 이후는 UP."""

    def __init__(self, conn: bytes, svc_x25519: bytes, svc_mlkem: bytes):
        self.conn = conn
        e_sk, self.e_pk = C.x25519_keygen()
        ss2, self.ct = C.mlkem_encaps(svc_mlkem)
        self.k_up, self.k_down = _keys(C.x25519(e_sk, svc_x25519), ss2, conn, self.e_pk, self.ct, svc_x25519)
        self.sent_init = False

    def seal(self, cell: bytes) -> bytes:
        if not self.sent_init:
            self.sent_init = True
            ts = struct.pack(">Q", int(time.time()))      # AEAD 안: 위조·변조 불가
            return _seal(self.k_up, T_INIT, self.conn, ts + cell, self.e_pk + self.ct)
        return _seal(self.k_up, T_UP, self.conn, cell)

    def open(self, msg: bytes) -> bytes:
        if msg[0] != T_DOWN or msg[1:17] != self.conn:
            raise E2EError("unexpected e2e message")
        return _open(self.k_down, msg)


class ServerSession:
    def __init__(self, conn: bytes, k_up: bytes, k_down: bytes):
        self.conn, self.k_up, self.k_down = conn, k_up, k_down

    @classmethod
    def accept(cls, msg: bytes, x25519_sk: bytes, mlkem_seed: bytes) -> tuple["ServerSession", bytes]:
        if msg[0] != T_INIT:
            raise E2EError("not an INIT")
        conn = msg[1:17]
        off = _HDR.size
        e_pk, ct = msg[off:off + 32], msg[off + 32:off + INIT_EXTRA]
        try:
            ss1 = C.x25519(x25519_sk, e_pk)
            ss2 = C.mlkem_decaps(mlkem_seed, ct)
        except Exception as e:      # noqa: BLE001
            raise E2EError("bad INIT") from e
        k_up, k_down = _keys(ss1, ss2, conn, e_pk, ct, C.x25519_pub(x25519_sk))
        s = cls(conn, k_up, k_down)
        pt = _open(k_up, msg, INIT_EXTRA)
        ts = struct.unpack(">Q", pt[:8])[0]
        if abs(time.time() - ts) > INIT_MAX_AGE:
            raise E2EError("stale INIT (replay?)")
        return s, pt[8:]

    def open(self, msg: bytes) -> bytes:
        if msg[0] != T_UP or msg[1:17] != self.conn:
            raise E2EError("unexpected e2e message")
        return _open(self.k_up, msg)

    def seal(self, cell: bytes) -> bytes:
        return _seal(self.k_down, T_DOWN, self.conn, cell)
