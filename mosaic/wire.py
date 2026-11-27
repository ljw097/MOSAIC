"""MOSAIC 링크 계층.

노드 간, 클라이언트-게이트웨이 간 TCP 연결 위에 동작한다.

핸드셰이크 (하이브리드 포스트-양자, 응답자 인증, 전방향 안전성)
  I -> R : MAGIC || e_I(32) || ct = ML-KEM-768.Encaps(K_R) (1088)
  R -> I : e_R(32) || confirm(32)
    ss1 = X25519(e_I, S_R)      정적 키 → 응답자 인증
    ss2 = ML-KEM 공유비밀         양자 내성 ("지금 수집, 나중에 해독" 대응)
    ss3 = X25519(e_I, e_R)      임시 키 → 전방향 안전성
    k   = HKDF(ss1||ss2||ss3, transcript)
  공격자는 X25519와 ML-KEM을 모두 깨야 링크를 해독할 수 있다.

프레이밍
  모든 프레임은 고정 길이(FRAME_PT 평문 → FRAME_CT 암호문)이다. 패킷, 우편함 전달,
  더미(커버) 프레임이 외부 관찰자에게 구별되지 않는다.
"""
from __future__ import annotations

import asyncio
import struct

from . import crypto as C
from .sphinx import PACKET_LEN

MAGIC = b"MOSAIC/1"
FRAME_PT = 1 + 16 + PACKET_LEN + 7     # 2456 (F_FORWARD가 가장 큼)
FRAME_CT = FRAME_PT + 16

# 프레임 타입
F_PACKET = 1      # Sphinx 패킷
F_DELIVER = 2     # 게이트웨이 -> 클라이언트: surb_id(8) || payload(2048)
F_REGISTER = 3    # 클라이언트 -> 게이트웨이: mailbox secret(32). 우편함 id = mailbox_id(secret)
F_DUMMY = 4       # 링크 커버 트래픽
F_ENDPOINT_FRAG = 6   # 출구 -> 엔드포인트 입구: 조각 하나 (E2E 암호문의 일부)
F_FORWARD = 5     # 클라이언트(서비스) -> 게이트웨이: target(16) || SURB 패킷. 게이트웨이가 대신 첫 홉으로 전달


class LinkError(Exception):
    pass


class Link:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, k_send: bytes, k_recv: bytes):
        self.reader, self.writer = reader, writer
        self._tx, self._rx = C.AEAD(k_send), C.AEAD(k_recv)
        self._ntx = self._nrx = 0
        self._wlock = asyncio.Lock()
        self.closed = False

    async def send(self, ftype: int, body: bytes) -> None:
        if len(body) > FRAME_PT - 1:
            raise LinkError("frame body too large")
        pt = bytes([ftype]) + body.ljust(FRAME_PT - 1, b"\0")
        async with self._wlock:
            ct = self._tx.seal(self._ntx, pt)
            self._ntx += 1
            self.writer.write(ct)
            await self.writer.drain()

    async def recv(self) -> tuple[int, bytes]:
        ct = await self.reader.readexactly(FRAME_CT)
        try:
            pt = self._rx.open(self._nrx, ct)
        except Exception as e:
            raise LinkError("frame authentication failed") from e
        self._nrx += 1
        return pt[0], pt[1:]

    def close(self) -> None:
        self.closed = True
        try:
            self.writer.close()
        except Exception:
            pass


def _derive(ss1: bytes, ss2: bytes, ss3: bytes, transcript: bytes) -> tuple[bytes, bytes, bytes]:
    th = C.h(b"transcript", transcript)
    okm = C.hkdf(ss1 + ss2 + ss3, b"MOSAIC link v1" + th, 96)
    return okm[:32], okm[32:64], okm[64:]     # i->r, r->i, confirm


BUNDLE_LEN = 32 + C.MLKEM_PK_LEN


def bundle_fingerprint(static_x25519: bytes, static_mlkem: bytes) -> bytes:
    return C.h(b"MOSAIC link bundle", static_x25519, static_mlkem)


async def connect(host: str, port: int, static_x25519: bytes, static_mlkem: bytes, timeout: float = 10) -> Link:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    return await handshake_initiator(reader, writer, static_x25519, static_mlkem, timeout)


async def connect_pinned(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, fingerprint: bytes,
                         timeout: float = 10) -> Link:
    """엔드포인트 입구 연결: 응답자가 먼저 정적 공개키 묶음을 보내고, 개시자는 32바이트 지문으로 검증한다.
    조각 헤더에는 ML-KEM 공개키(1184B) 대신 지문만 실으면 된다."""
    bundle = await asyncio.wait_for(reader.readexactly(BUNDLE_LEN), timeout)
    sx, sm = bundle[:32], bundle[32:]
    if not C.ct_eq(bundle_fingerprint(sx, sm), fingerprint):
        writer.close()
        raise LinkError("endpoint key fingerprint mismatch")
    return await handshake_initiator(reader, writer, sx, sm, timeout)


async def accept_pinned(reader, writer, static_x25519_sk: bytes, static_mlkem_seed: bytes, static_mlkem_pk: bytes,
                        timeout: float = 10) -> Link:
    writer.write(C.x25519_pub(static_x25519_sk) + static_mlkem_pk)
    await writer.drain()
    return await accept(reader, writer, static_x25519_sk, static_mlkem_seed, timeout)


async def handshake_initiator(reader, writer, static_x25519: bytes, static_mlkem: bytes, timeout: float = 10) -> Link:
    e_sk, e_pk = C.x25519_keygen()
    ss2, ct = C.mlkem_encaps(static_mlkem)
    msg1 = MAGIC + e_pk + ct
    writer.write(msg1)
    await writer.drain()
    msg2 = await asyncio.wait_for(reader.readexactly(64), timeout)
    e_r, confirm = msg2[:32], msg2[32:]
    ss1 = C.x25519(e_sk, static_x25519)
    ss3 = C.x25519(e_sk, e_r)
    k_ir, k_ri, k_c = _derive(ss1, ss2, ss3, msg1 + e_r + static_x25519)
    if not C.ct_eq(confirm, C.mac(k_c, b"responder-confirm")):
        writer.close()
        raise LinkError("responder authentication failed")
    return Link(reader, writer, k_ir, k_ri)


async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, static_x25519_sk: bytes,
                 static_mlkem_seed: bytes, timeout: float = 10) -> Link:
    msg1 = await asyncio.wait_for(reader.readexactly(len(MAGIC) + 32 + C.MLKEM_CT_LEN), timeout)
    if msg1[: len(MAGIC)] != MAGIC:
        raise LinkError("bad magic")
    e_i = msg1[len(MAGIC): len(MAGIC) + 32]
    ct = msg1[len(MAGIC) + 32:]
    ss1 = C.x25519(static_x25519_sk, e_i)
    ss2 = C.mlkem_decaps(static_mlkem_seed, ct)
    er_sk, er_pk = C.x25519_keygen()
    ss3 = C.x25519(er_sk, e_i)
    k_ir, k_ri, k_c = _derive(ss1, ss2, ss3, msg1 + er_pk + C.x25519_pub(static_x25519_sk))
    writer.write(er_pk + C.mac(k_c, b"responder-confirm"))
    await writer.drain()
    return Link(reader, writer, k_ri, k_ir)


def mailbox_id(secret: bytes) -> bytes:
    """우편함 id는 비밀값의 해시다. 서비스처럼 id가 공개돼도, 비밀값을 아는 쪽만 그 우편함을 등록(수신)할 수 있다."""
    return C.h(b"MOSAIC mailbox", secret, n=16)


def pack_deliver(surb_id: bytes, payload: bytes) -> bytes:
    return surb_id + payload


def unpack_deliver(body: bytes) -> tuple[bytes, bytes]:
    from .sphinx import PAYLOAD_LEN, SURB_ID_LEN
    return body[:SURB_ID_LEN], body[SURB_ID_LEN:SURB_ID_LEN + PAYLOAD_LEN]


__all__ = ["Link", "connect", "accept", "F_PACKET", "F_DELIVER", "F_REGISTER", "F_DUMMY", "F_FORWARD", "struct"]
