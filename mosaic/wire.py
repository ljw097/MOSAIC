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
FRAME_PT = 1 + PACKET_LEN + 7          # 2440
FRAME_CT = FRAME_PT + 16

# 프레임 타입
F_PACKET = 1      # Sphinx 패킷
F_DELIVER = 2     # 게이트웨이 -> 클라이언트: surb_id(8) || payload(2048)
F_REGISTER = 3    # 클라이언트 -> 게이트웨이: mailbox id(16)
F_DUMMY = 4       # 링크 커버 트래픽


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


async def connect(host: str, port: int, static_x25519: bytes, static_mlkem: bytes, timeout: float = 10) -> Link:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
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


def pack_deliver(surb_id: bytes, payload: bytes) -> bytes:
    return surb_id + payload


def unpack_deliver(body: bytes) -> tuple[bytes, bytes]:
    from .sphinx import PAYLOAD_LEN, SURB_ID_LEN
    return body[:SURB_ID_LEN], body[SURB_ID_LEN:SURB_ID_LEN + PAYLOAD_LEN]


__all__ = ["Link", "connect", "accept", "F_PACKET", "F_DELIVER", "F_REGISTER", "F_DUMMY", "struct"]
