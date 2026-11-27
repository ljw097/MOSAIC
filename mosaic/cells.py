"""종단(클라이언트 <-> 출구) 셀 포맷. Sphinx 페이로드 안에 실려 다닌다.

  type(1) session(16) seq(4) len(2) data(...)

세션 id는 무작위이며 클라이언트 신원과 무관하다. 출구는 세션 id와 SURB만 볼 뿐
클라이언트가 누구인지, 어느 게이트웨이를 쓰는지 알 수 없다.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .sphinx import INTEGRITY, PAYLOAD_LEN, SURB, SURB_LEN

HDR = struct.Struct(">B16sIH")
BODY_LEN = PAYLOAD_LEN - len(INTEGRITY)
DATA_MAX = BODY_LEN - HDR.size          # 2009
SURBS_PER_CELL = (DATA_MAX - 1) // SURB_LEN   # 4

# 상향 (client -> exit)
C_OPEN = 1
C_DATA = 2
C_CLOSE = 3
C_SURBS = 4
C_DROP = 5        # 커버 트래픽 (출구에서 폐기)
# 하향 (exit -> client)
D_CONNECTED = 11
D_DATA = 12
D_CLOSE = 13
D_ERROR = 14


@dataclass
class Cell:
    type: int
    session: bytes
    seq: int
    data: bytes

    def pack(self) -> bytes:
        if len(self.data) > DATA_MAX:
            raise ValueError("cell data too large")
        return HDR.pack(self.type, self.session, self.seq, len(self.data)) + self.data

    @classmethod
    def unpack(cls, b: bytes) -> "Cell":
        t, s, q, n = HDR.unpack_from(b)
        if n > DATA_MAX:
            raise ValueError("bad cell length")
        return cls(t, s, q, b[HDR.size: HDR.size + n])


def pack_surbs(surbs: list[SURB]) -> bytes:
    assert len(surbs) <= SURBS_PER_CELL
    return bytes([len(surbs)]) + b"".join(s.pack() for s in surbs)


def unpack_surbs(data: bytes) -> list[SURB]:
    n = data[0]
    if n > SURBS_PER_CELL:
        raise ValueError("too many surbs")
    return [SURB.unpack(data[1 + i * SURB_LEN: 1 + (i + 1) * SURB_LEN]) for i in range(n)]
