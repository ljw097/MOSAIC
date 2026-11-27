"""종단(클라이언트 <-> 출구) 셀 포맷. Sphinx 페이로드 안에 실려 다닌다.

  type(1) session(16) seq(4) len(2) data(...)

세션 id는 무작위이며 클라이언트 신원과 무관하다. 출구는 세션 id와 SURB만 볼 뿐
클라이언트가 누구인지, 어느 게이트웨이를 쓰는지 알 수 없다.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .sphinx import SURB, SURB_LEN
from .split import max_message

HDR = struct.Struct(">B16sIH")


def data_max(k: int) -> int:
    """k-of-n 분할 시 셀 하나에 실을 수 있는 데이터 최대 길이."""
    return max_message(k) - HDR.size


def sets_per_cell(k: int, set_size: int) -> int:
    return (data_max(k) - 2) // (set_size * SURB_LEN)

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
        return HDR.pack(self.type, self.session, self.seq, len(self.data)) + self.data

    @classmethod
    def unpack(cls, b: bytes) -> "Cell":
        t, s, q, n = HDR.unpack_from(b)
        if HDR.size + n > len(b):
            raise ValueError("bad cell length")
        return cls(t, s, q, b[HDR.size: HDR.size + n])


def pack_surb_sets(sets: list[list[SURB]], epoch: int) -> bytes:
    """SURB 묶음: 한 묶음 = 응답 메시지 하나를 n개 조각으로 보낼, 경로가 서로 겹치지 않는 SURB n개.
    epoch = SURB를 만들 때 쓴 노드 키의 epoch. 노드가 그 키를 지우면 SURB도 못 쓰므로 받는 쪽이 버린다."""
    size = len(sets[0])
    return bytes([len(sets), size]) + struct.pack(">I", epoch) + b"".join(s.pack() for st in sets for s in st)


SETS_HDR = 6


def unpack_surb_sets(data: bytes) -> tuple[list[list[SURB]], int]:
    count, size = data[0], data[1]
    if not 1 <= size <= 16 or SETS_HDR + count * size * SURB_LEN > len(data):
        raise ValueError("bad surb sets")
    epoch = struct.unpack_from(">I", data, 2)[0]
    out, off = [], SETS_HDR
    for _ in range(count):
        st = []
        for _ in range(size):
            st.append(SURB.unpack(data[off: off + SURB_LEN]))
            off += SURB_LEN
        out.append(st)
    return out, epoch
