"""메시지 분할: k-of-n 임계 분산 (Krawczyk "Secret Sharing Made Short", SSMS).

한 메시지를 n개 조각으로 나눠 서로 다른 경로로 보내고, 출구(또는 클라이언트)에서 다시
모은다. 경로를 선형 도면으로 그리면 마름모(◇) 모양이 된다.

                ┌─ G1 ─ L1a ─ L2a ─ L3a ─┐
   송신자 ◇─────┼─ G2 ─ L1b ─ L2b ─ L3b ─┼─────◇ 수신자(출구)
                └─ G1 ─ L1c ─ L2c ─ L3c ─┘

구성
  1. 메시지마다 새로운 무작위 키 K를 만든다. C = ChaCha20-Poly1305_K(m).
  2. C를 k개 행으로 자르고, GF(2^8) 위의 n×k Vandermonde 행렬로 n개 조각을 만든다
     (Rabin IDA). 아무 k개 조각이든 있으면 C를 복원할 수 있다.
  3. K는 차수 k-1인 다항식으로 Shamir 분할한다. 조각 i에는 x = i+1에서의 값을 넣는다.

성질
  - k-1개 이하의 조각으로는 K에 대한 정보가 전혀 없다 (정보이론적). 따라서 내용도 모른다.
    즉 노드 하나가 조각 하나를 붙잡아도(점거해도) 메시지를 장악할 수 없다.
  - 최대 n-k개 조각이 사라지거나 노드에 붙잡혀도 메시지가 도착한다 (가용성).
  - 조각을 변조하면 AEAD 태그가 깨진다. 남는 조각이 있으면 다른 조합으로 다시 시도한다.
  - 대역폭 비용은 약 n/k배다.
"""
from __future__ import annotations

import itertools
import os
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .sphinx import INTEGRITY, PAYLOAD_LEN

# ---------------------------------------------------------------- GF(2^8)
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x ^= (_x << 1) ^ (0x11B if _x & 0x80 else 0)   # 생성원 3 곱셈 (x*3 = x*2 ^ x)
    _x &= 0xFF
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def gmul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def ginv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF(256) inverse of 0")
    return _EXP[255 - _LOG[a]]


def gpow(a: int, e: int) -> int:
    if e == 0:
        return 1
    return 0 if a == 0 else _EXP[(_LOG[a] * e) % 255]


_MUL = [bytes(gmul(c, v) for v in range(256)) for c in range(256)]


def vmul(c: int, data: bytes) -> bytes:
    """바이트열 전체에 GF(256) 상수 곱 (translate 테이블로 벡터화)."""
    return data.translate(_MUL[c])


def vxor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).to_bytes(len(a), "little")


def lincomb(coeffs: list[int], vecs: list[bytes]) -> bytes:
    acc = bytes(len(vecs[0]))
    for c, v in zip(coeffs, vecs):
        if c:
            acc = vxor(acc, vmul(c, v))
    return acc


def matinv(m: list[list[int]]) -> list[list[int]]:
    n = len(m)
    a = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(m)]
    for col in range(n):
        piv = next((r for r in range(col, n) if a[r][col]), None)
        if piv is None:
            raise ValueError("singular matrix")
        a[col], a[piv] = a[piv], a[col]
        inv = ginv(a[col][col])
        a[col] = [gmul(inv, v) for v in a[col]]
        for r in range(n):
            if r != col and a[r][col]:
                f = a[r][col]
                a[r] = [v ^ gmul(f, w) for v, w in zip(a[r], a[col])]
    return [row[n:] for row in a]


# ---------------------------------------------------------------- 조각 포맷
MAGIC = 0xF5
FRAG_HDR = struct.Struct(">B16sBBBH32sH")    # magic id idx k n total key_share piece_len
BODY_LEN = PAYLOAD_LEN - len(INTEGRITY)       # 2032
FRAG_CAP = BODY_LEN - FRAG_HDR.size           # 1976
TAG_LEN = 16
MAX_N = 16
_AD = b"MOSAIC-split-v1"


def max_message(k: int) -> int:
    """k개 조각으로 실어 나를 수 있는 최대 평문 길이."""
    return k * FRAG_CAP - TAG_LEN


@dataclass
class Fragment:
    msg_id: bytes
    idx: int
    k: int
    n: int
    total: int
    key_share: bytes
    piece: bytes

    def pack(self) -> bytes:
        return FRAG_HDR.pack(MAGIC, self.msg_id, self.idx, self.k, self.n, self.total, self.key_share,
                             len(self.piece)) + self.piece


def parse(body: bytes) -> Fragment | None:
    if not body or body[0] != MAGIC or len(body) < FRAG_HDR.size:
        return None
    _m, mid, idx, k, n, total, ks, plen = FRAG_HDR.unpack_from(body)
    if not (1 <= k <= n <= MAX_N) or idx >= n or plen > FRAG_CAP or FRAG_HDR.size + plen > len(body):
        return None
    return Fragment(mid, idx, k, n, total, ks, body[FRAG_HDR.size: FRAG_HDR.size + plen])


def split(msg: bytes, k: int, n: int, msg_id: bytes | None = None) -> list[Fragment]:
    if not 1 <= k <= n <= MAX_N:
        raise ValueError("need 1 <= k <= n <= 16")
    if len(msg) > max_message(k):
        raise ValueError("message too large for k")
    key = os.urandom(32)
    ct = ChaCha20Poly1305(key).encrypt(b"\0" * 12, msg, _AD)    # 키는 메시지마다 새로 → 고정 nonce 안전
    l = -(-len(ct) // k)
    padded = ct.ljust(k * l, b"\0")
    rows = [padded[j * l:(j + 1) * l] for j in range(k)]
    poly = [key] + [os.urandom(32) for _ in range(k - 1)]       # Shamir: a_0 = K
    mid = msg_id or os.urandom(16)
    out = []
    for i in range(n):
        x = i + 1
        coeffs = [gpow(x, j) for j in range(k)]                  # Vandermonde 행
        out.append(Fragment(mid, i, k, n, len(ct), lincomb(coeffs, poly), lincomb(coeffs, rows)))
    return out


def combine(frags: list[Fragment]) -> bytes:
    """정확히 k개의 서로 다른 조각에서 복원. 실패 시 ValueError."""
    k = frags[0].k
    if len(frags) != k or len({f.idx for f in frags}) != k:
        raise ValueError("need k distinct fragments")
    inv = matinv([[gpow(f.idx + 1, j) for j in range(k)] for f in frags])
    key = lincomb(inv[0], [f.key_share for f in frags])
    pieces = [f.piece for f in frags]
    if len({len(p) for p in pieces}) != 1:
        raise ValueError("inconsistent piece lengths")
    rows = [lincomb(inv[j], pieces) for j in range(k)]
    ct = b"".join(rows)[: frags[0].total]
    try:
        return ChaCha20Poly1305(key).decrypt(b"\0" * 12, ct, _AD)
    except Exception as e:      # noqa: BLE001
        raise ValueError("fragment authentication failed") from e


@dataclass
class _Pending:
    frags: dict[int, Fragment] = field(default_factory=dict)
    t: float = field(default_factory=time.time)
    tried: set = field(default_factory=set)


class Reassembler:
    """조각을 모아 k개가 되면 복원한다. 늦게 도착하는 나머지 조각은 조용히 버린다."""

    def __init__(self, ttl: float = 180, max_pending: int = 20_000):
        self.ttl, self.max_pending = ttl, max_pending
        self.pending: dict[bytes, _Pending] = {}
        self.done: dict[bytes, float] = {}
        self.stats = {"fragments": 0, "messages": 0, "late": 0, "bad": 0}

    def add(self, f: Fragment) -> bytes | None:
        self.stats["fragments"] += 1
        if f.msg_id in self.done:
            self.stats["late"] += 1
            return None
        p = self.pending.get(f.msg_id)
        if p is None:
            if len(self.pending) >= self.max_pending:
                self.gc(force=True)
            p = self.pending[f.msg_id] = _Pending()
        first = next(iter(p.frags.values()), None)
        if first and (first.k, first.n, first.total) != (f.k, f.n, f.total):
            self.stats["bad"] += 1
            return None
        p.frags.setdefault(f.idx, f)
        if len(p.frags) < f.k:
            return None
        for combo in itertools.combinations(sorted(p.frags), f.k):
            if combo in p.tried:
                continue
            p.tried.add(combo)
            try:
                msg = combine([p.frags[i] for i in combo])
            except ValueError:
                self.stats["bad"] += 1
                continue
            del self.pending[f.msg_id]
            self.done[f.msg_id] = time.time()
            self.stats["messages"] += 1
            return msg
        return None

    def gc(self, force: bool = False):
        now = time.time()
        ttl = self.ttl / 4 if force else self.ttl
        self.pending = {k: v for k, v in self.pending.items() if now - v.t < ttl}
        self.done = {k: t for k, t in self.done.items() if now - t < self.ttl * 2}
