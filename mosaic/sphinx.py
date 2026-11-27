"""MOSAIC 패킷 포맷: Sphinx (Danezis & Goldberg, 2009) 의 X25519 구현.

성질
- 모든 패킷은 길이가 같다 (PACKET_LEN). 경로 길이·위치가 드러나지 않는다.
- 각 홉은 자신의 이전/다음 홉 외에는 아무것도 알 수 없다.
- 홉마다 그룹 원소(alpha)가 블라인딩되어, 입력 패킷과 출력 패킷을 비트 단위로
  연결(linking)할 수 없다.
- 헤더 무결성은 홉별 HMAC, 페이로드는 LIONESS 광폭 블록 암호로 보호 →
  변조(tagging) 시 최종 수신자가 감지한다.
- SURB(Single-Use Reply Block): 수신자가 송신자의 주소/신원을 모른 채 답장한다.
- 재전송(replay) 방지: 공유비밀에서 유도한 태그를 노드가 기억한다.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from . import crypto as C

MAX_HOPS = 5
ROUTING_LEN = 32           # flag(1) delay_ms(4) node/mailbox id(16) extra(11)
GAMMA_LEN = 32
HOP_LEN = ROUTING_LEN + GAMMA_LEN
BETA_LEN = MAX_HOPS * HOP_LEN
HEADER_LEN = 32 + BETA_LEN + GAMMA_LEN   # 384
PAYLOAD_LEN = 2048
PACKET_LEN = HEADER_LEN + PAYLOAD_LEN    # 2432
ID_LEN = 16
INTEGRITY = b"\0" * 16                   # 페이로드 앞 16바이트: 태깅 탐지용

# 라우팅 플래그
RELAY = 0x01          # 다음 노드로 지연 후 전달
DELIVER_EXIT = 0x02   # 이 노드(출구)가 최종 수신자
DELIVER_MAILBOX = 0x03  # 이 노드(게이트웨이)가 클라이언트 우편함으로 전달
FINAL_DROP = 0x04     # 커버(루프) 트래픽: 폐기
DELIVER_ENDPOINT = 0x05  # 이 노드(출구)가 페이로드의 조각을 MOSAIC 엔드포인트의 입구 포트로 전달


class SphinxError(Exception):
    pass


@dataclass
class Hop:
    node_id: bytes     # 16 bytes
    pubkey: bytes      # X25519 Sphinx 공개키


@dataclass
class Routing:
    flag: int
    delay_ms: int
    target: bytes      # 다음 노드 id 혹은 우편함 id
    extra: bytes       # 11 bytes (SURB id 등)

    def pack(self) -> bytes:
        return struct.pack(">BI", self.flag, self.delay_ms) + self.target.ljust(16, b"\0")[:16] + self.extra.ljust(11, b"\0")[:11]

    @classmethod
    def unpack(cls, b: bytes) -> "Routing":
        flag, delay = struct.unpack(">BI", b[:5])
        return cls(flag, delay, b[5:21], b[21:32])


def _keys(s: bytes) -> dict:
    return {
        "rho": C.kdf(s, b"rho"),
        "mu": C.kdf(s, b"mu"),
        "pi": C.kdf(s, b"pi"),
        "tag": C.kdf(s, b"replay"),
    }


def _blind(alpha: bytes, s: bytes) -> bytes:
    return C.h(b"blind", alpha, s)


def _derive_secrets(hops: list[Hop]) -> tuple[bytes, list[bytes]]:
    """클라이언트 측: 각 홉의 공유비밀 계산. alpha_0 = x*G,
    s_i = sk_i * b_{i-1} * ... * b_0 * x * G = b_{i-1}(...b_0(x*PK_i))."""
    while True:
        x = os.urandom(32)
        alpha = C.x25519_pub(x)
        blinds: list[bytes] = []
        secrets: list[bytes] = []
        try:
            for hop in hops:
                s = C.x25519(x, hop.pubkey)
                for b in blinds:
                    s = C.x25519(b, s)
                secrets.append(s)
                b = _blind(alpha, s)
                blinds.append(b)
                alpha = C.x25519(b, alpha)
        except ValueError:          # 극히 드문 저차수 점
            continue
        return C.x25519_pub(x), secrets


def create_header(hops: list[Hop], routes: list[Routing]) -> tuple[bytes, list[bytes]]:
    """routes[i] = hops[i]가 처리 후 따를 라우팅 지시. 반환: (header, 홉별 공유비밀)."""
    n = len(hops)
    if not 1 <= n <= MAX_HOPS or len(routes) != n:
        raise SphinxError("bad path length")
    alpha0, secrets = _derive_secrets(hops)
    ks = [_keys(s) for s in secrets]
    streams = [C.stream(k["rho"], BETA_LEN + HOP_LEN) for k in ks]

    # 필러(filler) 생성
    phi = b""
    for i in range(n - 1):
        phi = C.xor(phi + b"\0" * HOP_LEN, streams[i][BETA_LEN + HOP_LEN - len(phi) - HOP_LEN:])
    # 마지막 홉
    pad_len = BETA_LEN - HOP_LEN * (n - 1) - ROUTING_LEN
    last_plain = routes[-1].pack() + os.urandom(pad_len)
    beta = C.xor(last_plain, streams[-1][: len(last_plain)]) + phi
    gamma = C.mac(ks[-1]["mu"], beta)
    for i in range(n - 2, -1, -1):
        plain = routes[i].pack() + gamma + beta[: BETA_LEN - HOP_LEN]
        beta = C.xor(plain, streams[i][:BETA_LEN])
        gamma = C.mac(ks[i]["mu"], beta)
    return alpha0 + beta + gamma, secrets


def wrap_payload(secrets: list[bytes], body: bytes) -> bytes:
    """정방향 페이로드: 마지막 홉부터 역순으로 LIONESS 암호화."""
    if len(body) > PAYLOAD_LEN - len(INTEGRITY):
        raise SphinxError("payload too large")
    p = INTEGRITY + body.ljust(PAYLOAD_LEN - len(INTEGRITY), b"\0")
    for s in reversed(secrets):
        p = C.Lioness(_keys(s)["pi"]).encrypt(p)
    return p


def create_packet(hops: list[Hop], routes: list[Routing], body: bytes) -> tuple[bytes, list[bytes]]:
    header, secrets = create_header(hops, routes)
    return header + wrap_payload(secrets, body), secrets


@dataclass
class Processed:
    routing: Routing
    packet: bytes | None    # RELAY일 때 다음 패킷
    payload: bytes          # 이 홉에서 복호화된 페이로드
    tag: bytes


def process_packet(sk: bytes, packet: bytes) -> Processed:
    if len(packet) != PACKET_LEN:
        raise SphinxError("bad packet length")
    alpha = packet[:32]
    beta = packet[32: 32 + BETA_LEN]
    gamma = packet[32 + BETA_LEN: HEADER_LEN]
    payload = packet[HEADER_LEN:]
    try:
        s = C.x25519(sk, alpha)
    except ValueError as e:
        raise SphinxError("bad alpha") from e
    k = _keys(s)
    if not C.ct_eq(C.mac(k["mu"], beta), gamma):
        raise SphinxError("header MAC mismatch")
    B = C.xor(beta + b"\0" * HOP_LEN, C.stream(k["rho"], BETA_LEN + HOP_LEN))
    routing = Routing.unpack(B[:ROUTING_LEN])
    new_payload = C.Lioness(k["pi"]).decrypt(payload)
    if routing.flag == RELAY:
        next_gamma = B[ROUTING_LEN:HOP_LEN]
        next_beta = B[HOP_LEN:]
        new_alpha = C.x25519(_blind(alpha, s), alpha)
        return Processed(routing, new_alpha + next_beta + next_gamma + new_payload, new_payload, k["tag"])
    return Processed(routing, None, new_payload, k["tag"])


def check_integrity(payload: bytes) -> bytes:
    if payload[:16] != INTEGRITY:
        raise SphinxError("payload integrity failure (tagging?)")
    return payload[16:]


# ---------------------------------------------------------------- SURB
SURB_ID_LEN = 8
SURB_LEN = ID_LEN + HEADER_LEN + 32   # first hop id + header + k0 = 432


@dataclass
class SURB:
    first_hop: bytes
    header: bytes
    k0: bytes

    def pack(self) -> bytes:
        return self.first_hop + self.header + self.k0

    @classmethod
    def unpack(cls, b: bytes) -> "SURB":
        return cls(b[:ID_LEN], b[ID_LEN:ID_LEN + HEADER_LEN], b[ID_LEN + HEADER_LEN:SURB_LEN])


@dataclass
class SURBKeys:
    k0: bytes
    secrets: list[bytes]


def create_surb(hops: list[Hop], routes: list[Routing]) -> tuple[SURB, SURBKeys]:
    header, secrets = create_header(hops, routes)
    k0 = os.urandom(32)
    return SURB(hops[0].node_id, header, k0), SURBKeys(k0, secrets)


def use_surb(surb: SURB, body: bytes) -> tuple[bytes, bytes]:
    """응답자 측: (first_hop_id, packet)"""
    if len(body) > PAYLOAD_LEN - len(INTEGRITY):
        raise SphinxError("payload too large")
    p = INTEGRITY + body.ljust(PAYLOAD_LEN - len(INTEGRITY), b"\0")
    return surb.first_hop, surb.header + C.Lioness(surb.k0).encrypt(p)


def open_surb_reply(keys: SURBKeys, payload: bytes) -> bytes:
    """SURB 생성자(클라이언트) 측: 각 홉이 적용한 LIONESS 복호화를 되돌린다."""
    p = payload
    for s in reversed(keys.secrets):
        p = C.Lioness(_keys(s)["pi"]).encrypt(p)
    p = C.Lioness(keys.k0).decrypt(p)
    return check_integrity(p)
