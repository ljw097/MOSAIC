import os

import pytest

from mosaic import crypto as C
from mosaic import sphinx as S


def _path(n):
    keys = [C.x25519_keygen() for _ in range(n)]
    hops = [S.Hop(os.urandom(16), pk) for _, pk in keys]
    routes = [S.Routing(S.RELAY, 10 * i, hops[i + 1].node_id, b"") for i in range(n - 1)]
    routes.append(S.Routing(S.DELIVER_EXIT, 0, b"\x07" * 16, b"final"))
    return keys, hops, routes


@pytest.mark.parametrize("n", range(1, S.MAX_HOPS + 1))
def test_forward_all_lengths(n):
    keys, hops, routes = _path(n)
    pkt, _ = S.create_packet(hops, routes, b"secret message")
    seen = [pkt]
    for i, (sk, _) in enumerate(keys):
        assert len(pkt) == S.PACKET_LEN
        p = S.process_packet(sk, pkt)
        assert p.routing.flag == routes[i].flag
        assert p.routing.delay_ms == routes[i].delay_ms
        if p.packet:
            assert p.routing.target == hops[i + 1].node_id
            pkt = p.packet
            seen.append(pkt)
    assert p.routing.extra.rstrip(b"\0") == b"final"
    assert S.check_integrity(p.payload).rstrip(b"\0") == b"secret message"
    # 홉 사이 패킷은 비트 단위로 연결되지 않는다 (alpha, beta, payload 모두 바뀜)
    for a, b in zip(seen, seen[1:]):
        assert a[:32] != b[:32] and a[S.HEADER_LEN:] != b[S.HEADER_LEN:]


def test_surb_roundtrip():
    keys, hops, routes = _path(4)
    surb, sk = S.create_surb(hops, routes)
    surb = S.SURB.unpack(surb.pack())
    first, pkt = S.use_surb(surb, b"anonymous reply")
    assert first == hops[0].node_id
    for k, _ in keys:
        p = S.process_packet(k, pkt)
        pkt = p.packet or pkt
    assert S.open_surb_reply(sk, p.payload).rstrip(b"\0") == b"anonymous reply"


def test_header_tamper_detected():
    keys, hops, routes = _path(3)
    pkt, _ = S.create_packet(hops, routes, b"x")
    bad = bytearray(pkt)
    bad[100] ^= 1
    with pytest.raises(S.SphinxError):
        S.process_packet(keys[0][0], bytes(bad))


def test_payload_tagging_detected():
    keys, hops, routes = _path(3)
    pkt, _ = S.create_packet(hops, routes, b"x")
    bad = bytearray(pkt)
    bad[S.HEADER_LEN + 500] ^= 1       # 페이로드 한 비트 변조
    pkt = bytes(bad)
    for k, _ in keys:
        p = S.process_packet(k, pkt)
        pkt = p.packet or pkt
    with pytest.raises(S.SphinxError):
        S.check_integrity(p.payload)


def test_wrong_key_rejected():
    keys, hops, routes = _path(2)
    pkt, _ = S.create_packet(hops, routes, b"x")
    with pytest.raises(S.SphinxError):
        S.process_packet(C.x25519_keygen()[0], pkt)


def test_lioness_roundtrip():
    l = C.Lioness(os.urandom(32))
    m = os.urandom(S.PAYLOAD_LEN)
    assert l.decrypt(l.encrypt(m)) == m
    assert l.encrypt(m) != m
