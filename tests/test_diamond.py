"""마름모(◇) 다중 경로 분할 테스트."""
import asyncio
import itertools
import os
import random

import pytest

from mosaic import split as P
from mosaic.client import MosaicClient, disjoint_paths
from mosaic.directory import Consensus, Descriptor, NodeKeys
from mosaic.testnet import start_testnet


# ---------------------------------------------------------------- 분할/복원
@pytest.mark.parametrize("k,n", [(1, 1), (2, 3), (3, 5), (4, 4), (5, 9)])
def test_any_k_of_n_recovers(k, n):
    m = os.urandom(random.randint(1, P.max_message(k)))
    frags = P.split(m, k, n)
    for combo in itertools.combinations(frags, k):
        assert P.combine(list(combo)) == m


def test_fewer_than_k_reveals_nothing_usable():
    m = b"attack at dawn" * 100
    frags = P.split(m, 3, 5)
    # k-1개 조각으로 강제로 k=2인 것처럼 합쳐도 인증 실패 → 복원 불가
    fake = [P.Fragment(f.msg_id, f.idx, 2, f.n, f.total, f.key_share, f.piece) for f in frags[:2]]
    with pytest.raises(ValueError):
        P.combine(fake)
    # 조각 하나의 조각 데이터에 평문이 그대로 드러나지 않는다
    assert b"attack" not in frags[0].piece


def test_tampered_fragment_is_routed_around():
    m = os.urandom(3000)
    frags = P.split(m, 2, 4)
    bad = frags[0]
    bad.piece = bytes([bad.piece[0] ^ 1]) + bad.piece[1:]
    r = P.Reassembler()
    assert r.add(frags[0]) is None
    assert r.add(frags[1]) is None          # (0,1) 조합: 변조로 인증 실패
    assert r.add(frags[2]) == m             # (1,2) 조합으로 복원
    assert r.add(frags[3]) is None          # 늦게 온 조각은 무시
    assert r.stats["bad"] >= 1


# ---------------------------------------------------------------- 경로 선택
def _consensus(per_layer):
    nodes = {}
    for role, cnt in (("gateway", 2), ("mix", 3 * per_layer), ("exit", 1)):
        for i in range(cnt):
            d = Descriptor.create(NodeKeys.generate(), role, "h", i)
            nodes[d.node_id] = d
    c = Consensus(1, nodes)
    c.assign_layers()
    return c


def test_disjoint_paths_never_share_a_mix():
    c = _consensus(5)
    for n in range(1, 6):
        paths = disjoint_paths(c, n)
        assert len(paths) == n
        for layer in range(3):
            ids = [p[layer].node_id for p in paths]
            assert len(set(ids)) == n                       # 계층마다 서로 다른 노드
            assert all(p[layer].layer == layer for p in paths)


def test_disjoint_paths_spread_evenly_when_short():
    c = _consensus(2)
    paths = disjoint_paths(c, 5)
    for layer in range(3):
        counts = {}
        for p in paths:
            counts[p[layer].node_id] = counts.get(p[layer].node_id, 0) + 1
        assert max(counts.values()) - min(counts.values()) <= 1


# ---------------------------------------------------------------- 장악된 노드가 있어도 동작
def test_captured_mix_cannot_block_or_see_whole_message():
    async def echo(r, w):
        while d := await r.read(65536):
            w.write(bytes(b ^ 0x5A for b in d))
            await w.drain()
        w.close()

    async def run():
        es = await asyncio.start_server(echo, "127.0.0.1", 0)
        eport = es.sockets[0].getsockname()[1]
        tn = await start_testnet(base_port=17500, allow_private=True, gateways=3, mixes_per_layer=4)
        c = MosaicClient(tn.authority_specs, 2)
        await c.start()
        c.path_log = []
        # 믹스 하나를 공격자가 장악: 지나가는 패킷을 전부 버린다 (블랙홀)
        evil = next(n for n in tn.nodes if n.role == "mix")
        swallowed = []
        evil.on_packet = lambda pkt: swallowed.append(pkt)
        try:
            st = await c.open_stream("127.0.0.1", eport)
            data = os.urandom(60_000)
            await st.write(data)
            got = b""
            while len(got) < len(data):
                got += await st.read(60)
            assert got == bytes(b ^ 0x5A for b in data)
            st.close()
        finally:
            await c.stop()
            await tn.stop()
            es.close()

        assert swallowed, "장악된 노드로도 조각이 지나가야 테스트가 의미 있다"
        # 마름모: 메시지마다 각 믹스 계층에서 한 노드는 최대 ceil(n/4)개 조각만 본다
        evil_id = evil.keys.node_id
        assert c.path_log
        for msg_paths in c.path_log:
            n = len(msg_paths)
            for layer in (1, 2, 3):
                ids = [p[layer] for p in msg_paths]
                assert max(ids.count(x) for x in ids) <= -(-n // 4)
            assert sum(p.count(evil_id) for p in msg_paths) <= -(-n // 4)
        # 게이트웨이 여러 곳에 나눠 실린다
        assert any(len({p[0] for p in mp}) > 1 for mp in c.path_log)
        assert c.stats["messages_reassembled"] > 0

    asyncio.run(run())
