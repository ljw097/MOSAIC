"""epoch별 Sphinx 키 로테이션: 스트림은 끊기지 않고, 지난 키는 지워져 녹화된 패킷을 다시 열 수 없다."""
import asyncio
import os

import pytest

from mosaic import directory as D
from mosaic import sphinx as S
from mosaic.client import MosaicClient
from mosaic.testnet import start_testnet


def test_epoch_rotation_forward_secrecy(monkeypatch):
    monkeypatch.setattr(D, "EPOCH_LEN", 4)

    async def echo(r, w):
        while d := await r.read(65536):
            w.write(d)
            await w.drain()
        w.close()

    async def run():
        es = await asyncio.start_server(echo, "127.0.0.1", 0)
        tn = await start_testnet(base_port=18400, allow_private=True, mixes_per_layer=2, gateways=2)
        c = MosaicClient(tn.authority_specs, 2)
        await c.start()
        mix = next(n for n in tn.nodes if n.role == "mix")
        captured: list[bytes] = []
        orig = mix.on_packet

        def spy(pkt):
            if len(captured) < 5:
                captured.append(pkt)       # 공격자가 링크에서 녹화한 패킷이라고 본다
            orig(pkt)

        mix.on_packet = spy
        try:
            st = await c.open_stream("127.0.0.1", es.sockets[0].getsockname()[1])
            start_epoch = D.current_epoch()
            rounds = 0
            # 3개 epoch에 걸쳐 같은 스트림으로 계속 왕복 (SURB가 epoch 경계를 넘어 쓰인다)
            while D.current_epoch() < start_epoch + 3:
                msg = os.urandom(3000)
                await st.write(msg)
                got = b""
                while len(got) < len(msg):
                    got += await st.read(30)
                assert got == msg
                rounds += 1
                await asyncio.sleep(0.3)
            assert rounds >= 5
            st.close()

            assert captured
            # 재전송 방지: 아직 키가 있는 동안 같은 패킷을 다시 넣어도 처리되지 않는다 (캐시 또는 키 없음)
            # 전방향 안전성: 녹화 당시의 epoch 키는 이미 지워졌다 → 노드 자신도 이 패킷을 열 수 없다
            e = D.current_epoch()
            assert all(x >= e - 1 for x in mix.epoch_keys), mix.epoch_keys.keys()
            for pkt in captured:
                for sk, _pk in mix.epoch_keys.values():
                    with pytest.raises(S.SphinxError):
                        S.process_packet(sk, pkt)
            before = mix.stats["undecryptable"]
            mix.on_packet = orig
            mix.on_packet(captured[0])
            assert mix.stats["undecryptable"] == before + 1
        finally:
            await c.stop()
            await tn.stop()
            es.close()

    asyncio.run(run())


def test_replay_blocked_within_epoch():
    from mosaic.directory import NodeKeys
    from mosaic.node import Node

    async def run():
        n = Node(NodeKeys.generate(), "mix", "127.0.0.1", 0, [], 1)
        e = D.current_epoch()
        sk, pk = n.epoch_keys[e]
        hops = [S.Hop(n.keys.node_id, pk)]
        pkt, _ = S.create_packet(hops, [S.Routing(S.FINAL_DROP, 0, b"", b"")], b"x")
        n.on_packet(pkt)
        assert n.stats["replays"] == 0
        n.on_packet(pkt)
        assert n.stats["replays"] == 1
        d = n.descriptor()
        assert d.verify() and d.sphinx_key(e) == pk and (e + 1) in d.sphinx_epochs
        d.sphinx_epochs[e + 1] = os.urandom(32)       # 다음 epoch 키 바꿔치기 → 서명 깨짐
        assert not d.verify()

    asyncio.run(run())
