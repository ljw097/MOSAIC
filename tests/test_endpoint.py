"""다중 입구 엔드포인트: 서버가 서로 다른 출구에서 조각을 받아 직접 합친다 (출구 장악 무력화)."""
import asyncio
import json
import os

import pytest

from mosaic import e2e as E
from mosaic import split as P
from mosaic.client import MosaicClient
from mosaic.endpoint import EndpointHost, EndpointKeys, entry_header, parse_entry, parse_well_known
from mosaic.exit import ExitService
from mosaic.testnet import start_testnet

SECRET = b"CARD-4111-1111-1111-1111|PIN-0000"


def test_entry_header_roundtrip():
    f = P.split(b"x" * 100, 2, 3)[0]
    body = entry_header("shop.example", 7002, b"F" * 32) + f.pack()
    host, port, fp, frag = parse_entry(body.ljust(2032, b"\0"))
    assert (host, port, fp) == ("shop.example", 7002, b"F" * 32) and P.parse(frag).piece == f.piece


def test_well_known_binding():
    k = EndpointKeys.generate()
    ep = EndpointHost(k, "shop.example", "127.0.0.1", [7001, 7002, 7003], ("127.0.0.1", 1))
    doc = ep.well_known()
    d = parse_well_known("shop.example", doc)
    assert d.ports == [7001, 7002, 7003]
    with pytest.raises(ValueError):                 # 다른 도메인에 붙여 쓰기
        parse_well_known("evil.example", doc)
    j = json.loads(doc)
    j["x25519_pk"] = EndpointKeys.generate().x25519_pk.hex()   # 키 바꿔치기
    with pytest.raises(ValueError):
        parse_well_known("shop.example", json.dumps(j).encode())


def test_server_reassembles_from_distinct_exits(monkeypatch):
    seen_by_exits: list[bytes] = []
    orig = ExitService._to_endpoint

    async def spy(self, host, port, fp, frag):     # 모든 출구를 공격자가 장악했다고 가정하고 조각을 수집
        seen_by_exits.append(frag)
        await orig(self, host, port, fp, frag)

    monkeypatch.setattr(ExitService, "_to_endpoint", spy)

    async def echo(r, w):
        while d := await r.read(65536):
            w.write(d)
            await w.drain()
        w.close()

    async def run():
        tn = await start_testnet(base_port=17900, allow_private=True, gateways=3, mixes_per_layer=4, exits=4)
        es = await asyncio.start_server(echo, "127.0.0.1", 0)
        ep = EndpointHost(EndpointKeys.generate(), "shop.example", "127.0.0.1", [0, 0, 0],
                          es.sockets[0].getsockname()[:2])
        await ep.start()
        c = MosaicClient(tn.authority_specs, 2)
        await c.start()
        c.add_endpoint(parse_well_known("shop.example", ep.well_known()))
        c.path_log = []
        # 출구 하나는 완전히 장악돼 블랙홀: 받은 조각을 서버로 넘기지 않는다
        exits = [n for n in tn.nodes if n.exit_service]
        evil = exits[0]
        evil.exit_service.on_endpoint_payload = lambda payload: None
        try:
            st = await c.open_stream("shop.example", 443)
            data = SECRET * 1200
            await st.write(data)
            got = b""
            while len(got) < len(data):
                got += await st.read(60)
            assert got == data
            st.close()
        finally:
            await c.stop()
            await ep.stop()
            await tn.stop()
            es.close()

        # (1) 어느 출구도 메시지를 모으거나 연결을 대신 맺지 않았다
        for n in exits:
            assert n.exit_service.reasm.stats["fragments"] == 0 and not n.exit_service.sessions
        # (2) 서버는 입구 3곳 모두로 조각을 받았다
        assert all(v > 0 for v in ep.entry_stats.values()), ep.entry_stats
        # (3) 메시지마다 조각은 서로 다른 출구로 (출구 4대 → 한 출구가 보는 조각 ≤ ceil(n/4))
        for msg_paths in c.path_log:
            finals = [p[-1] for p in msg_paths]
            assert max(finals.count(x) for x in finals) <= -(-len(finals) // 4)
        # (4) 모든 출구의 조각을 다 모아 합쳐도 E2E 암호문뿐
        assert seen_by_exits
        r = P.Reassembler()
        msgs = [m for f in seen_by_exits if (m := r.add(P.parse(f))) is not None]
        assert msgs and all(m[0] in (E.T_INIT, E.T_UP) and SECRET not in m for m in msgs)
        assert all(SECRET not in f for f in seen_by_exits)

    asyncio.run(run())
