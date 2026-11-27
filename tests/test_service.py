""".mosaic 네이티브 서비스: 출구 노드가 없는 통신."""
import asyncio
import urllib.parse
import urllib.request

import pytest

from mosaic import e2e as E
from mosaic import node as N
from mosaic import sphinx as S
from mosaic import split as P
from mosaic.browser.server import BrowserServer
from mosaic.client import MosaicClient, StreamError
from mosaic.directory import ServiceDescriptor, ServiceKeys
from mosaic.service import ServiceHost
from mosaic.socks import SocksServer
from mosaic.testnet import start_testnet

SECRET = b"TOP-SECRET-PAYLOAD-0123456789"


def test_e2e_handshake_roundtrip_and_tamper():
    k = ServiceKeys.generate()
    c = E.ClientSession(b"c" * 16, k.x25519_pk, k.mlkem_pk)
    m1, m2 = c.seal(b"hello"), c.seal(b"again")
    assert m1[0] == E.T_INIT and m2[0] == E.T_UP and len(m1) == len(b"hello") + E.INIT_OVERHEAD
    srv, pt = E.ServerSession.accept(m1, k.x25519_sk, k.mlkem_seed)
    assert pt == b"hello" and srv.open(m2) == b"again"
    assert c.open(srv.seal(b"reply")) == b"reply"
    bad = bytearray(m2)
    bad[-1] ^= 1
    with pytest.raises(E.E2EError):
        srv.open(bytes(bad))
    other = ServiceKeys.generate()       # 다른 서비스 키로는 INIT을 못 연다
    with pytest.raises(E.E2EError):
        E.ServerSession.accept(c.__class__(b"d" * 16, k.x25519_pk, k.mlkem_pk).seal(b"x"),
                               other.x25519_sk, other.mlkem_seed)


def test_service_descriptor_is_self_authenticating():
    k = ServiceKeys.generate()
    d = ServiceDescriptor.create(k, [(b"g" * 16, b"m" * 16)])
    assert d.verify() and d.address.endswith(".mosaic")
    d.x25519_pk = ServiceKeys.generate().x25519_pk          # 키 바꿔치기
    assert not d.verify()
    impostor = ServiceKeys.generate()
    forged = ServiceDescriptor.create(impostor, [(b"g" * 16, b"m" * 16)])
    forged.address = k.address                              # 남의 주소 사칭
    assert not forged.verify()


def test_mosaic_service_without_exit(monkeypatch):
    delivered: list[tuple[bytes, bytes]] = []
    orig_put = N.Mailbox.put

    def spy(self, body):                 # 게이트웨이가 우편함에 넣는 모든 것을 가로챈다 (게이트웨이 장악)
        delivered.append(body)
        orig_put(self, body)

    monkeypatch.setattr(N.Mailbox, "put", spy)

    async def web(r, w):
        await r.readuntil(b"\r\n\r\n")
        body = b"<html><body><h1>native ok</h1>" + SECRET * 300 + b"</body></html>"
        w.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                % len(body) + body)
        await w.drain()
        w.close()

    async def echo(r, w):
        while d := await r.read(65536):
            w.write(d)
            await w.drain()
        w.close()

    async def run():
        tn = await start_testnet(base_port=17700, gateways=3, mixes_per_layer=4)
        ws = await asyncio.start_server(web, "127.0.0.1", 0)
        es = await asyncio.start_server(echo, "127.0.0.1", 0)
        svc = ServiceHost(ServiceKeys.generate(), tn.authority_specs, 2, ws.sockets[0].getsockname()[:2])
        await svc.start()
        echo_svc = ServiceHost(ServiceKeys.generate(), tn.authority_specs, 2, es.sockets[0].getsockname()[:2])
        await echo_svc.start()
        c = MosaicClient(tn.authority_specs, 2)
        await c.start()
        try:
            # 1) 양방향 스트림 (상향 40KB에 비밀 포함)
            st = await c.open_stream(echo_svc.address, 80)
            data = SECRET * 1400
            await st.write(data)
            got = b""
            while len(got) < len(data):
                got += await st.read(60)
            assert got == data
            st.close()

            # 2) 브라우저로 http://<addr>.mosaic/ — HTTPS 전용 모드에 걸리지 않고, 경고 띠도 없다
            socks = SocksServer(c, "127.0.0.1", 17790)
            await socks.start()
            br = BrowserServer(("127.0.0.1", 17790), "127.0.0.1", 17791, c, asyncio.get_running_loop())
            br.start()
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            url = br.url + "view?u=" + urllib.parse.quote(svc.address, safe="")
            html = await asyncio.to_thread(lambda: opener.open(url, timeout=90).read().decode())
            assert "native ok" in html and 'id="mosaic-warn"' not in html
            br.stop()

            # 3) 없는 주소
            with pytest.raises(StreamError):
                await c.open_stream("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.mosaic", 80)
        finally:
            await c.stop()
            await svc.stop()
            await echo_svc.stop()
            await tn.stop()

        # 출구 노드는 전혀 관여하지 않았다
        for n in tn.nodes:
            if n.exit_service:
                assert n.exit_service.reasm.stats["fragments"] == 0
                assert not n.exit_service.sessions
        # 게이트웨이(우편함)를 장악해 받은 조각을 전부 모아도 비밀은 보이지 않는다: E2E 암호문뿐
        assert delivered
        assert all(SECRET not in b for b in delivered)
        r = P.Reassembler()
        recovered = []
        for body in delivered:
            try:
                f = P.parse(S.check_integrity(body[S.SURB_ID_LEN:]))
            except S.SphinxError:
                continue                 # SURB 응답(아직 클라이언트 키로 감싸져 있음)·루프
            if f and (m := r.add(f)) is not None:
                recovered.append(m)
        assert recovered, "게이트웨이가 정방향 조각을 모아 복원하는 데까지는 성공해야 한다"
        assert all(m[0] in (E.T_INIT, E.T_UP) and SECRET not in m for m in recovered)

    asyncio.run(run())


def test_init_replay_after_gc_rejected(monkeypatch):
    """세션 정리 후에도 녹화된 INIT을 재전송해 요청을 다시 실행시킬 수 없다."""
    import time as _t

    from mosaic.service import E2EReceiver
    from mosaic import cells as K

    k = ServiceKeys.generate()

    class Rx(E2EReceiver):
        async def send_packet(self, first_hop, packet):
            pass

    rx = Rx(k.x25519_sk, k.mlkem_seed, ("127.0.0.1", 9))
    delivered = []
    rx.exit.on_cell = lambda cell: delivered.append(cell)
    conn = b"c" * 16
    init = E.ClientSession(conn, k.x25519_pk, k.mlkem_pk).seal(K.Cell(K.C_OPEN, conn, 0, b"{}").pack())
    rx._on_message(init)
    assert len(delivered) == 1
    rx._on_message(init)                          # 같은 INIT 재전송: 무시
    assert len(delivered) == 1
    rx.last_used[conn] = _t.time() - 10_000       # 오래 쉰 세션 → 정리
    rx.gc()
    assert conn not in rx.sessions and conn in rx.tombstones
    rx._on_message(init)                          # 정리 뒤 재전송: 묘비로 거부
    assert len(delivered) == 1
    # 오래된 INIT(타임스탬프 만료)은 묘비가 없어도 거부
    monkeypatch.setattr(_t, "time", lambda: 1_000_000.0)
    old = E.ClientSession(b"d" * 16, k.x25519_pk, k.mlkem_pk).seal(b"x")
    monkeypatch.undo()
    with pytest.raises(E.E2EError):
        E.ServerSession.accept(old, k.x25519_sk, k.mlkem_seed)
