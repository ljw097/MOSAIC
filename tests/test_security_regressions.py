"""보안 재검토에서 찾은 문제들의 회귀 테스트."""
import asyncio

from mosaic import wire as W
from mosaic.browser.fetcher import CookieJar
from mosaic.directory import Authority, Descriptor, NodeKeys, fetch_consensus
from mosaic.node import Node
from mosaic import crypto as C


def test_mailbox_cannot_be_hijacked_with_public_id():
    """서비스 intro의 우편함 id는 공개된다. id만으로 REGISTER해도 그 우편함을 가로챌 수 없다."""
    async def run():
        sk, _ = C.ed_keygen()
        auth = Authority(sk, "127.0.0.1", 0)
        gw = Node(NodeKeys.generate(), "gateway", "127.0.0.1", 0, [], 1, loop_rate=0, downstream_rate=200)
        gw.server = await asyncio.start_server(gw._on_conn, "127.0.0.1", 0)
        port = gw.server.sockets[0].getsockname()[1]
        k = gw.keys
        secret = b"S" * 32
        victim_id = W.mailbox_id(secret)

        owner = await W.connect("127.0.0.1", port, k.link_pk, k.mlkem_pk)
        await owner.send(W.F_REGISTER, secret)
        attacker = await W.connect("127.0.0.1", port, k.link_pk, k.mlkem_pk)
        await attacker.send(W.F_REGISTER, victim_id.ljust(32, b"\0"))     # 옛 방식: 공개 id를 그대로
        await asyncio.sleep(0.2)
        assert gw.mailboxes[victim_id].link is not None
        gw.mailboxes[victim_id].put(b"\x01" * 8 + b"secret-payload".ljust(2048, b"\0"))

        async def first_deliver(link):
            for _ in range(200):
                t, body = await link.recv()
                if t == W.F_DELIVER:
                    return body
            return None

        got = await asyncio.wait_for(first_deliver(owner), 5)
        assert got and b"secret-payload" in got
        # 공격자 링크로는 더미만 온다
        for _ in range(20):
            t, _b = await asyncio.wait_for(attacker.recv(), 5)
            assert t == W.F_DUMMY
        owner.close(); attacker.close()
        for t in gw.tasks:
            t.cancel()
        gw.server.close()
        del auth

    asyncio.run(run())


def test_consensus_larger_than_64kb():
    """노드가 많아 합의 문서가 64KB를 넘어도 받을 수 있어야 한다 (전에는 노드 20여 개에서 실패)."""
    async def run():
        sk, _ = C.ed_keygen()
        a = Authority(sk, "127.0.0.1", 0)
        a.server = await asyncio.start_server(a._handle, "127.0.0.1", 0)
        port = a.server.sockets[0].getsockname()[1]
        roles = ["gateway"] * 5 + ["mix"] * 45 + ["exit"] * 10
        for i, r in enumerate(roles):
            d = Descriptor.create(NodeKeys.generate(), r, "10.0.0.1", 7000 + i)
            a.descs[d.node_id] = d
        c = await fetch_consensus([("127.0.0.1", port, a.pk)], 1)
        assert len(c.nodes) == 60 and c.usable()
        a.server.close()

    asyncio.run(run())


def test_secure_cookies_never_sent_over_http():
    jar = CookieJar()
    jar.store("ex.com", "ex.com", ["sid=1; Secure; HttpOnly", "pref=dark"], secure=True)
    assert jar.header("ex.com", "ex.com", secure=True) == "sid=1; pref=dark"
    assert jar.header("ex.com", "ex.com", secure=False) == "pref=dark"        # 평문이면 Secure 쿠키 제외
    jar.store("ex.com", "ex.com", ["evil=1; Secure"], secure=False)           # 평문 응답이 Secure 쿠키를 심을 수 없다
    assert "evil" not in jar.header("ex.com", "ex.com")
    jar.store("ex.co.kr", "a.ex.co.kr", ["x=1; Domain=co.kr"], secure=True)   # 공개 접미사 도메인 쿠키 거부
    assert jar.header("ex.co.kr", "other.co.kr") == ""
    jar.store("ex.com", "ex.com", ["pref=; Max-Age=0"], secure=True)          # 삭제
    assert jar.header("ex.com", "ex.com") == "sid=1"
