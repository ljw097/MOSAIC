import asyncio
import time

import pytest

from mosaic import crypto as C
from mosaic import wire as W
from mosaic.browser.sanitizer import Rewriter, sanitize_html
from mosaic.browser.server import site_of
from mosaic.directory import Authority, Descriptor, NodeKeys, build_consensus
from mosaic.node import ReplayCache


def test_replay_cache():
    rc = ReplayCache()
    assert not rc.seen(b"a")
    assert rc.seen(b"a")


def test_descriptor_signature():
    k = NodeKeys.generate()
    d = Descriptor.create(k, "mix", "127.0.0.1", 1)
    assert d.verify()
    d.port = 2
    assert not d.verify()


def _authority_doc(descs):
    sk, _ = C.ed_keygen()
    a = Authority(sk, "127.0.0.1", 0)
    for d in descs:
        a.descs[d.node_id] = d
    return a, a.signed_document()


def test_consensus_threshold_blocks_rogue_authority():
    honest = [Descriptor.create(NodeKeys.generate(), r, "h", i) for i, r in
              enumerate(["gateway", "mix", "mix", "mix", "exit"])]
    rogue_node = Descriptor.create(NodeKeys.generate(), "exit", "evil", 9)
    a1, d1 = _authority_doc(honest)
    a2, d2 = _authority_doc(honest)
    a3, d3 = _authority_doc(honest + [rogue_node])
    c = build_consensus([d1, d2, d3], [a1.pk, a2.pk, a3.pk], 2)
    assert rogue_node.node_id not in c.nodes
    assert len(c.nodes) == 5 and c.usable()
    # 서명 위조된 문서는 무시
    d2["doc"]["descriptors"].append(rogue_node.to_json())
    with pytest.raises(RuntimeError):
        build_consensus([d2, d3], [a2.pk, a3.pk], 2)


def test_link_handshake_and_auth():
    async def run():
        k = NodeKeys.generate()
        got = asyncio.Queue()

        async def on(r, w):
            link = await W.accept(r, w, k.link_sk, k.mlkem_seed)
            got.put_nowait(await link.recv())

        srv = await asyncio.start_server(on, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        link = await W.connect("127.0.0.1", port, k.link_pk, k.mlkem_pk)
        await link.send(W.F_DUMMY, b"hi")
        t, body = await asyncio.wait_for(got.get(), 5)
        assert t == W.F_DUMMY and body.startswith(b"hi") and len(body) == W.FRAME_PT - 1
        # 잘못된 정적 키(사칭 노드) → 응답자 인증 실패
        other = NodeKeys.generate()
        with pytest.raises(W.LinkError):
            await W.connect("127.0.0.1", port, other.link_pk, k.mlkem_pk)
        srv.close()
    asyncio.run(run())


def test_sanitizer_removes_scripts_and_rewrites():
    doc = """<!doctype html><html><head><base href="https://cdn.example/"><script>alert(1)</script>
    <meta http-equiv="refresh" content="0;url=https://evil"><link rel="stylesheet" href="a.css">
    <link rel="preconnect" href="https://tracker"></head>
    <body onload="x()"><a href="javascript:alert(1)">j</a><a href="/p?q=1">p</a>
    <img src="//img.example/i.png" srcset="a.png 1x, b.png 2x" onerror="y()">
    <iframe src="https://ads"></iframe><div style="background:url(bg.png)">t</div>
    <form action="/s" method="post"><input name="q"></form><noscript><b>ns</b></noscript>
    <svg><use href="https://x/s.svg#a"/></svg><style>body{background:url('/z.png')} @import "i.css";</style>"""
    out = sanitize_html(doc, "https://site.example/dir/page", Rewriter("/T", "example"), "<div id=tb></div>")
    low = out.lower()
    for bad in ("<script", "alert(", "onload", "onerror", "<iframe", "http-equiv", "javascript:",
                "preconnect", "<base"):
        assert bad not in low, bad
    # 모든 URL이 로컬 프록시 경유
    import re
    for m in re.finditer(r'(?:href|src|action)="([^"]*)"', out):
        assert m.group(1).startswith("/T/"), m.group(1)
    assert "https%3A%2F%2Fcdn.example%2Fp%3Fq%3D1" in out             # <base> 반영
    assert "img.example%2Fi.png" in out and "b.png" in out
    assert 'url("/T/res?u=' in out and '@import "/T/res?u=' in out
    assert "__mosaic_u" in out and "<b>ns</b>" in out and "<div id=tb>" in out


def test_site_of():
    assert site_of("www.news.bbc.co.uk") == "bbc.co.uk"
    assert site_of("a.b.example.com") == "example.com"
    assert site_of("m.naver.co.kr") == "naver.co.kr"
    assert site_of("127.0.0.1") == "127.0.0.1"
