"""브라우저 셸 라우트: CSP 분리, 상태 API, 정적 파일 경로 제한, iframe 안에서는 도구 막대 생략."""
import json
import re
import urllib.parse
import urllib.error
import urllib.request

from mosaic.browser.server import BrowserServer

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        r = OPENER.open(req, timeout=10)
        return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def test_shell_routes():
    br = BrowserServer(("127.0.0.1", 1), "127.0.0.1", 17981)
    br.start()
    try:
        st, h, body = _get(br.url)
        assert st == 200 and b'id="omnibox"' in body
        csp = h["Content-Security-Policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert len(h.get_all("Content-Security-Policy")) == 1          # CSP가 겹쳐 보내지지 않는다

        st, h, body = _get(br.url + "static/shell.js")
        assert st == 200 and h["Content-Type"].startswith("text/javascript")
        for bad in ("static/..%2Fserver.py", "static/../server.py", "static/nope.js"):
            assert _get(br.url + bad)[0] == 404

        st, h, body = _get(br.url + "api/status")
        assert st == 200 and json.loads(body)["endpoints"] == []

        # 새 탭 페이지: 셸 iframe 안에서는 페이지 자체 도구 막대가 없고, 스크립트 금지 CSP
        st, h, body = _get(br.url + "start", {"Sec-Fetch-Dest": "iframe"})
        assert st == 200 and b"mosaic-bar" not in body and b"<script" not in body
        assert "script-src 'none'" in h["Content-Security-Policy"] and "frame-ancestors 'self'" in h["Content-Security-Policy"]
        st, h, body = _get(br.url + "start")                             # 셸 밖에서 직접 열면 도구 막대 포함
        assert b"mosaic-bar" in body

        # HTTPS 전용 안내는 iframe 안에서도 동작
        st, h, body = _get(br.url + "view?u=http%3A%2F%2Fexample.com%2F", {"Sec-Fetch-Dest": "iframe"})
        assert "암호화되지 않은 연결을 막았습니다" in body.decode()
        assert _get(br.url.replace(br.token, "wrong"))[0] == 404          # 토큰 없이는 접근 불가
    finally:
        br.stop()


def test_profile_api_and_client_switch():
    import pytest

    from mosaic.client import PROFILES, MosaicClient

    br = BrowserServer(("127.0.0.1", 1), "127.0.0.1", 17982)
    br.start()
    try:
        req = urllib.request.Request(br.url + "api/profile?name=paranoid", method="POST")
        with pytest.raises(urllib.error.HTTPError) as ei:       # 클라이언트 없이는 거부
            OPENER.open(req, timeout=10)
        assert ei.value.code == 400
    finally:
        br.stop()
    c = MosaicClient([], 1)
    c.set_profile("paranoid")
    assert c.profile is PROFILES["paranoid"]
    with pytest.raises(ValueError):
        c.set_profile("turbo")
    c.exit_for["user:site:example.com"] = object()
    c.exit_for["user:site:other.org"] = object()
    c.new_route("user:site:example.com")                        # 그 사이트만 새 출구
    assert list(c.exit_for) == ["user:site:other.org"]


def test_conn_pool_isolation():
    from mosaic.browser.fetcher import ConnPool

    class FakeConn:
        def __init__(self):
            self.sock, self.closed = object(), False

        def close(self):
            self.closed = True

    pool = ConnPool()
    a, b = FakeConn(), FakeConn()
    pool.put(("https", "x.com", 443, "site:x.com", None), a)
    pool.put(("https", "y.com", 443, "site:y.com", None), b)
    # 다른 사이트(격리 키)의 연결은 절대 재사용되지 않는다
    got, reused = pool.get(("https", "x.com", 443, "site:y.com", None), FakeConn)
    assert not reused and got is not a
    got, reused = pool.get(("https", "x.com", 443, "site:x.com", None), FakeConn)
    assert reused and got is a
    pool.drop("site:y.com")
    assert b.closed


def test_download_prompt_and_http_approval(monkeypatch):
    import mosaic.browser.server as BS
    from mosaic.browser.fetcher import Response

    calls = []

    def fake_fetch(proxy, url, iso, jar=None, top="", method="GET", body=None, extra=None, **kw):
        calls.append((url, kw.get("allow_insecure")))
        if url.endswith(".pdf"):
            return Response(200, "OK", [("Content-Type", "application/pdf")], b"%PDF-1.4 secret", url)
        return Response(200, "OK", [("Content-Type", "text/html")], b"<title>ok</title><img src='/i.png'>", url)

    monkeypatch.setattr(BS, "fetch", fake_fetch)
    br = BrowserServer(("127.0.0.1", 1), "127.0.0.1", 17983)
    br.start()
    try:
        # PDF는 바로 렌더링하지 않고 경고 페이지 → 확인 링크로만 받는다
        st, h, body = _get(br.url + "view?u=" + urllib.parse.quote("https://ex.com/report.pdf", safe=""),
                           {"Sec-Fetch-Dest": "iframe"})
        text = body.decode()
        assert "이 파일을 저장할까요?" in text and "%PDF" not in text and "report.pdf" in text
        did = re.search(r"download\?id=([\w-]+)", text).group(1)
        st, h, body = _get(br.url + "download?id=" + did)
        assert body.startswith(b"%PDF") and h["Content-Disposition"].startswith("attachment")
        assert _get(br.url + "download?id=" + did)[0] == 404            # 한 번만
        # HTTP 허락은 사이트 단위로 기억되고, 새 신원이면 잊는다
        http_url = "http://plain.example/a"
        st, h, body = _get(br.url + "view?u=" + urllib.parse.quote(http_url, safe=""))
        assert "암호화되지 않은 연결" in body.decode()
        _get(br.url + "view?u=" + urllib.parse.quote(http_url, safe="") + "&ok=1")
        st, h, body = _get(br.url + "view?u=" + urllib.parse.quote("http://plain.example/b", safe=""))
        assert "<title>ok</title>" in body.decode()
        br.new_identity()
        st, h, body = _get(br.url + "view?u=" + urllib.parse.quote("http://plain.example/b", safe=""))
        assert "암호화되지 않은 연결" in body.decode()
    finally:
        br.stop()
