"""브라우저 셸 라우트: CSP 분리, 상태 API, 정적 파일 경로 제한, iframe 안에서는 도구 막대 생략."""
import json
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
