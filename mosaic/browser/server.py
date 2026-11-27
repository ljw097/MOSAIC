"""MOSAIC 브라우저: 렌더링은 사용자의 기존 브라우저가 맡고, 네트워크·정책은 MOSAIC이 맡는다.

http://127.0.0.1:8118/<token>/ 을 열면 된다.
- 모든 요청은 MOSAIC 믹스넷을 거친다. 사이트(eTLD+1)마다 출구와 쿠키 저장소가 따로다.
- 스크립트는 실행되지 않는다 (정화 + CSP script-src 'none'). WebRTC·Canvas·폰트 열거 같은
  JS 기반 지문채취와 IP 누출이 원천적으로 막힌다.
- 같은 User-Agent, 같은 Accept-*, Referer 없음. 모든 사용자의 요청이 똑같아 보인다.
- HTTPS를 먼저 시도한다. 평문 HTTP로 내려가면 경고 띠를 표시한다.
- 무작위 토큰이 경로에 들어간다. 같은 컴퓨터의 다른 웹페이지가 이 프록시를 악용(CSRF)
  하기 어렵다.
"""
from __future__ import annotations

import html
import json
import logging
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from .fetcher import CookieJar, FetchError, fetch
from .sanitizer import Rewriter, rewrite_css, sanitize_html

log = logging.getLogger("mosaic.browser")

CSP = ("default-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'none'; object-src 'none'; frame-src 'none'; "
       "worker-src 'none'; connect-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
}
PASS_TYPES = ("image/", "font/", "audio/", "video/", "text/plain", "application/pdf", "application/font",
              "application/x-font", "application/vnd.ms-fontobject")
MULTI_SUFFIX = {"co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "co.uk", "org.uk", "ac.uk", "co.jp",
                "ne.jp", "or.jp", "com.au", "net.au", "com.cn", "com.br", "co.in", "github.io"}


def site_of(host: str) -> str:
    import ipaddress
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        pass
    labels = (host or "").lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIX:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


STYLE = """
#mosaic-bar{all:initial;position:sticky;top:0;z-index:2147483647;display:flex;gap:8px;align-items:center;
 padding:8px 12px;background:#101418;color:#e8edf2;font:14px/1.4 system-ui,sans-serif;border-bottom:2px solid #3fb68b}
#mosaic-bar *{font:inherit;color:inherit}
#mosaic-bar form{display:flex;flex:1;gap:6px;margin:0}
#mosaic-bar input[type=text]{flex:1;min-width:0;padding:6px 10px;border-radius:6px;border:1px solid #3a4550;background:#1b2229}
#mosaic-bar button,#mosaic-bar a.btn{padding:6px 10px;border-radius:6px;border:1px solid #3a4550;background:#222b33;
 cursor:pointer;text-decoration:none;white-space:nowrap}
#mosaic-bar .logo{font-weight:700;color:#3fb68b;text-decoration:none}
#mosaic-warn{all:initial;display:block;padding:6px 12px;background:#5a2a00;color:#ffd9b0;font:13px system-ui,sans-serif}
"""


class BrowserServer:
    def __init__(self, socks: tuple[str, int], host: str = "127.0.0.1", port: int = 8118, client=None, loop=None):
        self.socks, self.host, self.port = socks, host, port
        self.client, self.loop = client, loop
        self.token = secrets.token_urlsafe(16)
        self.jar = CookieJar()
        self.httpd: ThreadingHTTPServer | None = None

    @property
    def prefix(self) -> str:
        return f"/{self.token}"

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}{self.prefix}/"

    def start(self):
        srv = self

        class H(Handler):
            server_ref = srv

        self.httpd = ThreadingHTTPServer((self.host, self.port), H)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True, name="mosaic-browser").start()
        log.info("MOSAIC browser at %s", self.url)

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()

    def new_identity(self):
        self.jar.clear()
        if self.client and self.loop:
            self.loop.call_soon_threadsafe(self.client.new_identity)

    def toolbar(self, url: str, insecure: bool = False) -> str:
        p = self.prefix
        warn = ('<div id="mosaic-warn">⚠ 암호화되지 않은 HTTP 연결입니다. 출구 노드가 내용을 볼 수 있습니다.</div>'
                if insecure else "")
        return (f'<style>{STYLE}</style><div id="mosaic-bar"><a class="logo" href="{p}/">MOSAIC</a>'
                f'<form action="{p}/view" method="get"><input type="text" name="u" value="{html.escape(url)}" '
                f'placeholder="주소 또는 https://..." autocomplete="off"><button type="submit">이동</button></form>'
                f'<form action="{p}/newid" method="post" style="flex:0"><button type="submit" '
                f'title="쿠키 삭제 + 새 출구">새 신원</button></form><a class="btn" href="{p}/status">상태</a></div>{warn}')


class Handler(BaseHTTPRequestHandler):
    server_ref: BrowserServer
    protocol_version = "HTTP/1.1"
    server_version = "MOSAIC"
    sys_version = ""

    def log_message(self, fmt, *args):
        log.debug("browser: " + fmt, *args)

    # ------------------------------------------------------------ 응답 헬퍼
    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _page(self, title: str, inner: str, status: int = 200, url: str = ""):
        s = self.server_ref
        doc = (f'<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" '
               f'content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title><style>'
               'body{margin:0;font:15px/1.6 system-ui,sans-serif;background:#f6f8fa;color:#1d2329}'
               'main{max-width:760px;margin:32px auto;padding:0 16px}code{background:#e8ecef;padding:1px 4px;'
               'border-radius:4px}table{border-collapse:collapse}td{padding:4px 12px;border-bottom:1px solid #dde}'
               '@media (prefers-color-scheme:dark){body{background:#0d1114;color:#dfe6ec}code{background:#20282f}'
               'td{border-color:#2a333b}}</style></head><body>'
               f'{s.toolbar(url)}<main>{inner}</main></body></html>')
        self._send(status, doc.encode(), "text/html; charset=utf-8")

    def _err(self, msg: str, status: int = 502, url: str = ""):
        self._page("오류", f"<h2>요청 실패</h2><p>{html.escape(msg)}</p>", status, url)

    # ------------------------------------------------------------ 라우팅
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self._route("GET", None)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(n, 10 * 1024 * 1024)) if n else b""
        self._route("POST", body)

    def _route(self, method: str, body: bytes | None):
        s = self.server_ref
        sp = urlsplit(self.path)
        if not sp.path.startswith(s.prefix + "/") and sp.path != s.prefix:
            self._send(404, b"not found", "text/plain")
            return
        route = sp.path[len(s.prefix):] or "/"
        q = {k: v[0] for k, v in parse_qs(sp.query, keep_blank_values=True).items()}
        try:
            if route == "/":
                self._home()
            elif route == "/view" and "u" in q:
                self._view(q["u"], method="GET")
            elif route == "/res" and "u" in q:
                self._res(q["u"], q.get("top", ""))
            elif route == "/form":
                self._form(method, q, body)
            elif route == "/newid" and method == "POST":
                s.new_identity()
                self._page("새 신원", "<h2>새 신원</h2><p>쿠키를 모두 지웠습니다. 이제부터 모든 사이트가 새 출구를 씁니다.</p>")
            elif route == "/status":
                self._status()
            else:
                self._send(404, b"not found", "text/plain")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _home(self):
        self._page("MOSAIC", """
<h1>MOSAIC 익명 브라우저</h1>
<p>모든 요청은 5개 홉 믹스넷(게이트웨이 → 믹스 3계층 → 출구)을 지나갑니다. 홉마다 패킷이 무작위로 지연되고
섞이며, 실제 트래픽은 커버 트래픽 속에 섞여 보이지 않습니다.</p>
<ul>
<li>JavaScript를 실행하지 않습니다. 지문채취와 WebRTC IP 누출이 원천적으로 막힙니다.</li>
<li>사이트마다 출구와 쿠키 저장소가 따로라서, 사이트들이 서로 정보를 모아 당신을 추적할 수 없습니다.</li>
<li>HTTPS를 먼저 시도합니다. 출구 노드도 내용을 볼 수 없습니다.</li>
</ul>
<p>위 주소창에 주소를 입력하세요. 예: <code>example.com</code></p>""")

    def _status(self):
        c = self.server_ref.client
        rows = ""
        if c is not None:
            st = dict(c.stats)
            st["profile"] = c.profile.name
            st["gateways"] = ", ".join(l.gateway.node_id.hex()[:12] for l in c.lanes) or "-"
            st["split_forward"] = f"k∈{c.profile.split_k}, n=k+{c.profile.split_extra}"
            st["split_reply"] = f"{c.profile.reply_k}-of-{c.profile.reply_n}"
            st["nodes_in_consensus"] = len(c.consensus.nodes) if c.consensus else 0
            st["open_streams"] = len(c.streams)
            rows = "".join(f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>" for k, v in st.items())
        self._page("상태", f"<h2>MOSAIC 클라이언트 상태</h2><table>{rows}</table>"
                         "<p>sent_cover/sent_loop: 커버 트래픽, recv_dummy: 게이트웨이가 보낸 더미 프레임 수.</p>")

    # ------------------------------------------------------------ 페이지
    def _normalize(self, u: str) -> tuple[str, bool]:
        u = u.strip()
        if "://" not in u:
            return "https://" + u, True        # HTTPS 우선, 실패 시 http 시도
        return u, False

    def _view(self, raw: str, method: str = "GET", body: bytes | None = None, ctype: str | None = None):
        s = self.server_ref
        url, guessed = self._normalize(raw)
        sp = urlsplit(url)
        if sp.scheme not in ("http", "https") or not sp.hostname:
            self._err("http/https 주소만 지원합니다.", 400, raw)
            return
        top = site_of(sp.hostname)
        extra = {"Content-Type": ctype} if ctype else None
        try:
            r = fetch(s.socks, url, "site:" + top, s.jar, top, method, body, extra)
        except (FetchError, OSError, Exception) as e:      # noqa: BLE001
            if guessed:
                try:
                    url = "http://" + raw.strip()
                    r = fetch(s.socks, url, "site:" + top, s.jar, top, method, body, extra)
                except Exception as e2:      # noqa: BLE001
                    self._err(f"{e2}", url=raw)
                    return
            else:
                self._err(f"{type(e).__name__}: {e}", url=url)
                return
        self._deliver(r, top)

    def _deliver(self, r, top: str):
        s = self.server_ref
        ctype = r.header("Content-Type", "application/octet-stream")
        mime = ctype.split(";")[0].strip().lower()
        insecure = urlsplit(r.url).scheme == "http"
        if mime in ("text/html", "application/xhtml+xml"):
            text = r.body.decode(_charset(ctype, r.body), errors="replace")
            rw = Rewriter(s.prefix, top)
            out = sanitize_html(text, r.url, rw, s.toolbar(r.url, insecure))
            out = '<meta charset="utf-8">' + out if "<head" not in out[:2000].lower() else out.replace(
                "<head>", '<head><meta charset="utf-8">', 1)
            self._send(r.status, out.encode("utf-8"), "text/html; charset=utf-8")
        elif mime == "text/css":
            css = r.body.decode(_charset(ctype, r.body), errors="replace")
            self._send(r.status, rewrite_css(css, r.url, Rewriter(s.prefix, top)).encode(), "text/css; charset=utf-8")
        elif mime.startswith(PASS_TYPES) or mime in ("image/svg+xml",):
            extra = {"Content-Disposition": "inline"}
            if mime == "image/svg+xml":
                extra["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
            self._send(r.status, r.body, mime, extra)
        else:
            self._send(r.status, r.body, "application/octet-stream",
                       {"Content-Disposition": "attachment"})

    def _res(self, url: str, top: str):
        s = self.server_ref
        sp = urlsplit(url)
        if sp.scheme not in ("http", "https"):
            self._send(400, b"", "text/plain")
            return
        top = top or site_of(sp.hostname or "")
        try:
            r = fetch(s.socks, url, "site:" + top, s.jar, top, extra={"Accept": "*/*"})
        except Exception:      # noqa: BLE001
            self._send(502, b"", "text/plain")
            return
        mime = r.header("Content-Type", "").split(";")[0].strip().lower()
        if mime in ("application/javascript", "text/javascript", "application/x-javascript", "text/html"):
            self._send(204, b"", "text/plain")   # 스크립트/문서는 리소스로 쓰지 않는다
            return
        self._deliver(r, top)

    def _form(self, method: str, q: dict, body: bytes | None):
        if method == "GET":
            target = q.pop("__mosaic_u", "")
            sp = urlsplit(target)
            url = target.split("?")[0] + "?" + urlencode(q) if q else target
            if sp.scheme in ("http", "https"):
                self._view(url)
            else:
                self._err("잘못된 폼 대상", 400)
            return
        fields = parse_qs((body or b"").decode(errors="replace"), keep_blank_values=True)
        target = (fields.pop("__mosaic_u", [""]) or [""])[0]
        if urlsplit(target).scheme not in ("http", "https"):
            self._err("잘못된 폼 대상", 400)
            return
        data = urlencode([(k, v) for k, vs in fields.items() for v in vs]).encode()
        self._view(target, "POST", data, "application/x-www-form-urlencoded")


def _charset(ctype: str, body: bytes) -> str:
    import codecs
    import re
    m = re.search(r"charset=([\w-]+)", ctype, re.I) or re.search(rb"""<meta[^>]+charset=["']?([\w-]+)""",
                                                                 body[:4096], re.I)
    if m:
        cs = m.group(1)
        cs = cs.decode() if isinstance(cs, bytes) else cs
        try:
            codecs.lookup(cs)
            return cs
        except LookupError:
            pass
    return "utf-8"


__all__ = ["BrowserServer", "site_of", "json", "quote"]
