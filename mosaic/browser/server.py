"""MOSAIC 브라우저: 렌더링은 사용자의 기존 브라우저가 맡고, 네트워크·정책은 MOSAIC이 맡는다.

http://127.0.0.1:8118/<token>/ 을 열면 된다.
- 모든 요청은 MOSAIC 믹스넷을 거친다. 사이트(eTLD+1)마다 출구와 쿠키 저장소가 따로다.
- 스크립트는 실행되지 않는다 (정화 + CSP script-src 'none'). WebRTC·Canvas·폰트 열거 같은
  JS 기반 지문채취와 IP 누출이 원천적으로 막힌다.
- 같은 User-Agent, 같은 Accept-*, Referer 없음. 모든 사용자의 요청이 똑같아 보인다.
- HTTPS 전용이다. 평문 HTTP는 사용자가 매번 확인해야 하고, HTTPS→HTTP 리다이렉트와 HTTP 하위 리소스는 막는다.
- .mosaic 주소는 출구 없이 서비스까지 E2E로 간다.
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
from urllib.parse import parse_qs, quote, urlencode, urlsplit  # noqa: F401

from .fetcher import CookieJar, FetchError, fetch
from .sanitizer import Rewriter, rewrite_css, sanitize_html

log = logging.getLogger("mosaic.browser")

CSP = ("default-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'none'; object-src 'none'; frame-src 'none'; "
       "worker-src 'none'; connect-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'")
# 셸(우리 코드)만 스크립트를 실행한다. 외부 출처는 하나도 허용하지 않는다.
SHELL_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src 'self'; "
             "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
STATIC_DIR = __import__("pathlib").Path(__file__).with_name("static")
STATIC_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".html": "text/html; charset=utf-8"}
GEM = ('<svg viewBox="0 0 16 16"><path d="M8 1.5l6.5 6.5L8 14.5 1.5 8z" fill="none" stroke="currentColor" '
       'stroke-width="1.4"/><path d="M8 5.2L10.8 8 8 10.8 5.2 8z" fill="currentColor"/></svg>')
ICO_WARN = ('<svg viewBox="0 0 16 16"><path d="M8 2l6.5 11.5h-13z" fill="none" stroke="currentColor" stroke-width="1.5" '
            'stroke-linejoin="round"/><path d="M8 6.5v3.2M8 11.6v.1" stroke="currentColor" stroke-width="1.6" '
            'stroke-linecap="round"/></svg>')
ICO_ERR = ('<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.5"/>'
           '<path d="M5.8 5.8l4.4 4.4M10.2 5.8l-4.4 4.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>')
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


def is_secure(url: str, endpoints=()) -> bool:
    """출구 노드가 내용을 읽을 수 없는 URL인가: HTTPS(종단 TLS), .mosaic(E2E, 출구 없음),
    또는 다중 입구 엔드포인트 도메인(E2E, 출구는 조각 하나씩만 중계)."""
    sp = urlsplit(url)
    host = sp.hostname or ""
    return sp.scheme == "https" or host.endswith(".mosaic") or host in endpoints


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

    def endpoint_domains(self) -> frozenset:
        return frozenset(self.client.endpoints) if self.client is not None else frozenset()

    def discover_endpoint(self, url: str):
        """HTTPS 응답에 Mosaic-Endpoint 헤더가 있으면 .well-known 기술자를 HTTPS로 받아 검증하고 등록한다.
        도메인 인증서가 키 결합을 보증한다 (Tor의 Onion-Location과 같은 발상)."""
        from .fetcher import fetch as _fetch
        from ..endpoint import WELL_KNOWN, parse_well_known
        sp = urlsplit(url)
        if sp.scheme != "https" or self.client is None or sp.hostname in self.client.endpoints:
            return
        try:
            r = _fetch(self.socks, f"https://{sp.netloc}{WELL_KNOWN}", "site:" + site_of(sp.hostname), None, "",
                       extra={"Accept": "application/json"})
            if r.status == 200 and urlsplit(r.url).scheme == "https":
                d = parse_well_known(sp.hostname, r.body)
                self.loop.call_soon_threadsafe(self.client.add_endpoint, d)
                log.info("endpoint discovered for %s: %d entry ports", sp.hostname, len(d.ports))
        except Exception as e:      # noqa: BLE001
            log.info("endpoint discovery for %s failed: %s", sp.hostname, e)

    def new_identity(self):
        self.jar.clear()
        if self.client and self.loop:
            self.loop.call_soon_threadsafe(self.client.new_identity)

    def toolbar(self, url: str, insecure: bool = False) -> str:
        p = self.prefix
        host = urlsplit(url).hostname or ""
        badge = ""
        if host in self.endpoint_domains():
            badge = ('<span class="btn" title="이 사이트는 서로 다른 출구에서 조각을 받아 서버가 직접 합칩니다 '
                     '(종단 간 암호화)">◇ 다중 입구</span>')
        elif host.endswith(".mosaic"):
            badge = '<span class="btn" title="출구 없음, 종단 간 암호화">◇ .mosaic</span>'
        warn = ('<div id="mosaic-warn">⚠ 암호화되지 않은 HTTP 연결입니다. 출구 노드가 내용을 볼 수 있습니다.</div>'
                if insecure else "")
        return (f'<style>{STYLE}</style><div id="mosaic-bar"><a class="logo" href="{p}/">MOSAIC</a>'
                f'<form action="{p}/view" method="get"><input type="text" name="u" value="{html.escape(url)}" '
                f'placeholder="주소 또는 https://..." autocomplete="off"><button type="submit">이동</button></form>'
                f'<form action="{p}/newid" method="post" style="flex:0"><button type="submit" '
                f'title="쿠키 삭제 + 새 출구">새 신원</button></form>{badge}<a class="btn" href="{p}/status">상태</a></div>{warn}')


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
        # extra가 같은 헤더(예: CSP)를 주면 기본값을 대체한다. 두 번 보내면 브라우저가 둘 다 적용한다.
        for k, v in {**SECURITY_HEADERS, **(extra or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    @property
    def framed(self) -> bool:
        """셸의 iframe 안에서 요청됐는가. 그렇다면 페이지에 도구 막대를 넣지 않는다 (셸이 가진다)."""
        return self.headers.get("Sec-Fetch-Dest") == "iframe"

    def bar(self, url: str, insecure: bool = False) -> str:
        if self.framed:
            return ""
        return self.server_ref.toolbar(url, insecure)

    def _page(self, title: str, inner: str, status: int = 200, url: str = ""):
        s = self.server_ref
        doc = (f'<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" '
               f'content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>'
               f'<link rel="stylesheet" href="{s.prefix}/static/page.css"></head><body>'
               f'{self.bar(url)}{inner}</body></html>')
        self._send(status, doc.encode(), "text/html; charset=utf-8")

    def _notice(self, title: str, heading: str, url: str, body_html: str, actions: list[tuple[str, str, str]],
                warn: bool = False, detail: str = "", status: int = 200):
        acts = "".join(f'<a class="btn {c}" href="{html.escape(h)}">{html.escape(t)}</a>' for c, h, t in actions)
        det = f'<div class="detail">{html.escape(detail)}</div>' if detail else ""
        self._page(title, f'<div class="notice {"warn" if warn else ""}"><div class="ico">{ICO_WARN if warn else ICO_ERR}'
                          f'</div><h1>{html.escape(heading)}</h1><div class="url">{html.escape(url)}</div>{body_html}'
                          f'<div class="actions">{acts}</div>{det}</div>', status, url)

    def _err(self, msg: str, status: int = 502, url: str = ""):
        s = self.server_ref
        acts = [("primary", f"{s.prefix}/view?u={quote(url, safe='')}", "다시 시도")] if url else []
        acts.append(("quiet", f"{s.prefix}/start", "새 탭으로"))
        self._notice("연결할 수 없음", "이 페이지에 연결할 수 없습니다", url,
                     "<p>믹스넷 경로나 출구, 목적지 서버에서 요청이 실패했습니다. 잠시 후 다시 시도하거나 "
                     "<b>새 신원</b>으로 다른 출구를 써 보세요.</p>", acts, detail=msg, status=status)

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
            if sp.path == s.prefix:
                self.send_response(301)
                self.send_header("Location", s.prefix + "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif route == "/":
                self._static("shell.html", SHELL_CSP)
            elif route.startswith("/static/"):
                self._static(route[len("/static/"):], SHELL_CSP)
            elif route == "/start":
                self._start()
            elif route == "/go":
                self._go(q.get("q", ""))
            elif route == "/api/status":
                self._api_status()
            elif route == "/api/newid" and method == "POST":
                s.new_identity()
                self._send(204, b"", "text/plain")
            elif route == "/view" and "u" in q:
                self._view(q["u"], method="GET", ok=q.get("ok") == "1")
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

    def _static(self, name: str, csp: str):
        f = STATIC_DIR / name
        if "/" in name or ".." in name or f.suffix not in STATIC_TYPES or not f.is_file():
            self._send(404, b"not found", "text/plain")
            return
        hdrs = {"Content-Security-Policy": csp}
        if name == "page.css":
            hdrs = {}
        self._send(200, f.read_bytes(), STATIC_TYPES[f.suffix], hdrs)

    def _send_json(self, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self._send(200, body, "application/json; charset=utf-8")

    def _api_status(self):
        c = self.server_ref.client
        if c is None:
            self._send_json({"stats": {}, "endpoints": [], "services": []})
            return
        self._send_json({
            "stats": c.stats, "profile": c.profile.name,
            "gateways": [l.gateway.node_id.hex()[:10] for l in c.lanes],
            "split_forward": f"k∈{{{c.profile.split_k[0]}..{c.profile.split_k[1]}}}, n=k+{{{c.profile.split_extra[0]}..{c.profile.split_extra[1]}}}",
            "split_reply": f"{c.profile.reply_k}-of-{c.profile.reply_n}",
            "nodes": len(c.consensus.nodes) if c.consensus else 0,
            "open_streams": len(c.streams),
            "endpoints": sorted(c.endpoints),
            "services": sorted(c.consensus.services) if c.consensus else [],
        })

    def _go(self, query: str):
        """새 탭 검색창: 주소처럼 보이면 열고, 아니면 JS 없이 동작하는 DuckDuckGo HTML 검색."""
        qs = query.strip()
        host = qs.split("/")[0].split(":")[0].lower()
        if not qs:
            self._start()
        elif "://" in qs or (" " not in qs and "." in host):
            self._view(qs)
        else:
            self._view("https://html.duckduckgo.com/html/?" + urlencode({"q": qs}))

    def _start(self):
        s = self.server_ref
        c = s.client
        tiles = ""
        if c is not None:
            for d in sorted(c.endpoints):
                tiles += (f'<a class="tile" href="{s.prefix}/view?u={quote("http://" + d + "/", safe="")}">'
                          f'<b>◇ {html.escape(d)}</b><span>다중 입구 · 서버가 직접 합침</span></a>')
            for a in (sorted(c.consensus.services)[:6] if c.consensus else []):
                tiles += (f'<a class="tile" href="{s.prefix}/view?u={quote("http://" + a + "/", safe="")}">'
                          f'<b>◇ .mosaic 서비스</b><span>{html.escape(a)}</span></a>')
        prof = c.profile.name if c else "-"
        quick = f'<h2 class="sec">MOSAIC 네이티브</h2><div class="tiles">{tiles}</div>' if tiles else ""
        self._page("새 탭", f"""<div class="wrap">
<div class="hero">{GEM}<h1>MOSAIC</h1><p>믹스넷 위의 익명 브라우저</p></div>
<form class="search" action="{s.prefix}/go" method="get"><input name="q" placeholder="검색하거나 주소 입력"
 autocomplete="off" aria-label="검색"><button type="submit">이동</button></form>
<div class="status"><span class="tag">커버 트래픽 동작 중</span><span class="tag">조각 분할 (마름모 경로)</span>
<span class="tag">링크 X25519 + ML-KEM-768</span><span class="tag">스크립트 차단</span><span class="tag">프로파일: {html.escape(prof)}</span></div>
{quick}
<h2 class="sec">연결 방식</h2>
<div class="modes">
<div class="mode"><h3>◇ 다중 입구 <span class="k">가장 강함</span></h3><p>서버가 서로 다른 출구에서 조각을 받아 직접 합칩니다.
출구는 메시지당 조각 하나, 그것도 종단 간 암호문만 봅니다.</p></div>
<div class="mode"><h3>◇ .mosaic <span class="k">출구 없음</span></h3><p>상대 서비스까지 종단 간 암호화. 서로의 IP를 모릅니다.</p></div>
<div class="mode"><h3>🔒 HTTPS <span class="k mid">출구 경유</span></h3><p>MOSAIC을 모르는 사이트. 출구 1곳이 연결하지만 TLS 때문에
내용을 못 보고, 믹싱 때문에 당신을 추적할 수 없습니다.</p></div>
</div></div>""")

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
    def _normalize(self, u: str) -> str:
        u = u.strip()
        if "://" in u:
            return u
        host = u.split("/")[0].split(":")[0].lower()
        # .mosaic은 E2E 터널 안이므로 http로 충분하다. 일반 인터넷은 HTTPS만 쓴다 (http로 자동 후퇴하지 않음)
        return ("http://" if host.endswith(".mosaic") else "https://") + u

    def _view(self, raw: str, method: str = "GET", body: bytes | None = None, ctype: str | None = None,
              ok: bool = False):
        s = self.server_ref
        url = self._normalize(raw)
        sp = urlsplit(url)
        if sp.scheme not in ("http", "https") or not sp.hostname:
            self._err("http/https 주소만 지원합니다.", 400, raw)
            return
        if not is_secure(url, s.endpoint_domains()) and not ok:
            self._https_only(url, method)
            return
        top = site_of(sp.hostname)
        extra = {"Content-Type": ctype} if ctype else None
        try:
            r = fetch(s.socks, url, "site:" + top, s.jar, top, method, body, extra, allow_insecure=ok,
                      secure_hosts=s.endpoint_domains())
        except Exception as e:      # noqa: BLE001
            self._err(f"{type(e).__name__}: {e}", url=url)
            return
        self._deliver(r, top)

    def _https_only(self, url: str, method: str):
        s = self.server_ref
        https = "https://" + url.split("://", 1)[1]
        acts = [("primary", f"{s.prefix}/view?u={quote(https, safe='')}", "HTTPS로 열기 (권장)")]
        if method == "GET":
            acts.append(("", f"{s.prefix}/view?u={quote(url, safe='')}&ok=1", "위험을 감수하고 HTTP로 계속"))
        self._notice("HTTPS 전용 모드", "암호화되지 않은 연결을 막았습니다", url,
                     "<p>이 사이트는 MOSAIC을 지원하지 않아 마지막 구간을 <b>출구 노드</b>가 대신 연결합니다. "
                     "HTTP는 암호화되지 않아서, 출구를 장악한 사람이 페이지 내용, 입력값, 쿠키를 읽고 바꿀 수 있습니다. "
                     "누가 보냈는지는 출구도 모르지만, 내용에 이름이나 계정이 들어 있으면 그것만으로 신원이 드러납니다.</p>"
                     "<p>출구가 내용을 전혀 볼 수 없는 연결: <b>HTTPS</b>, <b>.mosaic</b>, <b>◇ 다중 입구</b> 사이트.</p>",
                     acts, warn=True)

    def _deliver(self, r, top: str):
        s = self.server_ref
        ctype = r.header("Content-Type", "application/octet-stream")
        mime = ctype.split(";")[0].strip().lower()
        insecure = not is_secure(r.url, s.endpoint_domains())
        if r.header("Mosaic-Endpoint") and urlsplit(r.url).scheme == "https":
            threading.Thread(target=s.discover_endpoint, args=(r.url,), daemon=True).start()
        if mime in ("text/html", "application/xhtml+xml"):
            text = r.body.decode(_charset(ctype, r.body), errors="replace")
            rw = Rewriter(s.prefix, top)
            out = sanitize_html(text, r.url, rw, self.bar(r.url, insecure))
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
        if not is_secure(url, s.endpoint_domains()):
            self._send(204, b"", "text/plain")    # 평문 HTTP 하위 리소스 차단 (출구가 읽을 수 있음)
            return
        try:
            r = fetch(s.socks, url, "site:" + top, s.jar, top, extra={"Accept": "*/*"},
                      secure_hosts=s.endpoint_domains())
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
                self._view(url, ok=False)
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
