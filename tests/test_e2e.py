"""전체 망 통합 테스트: 권한 서버 3대(2-of-3), 게이트웨이 2, 믹스 3계층×2, 출구 2."""
import asyncio
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mosaic.browser.server import BrowserServer
from mosaic.client import MosaicClient
from mosaic.socks import SocksServer
from mosaic.testnet import start_testnet


class Site(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = (b"<html><head><script>steal()</script></head><body><h1>hidden service ok</h1>"
                b"<img src='/pic.png'><a href='/next'>n</a>" + b"x" * 50000 + b"</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=42")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_end_to_end():
    web = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    wport = web.server_address[1]

    async def echo(r, w):
        while d := await r.read(65536):
            w.write(bytes(b ^ 0x55 for b in d))
            await w.drain()
        w.close()

    async def run():
        es = await asyncio.start_server(echo, "127.0.0.1", 0)
        eport = es.sockets[0].getsockname()[1]
        tn = await start_testnet(base_port=17300, allow_private=True, mixes_per_layer=2, gateways=2)
        c = MosaicClient(tn.authority_specs, 2)
        await c.start()
        try:
            # 1) 원시 스트림 (상향 100KB, 하향 100KB)
            st = await c.open_stream("127.0.0.1", eport)
            data = bytes(range(256)) * 400
            await st.write(data)
            got = b""
            while len(got) < len(data):
                got += await st.read(30)
            assert got == bytes(b ^ 0x55 for b in data)
            st.close()

            # 2) SOCKS5 + 브라우저 (HTTP, 정화)
            socks = SocksServer(c, "127.0.0.1", 17390)
            await socks.start()
            br = BrowserServer(("127.0.0.1", 17390), "127.0.0.1", 17391, c, asyncio.get_running_loop())
            br.start()
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            # HTTPS 전용 모드: 평문 HTTP는 확인 페이지로 막힌다
            url = br.url + "view?u=" + urllib.parse.quote(f"http://127.0.0.1:{wport}/", safe="")
            blocked = await asyncio.to_thread(lambda: opener.open(url, timeout=60).read().decode())
            assert "HTTPS 전용 모드" in blocked and "hidden service ok" not in blocked
            url += "&ok=1"
            html, hdrs = await asyncio.to_thread(lambda: (lambda r: (r.read().decode(), r.headers))(
                opener.open(url, timeout=60)))
            assert "hidden service ok" in html
            assert "steal()" not in html and "<script" not in html
            assert "script-src 'none'" in hdrs["Content-Security-Policy"]
            assert "/res?u=" in html
            assert br.jar.header("127.0.0.1", "127.0.0.1") == "sid=42"

            # 3) 커버 트래픽과 루프가 실제로 흐른다
            await asyncio.sleep(1.5)
            assert c.stats["sent_cover"] > 0 and c.stats["recv_dummy"] > 0
            assert c.stats["loops_back"] > 0
            # 출구는 클라이언트의 우편함 id를 본 적이 없다 (세션 id만 앎)
            assert all(l.mailbox not in s.sid for l in c.lanes for n in tn.nodes if n.exit_service
                       for s in n.exit_service.sessions.values())
            br.stop()
        finally:
            await c.stop()
            await tn.stop()
            es.close()

    asyncio.run(run())
    web.shutdown()
