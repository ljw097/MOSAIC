"""MOSAIC SOCKS5를 경유하는 HTTP/1.1 클라이언트. 모든 사용자가 같은 지문을 갖도록 헤더를 통일한다."""
from __future__ import annotations

import gzip
import http.client
import socket
import ssl
import struct
import threading
import zlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# 모든 MOSAIC 사용자가 똑같은 헤더를 보낸다 (군중 속에 숨기)
UNIFORM_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
}
MAX_BODY = 25 * 1024 * 1024


class FetchError(Exception):
    pass


def socks_connect(proxy: tuple[str, int], host: str, port: int, isolation: str, timeout: float) -> socket.socket:
    s = socket.create_connection(proxy, timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x02")
        if s.recv(2) != b"\x05\x02":
            raise FetchError("SOCKS auth negotiation failed")
        u = isolation.encode()[:255]
        s.sendall(b"\x01" + bytes([len(u)]) + u + b"\x01x")
        if s.recv(2)[1:2] != b"\x00":
            raise FetchError("SOCKS auth failed")
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
        resp = _recvn(s, 10)
        if resp[1] != 0:
            raise FetchError(f"mixnet could not reach {host}:{port} (SOCKS code {resp[1]})")
        return s
    except Exception:
        s.close()
        raise


def _recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise FetchError("SOCKS connection closed")
        b += c
    return b


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    url: str

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return default

    def headers_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]


@dataclass
class CookieJar:
    """최상위 사이트별로 분리된 메모리 쿠키 저장소 (first-party isolation). 디스크에 남지 않는다."""
    jars: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def header(self, top: str, host: str) -> str:
        with self.lock:
            j = self.jars.get(top, {})
            out = {}
            for dom, cookies in j.items():
                if host == dom or host.endswith("." + dom):
                    out.update(cookies)
            return "; ".join(f"{k}={v}" for k, v in out.items())

    def store(self, top: str, host: str, set_cookies: list[str]):
        with self.lock:
            j = self.jars.setdefault(top, {})
            for sc in set_cookies:
                parts = [p.strip() for p in sc.split(";")]
                if "=" not in parts[0]:
                    continue
                name, value = parts[0].split("=", 1)
                dom = host
                for p in parts[1:]:
                    if p.lower().startswith("domain="):
                        d = p[7:].lstrip(".").lower()
                        if host == d or host.endswith("." + d):
                            dom = d
                j.setdefault(dom, {})[name] = value

    def clear(self):
        with self.lock:
            self.jars.clear()


class _Conn(http.client.HTTPConnection):
    def __init__(self, host, port, proxy, isolation, timeout, tls: bool):
        super().__init__(host, port, timeout=timeout)
        self._proxy, self._iso, self._tls = proxy, isolation, tls

    def connect(self):
        s = socks_connect(self._proxy, self.host, self.port, self._iso, self.timeout)
        if self._tls:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            s = ctx.wrap_socket(s, server_hostname=self.host)
        self.sock = s


def fetch(proxy: tuple[str, int], url: str, isolation: str, jar: CookieJar | None = None, top: str = "",
          method: str = "GET", body: bytes | None = None, extra: dict | None = None,
          timeout: float = 120, max_redirects: int = 8, allow_insecure: bool = False) -> Response:
    for _ in range(max_redirects + 1):
        sp = urlsplit(url)
        if sp.scheme not in ("http", "https") or not sp.hostname:
            raise FetchError("unsupported URL")
        if sp.scheme == "http" and not sp.hostname.endswith(".mosaic") and not allow_insecure:
            raise FetchError(f"HTTPS 전용 모드: 평문 HTTP로 가는 요청/리다이렉트를 막았습니다 ({url})")
        port = sp.port or (443 if sp.scheme == "https" else 80)
        conn = _Conn(sp.hostname, port, proxy, isolation, timeout, sp.scheme == "https")
        headers = dict(UNIFORM_HEADERS)
        if extra:
            headers.update(extra)
        if jar is not None:
            c = jar.header(top, sp.hostname)
            if c:
                headers["Cookie"] = c
        path = (sp.path or "/") + (f"?{sp.query}" if sp.query else "")
        try:
            conn.request(method, path, body=body, headers=headers)
            r = conn.getresponse()
            data = r.read(MAX_BODY + 1)
        finally:
            conn.close()
        if len(data) > MAX_BODY:
            raise FetchError("response too large")
        hdrs = r.getheaders()
        if jar is not None:
            jar.store(top, sp.hostname, [v for k, v in hdrs if k.lower() == "set-cookie"])
        enc = r.getheader("Content-Encoding", "").lower()
        try:
            if enc == "gzip":
                data = gzip.decompress(data)
            elif enc == "deflate":
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    data = zlib.decompress(data, -15)
        except Exception as e:      # noqa: BLE001
            raise FetchError(f"decompression failed: {e}") from e
        if r.status in (301, 302, 303, 307, 308) and r.getheader("Location"):
            from urllib.parse import urljoin
            url = urljoin(url, r.getheader("Location"))
            if r.status in (301, 302, 303):
                method, body = "GET", None
            continue
        return Response(r.status, r.reason, hdrs, data, url)
    raise FetchError("too many redirects")
