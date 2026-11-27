"""로컬 SOCKS5 프록시 (RFC 1928, CONNECT 전용). 어떤 애플리케이션이든 MOSAIC으로 보낼 수 있다.

- 도메인 이름은 해석하지 않은 채 출구까지 넘긴다 (socks5h). 로컬 DNS 누출이 없다.
- 사용자명/비밀번호 인증(RFC 1929)의 사용자명을 격리 키로 쓴다. 다른 사용자명을 쓴
  연결은 서로 다른 출구를 탄다. 인증이 없으면 목적지 호스트 단위로 격리한다.
- 127.0.0.1에만 바인딩한다.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct

from .client import MosaicClient

log = logging.getLogger("mosaic.socks")


class SocksServer:
    def __init__(self, client: MosaicClient, host: str = "127.0.0.1", port: int = 9050):
        self.client, self.host, self.port = client, host, port
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        log.info("SOCKS5 proxy on %s:%d", self.host, self.port)

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        stream = None
        try:
            ver, n = await r.readexactly(2)
            methods = await r.readexactly(n)
            if ver != 5:
                return
            isolation = ""
            if 2 in methods:
                w.write(b"\x05\x02")
                await w.drain()
                _v, ul = await r.readexactly(2)
                user = await r.readexactly(ul)
                pl = (await r.readexactly(1))[0]
                await r.readexactly(pl)
                isolation = "user:" + user.decode(errors="replace")
                w.write(b"\x01\x00")
            elif 0 in methods:
                w.write(b"\x05\x00")
            else:
                w.write(b"\x05\xff")
                return
            await w.drain()
            ver, cmd, _rsv, atyp = await r.readexactly(4)
            if atyp == 1:
                host = str(ipaddress.IPv4Address(await r.readexactly(4)))
            elif atyp == 3:
                host = (await r.readexactly((await r.readexactly(1))[0])).decode()
            elif atyp == 4:
                host = str(ipaddress.IPv6Address(await r.readexactly(16)))
            else:
                return
            port = struct.unpack(">H", await r.readexactly(2))[0]
            if cmd != 1:
                w.write(b"\x05\x07\x00\x01" + b"\0" * 6)
                return
            try:
                stream = await self.client.open_stream(host, port, isolation or host)
            except Exception as e:      # noqa: BLE001
                log.info("open %s:%d failed: %s", host, port, e)
                w.write(b"\x05\x05\x00\x01" + b"\0" * 6)
                return
            w.write(b"\x05\x00\x00\x01" + b"\0" * 6)
            await w.drain()
            await asyncio.gather(self._up(r, stream), self._down(w, stream))
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as e:      # noqa: BLE001
            log.debug("socks error: %s", e)
        finally:
            if stream:
                stream.close()
            try:
                w.close()
            except Exception:      # noqa: BLE001
                pass

    async def _up(self, r, stream):
        try:
            while True:
                data = await r.read(16384)
                if not data:
                    break
                await stream.write(data)
        finally:
            stream.close()

    async def _down(self, w, stream):
        while True:
            data = await stream.read()
            if not data:
                break
            w.write(data)
            await w.drain()
