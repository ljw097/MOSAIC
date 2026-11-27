"""MOSAIC 출구 서비스: 믹스넷과 일반 인터넷 사이의 다리.

- 출구는 목적지(host:port)와 바이트 흐름을 본다. 하지만 누가 보냈는지는 모른다.
  답장은 클라이언트가 미리 건넨 SURB로만 보낼 수 있다.
- DNS 조회는 출구에서 한다. 클라이언트 쪽에서 DNS가 새어 나가지 않는다.
- 내용의 기밀성은 종단 간 TLS가 맡는다 (브라우저는 HTTPS를 우선 사용한다).
- 기본 출구 정책은 사설·루프백·링크로컬 주소와 SMTP 포트를 막는다.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import time

from . import cells as K
from . import sphinx as S

log = logging.getLogger("mosaic.exit")
SESSION_IDLE = 300
MAX_UP_BUFFER = 512


class Session:
    def __init__(self, sid: bytes):
        self.sid = sid
        self.surbs: list[S.SURB] = []
        self.surb_event = asyncio.Event()
        self.next_up = 0
        self.pending: dict[int, K.Cell] = {}
        self.next_down = 0
        self.writer: asyncio.StreamWriter | None = None
        self.reader_task: asyncio.Task | None = None
        self.last = time.time()
        self.closed = False
        self.connecting = False
        self.pending_data = b""
        self.close_after_connect = False


class ExitService:
    def __init__(self, allow_private: bool = False, blocked_ports=(25, 465, 587),
                 upstream_proxy: tuple[str, int] | None = None):
        self.node = None
        self.allow_private = allow_private
        self.blocked_ports = set(blocked_ports)
        self.upstream_proxy = upstream_proxy
        self.sessions: dict[bytes, Session] = {}
        self.closed_ids: dict[bytes, float] = {}
        self._gc = None

    def policy(self) -> dict:
        return {"reject_private": not self.allow_private, "reject_ports": sorted(self.blocked_ports)}

    async def close(self):
        for s in list(self.sessions.values()):
            self._teardown(s)

    # ------------------------------------------------------------ 상향 처리
    def on_payload(self, payload: bytes):
        try:
            body = S.check_integrity(payload)
            cell = K.Cell.unpack(body)
        except (S.SphinxError, ValueError) as e:
            log.debug("bad exit payload: %s", e)
            return
        if cell.type == K.C_DROP:
            return
        if self._gc is None:
            self._gc = asyncio.create_task(self._gc_loop())
        s = self.sessions.get(cell.session)
        if s is None and cell.session in self.closed_ids:
            return
        if s is None:
            if len(self.sessions) > 10_000:
                return
            s = self.sessions[cell.session] = Session(cell.session)
        s.last = time.time()
        if cell.seq < s.next_up or len(s.pending) > MAX_UP_BUFFER:
            return
        s.pending[cell.seq] = cell
        while s.next_up in s.pending:
            c = s.pending.pop(s.next_up)
            s.next_up += 1
            self._handle(s, c)

    def _handle(self, s: Session, c: K.Cell):
        if c.type == K.C_SURBS:
            try:
                s.surbs.extend(K.unpack_surbs(c.data))
            except Exception:     # noqa: BLE001
                return
            s.surb_event.set()
        elif c.type == K.C_OPEN:
            if s.writer is None and not s.connecting:
                s.connecting = True
                asyncio.create_task(self._open(s, c.data))
        elif c.type == K.C_DATA:
            if s.writer is not None:
                s.writer.write(c.data)
            else:
                s.pending_data += c.data
        elif c.type == K.C_CLOSE:
            if s.writer is not None:
                try:
                    s.writer.write_eof()
                except Exception:     # noqa: BLE001
                    pass
            else:
                s.close_after_connect = True

    def _allowed(self, host: str, port: int, addr: str) -> bool:
        if port in self.blocked_ports or not (0 < port < 65536):
            return False
        if self.allow_private:
            return True
        ip = ipaddress.ip_address(addr)
        return ip.is_global

    async def _open(self, s: Session, data: bytes):
        try:
            req = json.loads(data)
            host, port = str(req["host"]), int(req["port"])
            if self.upstream_proxy:
                r, w = await self._via_proxy(host, port)
            else:
                infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
                addr = infos[0][4][0]
                if not self._allowed(host, port, addr):
                    raise PermissionError("exit policy rejects destination")
                r, w = await asyncio.wait_for(asyncio.open_connection(addr, port), 20)
        except Exception as e:     # noqa: BLE001
            log.info("exit open failed: %s", e)
            await self._reply(s, K.D_ERROR, str(e)[:200].encode(), reserve=False)
            self._teardown(s)
            return
        s.writer = w
        if s.pending_data:
            w.write(s.pending_data)
            s.pending_data = b""
        await self._reply(s, K.D_CONNECTED, b"", reserve=False)
        if s.close_after_connect:
            w.write_eof()
        s.reader_task = asyncio.create_task(self._pump(s, r))

    async def _via_proxy(self, host: str, port: int):
        """테스트 환경용: 상위 HTTP CONNECT 프록시를 거쳐 나간다."""
        if port in self.blocked_ports:
            raise PermissionError("exit policy rejects port")
        ph, pp = self.upstream_proxy
        r, w = await asyncio.wait_for(asyncio.open_connection(ph, pp), 20)
        w.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        await w.drain()
        status = await r.readline()
        if b" 200" not in status:
            w.close()
            raise ConnectionError(f"upstream proxy: {status.strip().decode(errors='replace')}")
        while (await r.readline()) not in (b"\r\n", b"\n", b""):
            pass
        return r, w

    async def _pump(self, s: Session, r: asyncio.StreamReader):
        try:
            while True:
                while len(s.surbs) <= 1:    # 마지막 SURB 한 개는 CLOSE용으로 남긴다
                    s.surb_event.clear()
                    await asyncio.wait_for(s.surb_event.wait(), SESSION_IDLE)
                data = await r.read(K.DATA_MAX)
                if not data:
                    break
                s.last = time.time()
                await self._reply(s, K.D_DATA, data)
        except Exception:      # noqa: BLE001
            pass
        await self._reply(s, K.D_CLOSE, b"", reserve=False)
        self._teardown(s)

    async def _reply(self, s: Session, t: int, data: bytes, reserve: bool = True):
        deadline = time.time() + 30
        while not s.surbs:
            s.surb_event.clear()
            try:
                await asyncio.wait_for(s.surb_event.wait(), max(0.01, deadline - time.time()))
            except asyncio.TimeoutError:
                return
        surb = s.surbs.pop(0)
        cell = K.Cell(t, s.sid, s.next_down, data)
        s.next_down += 1
        first, pkt = S.use_surb(surb, cell.pack())
        await self.node.send_packet(first, pkt)

    def _teardown(self, s: Session):
        if s.closed:
            return
        s.closed = True
        if s.writer:
            try:
                s.writer.close()
            except Exception:     # noqa: BLE001
                pass
        self.sessions.pop(s.sid, None)
        self.closed_ids[s.sid] = time.time()

    async def _gc_loop(self):
        while True:
            await asyncio.sleep(30)
            now = time.time()
            self.closed_ids = {k: t for k, t in self.closed_ids.items() if now - t < 3600}
            for s in list(self.sessions.values()):
                if now - s.last > SESSION_IDLE:
                    if s.reader_task:
                        s.reader_task.cancel()
                    self._teardown(s)
