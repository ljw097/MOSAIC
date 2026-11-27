"""MOSAIC 출구 서비스: 믹스넷과 일반 인터넷 사이의 다리.

- 출구는 마름모(◇)의 오른쪽 꼭짓점이다. 서로 다른 경로로 들어온 조각을 k개 모아 메시지를 복원한다.
- 응답은 클라이언트가 건넨 SURB 묶음으로 보낸다. 한 묶음은 경로가 서로 겹치지 않는 SURB n개이고,
  응답 하나를 k-of-n으로 쪼개 묶음 안의 SURB에 하나씩 싣는다. 응답 방향도 마름모가 된다.
- 출구는 목적지(host:port)와 바이트 흐름을 본다. 하지만 누가 보냈는지는 모른다.
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
from . import split as P

log = logging.getLogger("mosaic.exit")
SESSION_IDLE = 300
MAX_UP_BUFFER = 512


class Session:
    def __init__(self, sid: bytes):
        self.sid = sid
        self.surb_sets: list[list[S.SURB]] = []
        self.surb_event = asyncio.Event()
        self.reply_k = 2
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
        self.reasm = P.Reassembler()
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
        except S.SphinxError as e:
            log.debug("bad exit payload: %s", e)
            return
        frag = P.parse(body)
        if frag is None:
            return          # 분할되지 않은 페이로드 = 드롭 커버
        msg = self.reasm.add(frag)
        if msg is None:
            return
        try:
            cell = K.Cell.unpack(msg)
        except ValueError:
            return
        self.on_cell(cell)

    def on_cell(self, cell: K.Cell):
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
                s.surb_sets.extend(K.unpack_surb_sets(c.data))
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
        return ipaddress.ip_address(addr).is_global

    async def _open(self, s: Session, data: bytes):
        try:
            req = json.loads(data)
            host, port = str(req["host"]), int(req["port"])
            s.reply_k = max(1, min(int(req.get("reply_k", 2)), P.MAX_N))
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
            await self._reply(s, K.D_ERROR, str(e)[:200].encode())
            self._teardown(s)
            return
        s.writer = w
        if s.pending_data:
            w.write(s.pending_data)
            s.pending_data = b""
        await self._reply(s, K.D_CONNECTED, b"")
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
                while len(s.surb_sets) <= 1:    # 마지막 묶음 하나는 CLOSE용으로 남긴다
                    s.surb_event.clear()
                    await asyncio.wait_for(s.surb_event.wait(), SESSION_IDLE)
                data = await r.read(K.data_max(s.reply_k))
                if not data:
                    break
                s.last = time.time()
                await self._reply(s, K.D_DATA, data)
        except Exception:      # noqa: BLE001
            pass
        await self._reply(s, K.D_CLOSE, b"")
        self._teardown(s)

    async def _reply(self, s: Session, t: int, data: bytes):
        deadline = time.time() + 30
        while not s.surb_sets:
            s.surb_event.clear()
            try:
                await asyncio.wait_for(s.surb_event.wait(), max(0.01, deadline - time.time()))
            except asyncio.TimeoutError:
                return
        surb_set = s.surb_sets.pop(0)
        cell = K.Cell(t, s.sid, s.next_down, data)
        s.next_down += 1
        k = min(s.reply_k, len(surb_set))
        # 응답도 k-of-n 분할: 조각 i는 SURB i (서로 다른 경로)로 → 마름모 응답 경로
        for frag, surb in zip(P.split(cell.pack(), k, len(surb_set)), surb_set):
            first, pkt = S.use_surb(surb, frag.pack())
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
            self.reasm.gc()
            self.closed_ids = {k: t for k, t in self.closed_ids.items() if now - t < 3600}
            for s in list(self.sessions.values()):
                if now - s.last > SESSION_IDLE:
                    if s.reader_task:
                        s.reader_task.cancel()
                    self._teardown(s)
