"""MOSAIC 클라이언트.

트래픽 형태 (Loopix 방식)
  클라이언트는 세 개의 독립된 Poisson 과정을 돌리며 패킷을 내보낸다.
    λ_P  페이로드 스트림. 보낼 실제 메시지가 있으면 그것을, 없으면 드롭 커버를 보낸다.
    λ_L  루프 커버. 망을 한 바퀴 돌아 자신에게 돌아온다 (능동 공격 탐지에도 쓴다).
    λ_D  드롭 커버. 무작위 출구로 가서 폐기된다.
  그래서 게이트웨이·ISP·전역 수동 관찰자 누구에게나 이 클라이언트가 "언제, 얼마나"
  실제로 통신하는지가 보이지 않는다. 보이는 것은 늘 같은 통계적 분포다.

경로
  정방향:  client → Gateway → L1 → L2 → L3 → Exit
  응답:   Exit → L1 → L2 → L3 → Gateway → client   (SURB)
  루프:   client → Gateway → L1 → L2 → L3 → Gateway → client
  패킷마다 믹스를 새로 고르고, 홉마다 지수분포 지연을 독립적으로 뽑는다.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass

from . import cells as K
from . import sphinx as S
from . import wire as W
from .directory import Consensus, Descriptor, fetch_consensus

log = logging.getLogger("mosaic.client")


@dataclass
class Profile:
    name: str = "interactive"
    rate_payload: float = 40.0      # λ_P  (packets/s)
    rate_loop: float = 2.0          # λ_L
    rate_drop: float = 2.0          # λ_D
    mean_delay_ms: float = 20.0     # 홉별 평균 지연 (1/μ)
    window: int = 32                # 세션당 미리 건넬 SURB 수


PROFILES = {
    "interactive": Profile(),
    "balanced": Profile("balanced", 25, 3, 3, 100, 32),
    "paranoid": Profile("paranoid", 10, 4, 4, 800, 24),
}


class StreamError(Exception):
    pass


class MStream:
    def __init__(self, client: "MosaicClient", exit_desc: Descriptor, sid: bytes):
        self.c, self.exit, self.sid = client, exit_desc, sid
        self.up_seq = 0
        self.down_next = 0
        self.down_pending: dict[int, K.Cell] = {}
        self.outstanding = 0        # 출구가 쥐고 있거나 전송 중인 SURB 수
        self.connected = asyncio.get_running_loop().create_future()
        self.data: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.eof = False
        self.closed_local = False

    def _cell(self, t: int, data: bytes) -> bytes:
        c = K.Cell(t, self.sid, self.up_seq, data)
        self.up_seq += 1
        return c.pack()

    def _send(self, t: int, data: bytes):
        self.c._enqueue(self.exit, self._cell(t, data))

    def _supply_surbs(self, n: int):
        while n > 0:
            k = min(n, K.SURBS_PER_CELL)
            surbs = [self.c._make_surb(self) for _ in range(k)]
            self._send(K.C_SURBS, K.pack_surbs(surbs))
            self.outstanding += k
            n -= k

    def _on_cell(self, cell: K.Cell):
        if cell.seq < self.down_next:
            return
        self.down_pending[cell.seq] = cell
        while self.down_next in self.down_pending:
            c = self.down_pending.pop(self.down_next)
            self.down_next += 1
            self.outstanding -= 1
            if c.type == K.D_CONNECTED:
                if not self.connected.done():
                    self.connected.set_result(True)
            elif c.type == K.D_DATA:
                self.data.put_nowait(c.data)
            elif c.type in (K.D_CLOSE, K.D_ERROR):
                if not self.connected.done():
                    self.connected.set_exception(StreamError(c.data.decode(errors="replace") or "closed"))
                self.eof = True
                self.data.put_nowait(None)
                self.c._forget(self)
                return
        if not self.eof and self.outstanding <= self.c.profile.window - K.SURBS_PER_CELL:
            self._supply_surbs(self.c.profile.window - self.outstanding)

    # ---------------------------------------------------------------- API
    async def write(self, data: bytes):
        for i in range(0, len(data), K.DATA_MAX):
            self._send(K.C_DATA, data[i:i + K.DATA_MAX])
        # 상향 큐가 너무 길어지면 기다린다 (역압)
        while self.c.queue.qsize() > 512:
            await asyncio.sleep(0.05)

    async def read(self, timeout: float = 120) -> bytes:
        if self.eof and self.data.empty():
            return b""
        try:
            d = await asyncio.wait_for(self.data.get(), timeout)
        except asyncio.TimeoutError as e:
            raise StreamError("mixnet read timeout") from e
        return d or b""

    def close(self):
        if not self.closed_local:
            self.closed_local = True
            self._send(K.C_CLOSE, b"")


class MosaicClient:
    def __init__(self, authorities: list[tuple[str, int, bytes]], threshold: int,
                 profile: Profile | str = "interactive", gateway_id: bytes | None = None):
        self.authorities, self.threshold = authorities, threshold
        self.profile = PROFILES[profile] if isinstance(profile, str) else profile
        self.gateway_id = gateway_id
        self.consensus: Consensus | None = None
        self.gateway: Descriptor | None = None
        self.link: W.Link | None = None
        self.mailbox = os.urandom(16)
        self.queue: asyncio.Queue[tuple[Descriptor, bytes]] = asyncio.Queue()
        self.surb_keys: dict[bytes, tuple[S.SURBKeys, MStream, float]] = {}
        self.loops: dict[bytes, float] = {}
        self.streams: dict[bytes, MStream] = {}
        self.exit_for: dict[str, Descriptor] = {}
        self.tasks: list[asyncio.Task] = []
        self.ready = asyncio.Event()
        self.stats = {"sent_real": 0, "sent_cover": 0, "sent_loop": 0, "loops_back": 0,
                      "recv_real": 0, "recv_dummy": 0, "loop_rtt_ms": 0.0}

    # ------------------------------------------------------------ 수명주기
    async def start(self, timeout: float = 60):
        deadline = time.time() + timeout
        while True:
            try:
                self.consensus = await fetch_consensus(self.authorities, self.threshold)
                if self.consensus.usable():
                    break
            except Exception as e:      # noqa: BLE001
                log.info("waiting for consensus: %s", e)
            if time.time() > deadline:
                raise RuntimeError("no usable consensus (need gateway, 3 mix layers, exit)")
            await asyncio.sleep(1)
        self._pick_gateway()
        await self._connect()
        for coro in (self._payload_loop(), self._poisson(self.profile.rate_loop, self._send_loop),
                     self._poisson(self.profile.rate_drop, self._send_drop), self._refresh_loop(),
                     self._gc_loop()):
            self.tasks.append(asyncio.create_task(coro))
        self.ready.set()
        log.info("client ready: gateway=%s profile=%s", self.gateway.node_id.hex()[:8], self.profile.name)

    async def stop(self):
        for t in self.tasks:
            t.cancel()
        if self.link:
            self.link.close()

    def _pick_gateway(self):
        gws = self.consensus.by_role("gateway")
        if self.gateway_id:
            gws = [g for g in gws if g.node_id == self.gateway_id] or gws
        # 가드(guard)처럼 오래 유지: 매번 바꾸면 악성 게이트웨이를 만날 확률이 누적된다
        self.gateway = self.gateway if self.gateway in gws else random.choice(gws)

    async def _connect(self):
        g = self.gateway
        self.link = await W.connect(g.host, g.port, g.link_pk, g.mlkem_pk)
        await self.link.send(W.F_REGISTER, self.mailbox)
        self.tasks.append(asyncio.create_task(self._receiver(self.link)))

    async def _reconnect(self):
        for attempt in range(30):
            try:
                await self._connect()
                return
            except Exception:      # noqa: BLE001
                await asyncio.sleep(min(2 ** attempt, 30))

    async def _refresh_loop(self):
        while True:
            await asyncio.sleep(60)
            try:
                c = await fetch_consensus(self.authorities, self.threshold)
                if c.usable():
                    self.consensus = c
            except Exception as e:      # noqa: BLE001
                log.warning("consensus refresh failed: %s", e)

    async def _gc_loop(self):
        while True:
            await asyncio.sleep(30)
            now = time.time()
            self.surb_keys = {k: v for k, v in self.surb_keys.items() if now - v[2] < 900}
            lost = [k for k, t in self.loops.items() if now - t > 60]
            for k in lost:
                del self.loops[k]
            if lost:
                log.warning("%d loop packets lost (possible active attack or congestion)", len(lost))

    # ------------------------------------------------------------ 경로
    def _delay(self) -> int:
        return int(random.expovariate(1 / self.profile.mean_delay_ms)) if self.profile.mean_delay_ms > 0 else 0

    def _mixes(self) -> list[Descriptor]:
        return [random.choice(self.consensus.layer(i)) for i in range(3)]

    def _forward_packet(self, final: Descriptor, final_routing: S.Routing, body: bytes) -> bytes:
        path = [self.gateway] + self._mixes() + [final]
        hops = [S.Hop(d.node_id, d.sphinx_pk) for d in path]
        routes = [S.Routing(S.RELAY, self._delay(), path[i + 1].node_id, b"") for i in range(len(path) - 1)]
        pkt, _ = S.create_packet(hops, routes + [final_routing], body)
        return pkt

    def _make_surb(self, stream: MStream) -> S.SURB:
        path = self._mixes() + [self.gateway]
        hops = [S.Hop(d.node_id, d.sphinx_pk) for d in path]
        surb_id = os.urandom(S.SURB_ID_LEN)
        routes = [S.Routing(S.RELAY, self._delay(), path[i + 1].node_id, b"") for i in range(3)]
        routes.append(S.Routing(S.DELIVER_MAILBOX, 0, self.mailbox, surb_id))
        surb, keys = S.create_surb(hops, routes)
        self.surb_keys[surb_id] = (keys, stream, time.time())
        return surb

    # ------------------------------------------------------------ 송신 (Poisson)
    def _enqueue(self, exit_desc: Descriptor, body: bytes):
        self.queue.put_nowait((exit_desc, body))

    async def _transmit(self, pkt: bytes):
        try:
            await self.link.send(W.F_PACKET, pkt)
        except Exception:      # noqa: BLE001
            self.link.close()
            await self._reconnect()

    async def _payload_loop(self):
        while True:
            await asyncio.sleep(random.expovariate(self.profile.rate_payload))
            try:
                exit_desc, body = self.queue.get_nowait()
                self.stats["sent_real"] += 1
                await self._transmit(self._forward_packet(exit_desc, S.Routing(S.DELIVER_EXIT, 0, b"", b""), body))
            except asyncio.QueueEmpty:
                await self._send_drop()

    async def _poisson(self, rate: float, fn):
        if rate <= 0:
            return
        while True:
            await asyncio.sleep(random.expovariate(rate))
            await fn()

    async def _send_drop(self):
        x = random.choice(self.consensus.by_role("exit"))
        body = K.Cell(K.C_DROP, os.urandom(16), 0, b"").pack()
        self.stats["sent_cover"] += 1
        await self._transmit(self._forward_packet(x, S.Routing(S.DELIVER_EXIT, 0, b"", b""), body))

    async def _send_loop(self):
        lid = os.urandom(S.SURB_ID_LEN)
        self.loops[lid] = time.time()
        self.stats["sent_loop"] += 1
        await self._transmit(self._forward_packet(
            self.gateway, S.Routing(S.DELIVER_MAILBOX, 0, self.mailbox, lid), b""))

    # ------------------------------------------------------------ 수신
    async def _receiver(self, link: W.Link):
        try:
            while True:
                ftype, body = await link.recv()
                if ftype == W.F_DELIVER:
                    self._on_deliver(*W.unpack_deliver(body))
                else:
                    self.stats["recv_dummy"] += 1
        except Exception:      # noqa: BLE001
            if link is self.link:
                link.close()
                await self._reconnect()

    def _on_deliver(self, surb_id: bytes, payload: bytes):
        if surb_id in self.loops:
            rtt = (time.time() - self.loops.pop(surb_id)) * 1000
            self.stats["loops_back"] += 1
            self.stats["loop_rtt_ms"] = 0.8 * self.stats["loop_rtt_ms"] + 0.2 * rtt
            return
        entry = self.surb_keys.pop(surb_id, None)
        if entry is None:
            return
        keys, stream, _ = entry
        try:
            cell = K.Cell.unpack(S.open_surb_reply(keys, payload))
        except (S.SphinxError, ValueError):
            log.warning("reply integrity failure (tagging attempt?)")
            return
        if cell.session != stream.sid:
            return
        self.stats["recv_real"] += 1
        stream._on_cell(cell)

    def _forget(self, stream: MStream):
        self.streams.pop(stream.sid, None)

    # ------------------------------------------------------------ 공개 API
    def exit_for_key(self, isolation: str) -> Descriptor:
        exits = self.consensus.by_role("exit")
        d = self.exit_for.get(isolation)
        if d is None or d not in exits:
            d = self.exit_for[isolation] = random.choice(exits)
        return d

    def new_identity(self):
        """모든 격리 키의 출구 매핑을 버린다. 이후 연결은 새 출구, 새 세션 id를 쓴다."""
        self.exit_for.clear()

    async def open_stream(self, host: str, port: int, isolation: str = "", timeout: float = 60) -> MStream:
        await self.ready.wait()
        exit_desc = self.exit_for_key(isolation or host)
        st = MStream(self, exit_desc, os.urandom(16))
        self.streams[st.sid] = st
        st._supply_surbs(self.profile.window)
        st._send(K.C_OPEN, json.dumps({"host": host, "port": port}).encode())
        try:
            await asyncio.wait_for(asyncio.shield(st.connected), timeout)
        except asyncio.TimeoutError as e:
            self._forget(st)
            raise StreamError("connect timeout") from e
        return st
