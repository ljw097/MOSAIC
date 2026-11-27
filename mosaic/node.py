"""MOSAIC 노드: 게이트웨이(gateway), 믹스(mix), 출구(exit).

믹스는 Loopix 방식의 연속 시간(Poisson) 믹싱을 한다. 송신자가 홉마다 지수분포 지연을
골라 헤더에 넣으면, 노드는 패킷을 그만큼 붙잡아 두었다 내보낸다. 이렇게 하면 들어온
순서와 나가는 순서가 무작위로 섞여서, 노드를 들여다보는 관찰자도 입력과 출력을 짝지을
수 없다. 노드는 자신에게 돌아오는 루프 커버 트래픽도 내보내므로 (n-1) 공격이나
트래픽 흐름 분석이 어려워진다.

게이트웨이는 클라이언트의 우편함 역할을 한다. 클라이언트에게 가는 하향 트래픽은
Poisson 속도로 흘려보내며, 보낼 실제 메시지가 없으면 더미 프레임을 대신 보낸다. 그래서
ISP 같은 링크 관찰자에게는 실제 수신과 무수신이 똑같아 보인다.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque

from . import sphinx as S
from . import wire as W
from .directory import Consensus, Descriptor, NodeKeys, fetch_consensus, register

log = logging.getLogger("mosaic.node")
MAX_DELAY_MS = 30_000
MAILBOX_LIMIT = 4096
MAILBOX_TTL = 600
MAX_MAILBOXES = 100_000


class ReplayCache:
    def __init__(self, limit: int = 2_000_000):
        self.limit = limit
        self.cur: set[bytes] = set()
        self.old: set[bytes] = set()

    def seen(self, tag: bytes) -> bool:
        if tag in self.cur or tag in self.old:
            return True
        self.cur.add(tag)
        if len(self.cur) > self.limit:      # 키 로테이션 전 메모리 상한
            self.old, self.cur = self.cur, set()
        return False


class LinkPool:
    """노드 id -> 송신 링크. 필요할 때 연결."""

    def __init__(self, node: "Node"):
        self.node = node
        self.links: dict[bytes, W.Link] = {}
        self.locks: dict[bytes, asyncio.Lock] = {}

    async def get(self, node_id: bytes) -> W.Link | None:
        link = self.links.get(node_id)
        if link and not link.closed:
            return link
        lock = self.locks.setdefault(node_id, asyncio.Lock())
        async with lock:
            link = self.links.get(node_id)
            if link and not link.closed:
                return link
            d = self.node.consensus.nodes.get(node_id) if self.node.consensus else None
            if d is None:
                return None
            try:
                link = await W.connect(d.host, d.port, d.link_pk, d.mlkem_pk)
            except Exception as e:     # noqa: BLE001
                log.warning("%s: connect to %s failed: %s", self.node.name, node_id.hex()[:8], e)
                return None
            self.links[node_id] = link
            return link

    async def send(self, node_id: bytes, packet: bytes) -> bool:
        for _ in range(2):
            link = await self.get(node_id)
            if link is None:
                return False
            try:
                await link.send(W.F_PACKET, packet)
                return True
            except Exception:          # noqa: BLE001
                link.close()
        return False


class Mailbox:
    def __init__(self):
        self.queue: deque[tuple[float, bytes]] = deque()
        self.link: W.Link | None = None
        self.event = asyncio.Event()

    def put(self, body: bytes):
        self.queue.append((time.time(), body))
        while len(self.queue) > MAILBOX_LIMIT:
            self.queue.popleft()
        self.event.set()

    def pop(self) -> bytes | None:
        now = time.time()
        while self.queue:
            t, b = self.queue.popleft()
            if now - t < MAILBOX_TTL:
                return b
        return None


class Node:
    def __init__(self, keys: NodeKeys, role: str, host: str, port: int,
                 authorities: list[tuple[str, int, bytes]], threshold: int,
                 loop_rate: float = 1.0, downstream_rate: float = 100.0, exit_service=None,
                 public_host: str | None = None, name: str | None = None):
        self.keys, self.role, self.host, self.port = keys, role, host, port
        self.public_host = public_host or host
        self.authorities, self.threshold = authorities, threshold
        self.loop_rate, self.downstream_rate = loop_rate, downstream_rate
        self.name = name or f"{role}-{keys.node_id.hex()[:6]}"
        self.consensus: Consensus | None = None
        self.replay = ReplayCache()
        self.pool = LinkPool(self)
        self.mailboxes: dict[bytes, Mailbox] = {}
        self.exit_service = exit_service
        if exit_service is not None:
            exit_service.node = self
        self.tasks: list[asyncio.Task] = []
        self.server = None
        self.stats = {"in": 0, "relayed": 0, "delivered": 0, "dropped": 0, "replays": 0, "loops_sent": 0}

    # ------------------------------------------------------------ 수명주기
    def descriptor(self) -> Descriptor:
        policy = self.exit_service.policy() if self.exit_service else {}
        return Descriptor.create(self.keys, self.role, self.public_host, self.port, policy)

    async def start(self):
        self.server = await asyncio.start_server(self._on_conn, self.host, self.port)
        await register(self.authorities, self.descriptor())
        self.tasks.append(asyncio.create_task(self._maintenance()))
        if self.loop_rate > 0 and self.role in ("mix", "gateway"):
            self.tasks.append(asyncio.create_task(self._loop_cover()))
        log.info("%s listening on %s:%d", self.name, self.host, self.port)

    async def stop(self):
        for t in self.tasks:
            t.cancel()
        if self.server:
            self.server.close()
        for l in self.pool.links.values():
            l.close()
        if self.exit_service:
            await self.exit_service.close()

    async def refresh(self):
        try:
            self.consensus = await fetch_consensus(self.authorities, self.threshold)
        except Exception as e:      # noqa: BLE001
            log.warning("%s: consensus fetch failed: %s", self.name, e)

    async def _maintenance(self):
        n = 0
        while True:
            await self.refresh()
            await asyncio.sleep(2 if not (self.consensus and self.consensus.usable()) else 60)
            n += 1
            if n % 5 == 0:
                await register(self.authorities, self.descriptor())

    # ------------------------------------------------------------ 수신
    async def _on_conn(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        try:
            link = await W.accept(r, w, self.keys.link_sk, self.keys.mlkem_seed)
        except Exception as e:      # noqa: BLE001
            log.debug("%s: handshake failed: %s", self.name, e)
            w.close()
            return
        mailbox_id = None
        try:
            while True:
                ftype, body = await link.recv()
                if ftype == W.F_PACKET:
                    self.on_packet(body[: S.PACKET_LEN])
                elif ftype == W.F_REGISTER and self.role == "gateway":
                    mailbox_id = body[:16]
                    mb = self.mailboxes.setdefault(mailbox_id, Mailbox())
                    mb.link = link
                    self.tasks.append(asyncio.create_task(self._downstream(mailbox_id, mb, link)))
                # F_DUMMY: 무시
        except (asyncio.IncompleteReadError, ConnectionError, W.LinkError):
            pass
        finally:
            if mailbox_id and self.mailboxes.get(mailbox_id) and self.mailboxes[mailbox_id].link is link:
                self.mailboxes[mailbox_id].link = None
            link.close()

    def on_packet(self, packet: bytes):
        self.stats["in"] += 1
        try:
            p = S.process_packet(self.keys.sphinx_sk, packet)
        except S.SphinxError as e:
            self.stats["dropped"] += 1
            log.debug("%s: drop: %s", self.name, e)
            return
        if self.replay.seen(p.tag):
            self.stats["replays"] += 1
            return
        r = p.routing
        if r.flag == S.RELAY:
            delay = min(r.delay_ms, MAX_DELAY_MS) / 1000
            asyncio.get_running_loop().call_later(delay, self._forward, r.target, p.packet)
        elif r.flag == S.DELIVER_EXIT and self.exit_service is not None:
            self.stats["delivered"] += 1
            self.exit_service.on_payload(p.payload)
        elif r.flag == S.DELIVER_MAILBOX and self.role == "gateway":
            if r.target not in self.mailboxes and len(self.mailboxes) >= MAX_MAILBOXES:
                self.stats["dropped"] += 1
                return
            self.stats["delivered"] += 1
            mb = self.mailboxes.setdefault(r.target, Mailbox())
            mb.put(W.pack_deliver(r.extra[: S.SURB_ID_LEN], p.payload))
        else:      # FINAL_DROP / 잘못된 역할
            self.stats["dropped"] += 1

    def _forward(self, node_id: bytes, packet: bytes):
        self.stats["relayed"] += 1
        asyncio.create_task(self.pool.send(node_id, packet))

    async def send_packet(self, first_hop: bytes, packet: bytes):
        """출구 서비스가 SURB 응답을 보낼 때 사용."""
        if first_hop == self.keys.node_id:
            self.on_packet(packet)
            return
        await self.pool.send(first_hop, packet)

    # ------------------------------------------------------------ 게이트웨이 하향
    async def _downstream(self, mailbox_id: bytes, mb: Mailbox, link: W.Link):
        """λ_down 속도의 Poisson 송출. 실제 메시지가 없으면 더미."""
        dummy = b""
        try:
            while not link.closed and mb.link is link:
                await asyncio.sleep(random.expovariate(self.downstream_rate))
                body = mb.pop()
                if body is not None:
                    await link.send(W.F_DELIVER, body)
                else:
                    await link.send(W.F_DUMMY, dummy)
        except Exception:      # noqa: BLE001
            link.close()

    # ------------------------------------------------------------ 노드 루프 커버
    async def _loop_cover(self):
        while True:
            await asyncio.sleep(random.expovariate(self.loop_rate))
            c = self.consensus
            if not c or not c.usable():
                continue
            me = c.nodes.get(self.keys.node_id)
            if me is None:
                continue
            path = [random.choice(c.layer(i)) for i in range(3)] + [me]
            hops = [S.Hop(d.node_id, d.sphinx_pk) for d in path]
            routes = [S.Routing(S.RELAY, int(random.expovariate(1 / 50)), path[i + 1].node_id, b"")
                      for i in range(3)] + [S.Routing(S.FINAL_DROP, 0, b"", b"")]
            pkt, _ = S.create_packet(hops, routes, b"")
            self.stats["loops_sent"] += 1
            await self.send_packet(path[0].node_id, pkt)
