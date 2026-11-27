"""MOSAIC 네이티브 서비스 호스트 (.mosaic): 출구 노드가 없는 통신.

  클라이언트 ◇─┬─ G_c ─ L1 ─ L2 ─ L3 ─ G_s1 ─┬─◇ 서비스 (조각을 직접 모으고 E2E를 푼다)
              └─ G_c'─ L1'─ L2'─ L3'─ G_s2 ─┘

- 서비스는 일반 클라이언트처럼 게이트웨이 여러 곳에 우편함을 두고, (게이트웨이, 우편함) 목록을
  자기 인증 기술자로 게시한다. 주소는 base32(H(서비스 공개키)) + ".mosaic"이다.
- 마름모의 오른쪽 꼭짓점이 제3자 출구가 아니라 서비스 자신이다. 내용을 볼 수 있는 중간 노드가 없다.
  서비스 측 게이트웨이는 자기 우편함으로 오는 조각을 보지만, 내용은 E2E로 암호화되어 있다.
- 응답은 클라이언트가 건넨 SURB 묶음으로 보낸다. 믹스가 서비스 IP를 알지 못하도록 SURB 패킷은
  서비스 자신의 게이트웨이를 거쳐 나간다 (F_FORWARD).
- 양쪽 모두 익명이다. 서비스는 클라이언트를 모르고(SURB), 클라이언트는 서비스의 IP를 모른다
  (게이트웨이만 앎).
"""
from __future__ import annotations

import asyncio
import logging
import random
import time

from . import cells as K
from . import e2e as E
from . import sphinx as S
from . import split as P
from . import wire as W
from .client import MosaicClient
from .directory import ServiceDescriptor, ServiceKeys, publish_service
from .exit import ExitService

log = logging.getLogger("mosaic.service")
PENDING_LIMIT = 64


class _ServiceExit(ExitService):
    """출구 세션 로직을 재사용하되, 요청된 host와 상관없이 로컬 백엔드에만 연결한다 (포트별 매핑 가능)."""

    def __init__(self, target: tuple[str, int] | None, port_map: dict[int, tuple[str, int]] | None = None):
        super().__init__(allow_private=True)
        self.target, self.port_map = target, port_map or {}

    async def _connect(self, host: str, port: int):
        t = self.port_map.get(port, self.target)
        if t is None:
            raise PermissionError(f"no backend for port {port}")
        return await asyncio.wait_for(asyncio.open_connection(*t), 20)


class E2EReceiver:
    """조각 → (k개) 복원 → E2E 복호 → 셀 → 백엔드 세션. .mosaic 서비스와 다중 입구 엔드포인트가 공유한다.
    send_packet(first_hop, packet)은 하위 클래스가 구현한다 (응답 SURB 패킷을 망에 넣는 방법)."""

    def __init__(self, x25519_sk: bytes, mlkem_seed: bytes, target, port_map=None):
        self._x25519_sk, self._mlkem_seed = x25519_sk, mlkem_seed
        self.exit = _ServiceExit(target, port_map)
        self.exit.node = self
        self.exit.wrap = self._wrap
        self.exit.reply_overhead = E.OVERHEAD
        self.reasm = P.Reassembler()
        self.sessions: dict[bytes, E.ServerSession] = {}
        self.waiting: dict[bytes, list[tuple[float, bytes]]] = {}
        self.stats = {"fragments": 0, "messages": 0, "e2e_fail": 0}

    def on_fragment_body(self, body: bytes):
        frag = P.parse(body)
        if frag is None:
            return
        self.stats["fragments"] += 1
        msg = self.reasm.add(frag)
        if msg is not None:
            self.stats["messages"] += 1
            self._on_message(msg)

    def gc(self):
        now = time.time()
        self.reasm.gc()
        self.waiting = {c: [(t, m) for t, m in v if now - t < 60] for c, v in self.waiting.items()}
        self.waiting = {c: v for c, v in self.waiting.items() if v}

    def _on_message(self, msg: bytes):
        info = E.peek(msg)
        if info is None:
            return
        t, conn = info
        try:
            if t == E.T_INIT:
                if conn in self.sessions:
                    return
                sess, pt = E.ServerSession.accept(msg, self._x25519_sk, self._mlkem_seed)
                self.sessions[conn] = sess
                self._deliver(conn, pt)
                for _t, m in self.waiting.pop(conn, []):     # INIT보다 먼저 도착한 메시지
                    self._deliver(conn, sess.open(m))
            elif t == E.T_UP:
                sess = self.sessions.get(conn)
                if sess is None:
                    q = self.waiting.setdefault(conn, [])
                    if len(q) < PENDING_LIMIT and len(self.waiting) < 10_000:
                        q.append((time.time(), msg))
                    return
                self._deliver(conn, sess.open(msg))
        except E.E2EError:
            self.stats["e2e_fail"] += 1

    def _deliver(self, conn: bytes, pt: bytes):
        try:
            cell = K.Cell.unpack(pt)
        except ValueError:
            return
        if cell.session != conn:        # 세션 id는 E2E 연결 id와 같아야 한다
            return
        self.exit.on_cell(cell)

    def _wrap(self, sid: bytes, msg: bytes) -> bytes:
        return self.sessions[sid].seal(msg)

    async def send_packet(self, first_hop: bytes, packet: bytes):
        raise NotImplementedError


class ServiceHost(E2EReceiver):
    def __init__(self, keys: ServiceKeys, authorities, threshold: int, target: tuple[str, int],
                 profile="interactive"):
        super().__init__(keys.x25519_sk, keys.mlkem_seed, target)
        self.keys = keys
        self.authorities = authorities
        self.client = MosaicClient(authorities, threshold, profile)
        self.client.on_forward = self._on_forward
        self.tasks: list[asyncio.Task] = []

    @property
    def address(self) -> str:
        return self.keys.address

    def descriptor(self) -> ServiceDescriptor:
        return ServiceDescriptor.create(self.keys, [(l.gateway.node_id, l.mailbox) for l in self.client.lanes])

    async def start(self):
        await self.client.start()
        n = await publish_service(self.authorities, self.descriptor())
        if n == 0:
            raise RuntimeError("no authority accepted the service descriptor")
        self.tasks.append(asyncio.create_task(self._republish()))
        log.info("service %s online via %d gateways", self.address, len(self.client.lanes))

    async def stop(self):
        for t in self.tasks:
            t.cancel()
        await self.exit.close()
        await self.client.stop()

    async def _republish(self):
        while True:
            await asyncio.sleep(300)
            await publish_service(self.authorities, self.descriptor())
            self.gc()

    def _on_forward(self, payload: bytes):
        try:
            body = S.check_integrity(payload)
        except S.SphinxError:
            return
        self.on_fragment_body(body)

    async def send_packet(self, first_hop: bytes, packet: bytes):
        """SURB 응답 패킷을 게이트웨이 링크의 Poisson 큐에 넣는다. 게이트웨이가 첫 홉으로 전달한다."""
        lane = random.choice(self.client.lanes)
        lane.queue.put_nowait((W.F_FORWARD, first_hop + packet))
