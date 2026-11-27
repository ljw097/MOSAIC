"""MOSAIC 클라이언트.

마름모(◇) 다중 경로 분할
  모든 종단 메시지(셀)는 k-of-n으로 분할된다 (split.py). n개 조각은 각각 독립된 Sphinx 패킷이 되어
  서로 다른 게이트웨이와 서로 겹치지 않는 믹스를 지난 뒤, 출구에서 다시 합쳐진다.

                ┌─ G1 ─ L1a ─ L2a ─ L3a ─┐
   클라이언트 ◇─┼─ G2 ─ L1b ─ L2b ─ L3b ─┼─◇ 출구        (응답도 SURB 묶음으로 같은 모양)
                └─ G1 ─ L1c ─ L2c ─ L3c ─┘

  - 계층마다 노드 수가 충분하면, 한 메시지의 조각 두 개가 같은 믹스를 지나지 않는다.
    노드 하나를 장악(점거)해도 메시지마다 조각을 최대 하나만 본다. k-1개 이하의 조각으로는
    아무것도 복원할 수 없다.
  - 노드가 조각을 버리거나 붙잡아 두는 공격(선택적 차단)을 해도, n-k개까지는 메시지가 도착한다.
  - k와 n은 메시지마다 정책 범위 안에서 무작위로 고른다 ("다양한 분할"). 관찰자가 패킷 수를 세어
    메시지 경계나 크기를 짐작하기 어렵다.

트래픽 형태 (Loopix 방식, 게이트웨이 링크마다 독립)
  λ_P  페이로드 스트림. 큐에 실제 조각이 있으면 보내고, 없으면 드롭 커버를 보낸다.
  λ_L  루프 커버. 자신에게 돌아온다 (능동 공격 탐지).
  λ_D  드롭 커버.
  링크마다 큐와 Poisson 과정이 따로 있다. 그래서 조각이 어느 게이트웨이로 몰려도 링크별 송신
  패턴은 변하지 않는다.
"""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import os
import random
import time
from dataclasses import dataclass

from . import cells as K
from . import directory as D
from . import e2e as E
from . import sphinx as S
from . import split as P
from . import wire as W
from .directory import Consensus, Descriptor, ServiceDescriptor, fetch_consensus

log = logging.getLogger("mosaic.client")


@dataclass
class Profile:
    name: str = "interactive"
    rate_payload: float = 40.0      # λ_P  (packets/s, 게이트웨이 링크당)
    rate_loop: float = 2.0          # λ_L
    rate_drop: float = 2.0          # λ_D
    mean_delay_ms: float = 20.0     # 홉별 평균 지연 (1/μ)
    window: int = 12                # 세션당 미리 건넬 SURB 묶음 수
    gateways: int = 2               # 동시에 쓰는 게이트웨이 수 (마름모 왼쪽 꼭짓점의 폭)
    split_k: tuple[int, int] = (2, 3)       # 정방향: 메시지마다 k ∈ [lo, hi]
    split_extra: tuple[int, int] = (1, 2)   # 정방향: n = k + extra, extra ∈ [lo, hi]
    reply_k: int = 2                # 응답 분할 k
    reply_n: int = 3                # 응답 분할 n (= SURB 묶음 크기)

    @property
    def max_cell_data(self) -> int:
        return K.data_max(self.split_k[0])


PROFILES = {
    "interactive": Profile(),
    "balanced": Profile("balanced", 25, 3, 3, 100, 12, 2, (2, 3), (1, 2), 2, 3),
    "paranoid": Profile("paranoid", 10, 4, 4, 800, 8, 3, (3, 4), (2, 3), 3, 5),
}


INITIAL_SETS = 4


class StreamError(Exception):
    pass


def disjoint_paths(consensus: Consensus, n: int, rng=random) -> list[list[Descriptor]]:
    """n개의 믹스 경로(L1, L2, L3)를 고른다. 계층마다 노드를 비복원 추출하므로, 노드가 충분하면
    어떤 믹스도 두 경로에 동시에 나타나지 않는다. 부족하면 최대한 고르게 돌려 쓴다."""
    cols = []
    for layer in range(3):
        nodes = list(consensus.layer(layer))
        rng.shuffle(nodes)
        cols.append([nodes[i % len(nodes)] for i in range(n)])
    return [[cols[l][i] for l in range(3)] for i in range(n)]


@dataclass
class ServiceDest:
    """네이티브 서비스 목적지. 마름모의 오른쪽 꼭짓점이 출구가 아니라 서비스 자신이다.
    조각들은 서비스의 여러 intro 게이트웨이로 나뉘어 들어간다."""
    desc: ServiceDescriptor
    intros: list[tuple[Descriptor, bytes]]


@dataclass
class EndpointDest:
    """다중 입구 엔드포인트. 조각 i → 출구 X_i → 서버 입구 포트 i. 서버가 직접 모은다."""
    desc: "EndpointDescriptor"

    @property
    def cap(self) -> int:
        from .endpoint import piece_cap
        return piece_cap(self.desc.host)


class Lane:
    """게이트웨이 하나와의 링크. 자기만의 우편함 id, 송신 큐, Poisson 과정을 가진다."""

    def __init__(self, gateway: Descriptor):
        self.gateway = gateway
        self.mailbox = os.urandom(16)     # 게이트웨이마다 다른 id → 게이트웨이끼리 공모해도 연결 불가
        self.link: W.Link | None = None
        self.queue: asyncio.Queue[tuple[int, bytes]] = asyncio.Queue()
        self.tasks: list[asyncio.Task] = []


class MStream:
    def __init__(self, client: "MosaicClient", dest, sid: bytes, e2e: E.ClientSession | None = None):
        self.c, self.dest, self.sid = client, dest, sid
        self.e2e = e2e
        self.overhead = E.OVERHEAD if e2e else 0
        self.cap = dest.cap if isinstance(dest, EndpointDest) else P.FRAG_CAP
        self.up_seq = 0
        self.down_next = 0
        self.down_pending: dict[int, K.Cell] = {}
        self.sets: collections.deque[int] = collections.deque()   # 출구에 건넨 SURB 묶음들의 epoch (FIFO)
        # SURB 창 슬로 스타트: 작게 시작해 실제로 데이터가 올 때마다 1씩 키운다 (왕복마다 약 2배).
        # 작은 응답(이미지, API 호출)에 SURB를 과하게 미리 보내 상향 대역을 낭비하지 않는다.
        self.target = min(INITIAL_SETS, client.profile.window)
        self.connected = asyncio.get_running_loop().create_future()
        self.data: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.eof = False
        self.closed_local = False

    def _send(self, t: int, data: bytes):
        cell = K.Cell(t, self.sid, self.up_seq, data)
        self.up_seq += 1
        msg = cell.pack()
        if self.e2e is not None:
            msg = self.e2e.seal(msg)       # 서비스 키로 종단 간 암호화 (게이트웨이·믹스는 못 읽음)
        self.c._send_message(self.dest, msg)

    @property
    def max_data(self) -> int:
        return P.max_message(self.c.profile.split_k[0], self.cap) - K.HDR.size - self.overhead

    def _supply_surbs(self, nsets: int):
        prof = self.c.profile
        per = max(1, (self.max_data - 2) // (prof.reply_n * S.SURB_LEN))
        while nsets > 0:
            k = min(nsets, per)
            epoch = self.c.surb_epoch()
            sets = [self.c._make_surb_set(self, epoch) for _ in range(k)]
            self._send(K.C_SURBS, K.pack_surb_sets(sets, epoch))
            self.sets.extend([epoch] * k)
            nsets -= k

    @property
    def outstanding(self) -> int:
        return len(self.sets)

    def _refill(self):
        """만료된 묶음(출구가 버릴 것)을 빼고, 창이 비면 새 묶음을 보낸다."""
        cur = D.current_epoch()
        while self.sets and self.sets[0] < cur:
            self.sets.popleft()
        w = self.target
        if not self.eof and self.outstanding <= w - max(1, w // 4):
            self._supply_surbs(w - self.outstanding)

    def _on_cell(self, cell: K.Cell):
        if cell.seq < self.down_next:
            return
        self.down_pending[cell.seq] = cell
        while self.down_next in self.down_pending:
            c = self.down_pending.pop(self.down_next)
            self.down_next += 1
            if self.sets:
                self.sets.popleft()
            if c.type == K.D_CONNECTED:
                if not self.connected.done():
                    self.connected.set_result(True)
            elif c.type == K.D_DATA:
                self.data.put_nowait(c.data)
                self.target = min(self.c.profile.window, self.target + 1)
            elif c.type in (K.D_CLOSE, K.D_ERROR):
                if not self.connected.done():
                    self.connected.set_exception(StreamError(c.data.decode(errors="replace") or "closed"))
                self.eof = True
                self.data.put_nowait(None)
                self.c._forget(self)
                return
        self._refill()

    # ---------------------------------------------------------------- API
    async def write(self, data: bytes):
        self._refill()          # 오래 쉬던 스트림: 응답을 받을 SURB가 만료됐을 수 있다
        step = self.max_data
        for i in range(0, len(data), step):
            self._send(K.C_DATA, data[i:i + step])
        while self.c.backlog() > 1024:      # 역압
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
                 profile: Profile | str = "interactive", gateway_ids: list[bytes] | None = None):
        self.authorities, self.threshold = authorities, threshold
        self.profile = PROFILES[profile] if isinstance(profile, str) else profile
        self.gateway_ids = gateway_ids
        self.consensus: Consensus | None = None
        self.lanes: list[Lane] = []
        self.surb_keys: dict[bytes, tuple[S.SURBKeys, MStream, float]] = {}
        self.loops: dict[bytes, float] = {}
        self.streams: dict[bytes, MStream] = {}
        self.exit_for: dict[str, Descriptor] = {}
        self.reasm = P.Reassembler()
        self.tasks: list[asyncio.Task] = []
        self.ready = asyncio.Event()
        self.path_log: list[list[list[bytes]]] | None = None     # 테스트/진단용
        self.on_forward = None          # 서비스 호스트가 설정: 정방향 조각 처리기
        self.endpoints: dict[str, "EndpointDescriptor"] = {}     # 도메인 → 다중 입구 엔드포인트
        self.stats = {"sent_real": 0, "sent_cover": 0, "sent_loop": 0, "loops_back": 0,
                      "recv_real": 0, "recv_dummy": 0, "loop_rtt_ms": 0.0,
                      "messages_split": 0, "fragments_sent": 0, "messages_reassembled": 0, "streams_opened": 0}

    # 호환용
    @property
    def gateway(self) -> Descriptor | None:
        return self.lanes[0].gateway if self.lanes else None

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
        for g in self._pick_gateways():
            lane = Lane(g)
            await self._connect(lane)
            self.lanes.append(lane)
            p = self.profile
            lane.tasks += [asyncio.create_task(self._payload_loop(lane)),
                           asyncio.create_task(self._poisson("rate_loop", self._send_loop, lane)),
                           asyncio.create_task(self._poisson("rate_drop", self._send_drop, lane))]
        self.tasks += [asyncio.create_task(self._refresh_loop()), asyncio.create_task(self._gc_loop()),
                       asyncio.create_task(self._epoch_watch())]
        self.ready.set()
        log.info("client ready: gateways=%s profile=%s",
                 ",".join(l.gateway.node_id.hex()[:8] for l in self.lanes), self.profile.name)

    async def stop(self):
        for t in self.tasks + [t for l in self.lanes for t in l.tasks]:
            t.cancel()
        for l in self.lanes:
            if l.link:
                l.link.close()

    def _pick_gateways(self) -> list[Descriptor]:
        gws = self.consensus.by_role("gateway")
        if self.gateway_ids:
            gws = [g for g in gws if g.node_id in self.gateway_ids] or gws
        # 가드처럼 소수를 오래 유지한다 (많이 쓸수록 IP를 아는 노드가 늘어난다)
        return random.sample(gws, min(self.profile.gateways, len(gws)))

    async def _connect(self, lane: Lane):
        g = lane.gateway
        lane.link = await W.connect(g.host, g.port, g.link_pk, g.mlkem_pk)
        await lane.link.send(W.F_REGISTER, lane.mailbox)
        lane.tasks.append(asyncio.create_task(self._receiver(lane, lane.link)))

    async def _reconnect(self, lane: Lane):
        for attempt in range(30):
            try:
                await self._connect(lane)
                return
            except Exception:      # noqa: BLE001
                await asyncio.sleep(min(2 ** attempt, 30))

    async def _refresh_loop(self):
        from . import directory as D
        while True:
            # epoch 키 로테이션을 따라가도록 epoch 길이보다 자주 받는다
            await asyncio.sleep(min(60.0, max(1.0, D.EPOCH_LEN / 4)))
            try:
                c = await fetch_consensus(self.authorities, self.threshold)
                if c.usable():
                    self.consensus = c
            except Exception as e:      # noqa: BLE001
                log.warning("consensus refresh failed: %s", e)

    async def _epoch_watch(self):
        """epoch가 바뀌면 열린 스트림마다 만료된 SURB 묶음을 새것으로 바꿔 보낸다.
        스트림이 읽기만 기다리며 쉬고 있어도 출구가 응답할 SURB를 잃지 않는다."""
        last = D.current_epoch()
        while True:
            await asyncio.sleep(min(1.0, max(0.1, D.EPOCH_LEN / 16)))
            cur = D.current_epoch()
            if cur != last:
                last = cur
                for st in list(self.streams.values()):
                    st._refill()

    async def _gc_loop(self):
        while True:
            await asyncio.sleep(30)
            now = time.time()
            self.reasm.gc()
            self.surb_keys = {k: v for k, v in self.surb_keys.items() if now - v[2] < 900}
            lost = [k for k, t in self.loops.items() if now - t > 60]
            for k in lost:
                del self.loops[k]
            if lost:
                log.warning("%d loop packets lost (possible active attack or congestion)", len(lost))

    def backlog(self) -> int:
        return sum(l.queue.qsize() for l in self.lanes)

    # ------------------------------------------------------------ 경로
    def _delay(self) -> int:
        return int(random.expovariate(1 / self.profile.mean_delay_ms)) if self.profile.mean_delay_ms > 0 else 0

    def _lanes_for(self, n: int) -> list[Lane]:
        off = random.randrange(len(self.lanes))
        return [self.lanes[(off + i) % len(self.lanes)] for i in range(n)]

    def _fresh(self, d: Descriptor) -> Descriptor:
        """링크·스트림이 쥐고 있는 기술자는 오래됐을 수 있다 (epoch 키가 바뀐다). 패킷을 만들 때마다 최신 합의로 바꾼다."""
        return self.consensus.nodes.get(d.node_id, d)

    def _forward_packet(self, gw: Descriptor, mixes: list[Descriptor], final: Descriptor,
                        final_routing: S.Routing, body: bytes) -> bytes:
        path = [self._fresh(d) for d in [gw] + mixes + [final]]
        hops = [S.Hop(d.node_id, d.sphinx_key()) for d in path]
        routes = [S.Routing(S.RELAY, self._delay(), path[i + 1].node_id, b"") for i in range(len(path) - 1)]
        pkt, _ = S.create_packet(hops, routes + [final_routing], body)
        return pkt

    def _send_message(self, dest, msg: bytes):
        """메시지 하나를 k-of-n으로 쪼개 마름모 경로로 보낸다.
        dest가 출구(Descriptor)면 모든 조각이 그 출구에서 모인다. ServiceDest면 서비스의 intro
        게이트웨이들로 나뉘어 들어가고 서비스 자신이 모은다 (출구 없음)."""
        p = self.profile
        k = random.randint(*p.split_k)
        cap = dest.cap if isinstance(dest, EndpointDest) else P.FRAG_CAP
        k = max(k, -(-(len(msg) + P.TAG_LEN) // cap))      # 너무 크면 k를 키운다
        n = min(P.MAX_N, k + random.randint(*p.split_extra))
        frags = P.split(msg, k, n, cap=cap)
        paths = disjoint_paths(self.consensus, n)
        lanes = self._lanes_for(n)
        finals: list[bytes] = []
        if isinstance(dest, EndpointDest):
            # 오른쪽 꼭짓점을 출구가 아니라 서버로: 조각마다 서로 다른 출구와 서로 다른 입구 포트
            exits = self.consensus.by_role("exit")
            random.shuffle(exits)
            ex_for = [exits[i % len(exits)] for i in range(n)]
        for i, (frag, mixes, lane) in enumerate(zip(frags, paths, lanes)):
            if isinstance(dest, EndpointDest):
                from .endpoint import entry_header
                d = dest.desc
                body = entry_header(d.host, d.ports[i % len(d.ports)], d.link_fp) + frag.pack()
                pkt = self._forward_packet(lane.gateway, mixes, ex_for[i],
                                           S.Routing(S.DELIVER_ENDPOINT, 0, b"", b""), body)
                finals.append(ex_for[i].node_id)
            elif isinstance(dest, ServiceDest):
                gw, mailbox = dest.intros[i % len(dest.intros)]
                pkt = self._forward_packet(lane.gateway, mixes, gw,
                                           S.Routing(S.DELIVER_MAILBOX, 0, mailbox, b"\0" * 8), frag.pack())
            else:
                pkt = self._forward_packet(lane.gateway, mixes, dest,
                                           S.Routing(S.DELIVER_EXIT, 0, b"", b""), frag.pack())
            lane.queue.put_nowait((W.F_PACKET, pkt))
        if self.path_log is not None:
            self.path_log.append([[l.gateway.node_id] + [m.node_id for m in mp] + finals[i:i + 1]
                                  for i, (l, mp) in enumerate(zip(lanes, paths))])
        self.stats["messages_split"] += 1
        self.stats["fragments_sent"] += n

    @staticmethod
    def surb_epoch() -> int:
        """새 SURB에 쓸 epoch. 노드는 다음 epoch 키를 미리 게시하므로, epoch의 마지막 1/4에는 다음 epoch 키로
        만든다. 그러면 경계에서 모든 SURB가 한꺼번에 만료되지 않는다."""
        now = time.time()
        cur = D.current_epoch(now)
        return cur + 1 if (now % D.EPOCH_LEN) > 0.75 * D.EPOCH_LEN else cur

    def _make_surb_set(self, stream: MStream, epoch: int | None = None) -> list[S.SURB]:
        """응답 하나용 SURB n개. 경로가 서로 겹치지 않고 게이트웨이도 나눠 쓴다 (응답 마름모)."""
        n = self.profile.reply_n
        epoch = self.surb_epoch() if epoch is None else epoch
        out = []
        for mixes, lane in zip(disjoint_paths(self.consensus, n), self._lanes_for(n)):
            path = [self._fresh(d) for d in mixes + [lane.gateway]]
            hops = [S.Hop(d.node_id, d.sphinx_key(epoch)) for d in path]
            surb_id = os.urandom(S.SURB_ID_LEN)
            routes = [S.Routing(S.RELAY, self._delay(), path[i + 1].node_id, b"") for i in range(3)]
            routes.append(S.Routing(S.DELIVER_MAILBOX, 0, lane.mailbox, surb_id))
            surb, keys = S.create_surb(hops, routes)
            self.surb_keys[surb_id] = (keys, stream, time.time())
            out.append(surb)
        return out

    # ------------------------------------------------------------ 송신 (Poisson)
    async def _transmit(self, lane: Lane, pkt: bytes, ftype: int = W.F_PACKET):
        try:
            await lane.link.send(ftype, pkt)
        except Exception:      # noqa: BLE001
            lane.link.close()
            await self._reconnect(lane)

    async def _payload_loop(self, lane: Lane):
        while True:
            await asyncio.sleep(random.expovariate(self.profile.rate_payload))
            try:
                ftype, pkt = lane.queue.get_nowait()
                self.stats["sent_real"] += 1
                await self._transmit(lane, pkt, ftype)
            except asyncio.QueueEmpty:
                await self._send_drop(lane)

    async def _poisson(self, rate_attr: str, fn, lane: Lane):
        """속도는 매번 현재 프로파일에서 읽는다 (보안 수준을 실행 중에 바꿀 수 있게)."""
        while True:
            rate = getattr(self.profile, rate_attr)
            if rate <= 0:
                await asyncio.sleep(1)
                continue
            await asyncio.sleep(random.expovariate(rate))
            await fn(lane)

    async def _send_drop(self, lane: Lane):
        x = random.choice(self.consensus.by_role("exit"))
        body = K.Cell(K.C_DROP, os.urandom(16), 0, b"").pack()
        self.stats["sent_cover"] += 1
        await self._transmit(lane, self._forward_packet(
            lane.gateway, disjoint_paths(self.consensus, 1)[0], x, S.Routing(S.DELIVER_EXIT, 0, b"", b""), body))

    async def _send_loop(self, lane: Lane):
        lid = os.urandom(S.SURB_ID_LEN)
        self.loops[lid] = time.time()
        self.stats["sent_loop"] += 1
        await self._transmit(lane, self._forward_packet(
            lane.gateway, disjoint_paths(self.consensus, 1)[0], lane.gateway,
            S.Routing(S.DELIVER_MAILBOX, 0, lane.mailbox, lid), b""))

    # ------------------------------------------------------------ 수신
    async def _receiver(self, lane: Lane, link: W.Link):
        try:
            while True:
                ftype, body = await link.recv()
                if ftype == W.F_DELIVER:
                    self._on_deliver(*W.unpack_deliver(body))
                else:
                    self.stats["recv_dummy"] += 1
        except Exception:      # noqa: BLE001
            if link is lane.link:
                link.close()
                await self._reconnect(lane)

    def _on_deliver(self, surb_id: bytes, payload: bytes):
        if surb_id in self.loops:
            rtt = (time.time() - self.loops.pop(surb_id)) * 1000
            self.stats["loops_back"] += 1
            self.stats["loop_rtt_ms"] = 0.8 * self.stats["loop_rtt_ms"] + 0.2 * rtt
            return
        entry = self.surb_keys.pop(surb_id, None)
        if entry is None:
            if self.on_forward is not None:     # 서비스 모드: 정방향 조각 수신
                self.on_forward(payload)
            return
        keys, stream, _ = entry
        try:
            frag = P.parse(S.open_surb_reply(keys, payload))
        except S.SphinxError:
            log.warning("reply integrity failure (tagging attempt?)")
            return
        if frag is None:
            return
        self.stats["recv_real"] += 1
        msg = self.reasm.add(frag)
        if msg is None:
            return
        try:
            if stream.e2e is not None:
                msg = stream.e2e.open(msg)
            cell = K.Cell.unpack(msg)
        except (ValueError, E.E2EError):
            return
        self.stats["messages_reassembled"] += 1
        if cell.session == stream.sid:
            stream._on_cell(cell)

    def _forget(self, stream: MStream):
        self.streams.pop(stream.sid, None)

    # ------------------------------------------------------------ 공개 API
    async def _service_dest(self, address: str) -> ServiceDest:
        d = self.consensus.services.get(address)
        if d is None:       # 막 게시된 서비스일 수 있다 → 합의를 한 번 새로 받는다
            c = await fetch_consensus(self.authorities, self.threshold)
            if c.usable():
                self.consensus = c
            d = self.consensus.services.get(address)
        if d is None:
            raise StreamError(f"unknown service {address}")
        intros = [(self.consensus.nodes[g], m) for g, m in d.intros
                  if g in self.consensus.nodes and self.consensus.nodes[g].role == "gateway"]
        if not intros:
            raise StreamError("service has no reachable intro gateway")
        return ServiceDest(d, intros)

    def add_endpoint(self, desc) -> None:
        """검증된 엔드포인트 기술자 등록. 이후 그 도메인으로 가는 연결은 다중 입구 마름모를 쓴다."""
        if desc.verify():
            old = self.endpoints.get(desc.domain)
            if old is None or old.published <= desc.published:
                self.endpoints[desc.domain] = desc

    def exit_for_key(self, isolation: str) -> Descriptor:
        exits = self.consensus.by_role("exit")
        d = self.exit_for.get(isolation)
        if d is None or d not in exits:
            d = self.exit_for[isolation] = random.choice(exits)
        return d

    def set_profile(self, name: str) -> None:
        """보안 수준을 실행 중에 바꾼다: 홉 지연, 커버 트래픽 속도, 분할 정책, SURB 창.
        게이트웨이 수는 이미 연결된 링크를 유지한다 (바꾸려면 재시작)."""
        if name not in PROFILES:
            raise ValueError(f"unknown profile {name}")
        self.profile = PROFILES[name]
        for st in self.streams.values():
            st.target = min(st.target, self.profile.window)
        log.info("profile changed to %s", name)

    def new_route(self, isolation: str) -> None:
        """한 사이트(격리 키)만 새 출구로. 다른 사이트에는 영향을 주지 않는다."""
        self.exit_for.pop(isolation, None)

    def new_identity(self):
        """모든 격리 키의 출구 매핑을 버린다. 이후 연결은 새 출구, 새 세션 id를 쓴다."""
        self.exit_for.clear()

    async def open_stream(self, host: str, port: int, isolation: str = "", timeout: float = 60) -> MStream:
        await self.ready.wait()
        sid = os.urandom(16)
        if host.lower().rstrip(".") in self.endpoints:
            ed = self.endpoints[host.lower().rstrip(".")]
            st = MStream(self, EndpointDest(ed), sid, E.ClientSession(sid, ed.x25519_pk, ed.mlkem_pk))
        elif host.lower().endswith(".mosaic"):
            dest = await self._service_dest(host.lower())
            st = MStream(self, dest, sid, E.ClientSession(sid, dest.desc.x25519_pk, dest.desc.mlkem_pk))
        else:
            st = MStream(self, self.exit_for_key(isolation or host), sid)
        self.streams[st.sid] = st
        st._send(K.C_OPEN, json.dumps({"host": host, "port": port, "reply_k": self.profile.reply_k}).encode())
        st._supply_surbs(st.target)
        self.stats["streams_opened"] += 1
        try:
            await asyncio.wait_for(asyncio.shield(st.connected), timeout)
        except asyncio.TimeoutError as e:
            self._forget(st)
            raise StreamError("connect timeout") from e
        return st
