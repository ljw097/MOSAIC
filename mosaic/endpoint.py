"""MOSAIC 다중 입구 엔드포인트: 공개 서버가 서로 다른 출구 노드에서 조각을 직접 받아 스스로 합친다.

  클라이언트 ◇─┬─ G ─ L1 ─ L2 ─ L3 ─ X1 ─▶ server:7001 ─┐
              ├─ G'─ L1'─ L2'─ L3'─ X2 ─▶ server:7002 ─┼─◇ 서버 (k개로 복원 → E2E 복호 → 백엔드)
              └─ G ─ L1"─ L2"─ L3"─ X3 ─▶ server:7003 ─┘

- 출구가 메시지를 모으지 않는다. 조각 i는 출구 X_i를 거쳐 입구 포트 i로 들어간다. 출구를 메시지마다
  서로 다르게 고르므로, 출구 하나는 메시지당 조각을 최대 1개만 본다.
- 조각 안의 내용은 서버 키로 종단 간 암호화(X25519 + ML-KEM-768)되어 있다. 출구 k개 이상이 공모해
  조각을 다 모아도 얻는 것은 E2E 암호문뿐이다.
- 응답 조각은 서버에 연결된 출구 링크들에 하나씩 나눠 실어 SURB로 돌려보낸다. 응답 방향도 마름모다.
- 서버 IP는 원래 공개되어 있다 (일반 웹사이트). 숨기는 대상은 클라이언트와, 누가 무엇을 보냈는지다.
  서버 자체를 숨겨야 한다면 .mosaic 서비스를 쓴다.

키 발견 (도메인 ↔ 키 결합)
  사이트는 https://<domain>/.well-known/mosaic.json 에 서명된 엔드포인트 기술자를 올리고, 응답 헤더
  `Mosaic-Endpoint: /.well-known/mosaic.json`으로 지원을 알린다 (Tor의 Onion-Location과 비슷하다).
  이 파일은 HTTPS로 받으므로 도메인 인증서가 결합을 보증한다. 출구가 키를 바꿔치기할 수 없다.

입구 헤더 (Sphinx 페이로드 본문 안, 조각 앞)
  0xED ‖ port(2) ‖ hlen(1) ‖ host ‖ link_fingerprint(32) ‖ fragment
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import struct
import time
from dataclasses import dataclass

from . import crypto as C
from . import split as P
from . import wire as W
from .directory import canonical
from .service import E2EReceiver

log = logging.getLogger("mosaic.endpoint")
ENTRY_MAGIC = 0xED
WELL_KNOWN = "/.well-known/mosaic.json"
HEADER_HINT = "Mosaic-Endpoint"
MAX_HOST = 253


def entry_header(host: str, port: int, fingerprint: bytes) -> bytes:
    h = host.encode("idna")
    if len(h) > MAX_HOST:
        raise ValueError("host too long")
    return struct.pack(">BHB", ENTRY_MAGIC, port, len(h)) + h + fingerprint


def parse_entry(body: bytes) -> tuple[str, int, bytes, bytes] | None:
    """-> (host, port, fingerprint, fragment_bytes)"""
    if len(body) < 4 or body[0] != ENTRY_MAGIC:
        return None
    _m, port, hl = struct.unpack_from(">BHB", body)
    off = 4 + hl
    if len(body) < off + 32:
        return None
    try:
        host = body[4:off].decode("idna")
    except UnicodeError:
        return None
    fp = body[off:off + 32]
    frag = body[off + 32:]
    f = P.parse(frag)
    if f is None:
        return None
    return host, port, fp, frag[:P.FRAG_HDR.size + len(f.piece)]


def piece_cap(host: str) -> int:
    """입구 헤더를 붙인 뒤 조각 하나에 남는 piece 용량."""
    return P.FRAG_CAP - (4 + len(host.encode("idna")) + 32)


@dataclass
class EndpointKeys:
    identity_sk: bytes
    identity_pk: bytes
    x25519_sk: bytes        # E2E
    x25519_pk: bytes
    mlkem_seed: bytes       # E2E
    mlkem_pk: bytes
    link_sk: bytes          # 입구 링크
    link_pk: bytes
    link_mlkem_seed: bytes
    link_mlkem_pk: bytes

    @classmethod
    def generate(cls) -> "EndpointKeys":
        isk, ipk = C.ed_keygen()
        xsk, xpk = C.x25519_keygen()
        ms, mp = C.mlkem_keygen()
        lsk, lpk = C.x25519_keygen()
        lms, lmp = C.mlkem_keygen()
        return cls(isk, ipk, xsk, xpk, ms, mp, lsk, lpk, lms, lmp)

    @classmethod
    def load_or_create(cls, path: str) -> "EndpointKeys":
        import os
        if os.path.exists(path):
            with open(path) as f:
                d = json.load(f)
            return cls(**{k: bytes.fromhex(d[k]) for k in cls.__dataclass_fields__})
        k = cls.generate()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({f_: getattr(k, f_).hex() for f_ in cls.__dataclass_fields__}, f)
        return k

    @property
    def fingerprint(self) -> bytes:
        return W.bundle_fingerprint(self.link_pk, self.link_mlkem_pk)


@dataclass
class EndpointDescriptor:
    domain: str
    host: str                   # 입구 주소 (IP 또는 호스트명)
    ports: list[int]            # 입구 포트들 (마름모 오른쪽 꼭짓점의 입구)
    identity_pk: bytes
    x25519_pk: bytes
    mlkem_pk: bytes
    link_fp: bytes
    published: int
    sig: bytes = b""

    def body(self) -> dict:
        return {"domain": self.domain, "host": self.host, "ports": self.ports,
                "identity_pk": self.identity_pk.hex(), "x25519_pk": self.x25519_pk.hex(),
                "mlkem_pk": self.mlkem_pk.hex(), "link_fp": self.link_fp.hex(), "published": self.published}

    def to_json(self) -> dict:
        d = self.body()
        d["sig"] = self.sig.hex()
        return d

    @classmethod
    def from_json(cls, d: dict) -> "EndpointDescriptor":
        return cls(str(d["domain"]).lower(), str(d["host"]), [int(p) for p in d["ports"]],
                   bytes.fromhex(d["identity_pk"]), bytes.fromhex(d["x25519_pk"]), bytes.fromhex(d["mlkem_pk"]),
                   bytes.fromhex(d["link_fp"]), int(d["published"]), bytes.fromhex(d.get("sig", "")))

    @classmethod
    def create(cls, keys: EndpointKeys, domain: str, host: str, ports: list[int]) -> "EndpointDescriptor":
        d = cls(domain.lower(), host, list(ports), keys.identity_pk, keys.x25519_pk, keys.mlkem_pk,
                keys.fingerprint, int(time.time()))
        d.sig = C.ed_sign(keys.identity_sk, b"MOSAIC-endpoint" + canonical(d.body()))
        return d

    def verify(self) -> bool:
        if not self.ports or len(self.ports) > 16 or not all(0 < p < 65536 for p in self.ports):
            return False
        if len(self.x25519_pk) != 32 or len(self.mlkem_pk) != C.MLKEM_PK_LEN or len(self.link_fp) != 32:
            return False
        if len(self.host.encode("idna")) > MAX_HOST or piece_cap(self.host) < 512:
            return False
        return C.ed_verify(self.identity_pk, self.sig, b"MOSAIC-endpoint" + canonical(self.body()))


def parse_well_known(domain: str, data: bytes) -> EndpointDescriptor:
    """HTTPS로 받은 .well-known 문서를 검증한다. 도메인이 일치하고 서명이 유효해야 한다."""
    d = EndpointDescriptor.from_json(json.loads(data))
    if d.domain != domain.lower().rstrip("."):
        raise ValueError("endpoint descriptor is for a different domain")
    if not d.verify():
        raise ValueError("invalid endpoint descriptor")
    return d


class EndpointHost(E2EReceiver):
    """공개 서버 측. 입구 포트마다 출구의 연결을 받는다."""

    def __init__(self, keys: EndpointKeys, domain: str, listen_host: str, ports: list[int],
                 target: tuple[str, int] | None = None, port_map: dict[int, tuple[str, int]] | None = None,
                 public_host: str | None = None):
        super().__init__(keys.x25519_sk, keys.mlkem_seed, target, port_map)
        self.keys, self.domain = keys, domain
        self.listen_host, self.ports = listen_host, list(ports)
        self.public_host = public_host or listen_host
        self.servers = []
        self.links: list[W.Link] = []
        self.entry_stats = {p: 0 for p in self.ports}
        self._rr = 0
        self.tasks: list[asyncio.Task] = []

    def descriptor(self) -> EndpointDescriptor:
        return EndpointDescriptor.create(self.keys, self.domain, self.public_host, self.ports)

    def well_known(self) -> bytes:
        return json.dumps(self.descriptor().to_json(), indent=1).encode()

    async def start(self):
        for i, p in enumerate(self.ports):
            srv = await asyncio.start_server(lambda r, w, idx=i: self._on_conn(r, w, idx), self.listen_host, p)
            self.ports[i] = srv.sockets[0].getsockname()[1]      # p == 0 이면 임의 포트 (테스트)
            self.servers.append(srv)
        self.entry_stats = {p: 0 for p in self.ports}
        self.tasks.append(asyncio.create_task(self._gc_loop()))
        log.info("endpoint %s: %d entry ports %s", self.domain, len(self.ports), self.ports)

    async def stop(self):
        for t in self.tasks:
            t.cancel()
        for s in self.servers:
            s.close()
        for l in self.links:
            l.close()
        await self.exit.close()

    async def _gc_loop(self):
        while True:
            await asyncio.sleep(60)
            self.gc()

    async def _on_conn(self, r, w, idx: int):
        port = self.ports[idx]
        k = self.keys
        try:
            link = await W.accept_pinned(r, w, k.link_sk, k.link_mlkem_seed, k.link_mlkem_pk)
        except Exception:      # noqa: BLE001
            w.close()
            return
        self.links.append(link)
        try:
            while True:
                ftype, body = await link.recv()
                if ftype == W.F_ENDPOINT_FRAG:
                    self.entry_stats[port] = self.entry_stats.get(port, 0) + 1
                    self.on_fragment_body(body)
        except Exception:      # noqa: BLE001
            pass
        finally:
            link.close()
            if link in self.links:
                self.links.remove(link)

    async def send_packet(self, first_hop: bytes, packet: bytes):
        """응답 조각마다 다른 출구 링크로 돌려보낸다 (라운드로빈). 출구가 첫 홉으로 전달한다."""
        links = [l for l in self.links if not l.closed]
        if not links:
            log.warning("no exit link available for reply")
            return
        self._rr = (self._rr + 1) % len(links)
        try:
            await links[self._rr].send(W.F_FORWARD, first_hop + packet)
        except Exception:      # noqa: BLE001
            links[self._rr].close()
            await random.choice(links).send(W.F_FORWARD, first_hop + packet)
