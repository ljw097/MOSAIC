"""MOSAIC 디렉터리: 노드 기술자(descriptor), 다중 권한 서버, 합의(consensus).

- 각 노드는 Ed25519 신원키로 서명한 기술자를 모든 디렉터리 권한 서버에 등록한다.
- 각 권한 서버는 자신이 본 기술자 목록에 서명해서 배포한다.
- 클라이언트는 권한 서버들의 공개키를 미리 알고 있으며(pinning), 서명이 유효한
  문서들 중 threshold 개 이상의 권한 서버가 공통으로 수록한 기술자만 신뢰한다.
  → 소수의 권한 서버가 장악되어도 가짜 노드를 주입하거나 클라이언트마다 다른 목록을
    보여주는 분할(partitioning) 공격이 어렵다.
- 믹스 계층 배정은 노드가 고르지 않는다. 합의 epoch와 노드 id의 해시로 결정된다.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import Counter
from dataclasses import dataclass, field

from . import crypto as C

log = logging.getLogger("mosaic.directory")
DESCRIPTOR_TTL = 3600
EPOCH_LEN = 3600            # Sphinx 키 로테이션 주기 (초). 테스트에서 줄일 수 있다.


def current_epoch(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // EPOCH_LEN)
NUM_LAYERS = 3
ROLES = ("gateway", "mix", "exit")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------- 키
@dataclass
class NodeKeys:
    identity_sk: bytes
    identity_pk: bytes
    sphinx_sk: bytes
    sphinx_pk: bytes
    link_sk: bytes
    link_pk: bytes
    mlkem_seed: bytes
    mlkem_pk: bytes

    @property
    def node_id(self) -> bytes:
        return C.h(b"node-id", self.identity_pk, n=16)

    @classmethod
    def generate(cls) -> "NodeKeys":
        isk, ipk = C.ed_keygen()
        ssk, spk = C.x25519_keygen()
        lsk, lpk = C.x25519_keygen()
        ms, mp = C.mlkem_keygen()
        return cls(isk, ipk, ssk, spk, lsk, lpk, ms, mp)

    def to_json(self) -> dict:
        return {k: getattr(self, k).hex() for k in self.__dataclass_fields__}

    @classmethod
    def from_json(cls, d: dict) -> "NodeKeys":
        return cls(**{k: bytes.fromhex(d[k]) for k in cls.__dataclass_fields__})

    @classmethod
    def load_or_create(cls, path: str) -> "NodeKeys":
        import os
        if os.path.exists(path):
            with open(path) as f:
                return cls.from_json(json.load(f))
        k = cls.generate()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(k.to_json(), f)
        return k


# ---------------------------------------------------------------- 기술자
@dataclass
class Descriptor:
    node_id: bytes
    role: str
    host: str
    port: int
    identity_pk: bytes
    sphinx_pk: bytes
    link_pk: bytes
    mlkem_pk: bytes
    published: int
    exit_policy: dict = field(default_factory=dict)
    sig: bytes = b""
    layer: int = -1           # 합의에서 계산 (서명 대상 아님)
    sphinx_epochs: dict = field(default_factory=dict)    # epoch → 그 epoch의 Sphinx 공개키 (로테이션)

    def body(self) -> dict:
        b = {
            "node_id": self.node_id.hex(), "role": self.role, "host": self.host, "port": self.port,
            "identity_pk": self.identity_pk.hex(), "sphinx_pk": self.sphinx_pk.hex(),
            "link_pk": self.link_pk.hex(), "mlkem_pk": self.mlkem_pk.hex(),
            "published": self.published, "exit_policy": self.exit_policy,
        }
        if self.sphinx_epochs:
            b["sphinx_epochs"] = {str(e): pk.hex() for e, pk in sorted(self.sphinx_epochs.items())}
        return b

    def sphinx_key(self, epoch: int | None = None) -> bytes:
        """패킷을 만들 시점의 epoch 키. 로테이션을 하지 않는 노드면 고정 키."""
        return self.sphinx_epochs.get(current_epoch() if epoch is None else epoch, self.sphinx_pk)

    def to_json(self) -> dict:
        d = self.body()
        d["sig"] = self.sig.hex()
        return d

    @classmethod
    def from_json(cls, d: dict) -> "Descriptor":
        return cls(bytes.fromhex(d["node_id"]), d["role"], d["host"], int(d["port"]),
                   bytes.fromhex(d["identity_pk"]), bytes.fromhex(d["sphinx_pk"]),
                   bytes.fromhex(d["link_pk"]), bytes.fromhex(d["mlkem_pk"]), int(d["published"]),
                   d.get("exit_policy", {}), bytes.fromhex(d.get("sig", "")), -1,
                   {int(e): bytes.fromhex(pk) for e, pk in d.get("sphinx_epochs", {}).items()})

    @classmethod
    def create(cls, keys: NodeKeys, role: str, host: str, port: int, exit_policy: dict | None = None,
               sphinx_epochs: dict | None = None) -> "Descriptor":
        cur = (sphinx_epochs or {}).get(current_epoch(), keys.sphinx_pk)
        d = cls(keys.node_id, role, host, port, keys.identity_pk, cur, keys.link_pk, keys.mlkem_pk,
                int(time.time()), exit_policy or {}, sphinx_epochs=dict(sphinx_epochs or {}))
        d.sig = C.ed_sign(keys.identity_sk, b"MOSAIC-desc" + canonical(d.body()))
        return d

    def verify(self) -> bool:
        if self.role not in ROLES:
            return False
        if self.node_id != C.h(b"node-id", self.identity_pk, n=16):
            return False
        if len(self.sphinx_pk) != 32 or len(self.link_pk) != 32 or len(self.mlkem_pk) != C.MLKEM_PK_LEN:
            return False
        if len(self.sphinx_epochs) > 4 or any(len(pk) != 32 for pk in self.sphinx_epochs.values()):
            return False
        return C.ed_verify(self.identity_pk, self.sig, b"MOSAIC-desc" + canonical(self.body()))

    def digest(self) -> str:
        return C.h(canonical(self.to_json())).hex()


# ---------------------------------------------------------------- 서비스 기술자
SERVICE_TTL = 3600


@dataclass
class ServiceKeys:
    identity_sk: bytes
    identity_pk: bytes
    x25519_sk: bytes
    x25519_pk: bytes
    mlkem_seed: bytes
    mlkem_pk: bytes

    @property
    def address(self) -> str:
        from .e2e import service_address
        return service_address(self.identity_pk)

    @classmethod
    def generate(cls) -> "ServiceKeys":
        isk, ipk = C.ed_keygen()
        xsk, xpk = C.x25519_keygen()
        ms, mp = C.mlkem_keygen()
        return cls(isk, ipk, xsk, xpk, ms, mp)

    @classmethod
    def load_or_create(cls, path: str) -> "ServiceKeys":
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


@dataclass
class ServiceDescriptor:
    """네이티브 서비스 기술자. 주소 = H(identity_pk)이므로 자기 인증된다. 권한 서버를 믿을 필요가 없다.
    intros: 서비스가 조각을 받는 (게이트웨이 id, 우편함 id) 목록. 마름모의 오른쪽 꼭짓점을 넓히는 데 쓴다."""
    address: str
    identity_pk: bytes
    x25519_pk: bytes
    mlkem_pk: bytes
    intros: list[tuple[bytes, bytes]]
    published: int
    sig: bytes = b""

    def body(self) -> dict:
        return {"address": self.address, "identity_pk": self.identity_pk.hex(), "x25519_pk": self.x25519_pk.hex(),
                "mlkem_pk": self.mlkem_pk.hex(), "intros": [[g.hex(), m.hex()] for g, m in self.intros],
                "published": self.published}

    def to_json(self) -> dict:
        d = self.body()
        d["sig"] = self.sig.hex()
        return d

    @classmethod
    def from_json(cls, d: dict) -> "ServiceDescriptor":
        return cls(d["address"], bytes.fromhex(d["identity_pk"]), bytes.fromhex(d["x25519_pk"]),
                   bytes.fromhex(d["mlkem_pk"]), [(bytes.fromhex(g), bytes.fromhex(m)) for g, m in d["intros"]],
                   int(d["published"]), bytes.fromhex(d.get("sig", "")))

    @classmethod
    def create(cls, keys: ServiceKeys, intros: list[tuple[bytes, bytes]]) -> "ServiceDescriptor":
        d = cls(keys.address, keys.identity_pk, keys.x25519_pk, keys.mlkem_pk, intros, int(time.time()))
        d.sig = C.ed_sign(keys.identity_sk, b"MOSAIC-svc" + canonical(d.body()))
        return d

    def verify(self) -> bool:
        from .e2e import service_address
        if self.address != service_address(self.identity_pk) or not self.intros or len(self.intros) > 16:
            return False
        if len(self.x25519_pk) != 32 or len(self.mlkem_pk) != C.MLKEM_PK_LEN:
            return False
        return C.ed_verify(self.identity_pk, self.sig, b"MOSAIC-svc" + canonical(self.body()))


# ---------------------------------------------------------------- 권한 서버
class Authority:
    def __init__(self, sk: bytes, host: str, port: int):
        self.sk, self.pk = sk, C.ed25519.Ed25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()
        self.host, self.port = host, port
        self.descs: dict[bytes, Descriptor] = {}
        self.services: dict[str, ServiceDescriptor] = {}
        self.server: asyncio.base_events.Server | None = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        log.info("authority %s listening on %s:%d", self.pk.hex()[:16], self.host, self.port)

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        try:
            line = await asyncio.wait_for(r.readline(), 10)
            if len(line) > 1 << 16:
                return
            req = json.loads(line)
            if req.get("op") == "register":
                d = Descriptor.from_json(req["descriptor"])
                ok = d.verify() and abs(time.time() - d.published) < 600
                if ok:
                    old = self.descs.get(d.node_id)
                    if old is None or old.published <= d.published:
                        self.descs[d.node_id] = d
                resp = {"ok": ok}
            elif req.get("op") == "publish_service":
                d = ServiceDescriptor.from_json(req["descriptor"])
                ok = d.verify() and abs(time.time() - d.published) < 600 and len(self.services) < 100_000
                if ok:
                    old = self.services.get(d.address)
                    if old is None or old.published <= d.published:
                        self.services[d.address] = d
                resp = {"ok": ok}
            elif req.get("op") == "consensus":
                resp = self.signed_document()
            else:
                resp = {"ok": False}
            w.write(canonical(resp) + b"\n")
            await w.drain()
        except Exception as e:      # noqa: BLE001
            log.debug("authority request error: %s", e)
        finally:
            w.close()

    def signed_document(self) -> dict:
        now = time.time()
        descs = sorted((d for d in self.descs.values() if now - d.published < DESCRIPTOR_TTL),
                       key=lambda d: d.node_id)
        svcs = sorted((d for d in self.services.values() if now - d.published < SERVICE_TTL),
                      key=lambda d: d.address)
        # 서비스 기술자는 합의 문서에 통째로 싣는다 → 조회해도 권한 서버는 어떤 서비스를 찾는지 모른다
        doc = {"epoch": int(now // EPOCH_LEN), "descriptors": [d.to_json() for d in descs],
               "services": [d.to_json() for d in svcs]}
        return {"authority": self.pk.hex(), "doc": doc,
                "sig": C.ed_sign(self.sk, b"MOSAIC-consensus" + canonical(doc)).hex()}


MAX_DOC = 64 * 1024 * 1024      # 합의 문서 최대 크기. 기본 readline 한도(64KB)로는 노드가 20개만 넘어도 받지 못한다


async def _request(host: str, port: int, req: dict, timeout: float = 10) -> dict:
    r, w = await asyncio.wait_for(asyncio.open_connection(host, port, limit=MAX_DOC), timeout)
    try:
        w.write(canonical(req) + b"\n")
        await w.drain()
        line = await asyncio.wait_for(r.readline(), timeout)
        return json.loads(line)
    finally:
        w.close()


async def publish_service(authorities: list[tuple[str, int, bytes]], desc: ServiceDescriptor) -> int:
    ok = 0
    for host, port, _pk in authorities:
        try:
            resp = await _request(host, port, {"op": "publish_service", "descriptor": desc.to_json()})
            ok += bool(resp.get("ok"))
        except Exception as e:     # noqa: BLE001
            log.warning("publish_service at %s:%d failed: %s", host, port, e)
    return ok


async def register(authorities: list[tuple[str, int, bytes]], desc: Descriptor) -> int:
    ok = 0
    for host, port, _pk in authorities:
        try:
            resp = await _request(host, port, {"op": "register", "descriptor": desc.to_json()})
            ok += bool(resp.get("ok"))
        except Exception as e:     # noqa: BLE001
            log.warning("register at %s:%d failed: %s", host, port, e)
    return ok


# ---------------------------------------------------------------- 합의
@dataclass
class Consensus:
    epoch: int
    nodes: dict[bytes, Descriptor]
    services: dict[str, ServiceDescriptor] = field(default_factory=dict)

    def by_role(self, role: str) -> list[Descriptor]:
        return [d for d in self.nodes.values() if d.role == role]

    def layer(self, i: int) -> list[Descriptor]:
        return [d for d in self.nodes.values() if d.role == "mix" and d.layer == i]

    def assign_layers(self) -> None:
        mixes = sorted(self.by_role("mix"), key=lambda d: C.h(b"layer", self.epoch.to_bytes(8, "big"), d.node_id))
        for i, d in enumerate(mixes):
            d.layer = i % NUM_LAYERS

    def usable(self) -> bool:
        return bool(self.by_role("gateway")) and bool(self.by_role("exit")) and all(
            self.layer(i) for i in range(NUM_LAYERS))


def build_consensus(documents: list[dict], authority_pks: list[bytes], threshold: int) -> Consensus:
    votes: Counter[str] = Counter()
    seen: dict[str, Descriptor] = {}
    epochs: Counter[int] = Counter()
    trusted = {pk.hex() for pk in authority_pks}
    voted: set[str] = set()
    services: dict[str, ServiceDescriptor] = {}
    for doc in documents:
        a = doc.get("authority", "")
        if a not in trusted or a in voted:
            continue
        if not C.ed_verify(bytes.fromhex(a), bytes.fromhex(doc.get("sig", "")),
                           b"MOSAIC-consensus" + canonical(doc["doc"])):
            log.warning("bad consensus signature from %s", a[:16])
            continue
        voted.add(a)
        epochs[doc["doc"]["epoch"]] += 1
        for sj in doc["doc"].get("services", []):
            try:
                sd = ServiceDescriptor.from_json(sj)
            except Exception:     # noqa: BLE001
                continue
            if sd.verify() and (sd.address not in services or services[sd.address].published < sd.published):
                services[sd.address] = sd
        for dj in doc["doc"]["descriptors"]:
            d = Descriptor.from_json(dj)
            if not d.verify():
                continue
            dg = d.digest()
            votes[dg] += 1
            seen[dg] = d
    if len(voted) < threshold:
        raise RuntimeError(f"only {len(voted)} valid authority documents (< threshold {threshold})")
    nodes: dict[bytes, Descriptor] = {}
    for dg, n in votes.items():
        if n >= threshold:
            d = seen[dg]
            if d.node_id not in nodes or nodes[d.node_id].published < d.published:
                nodes[d.node_id] = d
    c = Consensus(epochs.most_common(1)[0][0], nodes, services)
    c.assign_layers()
    return c


async def fetch_consensus(authorities: list[tuple[str, int, bytes]], threshold: int) -> Consensus:
    docs = []
    for host, port, _pk in authorities:
        try:
            docs.append(await _request(host, port, {"op": "consensus"}))
        except Exception as e:     # noqa: BLE001
            log.warning("consensus fetch from %s:%d failed: %s", host, port, e)
    return build_consensus(docs, [pk for _, _, pk in authorities], threshold)


def parse_authorities(spec: list[str]) -> list[tuple[str, int, bytes]]:
    """'host:port:pubkeyhex' 목록"""
    out = []
    for s in spec:
        host, port, pk = s.rsplit(":", 2)
        out.append((host, int(port), bytes.fromhex(pk)))
    return out
