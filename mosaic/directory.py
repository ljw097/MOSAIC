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
EPOCH_LEN = 3600
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

    def body(self) -> dict:
        return {
            "node_id": self.node_id.hex(), "role": self.role, "host": self.host, "port": self.port,
            "identity_pk": self.identity_pk.hex(), "sphinx_pk": self.sphinx_pk.hex(),
            "link_pk": self.link_pk.hex(), "mlkem_pk": self.mlkem_pk.hex(),
            "published": self.published, "exit_policy": self.exit_policy,
        }

    def to_json(self) -> dict:
        d = self.body()
        d["sig"] = self.sig.hex()
        return d

    @classmethod
    def from_json(cls, d: dict) -> "Descriptor":
        return cls(bytes.fromhex(d["node_id"]), d["role"], d["host"], int(d["port"]),
                   bytes.fromhex(d["identity_pk"]), bytes.fromhex(d["sphinx_pk"]),
                   bytes.fromhex(d["link_pk"]), bytes.fromhex(d["mlkem_pk"]), int(d["published"]),
                   d.get("exit_policy", {}), bytes.fromhex(d.get("sig", "")))

    @classmethod
    def create(cls, keys: NodeKeys, role: str, host: str, port: int, exit_policy: dict | None = None) -> "Descriptor":
        d = cls(keys.node_id, role, host, port, keys.identity_pk, keys.sphinx_pk, keys.link_pk, keys.mlkem_pk,
                int(time.time()), exit_policy or {})
        d.sig = C.ed_sign(keys.identity_sk, b"MOSAIC-desc" + canonical(d.body()))
        return d

    def verify(self) -> bool:
        if self.role not in ROLES:
            return False
        if self.node_id != C.h(b"node-id", self.identity_pk, n=16):
            return False
        if len(self.sphinx_pk) != 32 or len(self.link_pk) != 32 or len(self.mlkem_pk) != C.MLKEM_PK_LEN:
            return False
        return C.ed_verify(self.identity_pk, self.sig, b"MOSAIC-desc" + canonical(self.body()))

    def digest(self) -> str:
        return C.h(canonical(self.to_json())).hex()


# ---------------------------------------------------------------- 권한 서버
class Authority:
    def __init__(self, sk: bytes, host: str, port: int):
        self.sk, self.pk = sk, C.ed25519.Ed25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()
        self.host, self.port = host, port
        self.descs: dict[bytes, Descriptor] = {}
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
        doc = {"epoch": int(now // EPOCH_LEN), "descriptors": [d.to_json() for d in descs]}
        return {"authority": self.pk.hex(), "doc": doc,
                "sig": C.ed_sign(self.sk, b"MOSAIC-consensus" + canonical(doc)).hex()}


async def _request(host: str, port: int, req: dict, timeout: float = 10) -> dict:
    r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        w.write(canonical(req) + b"\n")
        await w.drain()
        line = await asyncio.wait_for(r.readline(), timeout)
        return json.loads(line)
    finally:
        w.close()


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
    c = Consensus(epochs.most_common(1)[0][0], nodes)
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
