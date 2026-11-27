"""로컬 테스트망: 권한 서버, 게이트웨이, 3계층 믹스, 출구를 한 프로세스에 띄운다."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from . import crypto as C
from .directory import Authority, NodeKeys
from .exit import ExitService
from .node import Node


@dataclass
class Testnet:
    authorities: list[Authority] = field(default_factory=list)
    nodes: list[Node] = field(default_factory=list)
    threshold: int = 2

    @property
    def authority_specs(self) -> list[tuple[str, int, bytes]]:
        return [(a.host, a.port, a.pk) for a in self.authorities]

    def authority_strings(self) -> list[str]:
        return [f"{h}:{p}:{pk.hex()}" for h, p, pk in self.authority_specs]

    async def wait_ready(self, timeout: float = 30):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            await asyncio.gather(*(n.refresh() for n in self.nodes))
            if all(n.consensus and n.consensus.usable() and len(n.consensus.nodes) == len(self.nodes)
                   for n in self.nodes):
                return
            await asyncio.sleep(0.3)
        raise RuntimeError("testnet did not converge")

    async def stop(self):
        for n in self.nodes:
            await n.stop()
        for a in self.authorities:
            a.server.close()


async def start_testnet(base_port: int = 47000, n_authorities: int = 3, threshold: int = 2,
                        gateways: int = 2, mixes_per_layer: int = 2, exits: int = 2,
                        allow_private: bool = False, upstream_proxy=None,
                        loop_rate: float = 1.0, downstream_rate: float = 150.0,
                        host: str = "127.0.0.1") -> Testnet:
    tn = Testnet(threshold=threshold)
    port = base_port
    for _ in range(n_authorities):
        sk, _pk = C.ed_keygen()
        a = Authority(sk, host, port)
        port += 1
        await a.start()
        tn.authorities.append(a)
    specs = tn.authority_specs
    roles = ["gateway"] * gateways + ["mix"] * (3 * mixes_per_layer) + ["exit"] * exits
    for i, role in enumerate(roles):
        svc = ExitService(allow_private=allow_private, upstream_proxy=upstream_proxy) if role == "exit" else None
        n = Node(NodeKeys.generate(), role, host, port, specs, threshold, loop_rate=loop_rate,
                 downstream_rate=downstream_rate, exit_service=svc, name=f"{role}{i}")
        port += 1
        await n.start()
        tn.nodes.append(n)
    await tn.wait_ready()
    return tn
