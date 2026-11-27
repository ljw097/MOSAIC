"""mosaic 명령줄 도구."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile

from . import crypto as C
from .browser.server import BrowserServer
from .client import PROFILES, MosaicClient
from .directory import Authority, NodeKeys, parse_authorities
from .exit import ExitService
from .node import Node
from .socks import SocksServer


def _hostport(s: str) -> tuple[str, int]:
    h, p = s.rsplit(":", 1)
    return h, int(p)


async def _forever():
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()


def chromium_flags(socks_port: int, profile_dir: str, no_js: bool) -> list[str]:
    """호환 모드: 실제 Chromium을 MOSAIC SOCKS로 강제한다. 지문 방어는 기본(no-JS) 모드보다 약하다."""
    flags = [
        f"--proxy-server=socks5://127.0.0.1:{socks_port}",
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",   # 로컬 DNS 누출 차단
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",    # WebRTC IP 누출 차단
        "--disable-quic", "--incognito", "--no-first-run", "--no-default-browser-check",
        "--disable-background-networking", "--disable-sync", "--disable-component-update",
        "--disable-domain-reliability", "--disable-breakpad", "--metrics-recording-only",
        "--disable-features=Translate,OptimizationHints,MediaRouter,InterestFeedContentSuggestions,"
        "AutofillServerCommunication,CertificateTransparencyComponentUpdater,DnsOverHttps",
        "--lang=en-US", "--window-size=1400,900",
        f"--user-data-dir={profile_dir}",
    ]
    if no_js:
        flags.append("--blink-settings=scriptEnabled=false")
    return flags


async def _run_client_stack(args, authorities, threshold):
    client = MosaicClient(authorities, threshold, args.profile)
    await client.start()
    for path in getattr(args, "endpoint_file", None) or []:
        from .endpoint import EndpointDescriptor
        with open(path) as f:
            d = EndpointDescriptor.from_json(json.load(f))
        if not d.verify():
            raise SystemExit(f"invalid endpoint descriptor: {path}")
        client.add_endpoint(d)
        print(f"[mosaic] 다중 입구 엔드포인트 등록: {d.domain} ({len(d.ports)}개 입구)", flush=True)
    socks = SocksServer(client, "127.0.0.1", args.socks)
    await socks.start()
    print(f"[mosaic] SOCKS5 프록시: socks5h://127.0.0.1:{args.socks}", flush=True)
    browser = None
    proc = None
    if getattr(args, "browser", True):
        browser = BrowserServer(("127.0.0.1", args.socks), "127.0.0.1", args.browser_port, client,
                                asyncio.get_running_loop())
        browser.start()
        print(f"[mosaic] 브라우저: {browser.url}", flush=True)
        if getattr(args, "chromium", False):
            exe = args.chromium_path or next((shutil.which(x) for x in (
                "chromium", "chromium-browser", "google-chrome", "chrome") if shutil.which(x)), None)
            if exe:
                pdir = tempfile.mkdtemp(prefix="mosaic-chromium-")
                proc = subprocess.Popen([exe] + chromium_flags(args.socks, pdir, not args.allow_js) + [browser.url])
                print(f"[mosaic] Chromium 실행: {exe}", flush=True)
            else:
                print("[mosaic] Chromium을 찾을 수 없습니다 (--chromium-path)", flush=True)
    return client, socks, browser, proc


def cmd_keygen(args):
    k = NodeKeys.load_or_create(args.out)
    print(json.dumps({"node_id": k.node_id.hex(), "file": args.out}))


def cmd_authority(args):
    async def main():
        if os.path.exists(args.key):
            sk = bytes.fromhex(open(args.key).read().strip())
        else:
            sk, _ = C.ed_keygen()
            fd = os.open(args.key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(sk.hex())
        h, p = _hostport(args.listen)
        a = Authority(sk, h, p)
        await a.start()
        print(f"[mosaic] authority spec: {args.public_host or h}:{p}:{a.pk.hex()}", flush=True)
        await _forever()
    asyncio.run(main())


def cmd_node(args):
    async def main():
        keys = NodeKeys.load_or_create(args.key)
        h, p = _hostport(args.listen)
        svc = None
        if args.role == "exit":
            svc = ExitService(allow_private=args.allow_private,
                              upstream_proxy=_hostport(args.upstream_proxy) if args.upstream_proxy else None)
        n = Node(keys, args.role, h, p, parse_authorities(args.authority), args.threshold,
                 loop_rate=args.loop_rate, downstream_rate=args.downstream_rate, exit_service=svc,
                 public_host=args.public_host)
        await n.start()
        print(f"[mosaic] {args.role} node {keys.node_id.hex()} on {h}:{p}", flush=True)
        await _forever()
        await n.stop()
    asyncio.run(main())


def cmd_client(args):
    async def main():
        client, _s, browser, proc = await _run_client_stack(args, parse_authorities(args.authority), args.threshold)
        await _forever()
        if proc:
            proc.terminate()
        await client.stop()
    asyncio.run(main())


def cmd_serve(args):
    from .directory import ServiceKeys
    from .service import ServiceHost

    async def main():
        keys = ServiceKeys.load_or_create(args.key)
        host = ServiceHost(keys, parse_authorities(args.authority), args.threshold, _hostport(args.target),
                           args.profile)
        await host.start()
        print(f"[mosaic] 서비스 주소: http://{host.address}/  →  {args.target}", flush=True)
        await _forever()
        await host.stop()
    asyncio.run(main())


def _demo_web(title: str, lead: str, items: list[str]):
    async def web(r, w):
        try:
            await r.readuntil(b"\r\n\r\n")
        except Exception:      # noqa: BLE001
            w.close()
            return
        lis = "".join(f"<li>{i}</li>" for i in items)
        body = (f"<!doctype html><html lang=ko><meta charset=utf-8><title>MOSAIC 데모</title>"
                f"<body style='font:16px system-ui;max-width:640px;margin:40px auto'>"
                f"<h1>{title}</h1><p>{lead}</p><ul>{lis}</ul></body></html>").encode()
        w.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await w.drain()
        w.close()
    return web


async def _demo_endpoint():
    """테스트망용 데모 다중 입구 엔드포인트: 입구 포트 3개, 서버가 직접 조각을 합친다."""
    from .endpoint import EndpointHost, EndpointKeys
    srv = await asyncio.start_server(_demo_web(
        "◇ 다중 입구 엔드포인트", "이 페이지의 요청은 서로 다른 출구 3곳을 거쳐 서버의 입구 3개로 들어왔습니다.",
        ["출구는 메시지당 조각 하나만 중계했습니다. 출구가 연결을 대신 맺지도, 내용을 모으지도 않았습니다.",
         "출구가 모두 공모해 조각을 합쳐도 종단 간 암호문(X25519 + ML-KEM-768)만 얻습니다.",
         "서버가 k개 조각으로 직접 복원했습니다. 출구 하나가 조각을 버려도 메시지는 도착합니다."]), "127.0.0.1", 0)
    ep = EndpointHost(EndpointKeys.generate(), "demo-shop.example", "127.0.0.1", [0, 0, 0],
                      srv.sockets[0].getsockname()[:2])
    await ep.start()
    return ep


async def _demo_service(authorities, threshold):
    """테스트망용 데모 .mosaic 서비스: 출구 없이 E2E로 도달하는 작은 웹사이트."""
    from .directory import ServiceKeys
    from .service import ServiceHost

    srv = await asyncio.start_server(_demo_web(
        "◇ 출구 없는 통신", "이 페이지는 <b>.mosaic</b> 네이티브 서비스에서 왔습니다.",
        ["출구 노드가 없습니다. 조각들이 서비스 자신에게서 다시 모입니다.",
         "종단 간 암호화(X25519 + ML-KEM-768). 게이트웨이와 믹스는 조각을 모아도 읽지 못합니다.",
         "서비스는 당신이 누구인지 모르고, 당신은 서비스의 IP를 모릅니다."]), "127.0.0.1", 0)
    host = ServiceHost(ServiceKeys.generate(), authorities, threshold, srv.sockets[0].getsockname()[:2])
    await host.start()
    return host


def cmd_endpoint(args):
    from .endpoint import EndpointHost, EndpointKeys

    async def main():
        keys = EndpointKeys.load_or_create(args.key)
        port_map = {}
        for b in args.backend:
            vport, target = b.split("=", 1)
            port_map[int(vport)] = _hostport(target)
        ports = [int(p) for p in args.ports.split(",")]
        ep = EndpointHost(keys, args.domain, args.listen, ports, None, port_map, args.public_host)
        await ep.start()
        doc = ep.well_known()
        if args.well_known_out:
            with open(args.well_known_out, "wb") as f:
                f.write(doc)
        print(f"[mosaic] 엔드포인트 {args.domain}: 입구 {ep.ports}, 백엔드 {port_map}", flush=True)
        print("[mosaic] 이 문서를 https://%s/.well-known/mosaic.json 에 올리고, 응답 헤더에 "
              "'Mosaic-Endpoint: /.well-known/mosaic.json'을 추가하세요." % args.domain, flush=True)
        await _forever()
        await ep.stop()
    asyncio.run(main())


def cmd_testnet(args):
    from .testnet import start_testnet

    async def main():
        tn = await start_testnet(base_port=args.base_port, gateways=args.gateways, mixes_per_layer=args.mixes,
                                 exits=args.exits, allow_private=args.allow_private,
                                 upstream_proxy=_hostport(args.upstream_proxy) if args.upstream_proxy else None)
        print("[mosaic] 테스트망 준비 완료. 권한 서버:", flush=True)
        for s in tn.authority_strings():
            print("    --authority", s, flush=True)
        demo = await _demo_service(tn.authority_specs, tn.threshold)
        print(f"[mosaic] 데모 .mosaic 서비스: http://{demo.address}/", flush=True)
        ep = await _demo_endpoint()
        client, _s, browser, proc = await _run_client_stack(args, tn.authority_specs, tn.threshold)
        client.add_endpoint(ep.descriptor())
        print(f"[mosaic] 데모 다중 입구 엔드포인트: http://{ep.domain}/  (입구 포트 {ep.ports})", flush=True)
        await _forever()
        await demo.stop()
        if proc:
            proc.terminate()
        await client.stop()
        await tn.stop()
    asyncio.run(main())


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mosaic", description="MOSAIC 익명 통신 시스템")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="노드 키 생성")
    k.add_argument("--out", required=True)
    k.set_defaults(fn=cmd_keygen)

    a = sub.add_parser("authority", help="디렉터리 권한 서버 실행")
    a.add_argument("--key", required=True)
    a.add_argument("--listen", default="0.0.0.0:7000")
    a.add_argument("--public-host")
    a.set_defaults(fn=cmd_authority)

    def add_auth(p):
        p.add_argument("--authority", action="append", required=True, help="host:port:pubkeyhex (여러 번)")
        p.add_argument("--threshold", type=int, default=1)

    def add_client(p):
        p.add_argument("--profile", choices=sorted(PROFILES), default="interactive")
        p.add_argument("--socks", type=int, default=9050)
        p.add_argument("--browser-port", type=int, default=8118)
        p.add_argument("--no-browser", dest="browser", action="store_false")
        p.add_argument("--chromium", action="store_true", help="Chromium을 MOSAIC 전용 설정으로 실행 (호환 모드)")
        p.add_argument("--chromium-path")
        p.add_argument("--allow-js", action="store_true", help="호환 모드에서 JS 허용 (익명성 약화)")
        p.add_argument("--endpoint-file", action="append", help="신뢰할 엔드포인트 기술자 JSON (여러 번)")

    n = sub.add_parser("node", help="게이트웨이/믹스/출구 노드 실행")
    n.add_argument("--role", choices=["gateway", "mix", "exit"], required=True)
    n.add_argument("--key", required=True)
    n.add_argument("--listen", default="0.0.0.0:7100")
    n.add_argument("--public-host")
    n.add_argument("--loop-rate", type=float, default=1.0)
    n.add_argument("--downstream-rate", type=float, default=100.0)
    n.add_argument("--allow-private", action="store_true", help="출구: 사설 주소 허용 (테스트용)")
    n.add_argument("--upstream-proxy", help="출구: 상위 HTTP CONNECT 프록시 host:port")
    add_auth(n)
    n.set_defaults(fn=cmd_node)

    c = sub.add_parser("client", help="클라이언트 + SOCKS5 + 브라우저")
    add_auth(c)
    add_client(c)
    c.set_defaults(fn=cmd_client)

    sv = sub.add_parser("serve", help="로컬 서버를 .mosaic 네이티브 서비스로 게시 (출구 없음, E2E)")
    sv.add_argument("--key", required=True)
    sv.add_argument("--target", required=True, help="host:port (예: 127.0.0.1:8080)")
    sv.add_argument("--profile", choices=sorted(PROFILES), default="interactive")
    add_auth(sv)
    sv.set_defaults(fn=cmd_serve)

    e = sub.add_parser("endpoint", help="공개 서버를 다중 입구 엔드포인트로 (서버가 여러 출구에서 조각을 직접 받아 합침)")
    e.add_argument("--key", required=True)
    e.add_argument("--domain", required=True)
    e.add_argument("--listen", default="0.0.0.0")
    e.add_argument("--public-host", required=True, help="출구가 접속할 입구 주소 (IP/호스트명)")
    e.add_argument("--ports", default="7001,7002,7003", help="입구 포트들 (쉼표)")
    e.add_argument("--backend", action="append", required=True, help="가상포트=host:port (예: 443=127.0.0.1:443)")
    e.add_argument("--well-known-out", help=".well-known/mosaic.json 저장 경로")
    e.set_defaults(fn=cmd_endpoint)

    t = sub.add_parser("testnet", help="로컬 테스트망 + 클라이언트 + 브라우저를 한 번에 실행")
    t.add_argument("--base-port", type=int, default=17000)
    t.add_argument("--gateways", type=int, default=3)
    t.add_argument("--mixes", type=int, default=4, help="계층당 믹스 수 (마름모 폭 이상 권장)")
    t.add_argument("--exits", type=int, default=2)
    t.add_argument("--allow-private", action="store_true")
    t.add_argument("--upstream-proxy", default=None)
    add_client(t)
    t.set_defaults(fn=cmd_testnet)

    args = ap.parse_args(argv)
    if args.cmd == "testnet" and args.upstream_proxy is None and os.environ.get("MOSAIC_UPSTREAM_PROXY"):
        args.upstream_proxy = os.environ["MOSAIC_UPSTREAM_PROXY"]
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
