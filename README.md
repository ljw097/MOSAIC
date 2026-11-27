# MOSAIC

**M**ix-network **O**verlay with **S**phinx, **A**nonymous **I**nternet access and **C**over traffic

MOSAIC은 인터넷용 익명 통신 시스템과 이를 쓰는 브라우저를 함께 담은 연구용 프로토타입이다.
네트워크 운영자, 통신사, 수동 감시자, 악성 중계 노드, 그리고 망 전체를 관찰할 수 있는 국가급
공격자까지 상정하고 설계했다. 목표는 두 가지다. 통신 내용을 숨기는 것, 그리고 **누가 누구와
통신하는지(관계 메타데이터)** 를 추적하기 어렵게 만드는 것이다.

> ⚠️ 아직 연구용 프로토타입이다. 독립적인 보안 감사를 받지 않았다. 생명이나 신변이 걸린
> 상황에서는 Tor Browser 같은 검증된 도구를 써야 한다. 한계는 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)에 정리했다.

## 왜 Tor와 다른가

Tor 같은 저지연 onion routing은 패킷을 바로바로 중계한다. 그래서 망의 입구와 출구를 동시에
보는 공격자는 패킷의 타이밍과 양을 맞춰 보는 것만으로 송신자와 수신자를 연결할 수 있다.
MOSAIC은 이 **트래픽 상관(correlation) 공격**을 겨냥해 믹스넷 계열 기법(Loopix, Nym, Katzenpost)을 조합했다.

| 계층 | 기법 | 막는 것 |
|---|---|---|
| 패킷 | **Sphinx** 고정 길이 패킷, 홉마다 블라인딩, LIONESS 페이로드 | 크기·비트 패턴으로 패킷 추적, 변조(tagging) 공격, 재전송 |
| 믹싱 | **연속 시간 Poisson 믹싱** (홉마다 지수분포 지연, 송신자가 결정) | 노드 입출력 타이밍 상관 |
| 커버 | 클라이언트 **λ_P / λ_L / λ_D** 세 가지 Poisson 흐름, 노드 루프, 게이트웨이 하향 더미 | "언제·얼마나 통신하는가" 노출, (n-1) 공격 |
| 링크 | **X25519 + ML-KEM-768 하이브리드** 핸드셰이크, 고정 길이 AEAD 프레임 | 지금 녹화해 두고 양자컴퓨터로 나중에 해독하기, 링크 내용 관찰 |
| 응답 | **SURB** (단일 사용 응답 블록) | 출구·서버가 응답을 돌려보내면서 클라이언트 위치를 알아내기 |
| 디렉터리 | **다중 권한 서버, k-of-n** 기술자 투표, 결정적 계층 배정 | 가짜 노드 주입, 클라이언트별로 다른 목록 보여주기(분할 공격), 노드가 원하는 위치 고르기 |
| 브라우저 | **스크립트 실행 안 함** + 강제 CSP, 사이트별 출구·쿠키 격리, 통일된 헤더, HTTPS 우선 | JS 지문채취, WebRTC IP 누출, 사이트 간 추적, DNS 누출 |

## 구조

```
               ┌──────── 링크: X25519+ML-KEM-768, 고정 길이 프레임 ─────────┐
 브라우저 ─▶ SOCKS5 ─▶ 클라이언트 ══▶ 게이트웨이 ─▶ 믹스 L1 ─▶ 믹스 L2 ─▶ 믹스 L3 ─▶ 출구 ─▶ 인터넷
                     ▲    (Poisson 송신 +      ▲                                   │
                     │     루프/드롭 커버)     │ (Poisson 하향 + 더미)              │
                     └═════════ 게이트웨이 ◀─ L3 ◀─ L2 ◀─ L1 ◀───── SURB 응답 ────┘
```

- **게이트웨이**는 클라이언트의 IP를 안다. 하지만 목적지는 모른다.
- **믹스**는 바로 앞 홉과 다음 홉만 안다.
- **출구**는 목적지는 안다. 하지만 송신자는 모르고, SURB로만 답할 수 있다.
- 종단 간 TLS를 쓰면 출구도 내용을 볼 수 없다.

## 빠른 시작

```bash
pip install -e .            # Python 3.11+, cryptography>=47 (ML-KEM 지원)

# 로컬 테스트망 전체 + 클라이언트 + SOCKS5 + 브라우저
mosaic testnet
#  → [mosaic] SOCKS5 프록시: socks5h://127.0.0.1:9050
#  → [mosaic] 브라우저: http://127.0.0.1:8118/<token>/   ← 평소 쓰는 브라우저로 연다

# 다른 프로그램도 MOSAIC으로 보낼 수 있다
curl --socks5-hostname 127.0.0.1:9050 https://example.com

# 호환 모드: Chromium을 MOSAIC 전용 설정(DNS/WebRTC/QUIC 누출 차단, 기본 JS 끔)으로 실행
mosaic testnet --chromium
```

### 실제 분산 배치

```bash
# 1) 권한 서버 (3대 이상 권장, 서로 다른 운영 주체)
mosaic authority --key auth.key --listen 0.0.0.0:7000 --public-host dir1.example.org
#  → authority spec: dir1.example.org:7000:<pubkey>

A="--authority dir1.example.org:7000:<pk1> --authority dir2...:<pk2> --authority dir3...:<pk3> --threshold 2"

# 2) 노드
mosaic node --role gateway --key gw.json  --listen 0.0.0.0:7100 --public-host gw.example.org $A
mosaic node --role mix     --key mix.json --listen 0.0.0.0:7100 --public-host m1.example.org $A
mosaic node --role exit    --key ex.json  --listen 0.0.0.0:7100 --public-host x1.example.org $A

# 3) 클라이언트 + 브라우저
mosaic client $A --profile balanced
```

### 익명성 프로파일

| 프로파일 | 홉당 평균 지연 | λ_P | 루프/드롭 | 용도 |
|---|---|---|---|---|
| `interactive` | 20 ms | 40/s | 2/s | 웹 탐색 (기본값) |
| `balanced` | 100 ms | 25/s | 3/s | 일반 |
| `paranoid` | 800 ms | 10/s | 4/s | 메시징, 강한 공격자 상정 |

지연이 길고 커버 트래픽이 많을수록 전역 관찰자에 대한 익명성이 커진다. 대신 속도는 느려진다.

## 테스트

```bash
pip install -e '.[test]'
pytest -q
```

테스트가 검증하는 내용:
- Sphinx: 1–5홉 경로 모두 정상 동작, SURB 왕복, 헤더 변조와 페이로드 태깅 탐지, 홉 사이 비트 단위 비연결성
- 다중 권한 서버 합의가 악성 권한 서버 하나가 주입한 노드와 위조 서명을 거부함
- 링크 핸드셰이크와 노드 사칭 거부
- HTML 정화기: 스크립트·이벤트 핸들러·iframe·base·meta refresh를 제거하고 모든 URL을 재작성함
- 통합 테스트: 권한 서버 3대(2-of-3), 노드 10개 망에서 100KB 양방향 스트림, SOCKS5, 브라우저 정화, 커버·루프 트래픽 흐름

## 문서

- [docs/PROTOCOL.md](docs/PROTOCOL.md): 패킷·링크·셀·디렉터리 명세
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): 위협 모델, 보장하는 것과 보장하지 않는 것, 로드맵
