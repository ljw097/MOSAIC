# MOSAIC 프로토콜 명세 v1 (초안)

## 1. 암호 프리미티브

| 용도 | 알고리즘 |
|---|---|
| Sphinx 키 합의·블라인딩 | X25519 (클램핑된 스칼라 곱의 교환법칙 이용) |
| 링크 키 합의 | X25519 (정적+임시) ‖ ML-KEM-768 → HKDF-SHA256 |
| 헤더 스트림 암호 | ChaCha20 |
| 헤더 MAC | HMAC-SHA256 |
| 페이로드 | LIONESS (ChaCha20 + 키 있는 BLAKE2b, 4라운드) |
| 링크 프레임 | ChaCha20-Poly1305, 방향별 키, 64비트 카운터 nonce |
| 서명 | Ed25519 (노드 신원, 권한 서버) |
| 키 유도 | 키 있는 BLAKE2b (`kdf(s, label)`), HKDF-SHA256 |

## 2. Sphinx 패킷

```
PACKET (2432B) = alpha(32) ‖ beta(320) ‖ gamma(32) ‖ payload(2048)
beta  = MAX_HOPS(5) × [routing(32) ‖ mac(32)]
routing = flag(1) ‖ delay_ms(4, BE) ‖ target(16) ‖ extra(11)
```

flag 값: `RELAY=1`, `DELIVER_EXIT=2`, `DELIVER_MAILBOX=3`, `FINAL_DROP=4`

**생성 (송신자)**
1. 무작위 x를 뽑는다. `alpha_0 = X25519(x, G)`.
2. 홉 i의 공유비밀은 `s_i = X25519(b_{i-1}, … X25519(b_0, X25519(x, PK_i)))`이다.
   여기서 `b_j = H("blind", alpha_j, s_j)`, `alpha_{j+1} = X25519(b_j, alpha_j)`.
3. `rho, mu, pi, tag`는 모두 `kdf(s_i, label)`로 유도한다.
4. 필러(filler)와 beta, gamma는 Danezis–Goldberg 방식으로, 뒤 홉부터 앞 홉 순서로 만든다.
5. 페이로드는 `0^16 ‖ body`이다. 마지막 홉부터 앞 홉 순서로 `LIONESS_enc(pi_i)`를 적용한다.

**처리 (노드)**
1. `s = X25519(sk, alpha)`. `HMAC(mu, beta) == gamma`인지 확인한다.
2. `tag`가 재전송 캐시에 있으면 폐기한다.
3. `B = (beta ‖ 0^64) ⊕ ChaCha20(rho)`. 다음 헤더는 `alpha' = X25519(b, alpha)`, `beta' = B[64:]`, `gamma' = B[32:64]`.
4. `payload' = LIONESS_dec(pi, payload)`.
5. RELAY이면 `delay_ms`만큼 붙잡아 둔 뒤 `target`으로 보낸다.

**SURB**는 `first_hop(16) ‖ header(384) ‖ k0(32)`로 이루어진다. 응답자는 `LIONESS_enc(k0, 0^16‖body)`를
헤더 뒤에 붙여 보낸다. 각 홉은 dec를 적용한다. SURB를 만든 쪽은 홉 키로 enc를 거꾸로 적용한 다음
`k0`로 dec 하고 무결성 접두어를 확인한다.

## 3. 링크 계층

```
I → R : "MOSAIC/1" ‖ e_I(32) ‖ ML-KEM.Encaps(K_R).ct(1088)
R → I : e_R(32) ‖ HMAC(k_c, "responder-confirm")
k_ir ‖ k_ri ‖ k_c = HKDF(DH(e_I,S_R) ‖ ss_kem ‖ DH(e_I,e_R), "MOSAIC link v1" ‖ H(transcript))
```

이후 모든 프레임은 평문 2456B(`type(1) ‖ body ‖ zero-pad`), 암호문 2472B로 길이가 고정된다.

| type | 의미 |
|---|---|
| 1 PACKET | Sphinx 패킷 |
| 2 DELIVER | 게이트웨이 → 클라이언트: `surb_id(8) ‖ payload(2048)` |
| 3 REGISTER | 클라이언트 → 게이트웨이: `mailbox_secret(32)`. 우편함 id = `H("MOSAIC mailbox", secret)[:16]` (id가 공개돼도 가로챌 수 없음) |
| 4 DUMMY | 커버 |
| 6 ENDPOINT_FRAG | 출구 → 엔드포인트 입구: 조각 하나 |
| 5 FORWARD | 클라이언트/서비스 → 게이트웨이: `target(16) ‖ packet` (SURB 응답 대리 전송) |

## 4. 마름모 분할 계층 (SSMS)

모든 종단 셀은 Sphinx에 싣기 전에 k-of-n 조각으로 나뉜다.

```
K ← random(32);  C = ChaCha20-Poly1305(K, nonce=0, m, ad="MOSAIC-split-v1")     (|C| = |m|+16)
C를 k개 행 R_0..R_{k-1}로 자른다 (길이 l = ceil(|C|/k), 0으로 채움)
Shamir: a_0 = K, a_1..a_{k-1} ← random(32)
조각 i (x = i+1, GF(2^8), 기약다항식 0x11B):
    piece_i     = Σ_j x^j · R_j          (Rabin IDA, Vandermonde 행)
    key_share_i = Σ_j x^j · a_j
FRAGMENT (Sphinx 본문, ≤2032B) = 0xF5 ‖ msg_id(16) ‖ idx(1) ‖ k(1) ‖ n(1) ‖ |C|(2) ‖ key_share(32) ‖ piece_len(2) ‖ piece
```

- 복원: 서로 다른 조각 k개로 Vandermonde 행렬의 역행렬 V⁻¹을 구한다. 그러면 R = V⁻¹·pieces,
  K = (V⁻¹·key_shares)[0]이다. 그다음 AEAD를 검증한다. 검증에 실패하면 다른 k개 조합으로 다시 시도한다.
- 조각 하나의 용량은 1976B이고, 메시지 최대 길이는 `k·1976 − 16`이다.
- 경로 선택: 조각 i는 게이트웨이 `lanes[(off+i) mod G]`를 쓴다. 믹스는 계층마다 무작위로 섞은 목록에서
  i번째(모자라면 순환)를 쓴다. 출구는 모든 조각이 같다 (마름모의 오른쪽 꼭짓점).
- 응답: 클라이언트는 SURB **묶음**(경로가 서로 겹치지 않는 SURB n개)을 건넨다. 출구는 응답 셀 하나를
  `reply_k`-of-n으로 나눠 묶음 안의 SURB에 하나씩 싣는다.

## 5. 종단 셀 (클라이언트 ↔ 출구)

분할 전 평문 셀 = `type(1) ‖ session(16) ‖ seq(4) ‖ len(2) ‖ data(≤ k·1976 − 39)`

- 상향: `OPEN{json host,port,reply_k}`, `DATA`, `CLOSE`, `SURBS{묶음 수(1) ‖ 묶음 크기 n(1) ‖ SURB(432)…}`, `DROP` (드롭 커버는 분할하지 않음)
- 하향: `CONNECTED`, `DATA`, `CLOSE`, `ERROR`
- 방향마다 seq를 따로 매긴다. Poisson 지연 때문에 순서가 뒤바뀌므로 받는 쪽이 재정렬한다.
- 흐름 제어: 출구는 SURB 묶음이 있을 때만 TCP에서 읽는다. 그래서 클라이언트가 미리 건넨 묶음 수가 곧 하향 혼잡 창이다.
  창은 4개에서 시작해 D_DATA를 하나 받을 때마다 1씩 늘어난다 (최대 `window`, 슬로 스타트).

## 6. 네이티브 서비스 (.mosaic)

- 주소: `base32(H("mosaic-service", identity_pk)[:20]) + ".mosaic"`. 자기 인증 주소다.
- 서비스 기술자 `{address, identity_pk, x25519_pk, mlkem_pk, intros[(gateway_id, mailbox_id)], published}`를
  Ed25519로 서명한다. 권한 서버는 이것을 합의 문서의 `services`에 실을 뿐이다. 클라이언트가 주소와 서명을
  직접 검증하므로 권한 서버를 믿을 필요가 없다. 조회도 합의 문서 전체를 받는 방식이라 어떤 서비스를 찾는지 드러나지 않는다.
- 정방향: 조각 i는 `client G_i → L1 → L2 → L3 → intro_gateway_(i mod m)`로 간다. 최종 지시는
  `DELIVER_MAILBOX(intro mailbox)`이다. 서비스가 조각을 모아 SSMS를 풀고 E2E를 연다.
- E2E (`mosaic/e2e.py`):
  ```
  INIT = 0xE1 ‖ conn(16) ‖ nonce(12) ‖ e_c(32) ‖ ML-KEM ct(1088) ‖ AEAD(k_up, timestamp(8) ‖ cell)   # 10분 지나면 거부
  UP   = 0xE2 ‖ conn ‖ nonce ‖ AEAD(k_up, cell)      DOWN = 0xE3 ‖ conn ‖ nonce ‖ AEAD(k_down, cell)
  k_up ‖ k_down = HKDF(X25519(e_c, S) ‖ ss_kem, "MOSAIC e2e v1" ‖ conn ‖ e_c ‖ H(ct) ‖ S)
  ```
  conn은 셀 세션 id와 같아야 한다. INIT보다 먼저 도착한 UP은 최대 64개까지 버퍼에 둔다.
- 응답: 서비스는 SURB 패킷을 자기 게이트웨이로 보낸다 (링크 프레임 `F_FORWARD = target(16) ‖ packet`).
  게이트웨이가 대신 첫 홉에 전달하므로 믹스는 서비스 IP를 알 수 없다.

## 6b. 다중 입구 엔드포인트 (공개 서버)

- 기술자 `{domain, host, ports[], identity_pk, x25519_pk, mlkem_pk (E2E), link_fp, published}`를 Ed25519로 서명한다.
  `link_fp = H("MOSAIC link bundle", link_x25519_pk, link_mlkem_pk)`.
- 발견: HTTPS 응답 헤더 `Mosaic-Endpoint`가 있으면 `https://<domain>/.well-known/mosaic.json`을 HTTPS로 받는다.
  `domain` 일치와 서명을 확인한다. 도메인 ↔ 키 결합은 도메인의 TLS 인증서가 보증한다.
- 정방향: 메시지마다 출구를 섞은 목록에서 조각 i를 출구 `X_i`로, 입구 포트 `ports[i mod m]`로 보낸다.
  Sphinx 최종 지시는 `DELIVER_ENDPOINT(0x05)`이고, 본문은 다음과 같다.
  ```
  0xED ‖ port(2) ‖ hlen(1) ‖ host ‖ link_fp(32) ‖ FRAGMENT
  ```
  조각 용량은 `1976 − (36 + |host|)`로 줄어든다.
- 출구 → 입구 링크: 응답자가 먼저 정적 공개키 묶음(32+1184B)을 보낸다. 출구는 `link_fp`로 검증한 뒤 일반
  하이브리드 핸드셰이크를 한다. 프레임 `F_ENDPOINT_FRAG(6)`로 조각 하나를 넘긴다. 출구 정책(사설 주소, 포트)은 그대로 적용된다.
- 서버는 조각을 모아 SSMS를 풀고, E2E(§6과 같은 INIT/UP/DOWN)를 연 뒤 가상 포트별 백엔드로 연결한다.
- 응답: 서버는 SURB 패킷을 연결된 출구 링크들에 라운드로빈으로 `F_FORWARD`로 실어 보낸다. 출구가 첫 홉에 전달한다.

## 7. 브라우저 HTTPS 전용 정책

일반 인터넷은 `https://`만 쓴다. 평문 `http://`는 확인 페이지를 거쳐야 하고(`ok=1`), HTTPS→HTTP 리다이렉트와
HTTP 하위 리소스는 차단한다. `.mosaic`과 등록된 다중 입구 엔드포인트 도메인은 E2E 터널 안이므로 `http://`를 허용한다.

## 8. 트래픽 스케줄링

- 클라이언트: 게이트웨이 링크마다 독립적으로, `Exp(λ_P)` 간격마다 큐에 실제 메시지가 있으면 보내고, 없으면 DROP 커버를 보낸다.
  이와 별도로 `Exp(λ_L)` 간격으로 루프를, `Exp(λ_D)` 간격으로 드롭을 보낸다.
- 게이트웨이: 클라이언트마다 `Exp(λ_down)` 간격으로 우편함의 메시지를 보내고, 비어 있으면 DUMMY를 보낸다.
- 믹스/게이트웨이 노드: `Exp(λ_M)` 간격으로 L1→L2→L3→자신 경로의 루프를 보낸다.
- 홉 지연은 송신자가 `Exp(1/μ)`에서 뽑는다. 노드는 최대 30초로 자른다.

## 8b. Sphinx 키 로테이션 (epoch)

- `epoch = floor(time / EPOCH_LEN)`이고, 기본 `EPOCH_LEN`은 3600초다. 노드는 epoch마다 새 X25519 Sphinx 키를 **무작위로** 만든다.
  장기 키에서 유도하지 않는다. 기술자의 `sphinx_epochs`에 현재와 다음 epoch의 공개키를 서명해 싣는다.
- 노드는 `{e-1, e, e+1}` 키만 보관하고 나머지는 지운다. 재전송 캐시도 epoch별로 두고 키와 함께 지운다.
  지워진 epoch의 녹화 패킷은 노드를 압수해도 복호할 수 없다 (전방향 안전성).
- 헤더에는 epoch 표시가 없다. 노드는 보관한 키를 현재 epoch부터 차례로 시도하고, 헤더 MAC으로 맞는 키를 가린다.
- `e-1` 키는 **이미 전송 중인 패킷을 위한 유예**일 뿐이다. 새로 보내는 SURB 응답은 `epoch ≥ 현재`인 묶음만 쓴다.
  SURB 묶음 셀에는 그 묶음을 만든 epoch를 싣는다 (`count(1) ‖ size(1) ‖ epoch(4) ‖ SURB…`).
  출구는 지난 epoch 묶음을 버리고, 클라이언트도 같은 FIFO 규칙으로 만료를 세어 새 묶음을 보낸다.
- 클라이언트는 epoch의 마지막 1/4에는 다음 epoch 키로 SURB를 만든다 (pre-roll). epoch가 바뀌면 열린 스트림마다 SURB를 다시 채운다.
- 클라이언트는 패킷을 만들 때마다 경로상의 기술자를 최신 합의로 다시 조회한다. 링크·스트림이 쥔 기술자는 오래됐을 수 있기 때문이다.

## 9. 디렉터리

- 기술자: `{node_id = H(identity_pk)[:16], role, host, port, identity/sphinx/link/mlkem 공개키,
  published, exit_policy}`를 Ed25519로 서명한다.
- 권한 서버는 TTL 안의 기술자 목록과 epoch에 서명해 배포한다.
- 클라이언트는 고정(pinned)된 권한 서버 키로 서명을 검증한다. 기술자 다이제스트가 threshold 개
  이상의 문서에 들어 있어야 채택한다.
- 믹스 계층은 `H("layer", epoch, node_id)` 순서로 정렬한 뒤 라운드로빈으로 배정한다.
