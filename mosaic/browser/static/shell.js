// MOSAIC 브라우저 셸. 이 스크립트만 우리 것이다. 사이트 내용은 스크립트가 꺼진 샌드박스 iframe 안에서 렌더링된다.
"use strict";
(() => {
  const P = location.pathname.replace(/\/+$/, "");          // "/<token>"
  const $ = (id) => document.getElementById(id);
  const tabsEl = $("tabs"), framesEl = $("frames"), addr = $("addr"), chip = $("chip"), progress = $("progress");
  const pop = $("popover"), drawer = $("drawer");
  let tabs = [], active = null, status = null, seq = 0;

  // ------------------------------------------------------------------ 아이콘
  const ICON = {
    gem: '<svg viewBox="0 0 16 16"><path d="M8 1.5l6.5 6.5L8 14.5 1.5 8z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M8 5.2L10.8 8 8 10.8 5.2 8z" fill="currentColor"/></svg>',
    lock: '<svg viewBox="0 0 16 16"><rect x="3" y="7" width="10" height="7" rx="1.6" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>',
    warn: '<svg viewBox="0 0 16 16"><path d="M8 2l6.5 11.5h-13z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M8 6.5v3.2M8 11.6v.1" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
    search: '<svg viewBox="0 0 16 16"><circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10.5 10.5L14 14" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    x: '<svg viewBox="0 0 16 16" width="12" height="12"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  };

  // ------------------------------------------------------------------ URL 분류
  const endpoints = () => new Set((status && status.endpoints) || []);
  function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } }
  function kindOf(u) {
    if (!u) return "start";
    const h = hostOf(u);
    if (h.endsWith(".mosaic")) return "mosaic";
    if (endpoints().has(h)) return "endpoint";
    if (u.startsWith("https://")) return "https";
    return "http";
  }
  const KIND = {
    start:    { icon: ICON.search, label: "", title: "새 탭" },
    mosaic:   { icon: ICON.gem,  label: ".mosaic", title: "출구 없음 · 종단 간 암호화" },
    endpoint: { icon: ICON.gem,  label: "다중 입구", title: "서버가 조각을 직접 합침 · 종단 간 암호화" },
    https:    { icon: ICON.lock, label: "HTTPS", title: "출구 1곳 경유 · TLS로 내용 보호" },
    http:     { icon: ICON.warn, label: "HTTP", title: "암호화되지 않음 · 출구가 내용을 볼 수 있음" },
  };

  function normalize(input) {
    input = input.trim();
    if (!input) return null;
    if (/^https?:\/\//i.test(input)) return input;
    const host = input.split("/")[0].split(":")[0].toLowerCase();
    const looksLikeHost = !/\s/.test(input) && (host.includes(".") || host === "localhost");
    if (!looksLikeHost) {
      // JS 없이 동작하는 검색. 검색어는 출구까지 TLS로 보호되고, 검색엔진은 출구 IP만 본다
      return "https://html.duckduckgo.com/html/?q=" + encodeURIComponent(input);
    }
    return (host.endsWith(".mosaic") || endpoints().has(host) ? "http://" : "https://") + input;
  }
  const viewURL = (u) => P + "/view?u=" + encodeURIComponent(u);

  function realURL(frame) {
    try {
      const l = frame.contentWindow.location;
      if (l.pathname === P + "/view") return new URLSearchParams(l.search).get("u") || "";
      if (l.pathname === P + "/start") return "";
      return "";
    } catch { return ""; }
  }

  // ------------------------------------------------------------------ 탭
  function newTab(url, activate = true) {
    const t = { id: ++seq, url: url || "", title: "새 탭", loading: false };
    t.frame = document.createElement("iframe");
    // allow-scripts는 절대 주지 않는다. same-origin은 주소·제목 동기화용 (스크립트가 없으니 안전)
    // 팝업 권한도 주지 않는다: 새 창은 셸이 MOSAIC 탭으로 연다
    t.frame.setAttribute("sandbox", "allow-same-origin allow-forms");
    t.frame.setAttribute("referrerpolicy", "no-referrer");
    t.frame.title = "페이지 내용";
    t.frame.addEventListener("load", () => onLoad(t));
    framesEl.appendChild(t.frame);

    t.el = document.createElement("div");
    t.el.className = "tab";
    t.el.setAttribute("role", "tab");
    t.el.innerHTML = '<span class="ico"></span><span class="title"></span><button class="close" aria-label="탭 닫기">' + ICON.x + "</button>";
    t.el.addEventListener("mousedown", (e) => { if (e.button === 0 && !e.target.closest(".close")) select(t); });
    t.el.addEventListener("auxclick", (e) => { if (e.button === 1) closeTab(t); });
    t.el.querySelector(".close").addEventListener("click", (e) => { e.stopPropagation(); closeTab(t); });
    tabsEl.appendChild(t.el);
    tabs.push(t);
    go(t, url);
    if (activate) select(t);
    renderTab(t);
    return t;
  }

  function closeTab(t) {
    const i = tabs.indexOf(t);
    if (i < 0) return;
    tabs.splice(i, 1);
    t.el.remove();
    t.frame.remove();
    if (!tabs.length) { newTab(""); return; }
    if (active === t) select(tabs[Math.min(i, tabs.length - 1)]);
  }

  function select(t) {
    active = t;
    for (const x of tabs) {
      x.el.classList.toggle("active", x === t);
      x.frame.classList.toggle("active", x === t);
    }
    addr.value = t.url;            // 탭을 바꾸면 주소창은 항상 그 탭의 주소
    if (document.activeElement === addr && t.url) addr.blur();
    syncChrome();
    closePop();
  }

  function go(t, url) {
    t.url = url || "";
    t.loading = true;
    t.ready = false;
    t.frame.src = url ? viewURL(url) : P + "/start";
    renderTab(t);
    if (t === active) syncChrome();
  }

  function onLoad(t) {
    if (!t.el) return;                         // iframe를 붙이는 순간 발생하는 about:blank 로드
    try { if (t.frame.contentWindow.location.href === "about:blank") return; } catch { /* */ }
    t.loading = false;
    t.url = realURL(t.frame);
    let title = "";
    try { title = t.frame.contentDocument.title; } catch { /* */ }
    t.title = title || (t.url ? hostOf(t.url) : "새 탭");
    // iframe 안의 링크 클릭으로 시작되는 탐색도 진행 막대에 반영
    try {
      t.frame.contentWindow.addEventListener("beforeunload", () => {
        t.loading = true; t.ready = false; renderTab(t); if (t === active) syncChrome();
      });
    } catch { /* */ }
    renderTab(t);
    if (t === active) syncChrome();
  }

  function renderTab(t) {
    if (!t.el) return;
    const k = kindOf(t.url);
    const ico = t.el.firstElementChild;
    if (t.loading && !t.ready) {
      ico.className = "spin";
      ico.textContent = "";
    } else {
      ico.className = "ico " + k;
      ico.textContent = k === "start" ? "◇" : (hostOf(t.url)[0] || "?").toUpperCase();
    }
    t.el.querySelector(".title").textContent = t.loading && !t.title ? "불러오는 중…" : t.title;
    t.el.title = t.title + (t.url ? "\n" + t.url : "");
  }

  function syncChrome() {
    if (!active) return;
    if (document.activeElement !== addr) addr.value = active.url;
    const k = kindOf(active.url);
    const meta = KIND[k];
    chip.className = "chip " + k;
    chip.innerHTML = meta.icon + (meta.label ? '<span class="txt">' + meta.label + "</span>" : "");
    chip.title = meta.title + " — 눌러서 경로 보기";
    document.title = (active.title && active.url ? active.title + " — " : "") + "MOSAIC";
    progress.className = "progress " + (active.loading ? "loading" : "done");
    try {
      $("back").disabled = false;
    } catch { /* */ }
  }

  // 문서가 파싱되면(이미지 로딩 전) 바로 제목과 주소를 반영한다
  setInterval(() => {
    for (const t of tabs) {
      if (!t.loading) continue;
      try {
        const d = t.frame.contentDocument;
        if (!d || d.readyState === "loading" || t.frame.contentWindow.location.href === "about:blank") continue;
        const u = realURL(t.frame), title = d.title;
        if (!t.ready) { t.ready = true; renderTab(t); }   // 문서 준비 완료: 탭 스피너는 멈추고 진행 막대만 이미지를 기다린다
        if ((title && title !== t.title) || u !== t.url) {
          t.url = u;
          t.title = title || (u ? hostOf(u) : "새 탭");
          renderTab(t);
          if (t === active) syncChrome();
        }
      } catch { /* */ }
    }
  }, 250);

  // ------------------------------------------------------------------ 탐색
  $("omnibox").addEventListener("submit", (e) => {
    e.preventDefault();
    const u = normalize(addr.value);
    if (u && active) { go(active, u); addr.blur(); active.frame.focus(); }
  });
  addr.addEventListener("focus", () => addr.select());
  addr.addEventListener("keydown", (e) => { if (e.key === "Escape") { addr.value = active.url; addr.blur(); } });
  $("back").addEventListener("click", () => { try { active.frame.contentWindow.history.back(); } catch { /* */ } });
  $("fwd").addEventListener("click", () => { try { active.frame.contentWindow.history.forward(); } catch { /* */ } });
  $("reload").addEventListener("click", () => {
    active.loading = true; renderTab(active); syncChrome();
    try { active.frame.contentWindow.location.reload(); } catch { go(active, active.url); }
  });
  $("newtab").addEventListener("click", () => { newTab(""); addr.focus(); });

  document.addEventListener("keydown", (e) => {
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === "t") { e.preventDefault(); newTab(""); addr.focus(); }
    else if (mod && e.key.toLowerCase() === "w") { e.preventDefault(); closeTab(active); }
    else if (mod && e.key.toLowerCase() === "l") { e.preventDefault(); addr.focus(); }
    else if (mod && e.key.toLowerCase() === "r") { e.preventDefault(); $("reload").click(); }
    else if (e.altKey && e.key === "ArrowLeft") $("back").click();
    else if (e.altKey && e.key === "ArrowRight") $("fwd").click();
    else if (e.key === "Escape") closePop();
  });

  // ------------------------------------------------------------------ 새 신원
  const toast = (msg) => {
    const t = $("toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toast._h);
    toast._h = setTimeout(() => t.classList.remove("show"), 2400);
  };
  $("newid").addEventListener("click", async () => {
    try {
      await fetch(P + "/api/newid", { method: "POST" });
      toast("새 신원: 쿠키를 지웠고 모든 사이트가 새 출구를 씁니다");
      for (const t of tabs) if (t.url) go(t, t.url);
    } catch { toast("실패했습니다"); }
  });

  // ------------------------------------------------------------------ 경로 팝오버
  function closePop() { pop.classList.remove("open"); }
  chip.addEventListener("click", (e) => {
    e.stopPropagation();
    if (pop.classList.contains("open")) return closePop();
    renderPop();
    const r = chip.getBoundingClientRect();
    pop.style.left = Math.max(12, Math.min(r.left, innerWidth - pop.offsetWidth - 12)) + "px";
    pop.style.top = r.bottom + 10 + "px";
    pop.classList.add("open");
  });
  document.addEventListener("click", (e) => { if (!pop.contains(e.target)) closePop(); });

  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  function routeSVG(kind, host) {
    // 마름모: 나 → 경로 3개 → (출구로 합쳐짐 | 서버/서비스에서 합쳐짐)
    const W = 520, H = 170, ink = css("--ink"), ink3 = css("--ink-3"), line = css("--line"),
          acc = css("--accent"), warn = css("--warn"), surf = css("--surface"), soft = css("--chrome-2");
    const rows = [38, 85, 132], cx0 = 30, cxN = W - 34;
    const cols = kind === "https" || kind === "http"
      ? ["G", "L1", "L2", "L3"] : kind === "mosaic" ? ["G", "L1", "L2", "L3", "Gₛ"] : ["G", "L1", "L2", "L3", "X"];
    const merge = kind === "https" || kind === "http";
    const x0 = 78, x1 = merge ? 360 : 420, step = (x1 - x0) / (cols.length - 1);
    const stroke = kind === "http" ? warn : acc;
    let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="연결 경로">`;
    // 선
    for (const y of rows) {
      s += `<path d="M${cx0 + 16} 85 L${x0 - 18} ${y} H${x1 + 18}" fill="none" stroke="${stroke}" stroke-width="2" opacity=".85"/>`;
      if (merge) s += `<path d="M${x1 + 18} ${y} L${420} 85" fill="none" stroke="${stroke}" stroke-width="2" opacity=".85"/>`;
      else s += `<path d="M${x1 + 18} ${y} L${cxN - 18} 85" fill="none" stroke="${stroke}" stroke-width="2" opacity=".85"/>`;
    }
    if (merge) s += `<path d="M444 85 H${cxN - 18}" fill="none" stroke="${stroke}" stroke-width="2" stroke-dasharray="${kind === "http" ? "0" : "5 4"}"/>`;
    // 노드
    rows.forEach((y, r) => cols.forEach((c, i) => {
      const x = x0 + i * step;
      s += `<rect x="${x - 17}" y="${y - 12}" width="34" height="24" rx="6" fill="${soft}" stroke="${line}"/>` +
           `<text x="${x}" y="${y + 4}" text-anchor="middle" font-size="11" font-weight="600" fill="${ink}">${c}</text>`;
    }));
    if (merge) {
      s += `<rect x="404" y="71" width="40" height="28" rx="7" fill="${kind === "http" ? css("--warn-soft") : soft}" stroke="${kind === "http" ? warn : line}"/>` +
           `<text x="424" y="89" text-anchor="middle" font-size="11" font-weight="700" fill="${kind === "http" ? warn : ink}">출구</text>`;
    }
    const circ = (x, label, sub, hi, anchor) =>
      `<circle cx="${x}" cy="85" r="22" fill="${hi ? css("--accent-soft") : surf}" stroke="${hi ? acc : line}" stroke-width="1.6"/>` +
      `<text x="${x}" y="89" text-anchor="middle" font-size="11" font-weight="700" fill="${ink}">${label}</text>` +
      `<text x="${anchor === "end" ? W - 2 : anchor === "start" ? 2 : x}" y="${H - 6}" text-anchor="${anchor || "middle"}" font-size="10" fill="${ink3}">${sub}</text>`;
    s += circ(cx0 + 4, "나", "분할", true, "start");
    const dest = kind === "mosaic" ? "서비스" : "서버";
    s += circ(cxN, dest, merge ? "출구가 대신 연결" : "직접 복원", !merge, "end");
    s += `<text x="${x0}" y="14" font-size="10" fill="${ink3}">게이트웨이</text>` +
         `<text x="${x0 + step * 2}" y="14" text-anchor="middle" font-size="10" fill="${ink3}">믹스 3계층 (Poisson 지연)</text>`;
    if (!merge) s += `<text x="${x1}" y="14" text-anchor="middle" font-size="10" fill="${ink3}">${kind === "mosaic" ? "서비스 게이트웨이" : "서로 다른 출구"}</text>`;
    return s + "</svg>";
  }

  function renderPop() {
    const u = active ? active.url : "", k = kindOf(u), h = hostOf(u) || "새 탭";
    const split = status ? status.split_forward : "k-of-n";
    const facts = {
      endpoint: [["good", "메시지가 모이는 곳", "서버 자신 (입구 여러 개)"], ["good", "출구가 보는 것", "메시지당 조각 1개, E2E 암호문"],
                 ["good", "출구 전부 장악 시", "조각을 합쳐도 암호문뿐"], ["good", "송신자", "누구도 모름 (SURB 응답)"]],
      mosaic:   [["good", "출구", "없음"], ["good", "내용", "종단 간 X25519 + ML-KEM-768"],
                 ["good", "서비스가 아는 것", "당신이 누구인지 모름"], ["good", "당신이 아는 것", "서비스의 IP를 모름"]],
      https:    [["", "메시지가 모이는 곳", "출구 1곳 (서버가 MOSAIC 미지원)"], ["good", "출구가 보는 것", "목적지, TLS 암호문의 양"],
                 ["good", "내용", "TLS로 보호, 출구가 못 읽음"], ["good", "송신자", "믹싱·커버로 추적 차단"]],
      http:     [["bad", "내용", "암호화 안 됨, 출구가 읽고 바꿀 수 있음"], ["bad", "권장", "HTTPS 또는 .mosaic 사용"],
                 ["good", "송신자", "출구도 모름"], ["", "메시지가 모이는 곳", "출구 1곳"]],
      start:    [["good", "커버 트래픽", "항상 흐름"], ["good", "분할", split], ["good", "링크 암호", "X25519 + ML-KEM-768"], ["good", "스크립트", "실행 안 함"]],
    }[k];
    const head = {
      endpoint: ["다중 입구 엔드포인트", "조각이 서로 다른 출구를 거쳐 서버 입구로 들어가고, 서버가 직접 합칩니다"],
      mosaic: [".mosaic 네이티브 서비스", "출구 노드 없이 서비스까지 종단 간 암호화"],
      https: ["HTTPS · 출구 경유", "이 서버는 MOSAIC을 지원하지 않아 출구 1곳이 연결을 대신 맺습니다"],
      http: ["암호화되지 않은 연결", "출구 노드가 이 페이지 내용을 볼 수 있습니다"],
      start: ["MOSAIC 보호 중", "모든 탭이 믹스넷을 거칩니다"],
    }[k];
    pop.innerHTML =
      `<div class="head"><div class="badge ${k === "http" ? "http" : ""}">${KIND[k].icon}</div>` +
      `<div><b>${esc(head[0])}</b><span>${esc(h)} · ${esc(head[1])}</span></div></div>` +
      `<div class="route">${routeSVG(k === "start" ? "endpoint" : k, h)}</div>` +
      `<div class="facts">${facts.map(([c, b, t]) => `<div class="fact ${c}"><b>${esc(b)}</b>${esc(t)}</div>`).join("")}</div>` +
      (k === "https" || k === "http" || k === "endpoint"
        ? `<div class="pop-actions"><p class="note">${k === "endpoint" ? "조각마다 출구를 새로 고릅니다." : "이 사이트에만 다른 출구를 씁니다. 쿠키와 다른 사이트는 그대로입니다."}</p>` +
          (k === "endpoint" ? "" : `<button class="pill" id="newroute">이 사이트 새 경로</button>`) + `</div>`
        : "");
    const nr = $("newroute");
    if (nr) nr.addEventListener("click", async (e) => {
      e.stopPropagation();
      await fetch(P + "/api/newroute?host=" + encodeURIComponent(h), { method: "POST" });
      closePop();
      toast(h + ": 새 출구로 다시 연결합니다");
      go(active, active.url);
    });
  }

  // ------------------------------------------------------------------ 네트워크 패널
  const toggle = $("paneltoggle");
  toggle.addEventListener("click", () => {
    const open = !drawer.classList.contains("open");
    drawer.classList.toggle("open", open);
    toggle.setAttribute("aria-pressed", String(open));
    try { localStorage.setItem("mosaic.panel", open ? "1" : "0"); } catch { /* */ }
  });
  try { if (localStorage.getItem("mosaic.panel") === "1") toggle.click(); } catch { /* */ }

  const series = [];          // [{real, cover}]
  let prev = null;
  function drawChart() {
    const c = $("chart"), g = c.getContext("2d"), w = c.width, h = c.height;
    g.clearRect(0, 0, w, h);
    const max = Math.max(10, ...series.map((p) => p.real + p.cover));
    const n = 60, dx = w / (n - 1);
    g.strokeStyle = css("--line"); g.lineWidth = 1;
    for (let i = 1; i < 4; i++) { g.beginPath(); g.moveTo(0, (h * i) / 4); g.lineTo(w, (h * i) / 4); g.stroke(); }
    const pts = series.slice(-n);
    const off = n - pts.length;
    const area = (key, color, stack) => {
      g.beginPath();
      pts.forEach((p, i) => {
        const v = stack ? p.real + p.cover : p.real;
        const x = (off + i) * dx, y = h - (v / max) * (h - 6);
        i ? g.lineTo(x, y) : g.moveTo(x, y);
      });
      g.lineTo((off + pts.length - 1) * dx, h); g.lineTo(off * dx, h); g.closePath();
      g.fillStyle = color; g.fill();
    };
    if (pts.length > 1) {
      area("total", css("--cover"), true);
      area("real", css("--accent"), false);
    }
  }

  function setRows(s) {
    const rows = [
      ["프로파일", s.profile], ["게이트웨이", s.gateways.join(", ")], ["분할 (정방향)", s.split_forward],
      ["분할 (응답)", s.split_reply], ["합의 노드", s.nodes], ["열린 스트림", s.open_streams],
      ["다중 입구 사이트", s.endpoints.length], ["더미 수신", s.stats.recv_dummy.toLocaleString()],
    ];
    $("rows").innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
  }

  const LEVEL = {
    interactive: ["빠름", "웹 탐색용. 홉당 평균 지연이 짧습니다."],
    balanced: ["균형", "지연과 커버 트래픽을 늘려 상관 공격에 더 강합니다."],
    paranoid: ["최고", "긴 지연, 3-of-5 이상 분할, 게이트웨이 3곳(재시작 시). 메시징·민감한 작업용."],
  };
  function renderSeg(s) {
    const seg = $("seg");
    const names = s.profiles || [];
    if (seg.childElementCount !== names.length) {
      seg.innerHTML = names.map((n) => `<button role="radio" data-p="${esc(n)}">${esc((LEVEL[n] || [n])[0])}</button>`).join("");
      seg.querySelectorAll("button").forEach((b) => b.addEventListener("click", async () => {
        const name = b.dataset.p;
        await fetch(P + "/api/profile?name=" + encodeURIComponent(name), { method: "POST" });
        status.profile = name;
        renderSeg(status);
        toast("보안 수준: " + (LEVEL[name] || [name])[0]);
      }));
    }
    seg.querySelectorAll("button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.p === s.profile)));
    const info = (s.profile_info || {})[s.profile];
    $("segnote").textContent = ((LEVEL[s.profile] || ["", ""])[1]) +
      (info ? ` 홉당 평균 ${info.delay_ms}ms · 링크당 ${info.rate}패킷/초 · 분할 k=${info.split}` : "");
  }

  async function poll() {
    try {
      const r = await fetch(P + "/api/status", { cache: "no-store" });
      status = await r.json();
      const st = status.stats;
      const cover = st.sent_cover + st.sent_loop;
      if (prev) series.push({ real: Math.max(0, st.sent_real - prev.sent_real), cover: Math.max(0, cover - prev.cover) });
      prev = { sent_real: st.sent_real, cover };
      if (series.length > 120) series.shift();
      const total = st.sent_real + cover;
      $("k-cover").textContent = total ? Math.round((cover / total) * 100) + "%" : "–";
      $("k-rtt").textContent = st.loop_rtt_ms ? Math.round(st.loop_rtt_ms) : "–";
      $("k-frag").textContent = st.messages_split ? (st.fragments_sent / st.messages_split).toFixed(1) : "–";
      $("k-loop").textContent = st.sent_loop ? Math.min(100, Math.round((st.loops_back / st.sent_loop) * 100)) + "%" : "–";
      $("pulse").classList.remove("off");
      setRows(status);
      renderSeg(status);
      drawChart();
      if (active) { renderTab(active); syncChrome(); }
    } catch {
      $("pulse").classList.add("off");
    }
  }
  poll();
  setInterval(poll, 1000);

  // ------------------------------------------------------------------ 시작
  const start = new URLSearchParams(location.search).get("u");
  newTab(start || "");
  if (!start) addr.focus();
})();
