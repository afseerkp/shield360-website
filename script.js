(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const rand = (a, b) => a + Math.random() * (b - a);
  const pad = (n) => String(n).padStart(2, "0");
  const clock = () => { const d = new Date(); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  const announce = (msg) => { const s = $("#sr-status"); s.textContent = ""; setTimeout(() => { s.textContent = msg; }, 50); };

  // Decorative tickers run only while on screen, the tab is visible and the visitor hasn't paused them.
  let paused = false;
  const ambient = (el, fn, ms) => {
    if (reduced || !el) return;
    let seen = false;
    new IntersectionObserver(([e]) => { seen = e.isIntersecting; }).observe(el);
    setInterval(() => { if (seen && !paused && !document.hidden) fn(); }, ms);
  };
  const motionBtn = $("#motion-toggle");
  motionBtn.addEventListener("click", () => {
    paused = !paused;
    motionBtn.setAttribute("aria-pressed", paused);
    motionBtn.setAttribute("aria-label", paused ? "Resume animations" : "Pause animations");
    document.body.classList.toggle("motion-paused", paused);
    $$("svg").forEach((s) => (paused ? s.pauseAnimations?.() : s.unpauseAnimations?.()));
    announce(paused ? "Animations paused" : "Animations resumed");
  });

  /* ---------------- nav ---------------- */
  const nav = $("#nav");
  const onScroll = () => nav.classList.toggle("scrolled", scrollY > 12);
  addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  const toggle = $("#nav-toggle"), links = $("#nav-links");
  toggle.addEventListener("click", () => {
    const open = toggle.getAttribute("aria-expanded") !== "true";
    toggle.setAttribute("aria-expanded", open);
    links.classList.toggle("open", open);
  });
  $$("a", links).forEach((a) => a.addEventListener("click", () => {
    toggle.setAttribute("aria-expanded", "false");
    links.classList.remove("open");
  }));

  const sections = $$("a", links).map((a) => $(a.getAttribute("href"))).filter(Boolean);
  const navObs = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      $$("a", links).forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + e.target.id));
    });
  }, { rootMargin: "-45% 0px -50% 0px" });
  sections.forEach((s) => navObs.observe(s));

  /* ---------------- reveal ---------------- */
  const revObs = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      const el = e.target;
      const siblings = [...el.parentElement.children].filter((c) => c.classList.contains("reveal"));
      el.style.transitionDelay = Math.min(siblings.indexOf(el), 6) * 70 + "ms";
      el.classList.add("in");
      revObs.unobserve(el);
    });
  }, { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
  $$(".reveal").forEach((el) => revObs.observe(el));

  /* ---------------- counters ---------------- */
  const cntObs = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      const el = e.target, to = +el.dataset.count, t0 = performance.now(), dur = 1400;
      const step = (t) => {
        const p = Math.min((t - t0) / dur, 1);
        el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3)));
        if (p < 1) requestAnimationFrame(step);
      };
      reduced ? (el.textContent = to) : requestAnimationFrame(step);
      cntObs.unobserve(el);
    });
  }, { threshold: 0.5 });
  $$("[data-count]").forEach((el) => cntObs.observe(el));

  /* ---------------- hero console ---------------- */
  const hosts = [
    { h: "DC-01", os: "Server 2022", cpu: 22, st: "ok" },
    { h: "SQL-PROD-02", os: "Server 2019", cpu: 64, st: "ok" },
    { h: "WS-FIN-07", os: "Windows 11", cpu: 31, st: "ok" },
    { h: "WS-HR-12", os: "Windows 11", cpu: 12, st: "warn" },
    { h: "FS-01", os: "Server 2025", cpu: 41, st: "ok" },
  ];
  const stLabel = { ok: "Protected", warn: "Updates", bad: "Threat", off: "Offline" };
  const table = $("#c-table");
  hosts.forEach((r, i) => {
    const row = document.createElement("div");
    row.className = "c-row";
    row.innerHTML = `<span class="host">${r.h}</span><span>${r.os}</span><span>Defender</span><span><span class="bar"><i style="width:${r.cpu}%"></i></span></span><span class="st ${r.st}">${stLabel[r.st]}</span>`;
    r.el = row; r.bar = $(".bar i", row); r.stEl = $(".st", row);
    table.appendChild(row);
  });

  const N = 48;
  let cpu = Array.from({ length: N }, (_, i) => 30 + 14 * Math.sin(i / 5) + rand(-6, 6));
  let mem = Array.from({ length: N }, (_, i) => 55 + 6 * Math.sin(i / 9) + rand(-2, 2));
  const toPath = (arr) => arr.map((v, i) => `${i ? "L" : "M"}${(i / (N - 1)) * 400},${90 - v * 0.85}`).join(" ");
  const drawSpark = () => {
    const p = toPath(cpu);
    $("#spark-cpu").setAttribute("d", p);
    $("#spark-cpu-area").setAttribute("d", p + " L400,90 L0,90 Z");
    $("#spark-mem").setAttribute("d", toPath(mem));
  };
  drawSpark();

  const kOnline = $("#k-online");
  let secs = 0;
  const tickConsole = () => {
    cpu.shift(); cpu.push(Math.max(8, Math.min(92, cpu[cpu.length - 1] + rand(-9, 9))));
    mem.shift(); mem.push(Math.max(40, Math.min(80, mem[mem.length - 1] + rand(-3, 3))));
    drawSpark();
    hosts.forEach((r) => { r.cpu = Math.max(4, Math.min(96, r.cpu + rand(-12, 12))); r.bar.style.width = r.cpu + "%"; });
    secs = (secs + 3) % 60;
    $("#c-ago").textContent = secs < 4 ? "just now" : secs + "s ago";
    const on = 239 + Math.round(rand(0, 4));
    if (kOnline.textContent !== String(on)) {
      kOnline.textContent = on;
      kOnline.classList.add("flash");
      setTimeout(() => kOnline.classList.remove("flash"), 500);
    }
  };
  ambient($("#hero-console"), tickConsole, 3000);

  // rotating float alert
  const alerts = [
    ["Brute-force blocked", "185.220.101.42 · 47 failed RDP logons"],
    ["Signatures updated", "1.421.882.0 · 248 / 248 endpoints"],
    ["ASR rule blocked", "LSASS credential theft · SQL-PROD-02"],
    ["Firewall re-enabled", "Public profile restored · WS-HR-12"],
  ];
  let ai = 0;
  const fc = $("#fc-alert");
  ambient(fc, () => {
    ai = (ai + 1) % alerts.length;
    fc.style.transition = "opacity .3s"; fc.style.opacity = 0;
    setTimeout(() => {
      $("b", fc).textContent = alerts[ai][0];
      $("small", fc).textContent = alerts[ai][1];
      $(".sev", fc).style.background = ai === 0 || ai === 2 ? "" : "var(--good)";
      $(".sev", fc).style.boxShadow = ai === 0 || ai === 2 ? "" : "0 0 0 4px rgba(61,220,132,.18)";
      fc.style.opacity = 1;
    }, 300);
  }, 4200);

  /* ---------------- visibility tabs ---------------- */
  const tile = (k, v, cls = "") => `<div class="va-tile ${cls}"><span>${k}</span><b>${v}</b></div>`;
  const row = (k, v) => `<div class="va-row"><span class="k">${k}</span><span class="v">${v}</span></div>`;
  const meter = (k, v) => `<div class="va-tile"><span>${k} · ${v}%</span><div class="va-meter"><i style="width:${v}%"></i></div></div>`;
  const TABS = {
    overview: {
      t: "Your whole estate at a glance",
      d: "Endpoint counts, online and offline, percent protected and alerts grouped by severity — with the machines that need attention surfaced first.",
      l: ["Online / offline in real time", "Protection coverage across the fleet", "Alerts grouped by severity", "Needs‑attention shortlist"],
      a: `<div class="va-grid">${tile("Endpoints", "248")}${tile("Protected", "99.2%", "acc")}${tile("Offline", "7")}${tile("Critical alerts", "1")}</div>
          ${row("Needs attention", "WS-HR-12 · pending security updates")}${row("Needs attention", "LAB-03 · offline 2h 14m")}${row("Needs attention", "WS-MKT-04 · no BitLocker")}`,
    },
    endpoints: {
      t: "Search, filter, act",
      d: "A searchable list with filters for servers, workstations, offline and at‑risk machines. Live CPU, memory, disk, AV status, alerts and last‑seen time on every row.",
      l: ["Filter: servers · workstations · offline · at‑risk", "Live CPU, memory and disk", "AV status and alert count per machine", "Matched by MachineGuid — history survives reinstall"],
      a: `${row("DC-01", "CPU 22% · MEM 48% · seen 12s")}${row("SQL-PROD-02", "CPU 64% · MEM 81% · seen 8s")}${row("WS-FIN-07", "CPU 31% · MEM 52% · seen 41s")}${row("WS-HR-12", "CPU 12% · MEM 37% · seen 3s")}${row("LAB-03", "offline · seen 2h ago")}${row("FS-01", "CPU 41% · DISK 91% ⚠")}`,
    },
    system: {
      t: "Everything about the machine",
      d: "OS and build, domain, logged‑on users (console and RDP), hardware, serial number, last boot, a 24‑hour performance chart and every disk.",
      l: ["OS, build and domain", "Logged‑on users — console and RDP", "Hardware, serial and last boot", "24‑hour CPU / memory / disk history"],
      a: `${row("OS", "Windows Server 2022 · 20348.2762")}${row("Domain", "CORP.LOCAL")}${row("Users", "corp\\a.khan (RDP) · corp\\svc_sql")}${row("Hardware", "Dell PowerEdge R650 · 64 GB")}${row("Last boot", "14 days ago")}<div class="va-grid">${meter("C:", 62)}${meter("D:", 91)}</div>`,
    },
    security: {
      t: "Security posture, setting by setting",
      d: "Defender real‑time, tamper protection, signature age and mode. Third‑party AV, threat detections, firewall profiles, BitLocker, failed logons, UAC, RDP/NLA and local administrators.",
      l: ["Defender status, mode and signature age", "Firewall profiles and BitLocker", "Failed logons and local admins", "UAC and RDP / NLA configuration"],
      a: `<div class="va-grid">${tile("Real-time", "On", "acc")}${tile("Tamper", "On", "acc")}${tile("Signatures", "2h old")}${tile("Failed logons", "3 / h")}</div>${row("Firewall", "Domain ✓ · Private ✓ · Public ✓")}${row("BitLocker", "C: encrypted · XTS-AES 256")}${row("RDP", "Enabled · NLA required")}`,
    },
    inventory: {
      t: "Know what's installed — and what's open",
      d: "Installed software, hotfixes, pending Windows Updates, stopped automatic services, listening ports and shared folders.",
      l: ["Installed software and hotfixes", "Pending Windows Updates", "Stopped automatic services", "Listening ports and shared folders"],
      a: `${row("Software", "184 packages")}${row("Hotfixes", "KB5044281 · KB5043936 · +41")}${row("Pending updates", "2 security · 1 optional")}${row("Listening", "tcp/135 · 445 · 1433 · 3389 · 5985")}${row("Shares", "ADMIN$ · C$ · Finance")}${row("Stopped auto", "gupdate · MapsBroker")}`,
    },
    actions: {
      t: "One click, the safe way",
      d: "Refresh inventory, Defender quick or full scan, update signatures, list processes and connections, restart with a 2‑minute warning to users — or cancel it.",
      l: ["Quick or full Defender scan", "Update signatures on demand", "List processes and connections", "Restart with 2‑minute user warning"],
      a: `<div class="va-btn run"><span>Defender quick scan</span><span>running · 38%</span></div><div class="va-btn"><span>Update signatures</span><span>ready</span></div><div class="va-btn"><span>Refresh inventory</span><span>ready</span></div><div class="va-btn"><span>List processes</span><span>ready</span></div><div class="va-btn"><span>List connections</span><span>ready</span></div><div class="va-btn"><span>Restart (2‑min warning)</span><span>ready</span></div>`,
    },
    alerts: {
      t: "Raised and resolved automatically",
      d: "Alerts open when a condition is detected and close themselves when it clears. Acknowledge with one button — no stale queue to clean up.",
      l: ["Auto‑raise and auto‑resolve", "Acknowledge with one click", "Severity: critical · high · warning · info", "Thresholds tunable in config.json"],
      a: `${row("<span class='badge crit'>critical</span>", "Threat detected · WS-FIN-07")}${row("<span class='badge high'>high</span>", "Failed‑logon spike · DC-01")}${row("<span class='badge warn'>warning</span>", "Disk ≥ 90% · FS-01")}${row("<span class='badge info'>info</span>", "Restart pending · WS-HR-12")}${row("<span class='badge' style='color:var(--good)'>resolved</span>", "Firewall profile disabled · 4m")}`,
    },
    audit: {
      t: "Every action, on the record",
      d: "Logins, failed logins, actions, enrollments and token rotations — a complete trail of who did what, and when.",
      l: ["Admin logins and failed attempts", "Every remote action issued", "Enrollments and removals", "Enrollment token rotations"],
      a: `<div class="va-mono"><b>09:42:11</b> admin · login · 10.0.4.20</div><div class="va-mono"><b>09:43:02</b> admin · action quick-scan → WS-FIN-07</div><div class="va-mono"><b>09:47:55</b> agent · enrolled SQL-PROD-02</div><div class="va-mono"><b>10:01:18</b> unknown · <span style="color:var(--bad)">failed login</span> · 10.0.9.71</div><div class="va-mono"><b>10:12:40</b> admin · rotated enrollment token</div><div class="va-mono"><b>10:15:03</b> admin · release-isolation → WS-FIN-07</div>`,
    },
  };
  const vp = $("#vp");
  const setTab = (key) => {
    const d = TABS[key];
    vp.classList.add("swap");
    setTimeout(() => {
      $("#vp-title").textContent = d.t;
      $("#vp-desc").textContent = d.d;
      $("#vp-list").innerHTML = d.l.map((x) => `<li>${x}</li>`).join("");
      $("#vp-art").innerHTML = d.a;
      vp.classList.remove("swap");
    }, reduced ? 0 : 220);
  };
  const tabBtns = $$("#vis-tabs button");
  tabBtns.forEach((b, i) => {
    b.addEventListener("click", () => {
      tabBtns.forEach((x) => x.setAttribute("aria-selected", x === b));
      setTab(b.dataset.tab);
    });
    b.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      const n = tabBtns[(i + (e.key === "ArrowRight" ? 1 : -1) + tabBtns.length) % tabBtns.length];
      n.focus(); n.click();
    });
  });
  setTab("overview");

  /* ---------------- bento extras ---------------- */
  const asr = $("#asr-grid");
  const asrState = ["", "", "", "audit", "", "", "", "", "off", "", "", "audit", "", "", "", "", ""];
  asrState.forEach((s) => { const i = document.createElement("i"); if (s) i.className = s; asr.appendChild(i); });

  const bf = $("#bf-log");
  const ips = ["185.220.101.42", "45.155.205.11", "91.240.118.7", "203.0.113.54", "193.32.162.9", "10.0.4.20"];
  const pushBf = () => {
    const ip = ips[Math.floor(Math.random() * ips.length)];
    const allow = ip.startsWith("10.");
    const d = document.createElement("div");
    if (allow) d.className = "allow";
    d.innerHTML = `<span>${ip}</span><b>${allow ? "allowlisted" : "blocked · " + Math.round(rand(20, 90)) + " fails"}</b>`;
    bf.prepend(d);
    while (bf.children.length > 5) bf.lastChild.remove();
  };
  for (let i = 0; i < 5; i++) pushBf();
  ambient(bf, pushBf, 2600);

  $$("[data-glow]").forEach((c) => c.addEventListener("pointermove", (e) => {
    const r = c.getBoundingClientRect();
    c.style.setProperty("--mx", e.clientX - r.left + "px");
    c.style.setProperty("--my", e.clientY - r.top + "px");
  }));

  // self-heal countdown (accelerated: 15 simulated seconds per real second)
  const C = 2 * Math.PI * 52, prog = $("#sh-prog"), shMin = $("#sh-min");
  prog.style.strokeDasharray = C;
  let left = 900;
  const shTick = () => {
    left -= 15;
    if (left <= 0) left = 900;
    shMin.textContent = `${pad(Math.floor(left / 60))}:${pad(left % 60)}`;
    prog.style.strokeDashoffset = C * (1 - left / 900);
  };
  ambient(prog, shTick, 1000);

  /* ---------------- isolation demo ---------------- */
  const svgNS = "http://www.w3.org/2000/svg";
  const ICONS = {
    cloud: "M-9 4h17a5 5 0 0 0 0-10 7 7 0 0 0-13-1A5 5 0 0 0-9 4z",
    shield: "M0-10-8-7v5c0 5 3.4 9 8 10 4.6-1 8-5 8-10v-5z M-3.5 0l2.5 2.5 4.5-5",
    switch: "M-9-4h18M-9 4h18M5-8l4 4-4 4M-5 0l-4 4 4 4",
    pc: "M-9-8h18v12h-18z M-4 8h8 M0 4v4",
    server: "M-8-9h16v7h-16z M-8 2h16v7h-16z M-4-5.5h.1 M-4 5.5h.1",
  };
  const NODES = {
    inet: { x: 80, y: 70, label: "Internet", icon: "cloud", cls: "inet" },
    srv: { x: 400, y: 70, label: "Shield360", icon: "shield", cls: "srv" },
    sw: { x: 240, y: 180, label: "LAN", icon: "switch" },
    fin: { x: 90, y: 300, label: "WS-FIN-07", icon: "pc" },
    hr: { x: 240, y: 315, label: "WS-HR-12", icon: "pc" },
    fs: { x: 390, y: 300, label: "FS-01", icon: "server" },
  };
  const LINKS = [["inet", "sw"], ["srv", "sw"], ["sw", "fin"], ["sw", "hr"], ["sw", "fs"]];
  const gL = $("#net-links"), gN = $("#net-nodes");
  const linkEls = {};
  const mk = (tag, attrs) => { const e = document.createElementNS(svgNS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };
  LINKS.forEach(([a, b]) => {
    const l = mk("line", { x1: NODES[a].x, y1: NODES[a].y, x2: NODES[b].x, y2: NODES[b].y, class: "lk flow" });
    gL.appendChild(l); linkEls[a + "-" + b] = l;
  });
  // dedicated control channel fin → server (shown only when isolated)
  const ctrl = mk("path", { d: `M${NODES.fin.x},${NODES.fin.y} C 60 160, 300 40, ${NODES.srv.x},${NODES.srv.y}`, class: "lk keep", fill: "none", opacity: 0 });
  gL.appendChild(ctrl);
  // lateral movement attempts
  const lat1 = mk("path", { d: `M${NODES.fin.x},${NODES.fin.y} Q 165 360 ${NODES.hr.x},${NODES.hr.y}`, class: "lk", fill: "none", opacity: 0, stroke: "#ff4d5e" });
  const lat2 = mk("path", { d: `M${NODES.fin.x},${NODES.fin.y} Q 240 400 ${NODES.fs.x},${NODES.fs.y}`, class: "lk", fill: "none", opacity: 0, stroke: "#ff4d5e" });
  gL.append(lat1, lat2);
  [lat1, lat2].forEach((p) => { p.style.strokeDasharray = "3 5"; p.style.stroke = "#ff4d5e"; });

  const nodeEls = {};
  Object.entries(NODES).forEach(([k, n]) => {
    const g = mk("g", { class: "nd " + (n.cls || ""), transform: `translate(${n.x},${n.y})` });
    g.append(mk("circle", { r: 30, class: "halo" }), mk("circle", { r: 24, class: "core" }), mk("path", { d: ICONS[n.icon], class: "ic" }));
    const t = mk("text", { y: 46 }); t.textContent = n.label; g.appendChild(t);
    gN.appendChild(g); nodeEls[k] = g;
  });
  // firewall wall around fin
  const wall = mk("circle", { cx: NODES.fin.x, cy: NODES.fin.y, r: 40, fill: "none", stroke: "#3b7bff", "stroke-width": 1.5, "stroke-dasharray": "2 4", class: "shield-wall" });
  gN.prepend(wall);

  const log = $("#demo-log"), state = $("#demo-state"), card = $("#demo"), runBtn = $("#demo-run"), resetBtn = $("#demo-reset");
  const addLog = (msg, cls = "") => {
    const d = document.createElement("div");
    d.innerHTML = `<span class="t">${clock()}</span><span class="${cls}">${msg}</span>`;
    log.appendChild(d);
    while (log.children.length > 6) log.firstChild.remove();
  };
  const setState = (txt, cls) => { state.textContent = txt; state.className = "demo-state " + (cls || ""); };
  addLog("agent WS-FIN-07 · check-in ok · policy Enforce", "g");
  addLog("agent WS-HR-12 · check-in ok");
  addLog("agent FS-01 · check-in ok");

  let timers = [];
  const later = (ms, fn) => timers.push(setTimeout(fn, reduced ? 0 : ms));
  const run = () => {
    runBtn.disabled = true;
    later(0, () => { addLog("Defender: Ransom:Win32/Test blocked — C:\\Users\\Public\\inv.exe", "e"); nodeEls.fin.classList.add("bad"); card.classList.add("alarm"); setState("Compromise detected", "bad"); });
    later(900, () => { addLog("trigger: ransomware activity blocked → isolate", "e"); lat1.setAttribute("opacity", 1); lat2.setAttribute("opacity", 1); });
    later(1900, () => {
      addLog("firewall: block all in/out (IPv4 + IPv6) except Shield360", "o");
      ["sw-fin"].forEach((k) => linkEls[k].classList.replace("flow", "cut"));
      lat1.setAttribute("opacity", 0.25); lat2.setAttribute("opacity", 0.25);
      wall.classList.add("on");
    });
    later(2700, () => { addLog("hosts: pinned shield360.corp.local → 10.0.0.10", "o"); ctrl.setAttribute("opacity", 1); });
    later(3500, () => {
      lat1.setAttribute("opacity", 0); lat2.setAttribute("opacity", 0);
      nodeEls.fin.classList.remove("bad"); nodeEls.fin.classList.add("iso");
      card.classList.remove("alarm"); card.classList.add("contained");
      setState("WS-FIN-07 isolated", "iso");
      addLog("ALERT critical · AUTO-ISOLATED · WS-FIN-07", "e");
      $("#k-iso").textContent = "1";
      resetBtn.disabled = false;
    });
  };
  const reset = () => {
    timers.forEach(clearTimeout); timers = [];
    resetBtn.disabled = true;
    addLog("admin · release-isolation → WS-FIN-07", "g");
    linkEls["sw-fin"].classList.replace("cut", "flow");
    ctrl.setAttribute("opacity", 0); wall.classList.remove("on");
    nodeEls.fin.classList.remove("iso", "bad");
    card.classList.remove("alarm", "contained");
    setState("Network healthy");
    $("#k-iso").textContent = "0";
    later(600, () => { addLog("agent WS-FIN-07 · check-in ok · isolation released", "g"); runBtn.disabled = false; });
  };
  runBtn.addEventListener("click", run);
  resetBtn.addEventListener("click", reset);

  /* ---------------- deploy ---------------- */
  const SITE = "https://shield360.biz";
  const SERVER_CMDS = {
    quick: {
      d: "In an elevated PowerShell on your Windows Server. Installs Node.js if needed, verifies the download, enables HTTPS and starts the server.",
      c: `<span class="c-k">irm</span> ${SITE}/install.ps1 <span class="c-f">|</span> <span class="c-k">iex</span>`,
    },
    options: {
      d: "Pass the DNS names for the HTTPS certificate, a different folder or port. Add -NoTls to skip the certificate.",
      c: `<span class="c-f">&amp;</span> ([scriptblock]::Create((<span class="c-k">irm</span> ${SITE}/install.ps1))) \`\n  -DnsName shield360.corp.local, shield360 \`\n  -InstallDir 'C:\\Shield360 Endpoint' -Port 8443`,
    },
    manual: {
      d: "Download the package below, extract it on the server, then run the two scripts from an elevated PowerShell.",
      c: `<span class="c-c">cd "C:\\Shield360 Endpoint\\server"</span>\n<span class="c-k">.\\New-Shield360Certificate.ps1</span> -DnsName shield360.corp.local\n<span class="c-k">.\\Install-Shield360Server.ps1</span>`,
    },
  };
  const segment = (groupSel, descSel, codeSel, cmds, first) => {
    const btns = $$(groupSel + " button");
    const set = (m) => {
      btns.forEach((b) => b.setAttribute("aria-selected", b.dataset.m === m));
      $(descSel).textContent = cmds[m].d;
      $(codeSel).innerHTML = cmds[m].c;
    };
    btns.forEach((b) => b.addEventListener("click", () => set(b.dataset.m)));
    set(first);
  };

  const rel = window.SHIELD360_RELEASE;
  if (rel) {
    const zip = $("#dl-zip");
    zip.href = "download/" + rel.file;
    $("#dl-zip-name").textContent = `${rel.file} · ${Math.round(rel.size / 1024)} KB`;
    $("#dl-meta").textContent = `Version ${rel.version}, released ${rel.released}.`;
    $("#dl-sha").textContent = rel.sha256;
  }

  const CMDS = {
    one: {
      d: "Paste the one‑line command from the Deploy page into an elevated prompt. URL and token are pre‑filled.",
      c: `<span class="c-k">iwr</span> 'https://shield360.corp.local:8443/download/Install-Shield360Agent.ps1' \`\n  -UseBasicParsing -OutFile $env:TEMP\\s360-install.ps1\n<span class="c-f">&amp;</span> $env:TEMP\\s360-install.ps1 \`\n  -ServerUrl 'https://shield360.corp.local:8443' -EnrollToken '&lt;token&gt;'`,
    },
    offline: {
      d: "Download the three .ps1 files from the console or the Downloads panel below, then run the installer with your certificate.",
      c: `<span class="c-k">.\\Install-Shield360Agent.ps1</span> \`\n  -ServerUrl https://shield360.corp.local:8443 \`\n  -EnrollToken &lt;token&gt; \`\n  -CertificateFile .\\server.cer`,
    },
    gpo: {
      d: "Put the three files on a share readable by Domain Computers and use this as a startup script. Intune, SCCM or any RMM tool can run the same command.",
      c: `<span class="c-c"># Computer Configuration › Scripts › Startup</span>\n<span class="c-k">powershell.exe</span> -NoProfile -ExecutionPolicy Bypass \`\n  -File "\\\\fileserver\\share\\Shield360\\Install-Shield360Agent.ps1" \`\n  -ServerUrl "https://shield360.corp.local:8443" -EnrollToken "&lt;token&gt;"`,
    },
  };
  segment("#seg-srv", "#seg-srv-desc", "#s1", SERVER_CMDS, "quick");
  segment("#seg", "#seg-desc", "#s2", CMDS, "one");

  $$(".copy").forEach((btn) => btn.addEventListener("click", async () => {
    const text = $("#" + btn.dataset.copy).innerText;
    try { await navigator.clipboard.writeText(text); btn.textContent = "Copied"; announce("Command copied to clipboard"); }
    catch { btn.textContent = "Select & copy"; announce("Copy failed. Select the command and copy it manually"); }
    btn.classList.add("done");
    setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("done"); }, 1800);
  }));

  $("#yr").textContent = new Date().getFullYear();
})();
