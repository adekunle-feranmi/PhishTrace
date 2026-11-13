/* PhishTrace console.
 *
 * Security rule for this file: every value that came from the API, a provider,
 * a seed or an attacker-controlled page is inserted with textContent / DOM
 * properties. innerHTML is never used for untrusted data. External links are
 * restricted to http(s) and carry rel="noopener noreferrer". The one exception
 * is the evidence viewer: a stored capture is inert-parsed, stripped of active
 * content and shown in a fully sandboxed frame - see hardenEvidenceHtml().
 */
(function () {
  "use strict";

  const $ = (selector, root) => (root || document).querySelector(selector);
  const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));
  const SVG_NS = "http://www.w3.org/2000/svg";

  const state = {
    session: { csrf: "", user: null, auth_enabled: false, version: "" },
    investigations: [],
    id: null,
    detail: null,
    progress: null,
    lastSeq: 0,
    terminal: false,
    refreshedFor: null,
    source: null,
    pollTimer: null,
    sseEnded: false,
    graph: null,
    evidence: [],
    activeTab: "overview",
    kitReports: [],
    evidenceDetail: null,
    evidenceMode: "rendered",
  };

  const TYPE_COLORS = {
    url: "#38bdf8", domain: "#a78bfa", ip: "#f5c451", email: "#3ddc97",
    phone: "#fb923c", sha256: "#f472b6", file_hash: "#f472b6", telegram: "#22d3ee",
    analytics: "#c084fc", certificate: "#94a3b8", asn: "#facc15", wallet: "#84cc16",
    social: "#f97316", other: "#94a3b8",
  };
  const STAGE_LABELS = {
    starting: "starting", pivot: "pivoting infrastructure", sightings: "collecting sightings",
    archive: "archiving snapshots", done: "complete", failed: "failed", queued: "queued",
  };
  const STAGE_PROGRESS = { queued: 3, starting: 8, pivot: 45, sightings: 72, archive: 90, done: 100, failed: 100 };

  /* ---------------------------------------------------------------- helpers */
  function el(tag, attrs) {
    const node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach((key) => {
        const value = attrs[key];
        if (value === null || value === undefined || value === false) return;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = String(value);
        else if (key === "dataset") Object.assign(node.dataset, value);
        else if (key === "attrs") Object.keys(value).forEach((k) => node.setAttribute(k, String(value[k])));
        else if (key === "on") Object.keys(value).forEach((k) => node.addEventListener(k, value[k]));
        else node[key] = value;
      });
    }
    for (let i = 2; i < arguments.length; i += 1) append(node, arguments[i]);
    return node;
  }

  function append(parent, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach((item) => append(parent, item)); return; }
    parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }

  function svg(tag, attrs) {
    const node = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      Object.keys(attrs).forEach((key) => {
        if (attrs[key] === null || attrs[key] === undefined) return;
        node.setAttribute(key, String(attrs[key]));
      });
    }
    for (let i = 2; i < arguments.length; i += 1) {
      const child = arguments[i];
      if (child === null || child === undefined) continue;
      if (Array.isArray(child)) child.forEach((item) => item && node.appendChild(item));
      else if (child instanceof Node) node.appendChild(child);
      else node.appendChild(document.createTextNode(String(child)));
    }
    return node;
  }

  function clear(node) { if (node) while (node.firstChild) node.removeChild(node.firstChild); }

  function safeHttpUrl(value) {
    if (!value || typeof value !== "string") return null;
    try {
      const url = new URL(value, window.location.origin);
      return (url.protocol === "http:" || url.protocol === "https:") ? url.href : null;
    } catch (_) { return null; }
  }

  function statusClass(status) {
    const known = ["running", "starting", "completed", "partial", "failed", "skipped", "enabled", "queued", "ran"];
    const key = String(status || "queued").toLowerCase();
    return `status-pill status-${known.includes(key) ? key : "queued"}`;
  }

  function fmtDate(value, withTime) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    try {
      return new Intl.DateTimeFormat(undefined, {
        year: "numeric", month: "short", day: "2-digit",
        ...(withTime === false ? {} : { hour: "2-digit", minute: "2-digit", timeZoneName: "short" }),
      }).format(date);
    } catch (_) { return date.toISOString(); }
  }

  function fmtDuration(ms) {
    const value = Number(ms || 0);
    if (!value) return "—";
    if (value < 1000) return `${value} ms`;
    const seconds = Math.round(value / 100) / 10;
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m ${Math.round(seconds % 60)}s`;
  }

  function fmtBytes(value) {
    const size = Number(value || 0);
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  }

  function shortHash(value, size) {
    const text = String(value || "");
    return text.length > (size || 16) ? `${text.slice(0, size || 16)}…` : text || "—";
  }

  function pretty(value) {
    return String(value || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function showError(target, message) {
    if (!target) return;
    target.textContent = String(message || "Request failed");
    target.hidden = false;
  }

  function hideError(target) { if (target) target.hidden = true; }

  async function api(path, options) {
    const opts = Object.assign({ credentials: "same-origin" }, options || {});
    const headers = new Headers(opts.headers || {});
    headers.set("Accept", "application/json");
    if (opts.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    if (opts.method && opts.method.toUpperCase() !== "GET" && state.session.csrf) {
      headers.set("X-CSRF-Token", state.session.csrf);
    }
    opts.headers = headers;
    const response = await fetch(path, opts);
    const text = await response.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch (_) { data = { detail: text.slice(0, 800) }; }
    }
    if (response.status === 401) {
      window.location.href = "/login";
      throw new Error("Session expired");
    }
    if (!response.ok) {
      const detail = data && data.detail;
      const message = typeof detail === "string" ? detail
        : detail ? JSON.stringify(detail).slice(0, 400) : `HTTP ${response.status}`;
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function copyText(value, button) {
    const text = String(value || "");
    const done = () => {
      if (!button) return;
      const old = button.textContent;
      button.textContent = "copied";
      setTimeout(() => { button.textContent = old; }, 1200);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done).catch(() => {});
    } else {
      const area = el("textarea", { value: text, attrs: { "aria-hidden": "true" } });
      area.style.position = "fixed"; area.style.opacity = "0";
      document.body.appendChild(area); area.select();
      try { document.execCommand("copy"); done(); } catch (_) {}
      document.body.removeChild(area);
    }
  }

  function setConn(mode, text) {
    const node = $("#conn");
    if (!node) return;
    node.classList.remove("live", "offline");
    if (mode) node.classList.add(mode);
    const label = $("#conn-text");
    if (label) label.textContent = text;
  }

  /* ---------------------------------------------------------------- boot */
  async function boot() {
    bindEvents();
    try {
      const session = await api("/api/session");
      state.session = session;
      window.PHISHTRACE = { csrf: session.csrf || "", user: session.user || null };
      const who = $("#who");
      if (who && session.user) {
        who.textContent = `${session.user.username}${session.user.is_admin ? " · admin" : ""}`;
      }
      if (session.auth_enabled === false) {
        const logout = $("#logout");
        if (logout) logout.hidden = true;
      }
    } catch (error) {
      setConn("offline", "offline");
      return;
    }
    await loadInvestigations();
    const match = window.location.hash.match(/^#\/inv\/([a-f0-9]{16,64})$/i);
    if (match) await openInvestigation(match[1]);
    else if (state.investigations.length) await openInvestigation(state.investigations[0].id);
  }

  function bindEvents() {
    const form = $("#start-form");
    if (form) form.addEventListener("submit", startInvestigation);
    const seed = $("#seed");
    if (seed) seed.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        if (form) form.requestSubmit();
      }
    });
    const refresh = $("#refresh-list");
    if (refresh) refresh.addEventListener("click", () => loadInvestigations());
    const refreshInv = $("#refresh-inv");
    if (refreshInv) refreshInv.addEventListener("click", () => {
      if (!state.id) return;
      refreshAll(state.id);
      loadInvestigations();
    });
    const copy = $("#copy-id");
    if (copy) copy.addEventListener("click", () => copyText(state.id, copy));
    const logout = $("#logout");
    if (logout) logout.addEventListener("click", async () => {
      try {
        await api("/logout", { method: "POST" });
      } catch (_) { /* redirect happens even when the session already expired */ }
      window.location.href = "/login";
    });
    $$(".tab").forEach((button) => button.addEventListener("click", () => activateTab(button.dataset.tab)));
    const fit = $("#graph-fit");
    if (fit) fit.addEventListener("click", () => { if (state.graph) renderGraph(state.graph); });
    const kitForm = $("#kit-form");
    if (kitForm) kitForm.addEventListener("submit", submitKit);
    window.addEventListener("hashchange", () => {
      const match = window.location.hash.match(/^#\/inv\/([a-f0-9]{16,64})$/i);
      if (match && match[1] !== state.id) openInvestigation(match[1]);
    });
  }

  /* ---------------------------------------------------------------- investigation list */
  async function loadInvestigations() {
    try {
      const data = await api("/api/investigations?limit=100");
      state.investigations = data.investigations || [];
      renderInvestigationList();
    } catch (error) {
      const list = $("#inv-list");
      clear(list);
      list.appendChild(el("p", { class: "error", text: `Could not load investigations: ${error.message}` }));
    }
  }

  function renderInvestigationList() {
    const list = $("#inv-list");
    const count = $("#inv-count");
    if (count) count.textContent = String(state.investigations.length);
    if (!list) return;
    clear(list);
    if (!state.investigations.length) {
      list.appendChild(el("p", { class: "muted small", text: "No investigations yet. Start one above." }));
      return;
    }
    state.investigations.forEach((item) => {
      const button = el("button", {
        class: `inv-item${item.id === state.id ? " active" : ""}`,
        type: "button",
        title: item.seed_normalized || item.seed || item.id,
        on: { click: () => openInvestigation(item.id) },
      });
      button.appendChild(el("div", { class: "inv-top" },
        el("span", { class: "inv-seed", text: item.seed_normalized || item.seed || "(unnamed seed)" }),
        el("span", { class: statusClass(item.status), text: item.status || "queued" })));
      button.appendChild(el("div", { class: "inv-sub" },
        el("span", { text: item.seed_type || "" }),
        el("span", { text: fmtDate(item.started_at) })));
      list.appendChild(button);
    });
  }

  /* ---------------------------------------------------------------- open + live channel */
  async function openInvestigation(id) {
    if (!id) return;
    if (!/^[a-f0-9]{16,64}$/i.test(id)) return;
    const switching = state.id !== id;
    state.id = id;
    if (switching) {
      state.detail = null;
      state.progress = null;
      state.lastSeq = 0;
      state.terminal = false;
      state.refreshedFor = null;
      state.graph = null;
      state.evidence = [];
      clear($("#event-log"));
      const eventLog = $("#event-log");
      if (eventLog) eventLog.dataset.lastSeq = "0";
      clear($("#graph-canvas"));
      clear($("#kit-result"));
      const preview = $("#evidence-preview"); if (preview) preview.textContent = "Select an evidence capture.";
      const raw = $("#evidence-raw"); if (raw) raw.hidden = true;
    }
    const empty = $("#empty"); if (empty) empty.hidden = true;
    const workspace = $("#workspace"); if (workspace) workspace.hidden = false;
    try {
      window.history.replaceState(null, "", `#/inv/${id}`);
    } catch (_) { /* history may be unavailable in hardened browsers */ }
    renderInvestigationList();
    attachLive(id);
    await refreshAll(id);
  }

  function attachLive(id) {
    stopLive();
    state.sseEnded = false;
    setConn("live", "live");
    if (!window.EventSource) { startPolling(id); return; }
    let source;
    try {
      source = new EventSource(`/api/investigations/${encodeURIComponent(id)}/progress/stream`);
    } catch (_) { startPolling(id); return; }
    state.source = source;
    source.addEventListener("progress", (event) => {
      try { applyProgress(JSON.parse(event.data)); } catch (_) { /* ignore malformed frame */ }
    });
    source.addEventListener("end", () => {
      state.sseEnded = true;
      stopLive();
      setConn("live", "complete");
    });
    source.onerror = () => {
      if (state.sseEnded || state.source !== source) { try { source.close(); } catch (_) {} return; }
      try { source.close(); } catch (_) {}
      state.source = null;
      if (state.id === id) startPolling(id);
    };
  }

  function startPolling(id) {
    stopPolling();
    setConn("offline", "polling");
    const tick = async () => {
      if (state.id !== id) return;
      try {
        const payload = await api(`/api/investigations/${encodeURIComponent(id)}/progress?after=${state.lastSeq}`);
        setConn("live", "polling");
        applyProgress(payload);
      } catch (_) {
        setConn("offline", "reconnecting");
      }
      if (state.id === id && !state.terminal) state.pollTimer = setTimeout(tick, 1800);
    };
    tick();
  }

  function stopLive() {
    if (state.source) {
      try { state.source.close(); } catch (_) {}
      state.source = null;
    }
    stopPolling();
  }

  function stopPolling() {
    if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
  }

  /* ---------------------------------------------------------------- progress */
  function applyProgress(payload) {
    if (!payload || (payload.investigation_id && payload.investigation_id !== state.id)) return;
    state.progress = Object.assign({}, state.progress || {}, payload);
    state.terminal = Boolean(payload.terminal);
    if (typeof payload.cursor === "number" && payload.cursor >= state.lastSeq) state.lastSeq = payload.cursor;
    if (payload.seed_normalized) {
      const seedNode = $("#ov-seed");
      if (seedNode) seedNode.textContent = payload.seed_normalized;
    }
    if (payload.seed_type) {
      const typeNode = $("#ov-type"); if (typeNode) typeNode.textContent = payload.seed_type;
    }
    updateStatusPill(payload.status);
    setCounts(payload.counts || {});
    updateCoverageCounts(payload.coverage || {});
    updateStage(payload);
    appendEvents(payload.events || []);
    if (payload.summary) updateSummaryHighlights(payload.summary, payload.terminal);
    if (payload.error) {
      const note = $("#terminal-note");
      if (note) {
        note.textContent = payload.error;
        note.className = "small error";
      }
    }
    if (payload.terminal && state.refreshedFor !== state.id) {
      state.refreshedFor = state.id;
      stopLive();
      setConn("live", payload.status === "failed" ? "failed" : "complete");
      refreshAll(state.id);
      loadInvestigations();
    }
  }

  function updateStatusPill(status) {
    const pill = $("#ov-status");
    if (!pill) return;
    pill.className = statusClass(status);
    pill.textContent = status || "queued";
  }

  function setCounts(counts) {
    const map = {
      "c-indicators": counts.indicators, "c-edges": counts.edges, "c-sightings": counts.sightings,
      "c-events": counts.events, "c-evidence": counts.evidence, "c-kits": counts.kits,
    };
    Object.keys(map).forEach((id) => {
      const node = document.getElementById(id);
      if (node) node.textContent = String(Number(map[id] || 0));
    });
  }

  function updateCoverageCounts(coverage) {
    const ran = document.getElementById("c-ran");
    const skipped = document.getElementById("c-skipped");
    if (ran) ran.textContent = String(Number(coverage.ran || 0));
    if (skipped) skipped.textContent = String(Number(coverage.skipped || 0));
  }

  function updateStage(payload) {
    const stage = payload.stage || "queued";
    const label = $("#stage-label");
    if (label) label.textContent = STAGE_LABELS[stage] || stage;
    const bar = $("#progress-bar");
    if (bar) {
      bar.classList.remove("indeterminate");
      if (payload.terminal) bar.style.width = "100%";
      else if (stage === "queued" || stage === "starting") { bar.classList.add("indeterminate"); bar.style.width = "35%"; }
      else bar.style.width = `${STAGE_PROGRESS[stage] || 50}%`;
    }
    const elapsed = $("#elapsed");
    if (elapsed) elapsed.textContent = payload.elapsed_ms ? fmtDuration(payload.elapsed_ms) : "";
    const note = $("#terminal-note");
    if (note && !payload.error) {
      note.className = "small muted";
      if (payload.terminal) note.textContent = payload.status === "failed" ? "run failed" : "run complete";
      else if (payload.live_channel === false && payload.status === "running") note.textContent = "no live channel in this process";
      else note.textContent = "";
    }
  }

  function eventSummary(event) {
    switch (event.event) {
      case "seed":
        return `${event.type || "seed"} ${event.normalized || event.value || ""}${event.expand === false ? " · stop-listed" : ""}`;
      case "stoplist":
        return `${event.indicator || ""} · ${event.reason || event.role || "not expanded"}`;
      case "node.start":
        return `${event.type || ""} ${event.value || ""} · ${(event.providers || []).length} provider(s)`;
      case "node.done":
        return `${event.value || ""} · ${event.children || 0} child(ren)${event.expand === false ? " · not expanded" : ""}`;
      case "node.skipped":
        return `${event.value || ""} · ${event.reason || "skipped"}`;
      case "node.capped":
        return `${event.value || ""} · capped: ${event.reason || "budget"}`;
      case "children.capped":
        return `children capped: ${event.reason || event.count || ""}`;
      case "provider.done":
        return `${event.provider || ""} · ${event.status || ""} · ${event.observations || 0} obs · ${event.requests || 0} req`;
      case "run.complete":
        return "pivot complete";
      case "stage.pivot":
        return `indicators: ${event.indicators || 0}`;
      case "stage.sightings":
        return "collecting public sightings";
      case "stage.archive":
        return `snapshots archived: ${event.archived || 0}`;
      case "run.finalized":
        return `status: ${event.status || "complete"}`;
      case "run.failed":
        return event.error || "run failed";
      default: {
        const skip = new Set(["event", "at", "seq", "investigation_id"]);
        return Object.keys(event).filter((key) => !skip.has(key) && event[key] !== null && event[key] !== undefined)
          .map((key) => `${key}=${typeof event[key] === "object" ? JSON.stringify(event[key]) : event[key]}`)
          .join(" ").slice(0, 220);
      }
    }
  }

  function appendEvents(events) {
    const log = $("#event-log");
    if (!log || !events.length) return;
    const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 60;
    events.forEach((event) => {
      if (!event || typeof event.seq !== "number") return;
      if (event.seq <= Number(log.dataset.lastSeq || 0)) return;
      log.dataset.lastSeq = String(event.seq);
      const name = String(event.event || "event");
      const row = el("li", { class: `event-row ${name.replace(/\./g, "-")}` },
        el("span", { class: "ev-time", text: event.at ? new Date(event.at).toLocaleTimeString() : "—" }),
        el("span", { class: "ev-name", text: name }),
        el("span", { class: "ev-detail", text: eventSummary(event) || "" }));
      log.appendChild(row);
    });
    while (log.children.length > 300) log.removeChild(log.firstChild);
    const count = $("#event-count");
    if (count) count.textContent = `${log.children.length} events`;
    if (nearBottom) log.scrollTop = log.scrollHeight;
  }

  function updateSummaryHighlights(summary, terminal) {
    const headline = $("#headline");
    if (headline && summary.headline) headline.textContent = summary.headline;
    const timeline = summary.timeline || {};
    const earliest = $("#earliest-text");
    if (earliest && timeline.earliest_observed) {
      earliest.textContent = `${fmtDate(timeline.earliest_observed)} · ${timeline.earliest_label || "event"} (${timeline.earliest_stage || "stage unknown"})`;
    } else if (earliest && terminal) {
      earliest.textContent = "No dated evidence was observed from the covered sources. Absence is not proof of non-existence.";
    }
    renderWarnings($("#ov-warnings"), summary.warnings || []);
  }

  function renderWarnings(target, warnings) {
    if (!target) return;
    clear(target);
    (warnings || []).slice(0, 12).forEach((warning) => {
      target.appendChild(el("p", { class: "warning-item", text: warning }));
    });
    if (!(warnings || []).length) {
      target.appendChild(el("p", { class: "muted small", text: "No run warnings." }));
    }
  }

  /* ---------------------------------------------------------------- refresh all */
  async function refreshAll(id) {
    if (!id || state.id !== id) return;
    const results = await Promise.allSettled([
      api(`/api/investigations/${encodeURIComponent(id)}`),
      api(`/api/investigations/${encodeURIComponent(id)}/graph`),
      api(`/api/investigations/${encodeURIComponent(id)}/timeline`),
      api(`/api/investigations/${encodeURIComponent(id)}/sightings`),
      api(`/api/investigations/${encodeURIComponent(id)}/coverage`),
      api(`/api/investigations/${encodeURIComponent(id)}/evidence`),
      api(`/api/investigations/${encodeURIComponent(id)}/kits`),
    ]);
    if (state.id !== id) return;
    const value = (index) => results[index].status === "fulfilled" ? results[index].value : null;
    const detail = value(0);
    if (detail) {
      state.detail = detail;
      renderHeader(detail);
      setCounts(detail.counts || {});
      updateCoverageCounts((detail.coverage && {
        ran: (detail.coverage.ran || []).length, skipped: (detail.coverage.skipped || []).length,
      }) || {});
      renderSummary(detail);
      if (!state.terminal && detail.status) updateStatusPill(detail.status);
    }
    const graphData = value(1); if (graphData) renderGraph(graphData);
    const timelineData = value(2); if (timelineData) renderTimeline(timelineData);
    const sightingsData = value(3); if (sightingsData) renderSightings(sightingsData);
    const coverageData = value(4); if (coverageData) renderCoverage(coverageData);
    const evidenceData = value(5); if (evidenceData) renderEvidence(evidenceData);
    const kitData = value(6); if (kitData) renderKits(kitData.kits || []);
  }

  function renderHeader(inv) {
    const seed = inv.seed_normalized || inv.seed || "—";
    const seedNode = $("#ov-seed"); if (seedNode) seedNode.textContent = seed;
    const typeNode = $("#ov-type"); if (typeNode) typeNode.textContent = inv.seed_type || "indicator";
    updateStatusPill(inv.status);
    const idNode = $("#ov-id"); if (idNode) idNode.textContent = `id ${inv.id}`;
    const started = $("#ov-started");
    if (started) started.textContent = inv.started_at ? `started ${fmtDate(inv.started_at)}` : "";
    const raw = $("#raw-json");
    if (raw) raw.href = `/api/investigations/${encodeURIComponent(inv.id)}`;
    if (inv.id) wireReportLinks(inv.id);
    const mode = $("#ov-mode");
    if (mode) mode.textContent = inv.finished_at ? `finished ${fmtDate(inv.finished_at)}` : "live";
    document.title = `${shortHash(seed, 42)} · PhishTrace`;
    const bar = $("#progress-bar");
    if (bar && inv.status && ["completed", "partial", "failed"].includes(inv.status)) {
      bar.classList.remove("indeterminate");
      bar.style.width = "100%";
    }
  }

  /* ---------------------------------------------------------------- reports */
  function wireReportLinks(id) {
    const base = `/api/investigations/${encodeURIComponent(id)}`;
    const links = [
      ["#report-html", `${base}/report?format=html&inline=1`],
      ["#report-pdf", `${base}/report?format=pdf`],
      ["#report-json", `${base}/report?format=json`],
      ["#report-stix", `${base}/report?format=stix`],
      ["#report-misp", `${base}/report?format=misp`],
      ["#report-abuse", `${base}/abuse?download=1`],
    ];
    links.forEach(([selector, href]) => {
      const link = $(selector);
      if (!link) return;
      link.href = href;
      link.hidden = false;
    });
  }

  function renderSummary(inv) {
    const grid = $("#summary-grid");
    if (!grid) return;
    clear(grid);
    const summary = inv.summary || {};
    const stats = inv.stats || {};
    const timeline = summary.timeline || {};
    const cards = [
      ["Seed type", inv.seed_type || "—"],
      ["Owner", inv.owner || "—"],
      ["Status", inv.status || "—"],
      ["Started", fmtDate(inv.started_at)],
      ["Finished", fmtDate(inv.finished_at)],
      ["Duration", summary.duration_ms ? fmtDuration(summary.duration_ms) : (stats.duration_ms ? fmtDuration(stats.duration_ms) : "—")],
      ["Headline", summary.headline || "—"],
      ["Stop-list hits", String(summary.stoplist_hits ?? 0)],
      ["Budget truncated", summary.truncated ? "yes" : "no"],
      ["Timeline precision", timeline.precision || "—"],
      ["Timeline events", String(timeline.event_count ?? 0)],
      ["Gaps ≥ 90 days", String((timeline.gaps || []).length)],
    ];
    cards.forEach(([label, value]) => {
      grid.appendChild(el("div", { class: "summary-card" },
        el("div", { class: "label", text: label }),
        el("div", { class: "value", text: String(value) })));
    });
    const cov = inv.coverage || {};
    const mini = $("#coverage-mini");
    if (mini) {
      clear(mini);
      const rows = [
        ["ran", (cov.ran || []).length, "ran"],
        ["skipped", (cov.skipped || []).length, "skipped"],
        ["failed", (cov.failed || []).length, "failed"],
      ];
      const total = Math.max(1, (cov.providers || []).length);
      rows.forEach(([label, count, kind]) => {
        mini.appendChild(el("div", { class: `coverage-row ${kind}` },
          el("span", { text: label }),
          el("span", { class: "bar" }, el("span", { attrs: { style: `width:${Math.round((count / total) * 100)}%` } })),
          el("span", { text: String(count) })));
      });
      mini.appendChild(el("p", { class: "muted small", text: `${total} providers in this run's coverage block.` }));
    }
    const precision = $("#precision-list");
    if (precision) {
      clear(precision);
      const stages = timeline.stages || {};
      const keys = Object.keys(stages);
      if (!keys.length) precision.appendChild(el("p", { class: "muted small", text: "No dated timeline stages yet." }));
      keys.forEach((key) => {
        precision.appendChild(el("div", { class: "precision-row" },
          el("span", { text: pretty(key) }),
          el("strong", { text: fmtDate(stages[key]) })));
      });
      if (timeline.wording && timeline.wording.note) {
        precision.appendChild(el("p", { class: "muted small", text: timeline.wording.note }));
      }
    }
  }

  /* ---------------------------------------------------------------- graph */
  function graphNodeTitle(node) {
    const bits = [`${node.type}: ${node.value}`];
    if (node.depth !== undefined) bits.push(`depth ${node.depth}`);
    if (node.path_confidence !== undefined) bits.push(`path confidence ${Number(node.path_confidence).toFixed(2)}`);
    return bits.join("\n");
  }

  function renderGraph(data) {
    const canvas = $("#graph-canvas");
    if (!canvas) return;
    state.graph = data;
    const nodes = (data && data.nodes) || [];
    const edges = (data && data.edges) || [];
    clear(canvas);
    const meta = $("#graph-meta");
    if (meta) meta.textContent = `${nodes.length} nodes · ${edges.length} edges`;
    if (!nodes.length) {
      canvas.appendChild(el("p", { class: "muted small", text: "No indicators have been materialized yet. The graph fills in as pivots complete." }));
      return;
    }
    const width = 1000;
    const height = 620;
    const cx = width / 2;
    const cy = height / 2;
    const maxDepth = nodes.reduce((max, node) => Math.max(max, Math.min(5, Number(node.depth || 0))), 0);
    const rings = [0, 105, 180, 245, 300, 340];
    const byDepth = new Map();
    nodes.forEach((node) => {
      const depth = Math.min(5, Math.max(0, Number(node.depth || 0)));
      if (!byDepth.has(depth)) byDepth.set(depth, []);
      byDepth.get(depth).push(node);
    });
    const positions = new Map();
    byDepth.forEach((ringNodes, depth) => {
      ringNodes.sort((a, b) => String(a.type).localeCompare(String(b.type)) || String(a.value).localeCompare(String(b.value)));
      const radius = rings[Math.min(depth, rings.length - 1)];
      if (depth === 0) {
        positions.set(ringNodes[0].id, { x: cx, y: cy, node: ringNodes[0] });
        ringNodes.slice(1).forEach((node, index) => {
          const angle = (index / Math.max(1, ringNodes.length - 1)) * Math.PI * 2;
          positions.set(node.id, { x: cx + Math.cos(angle) * 78, y: cy + Math.sin(angle) * 78, node });
        });
        return;
      }
      ringNodes.forEach((node, index) => {
        const angle = (index / ringNodes.length) * Math.PI * 2 - Math.PI / 2 + depth * 0.31;
        const jitter = ((index * 37) % 13) - 6;
        positions.set(node.id, {
          x: cx + Math.cos(angle) * (radius + jitter),
          y: cy + Math.sin(angle) * (radius + jitter),
          node,
        });
      });
    });
    const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Indicator relationship graph" });
    root.appendChild(svg("title", {}, `${nodes.length} indicators and ${edges.length} relationships`));
    const edgeLayer = svg("g", {});
    const nodeLayer = svg("g", {});
    root.appendChild(edgeLayer);
    root.appendChild(nodeLayer);
    edges.forEach((edge) => {
      const source = positions.get(edge.src);
      const target = positions.get(edge.dst);
      if (!source || !target) return;
      const confidence = Number(edge.confidence || 0);
      const line = svg("line", {
        x1: source.x, y1: source.y, x2: target.x, y2: target.y,
        class: `edge${confidence >= 0.7 ? " strong" : ""}`,
        "stroke-width": Math.max(0.8, Math.min(3, confidence * 2.4)),
      });
      line.appendChild(svg("title", {}, `${edge.relation || "related"} · ${edge.provider || "unknown source"} · confidence ${confidence.toFixed(2)}`));
      edgeLayer.appendChild(line);
    });
    const showLabels = nodes.length <= 70;
    const groups = new Map();
    positions.forEach((position) => {
      const node = position.node;
      const color = TYPE_COLORS[node.type] || TYPE_COLORS.other;
      const confidence = Number(node.path_confidence || 0);
      const radius = node.depth === 0 ? 15 : 7 + Math.min(7, confidence * 6);
      const group = svg("g", { class: "node", tabindex: "0", role: "button", "aria-label": graphNodeTitle(node).replace(/\n/g, ", ") });
      group.appendChild(svg("title", {}, graphNodeTitle(node)));
      const circle = svg("circle", {
        cx: position.x, cy: position.y, r: radius,
        fill: color, "fill-opacity": node.context_only ? "0.45" : "0.92",
        stroke: node.depth === 0 ? "#3ddc97" : "#07101a",
        "stroke-width": node.depth === 0 ? "3" : "2",
      });
      group.appendChild(circle);
      if (showLabels) {
        const label = String(node.value || node.type || "");
        const text = svg("text", {
          x: position.x + radius + 4,
          y: position.y + 3,
          "text-anchor": position.x > cx ? "start" : "end",
          ...(position.x > cx ? {} : { x: position.x - radius - 4 }),
        }, label.length > 26 ? `${label.slice(0, 25)}…` : label);
        group.appendChild(text);
      }
      const select = () => selectGraphNode(node, group);
      group.addEventListener("click", select);
      group.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); }
      });
      groups.set(node.id, group);
      nodeLayer.appendChild(group);
    });
    canvas.appendChild(root);
    state.graphPositions = positions;
    state.graphGroups = groups;
    renderLegend(nodes);
  }

  function selectGraphNode(node, group) {
    if (state.graphGroups) state.graphGroups.forEach((item) => item.classList.remove("selected"));
    if (group) group.classList.add("selected");
    const detail = $("#graph-detail");
    if (!detail) return;
    clear(detail);
    detail.appendChild(el("h3", { text: "Indicator" }));
    detail.appendChild(el("p", { class: "mono small", text: node.value || "—" }));
    const rows = [
      ["Type", node.type], ["Depth", node.depth], ["Path confidence", Number(node.path_confidence || 0).toFixed(3)],
      ["Context only", node.context_only ? "yes" : "no"], ["First seen in run", fmtDate(node.first_seen_in_run)],
      ["Indicator id", node.id],
    ];
    rows.forEach(([key, value]) => detail.appendChild(el("div", { class: "detail-row" },
      el("span", { class: "k", text: key }), el("span", { class: "v", text: String(value ?? "—") }))));
    const tags = Array.isArray(node.tags) ? node.tags : [];
    if (tags.length) {
      const wrap = el("div", { class: "detail-tags" });
      tags.forEach((tag) => wrap.appendChild(el("span", { class: "detail-tag", text: String(tag) })));
      detail.appendChild(wrap);
    }
    const meta = node.meta && typeof node.meta === "object" ? node.meta : {};
    const keys = Object.keys(meta).slice(0, 12);
    if (keys.length) {
      detail.appendChild(el("h3", { text: "Metadata", attrs: { style: "margin-top:14px" } }));
      keys.forEach((key) => {
        const value = meta[key];
        detail.appendChild(el("div", { class: "detail-row" },
          el("span", { class: "k", text: key }),
          el("span", { class: "v", text: typeof value === "object" ? JSON.stringify(value).slice(0, 300) : String(value).slice(0, 300) })));
      });
    }
  }

  function renderLegend(nodes) {
    const legend = $("#graph-legend");
    if (!legend) return;
    clear(legend);
    const types = Array.from(new Set(nodes.map((node) => node.type).filter(Boolean))).sort();
    types.forEach((type) => {
      legend.appendChild(el("span", { class: "legend-item" },
        el("span", { class: "legend-swatch", attrs: { style: `background:${TYPE_COLORS[type] || TYPE_COLORS.other}` } }),
        el("span", { text: type })));
    });
  }

  /* ---------------------------------------------------------------- timeline */
  function renderTimeline(data) {
    const rows = Array.isArray(data.timeline) ? data.timeline : [];
    const merged = data.merged || {};
    const summary = $("#timeline-summary");
    if (summary) {
      clear(summary);
      const earliest = merged.earliest_observed;
      summary.appendChild(el("div", { class: "tl-stage" },
        el("span", { class: "s", text: "earliest observed" }),
        el("strong", { text: earliest ? fmtDate(earliest.occurred_at) : "none observed" }),
        earliest ? el("span", { class: "muted small", text: ` · ${earliest.label || earliest.stage || ""}` }) : null));
      const stages = merged.stages || {};
      Object.keys(stages).forEach((key) => {
        summary.appendChild(el("div", { class: "tl-stage" },
          el("span", { class: "s", text: pretty(key) }),
          el("span", { text: fmtDate(stages[key].earliest_observed) }),
          el("span", { class: "muted small", text: ` · ${stages[key].count || 1} event(s)` })));
      });
    }
    const list = $("#timeline-list");
    if (!list) return;
    clear(list);
    if (!rows.length) {
      list.appendChild(el("p", { class: "muted", text: "No dated timeline events were observed. A missing stage is not proof that it never happened." }));
      return;
    }
    const gaps = (merged.gaps || []).slice(0, 12);
    rows.forEach((row, index) => {
      const item = el("div", { class: `timeline-item${index === 0 ? " first" : ""}` },
        el("div", { class: "tl-date" },
          el("time", { text: fmtDate(row.occurred_at), datetime: row.occurred_at || "" }),
          el("span", { class: "prec", text: row.precision || "exact" })),
        el("div", { class: "tl-rail" }, el("span", { class: "tl-dot" })),
        el("div", { class: "tl-body" },
          el("div", { class: "tl-label", text: row.label || row.kind || "event" }),
          el("div", { class: "tl-meta" },
            el("span", { text: (row.sources || []).join(", ") || row.source || "unknown source" }),
            el("span", { text: row.stage ? pretty(row.stage) : "" }),
            el("span", { text: row.indicator_value || "" })),
          row.detail ? el("div", { class: "tl-detail", text: row.detail }) : null,
          row.url && safeHttpUrl(row.url) ? el("a", { href: safeHttpUrl(row.url), text: "source record", target: "_blank", rel: "noopener noreferrer", class: "small" }) : null));
      list.appendChild(item);
      if (gaps[index]) {
        const gap = gaps[index];
        list.appendChild(el("div", { class: "tl-gap" },
          el("div", { class: "tl-date", text: `${gap.days} days` }),
          el("div", { class: "tl-rail" }),
          el("div", { class: "gap-label", text: `Gap between ${pretty(gap.from_stage)} and ${pretty(gap.to_stage)} observations` })));
      }
    });
  }

  /* ---------------------------------------------------------------- sightings */
  function renderSightings(data) {
    const rows = data.sightings || [];
    const meta = $("#sightings-meta");
    if (meta) meta.textContent = `${rows.length} sighting(s)`;
    const list = $("#sightings-list");
    if (!list) return;
    clear(list);
    if (!rows.length) {
      list.appendChild(el("p", { class: "muted", text: "No public sightings matched a seed or derived selector in this run. Providers that require keys are listed as skipped in Coverage." }));
      return;
    }
    rows.forEach((row) => {
      const card = el("article", { class: "sighting-card" });
      card.appendChild(el("div", { class: "sighting-head" },
        el("span", { class: "platform", text: row.platform || "platform" }),
        el("span", { class: "role-pill", text: row.role || "unknown" })));
      card.appendChild(el("div", { class: "sighting-author", text: row.author_handle || row.author_id || "author unknown" }));
      card.appendChild(el("p", { class: "sighting-text", text: row.text_excerpt || "(no text excerpt)" }));
      const metaRow = el("div", { class: "sighting-meta" },
        el("span", { text: row.posted_at ? `posted ${fmtDate(row.posted_at)}` : "posted date unknown" }),
        el("span", { text: `matched ${row.indicator_form_matched || "selector"}` }));
      const post = safeHttpUrl(row.post_url);
      if (post) metaRow.appendChild(el("a", { href: post, text: "view post", target: "_blank", rel: "noopener noreferrer" }));
      const archive = safeHttpUrl(row.archive_snapshot_url);
      if (archive) metaRow.appendChild(el("a", { href: archive, text: "archived copy", target: "_blank", rel: "noopener noreferrer" }));
      if (row.evidence_id) metaRow.appendChild(el("span", { text: `evidence ${shortHash(row.evidence_id, 10)}` }));
      card.appendChild(metaRow);
      list.appendChild(card);
    });
  }

  /* ---------------------------------------------------------------- coverage */
  function renderCoverage(data) {
    const coverage = data.coverage || {};
    const runs = data.providers || [];
    const entries = coverage.providers || [];
    const merged = new Map();
    entries.forEach((entry) => merged.set(entry.name || entry.provider, Object.assign({}, entry)));
    runs.forEach((run) => {
      const name = run.provider;
      const existing = merged.get(name) || { name };
      merged.set(name, Object.assign(existing, {
        status: run.status === "ran" ? "enabled" : run.status,
        reason: run.reason || (run.errors && run.errors[0]) || existing.reason,
        requests: run.requests, observations: run.observations, duration_ms: run.duration_ms,
        category: run.category || existing.category,
      }));
    });
    const summary = $("#coverage-summary");
    if (summary) {
      clear(summary);
      [["ran", (coverage.ran || []).length], ["skipped", (coverage.skipped || []).length],
       ["failed", (coverage.failed || []).length], ["total", merged.size]].forEach(([label, count]) => {
        summary.appendChild(el("div", { class: `cov-chip ${label}` },
          el("strong", { text: String(count) }), el("span", { text: label })));
      });
    }
    const body = $("#coverage-body");
    if (body) {
      clear(body);
      const rows = Array.from(merged.values()).sort((a, b) => String(a.name).localeCompare(String(b.name)));
      if (!rows.length) {
        const tr = el("tr", {});
        tr.appendChild(el("td", { attrs: { colspan: "7" }, class: "muted", text: "No provider coverage recorded yet." }));
        body.appendChild(tr);
      }
      rows.forEach((row) => {
        const status = row.status || "skipped";
        const className = ["enabled", "ran"].includes(status) ? "prov-ran" : status === "failed" ? "prov-failed" : "prov-skipped";
        body.appendChild(el("tr", {},
          el("td", { class: "provider-name", text: row.name || "—" }),
          el("td", { text: row.category || "—" }),
          el("td", {}, el("span", { class: `prov-pill ${className}`, text: status })),
          el("td", { text: String(row.requests ?? 0) }),
          el("td", { text: String(row.observations ?? 0) }),
          el("td", { text: row.duration_ms ? fmtDuration(row.duration_ms) : "—" }),
          el("td", { class: "reason", text: row.reason || row.error || "—" })));
      });
    }
    const stop = $("#stoplist");
    if (stop) {
      clear(stop);
      const info = coverage.stoplist || {};
      stop.appendChild(el("p", { text: `${info.networks ?? 0} protected network(s), ${info.domains ?? 0} protected domain(s).` }));
      (info.warnings || []).forEach((warning) => stop.appendChild(el("p", { class: "warning-item", text: warning })));
      const breakers = coverage.circuit_breakers || [];
      stop.appendChild(el("p", { class: "muted", text: breakers.length ? `Circuit breakers open: ${breakers.join(", ")}` : "No provider circuit breakers opened." }));
    }
    renderWarnings($("#coverage-warnings"), (state.detail && state.detail.summary && state.detail.summary.warnings) || []);
  }

  /* ---------------------------------------------------------------- evidence */
  function renderEvidence(data) {
    const rows = data.evidence || [];
    state.evidence = rows;
    const meta = $("#evidence-meta");
    if (meta) meta.textContent = `${rows.length} capture(s)`;
    const list = $("#evidence-list");
    if (!list) return;
    clear(list);
    if (!rows.length) {
      list.appendChild(el("p", { class: "muted small", text: "No raw captures for this investigation." }));
      return;
    }
    rows.forEach((row) => {
      const button = el("button", { class: "evidence-item", type: "button", on: { click: () => selectEvidence(row, button) } });
      button.appendChild(el("span", { class: "ev-url", text: row.url || "(no URL)" }));
      button.appendChild(el("span", { class: "ev-sub" },
        el("span", { text: row.provider || "provider" }),
        el("span", { text: `${row.status_code || "—"} · ${fmtBytes(row.size_bytes)}` })));
      list.appendChild(button);
    });
  }

  const EVIDENCE_KIND_LABEL = {
    html: "HTML page", json: "JSON", image: "Image", pdf: "PDF", text: "Text", binary: "Binary",
  };

  function rawEvidenceUrl(id) {
    return `/api/investigations/${encodeURIComponent(state.id)}/evidence/${encodeURIComponent(id)}/raw`;
  }

  function setEvidenceMode(mode) {
    state.evidenceMode = mode === "source" ? "source" : "rendered";
    $$("#ev-toggle .ev-mode").forEach((button) => {
      const active = button.dataset.mode === state.evidenceMode;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", active ? "true" : "false");
    });
    renderEvidenceBody();
  }

  function evidenceHeader(detail) {
    return `${detail.provider || "provider"} · HTTP ${detail.status_code || "—"} · ${fmtBytes(detail.size_bytes)} · sha256 ${detail.sha256 || "—"}\n${detail.url || ""}\n\n`;
  }

  /* The single place where the console hands untrusted markup to the browser.
   *
   * The capture is parsed inertly with DOMParser (which neither runs scripts
   * nor loads resources), stripped of anything active, and injected into a
   * frame with sandbox="" - an opaque origin with no scripts, forms or
   * top-level navigation - plus a policy that forbids every network fetch.
   * A hostile page therefore cannot beacon, frame or redirect anywhere, and
   * inline handlers are inert because scripts never execute. Layout comes
   * from the capture's own <style> blocks and attributes only.
   */
  function hardenEvidenceHtml(html) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    doc.querySelectorAll("script, iframe, frame, frameset, object, embed, applet, base, link, meta").forEach((node) => node.remove());
    const policy = doc.createElement("meta");
    policy.setAttribute("http-equiv", "Content-Security-Policy");
    policy.setAttribute("content", "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:; media-src data:; form-action 'none'; base-uri 'none'");
    const head = doc.head || doc.documentElement.insertBefore(doc.createElement("head"), doc.documentElement.firstChild);
    head.insertBefore(policy, head.firstChild);
    const css = doc.createElement("style");
    css.textContent = "a{pointer-events:none!important}";
    head.appendChild(css);
    return "<!doctype html>\n" + doc.documentElement.outerHTML;
  }

  function evidenceFrame(detail) {
    const frame = el("iframe", {
      class: "evidence-frame",
      title: "Rendered evidence capture",
      attrs: { sandbox: "", referrerpolicy: "no-referrer" },
    });
    frame.srcdoc = hardenEvidenceHtml(detail.preview || "");
    return el("div", { class: "evidence-frame-wrap" },
      frame,
      el("p", { class: "muted tiny", text: "Rendered offline from the stored capture: scripts, frames, forms and network requests are blocked, so layout may differ from the original page." }));
  }

  function jsonValueNode(value, key) {
    const label = key === null ? null : el("span", { class: "json-key", text: key });
    if (value === null) return el("div", { class: "json-row" }, label, el("span", { class: "json-null", text: "null" }));
    if (Array.isArray(value)) return jsonBranchNode(value, key, `${value.length} item${value.length === 1 ? "" : "s"}`);
    if (typeof value === "object") {
      const keys = Object.keys(value);
      return jsonBranchNode(value, key, `${keys.length} key${keys.length === 1 ? "" : "s"}`);
    }
    return el("div", { class: "json-row" }, label, el("span", { class: `json-${typeof value}`, text: JSON.stringify(value) }));
  }

  function jsonBranchNode(value, key, summary) {
    const children = Array.isArray(value)
      ? value.map((item, index) => jsonValueNode(item, String(index)))
      : Object.keys(value).map((name) => jsonValueNode(value[name], name));
    return el("details", { class: "json-branch", open: true },
      el("summary", {},
        key === null ? null : el("span", { class: "json-key", text: key }),
        el("span", { class: "json-count", text: summary })),
      el("div", { class: "json-children" }, children));
  }

  function evidenceJson(capture) {
    let parsed;
    try {
      parsed = JSON.parse(capture);
    } catch (error) {
      return el("pre", { class: "evidence-preview", text: capture });
    }
    if (capture.length > 20000) {
      return el("pre", { class: "evidence-preview", text: JSON.stringify(parsed, null, 2) });
    }
    return el("div", { class: "evidence-json" }, jsonValueNode(parsed, null));
  }

  function renderEvidenceBody() {
    const view = $("#evidence-view");
    const detail = state.evidenceDetail;
    if (!view || !detail) return;
    clear(view);
    const kind = detail.kind || "text";
    if (state.evidenceMode === "source") {
      view.appendChild(el("pre", { class: "evidence-preview", text: evidenceHeader(detail) + (detail.preview || "(empty capture)") }));
      return;
    }
    if (kind === "html") { view.appendChild(evidenceFrame(detail)); return; }
    if (kind === "json") { view.appendChild(evidenceJson(detail.preview || "")); return; }
    if (kind === "image") { view.appendChild(el("img", { class: "evidence-image", src: rawEvidenceUrl(detail.id), alt: "Evidence capture" })); return; }
    if (kind === "pdf") { view.appendChild(el("iframe", { class: "evidence-frame", title: "Evidence PDF", src: rawEvidenceUrl(detail.id) })); return; }
    if (kind === "binary") {
      view.appendChild(el("p", { class: "muted small", text: "This capture is binary; use \"download raw\" to inspect it." }));
      return;
    }
    view.appendChild(el("pre", { class: "evidence-preview", text: detail.preview || "(empty capture)" }));
  }

  function renderEvidenceMeta(detail) {
    const bar = $("#evidence-meta-bar");
    if (!bar) return;
    clear(bar);
    [
      EVIDENCE_KIND_LABEL[detail.kind] || "Capture",
      `HTTP ${detail.status_code || "—"}`,
      fmtBytes(detail.size_bytes),
      `sha256 ${(detail.sha256 || "—").slice(0, 16)}…`,
      detail.provider || "provider",
    ].forEach((chip) => bar.appendChild(el("span", { class: "ev-chip", text: chip })));
    if (detail.preview_truncated) {
      bar.appendChild(el("span", { class: "ev-chip ev-chip-warn", text: `preview limited to ${fmtBytes(detail.preview_limit || 100000)}` }));
    }
    bar.hidden = false;
  }

  async function selectEvidence(row, button) {
    $$(".evidence-item").forEach((item) => item.classList.remove("active"));
    if (button) button.classList.add("active");
    const title = $("#evidence-title");
    const raw = $("#evidence-raw");
    const view = $("#evidence-view");
    const toggle = $("#ev-toggle");
    const bar = $("#evidence-meta-bar");
    if (title) title.textContent = row.url || "Evidence capture";
    if (raw) { raw.href = rawEvidenceUrl(row.id); raw.hidden = false; }
    if (toggle) toggle.hidden = true;
    if (bar) bar.hidden = true;
    if (view) { clear(view); view.appendChild(el("p", { class: "muted small", text: "Loading preview…" })); }
    state.evidenceDetail = null;
    state.evidenceMode = "rendered";
    try {
      const detail = await api(`/api/investigations/${encodeURIComponent(state.id)}/evidence/${encodeURIComponent(row.id)}`);
      state.evidenceDetail = detail;
      if (toggle) toggle.hidden = false;
      setEvidenceMode("rendered");
      renderEvidenceMeta(detail);
    } catch (error) {
      if (view) { clear(view); view.appendChild(el("p", { class: "small", text: `Could not load evidence: ${error.message}` })); }
    }
  }

  /* ---------------------------------------------------------------- kit lab */
  async function submitKit(event) {
    event.preventDefault();
    if (!state.id) return;
    const errorBox = $("#kit-error");
    hideError(errorBox);
    const url = $("#kit-url").value.trim();
    if (!url) return;
    const button = $("#kit-btn");
    if (button) { button.disabled = true; button.textContent = "Analyzing…"; }
    try {
      const payload = await api(`/api/investigations/${encodeURIComponent(state.id)}/kit`, {
        method: "POST",
        body: JSON.stringify({
          url,
          force: Boolean($("#kit-force").checked),
          verdict: $("#kit-verdict").value || null,
        }),
      });
      renderKitReport(payload.kit || {}, payload.persisted);
      const kits = await api(`/api/investigations/${encodeURIComponent(state.id)}/kits`);
      renderKits(kits.kits || []);
    } catch (error) {
      showError(errorBox, error.message);
    } finally {
      if (button) { button.disabled = false; button.textContent = "Analyze kit"; }
    }
  }

  function kitField(label, value, mono) {
    return el("div", { class: "kit-field" },
      el("span", { class: "k", text: label }),
      el("span", { class: `v${mono === false ? "" : ""}`, text: value === null || value === undefined || value === "" ? "—" : String(value) }));
  }

  function renderKitReport(kit, persisted) {
    const target = $("#kit-result");
    if (!target) return;
    clear(target);
    if (kit.skipped) {
      target.appendChild(el("div", { class: "kit-card" },
        el("h4", { text: "Analysis skipped" }),
        el("p", { class: "warning-item", text: kit.skipped })));
      return;
    }
    const card = el("div", { class: "kit-card" });
    card.appendChild(el("h4", { text: kit.final_url || kit.url || "Kit analysis" }));
    card.appendChild(el("div", { class: "kit-grid" },
      kitField("HTTP status", kit.status_code),
      kitField("Persisted", persisted ? "yes" : "no"),
      kitField("Kit SHA-256", kit.kit_sha256),
      kitField("File tree hash", kit.file_tree_hash),
      kitField("Brand", kit.brand),
      kitField("Brand confidence", kit.brand_confidence),
      kitField("Exfil emails", (kit.exfil_emails || []).length),
      kitField("Telegram bots", (kit.telegram_bots || []).length),
      kitField("Webhooks", (kit.webhooks || []).length),
      kitField("Analytics IDs", (kit.analytics_ids || []).length),
      kitField("Credential exposures", kit.credential_exposure_count),
      kitField("Fetch time", kit.elapsed_ms ? fmtDuration(kit.elapsed_ms) : "—")));
    if ((kit.files || []).length) {
      card.appendChild(el("h3", { text: "Files", attrs: { style: "margin-top:14px" } }));
      kit.files.slice(0, 60).forEach((file) => {
        card.appendChild(el("div", { class: "kit-file" },
          el("span", { text: `${file.path || ""} · ${file.kind || ""}` }),
          el("span", { text: `${file.status_code || "—"} · ${fmtBytes(file.size)}` })));
      });
    }
    const extras = [];
    if ((kit.exfil_emails || []).length) extras.push(["Exfil emails", (kit.exfil_emails || []).map((item) => item.value || item).join(", ")]);
    if ((kit.telegram_bots || []).length) extras.push(["Telegram bot IDs", (kit.telegram_bots || []).map((item) => item.bot_id || item.id || JSON.stringify(item)).join(", ")]);
    if ((kit.webhooks || []).length) extras.push(["Webhooks", (kit.webhooks || []).map((item) => item.url || JSON.stringify(item)).join(", ")]);
    if ((kit.author_strings || []).length) extras.push(["Author strings", (kit.author_strings || []).join(", ")]);
    if ((kit.exposed_paths || []).length) extras.push(["Exposed paths", (kit.exposed_paths || []).join(", ")]);
    if (kit.notes) extras.push(["Notes", kit.notes]);
    if ((kit.errors || []).length) extras.push(["Errors", (kit.errors || []).join(" · ")]);
    extras.forEach(([label, value]) => card.appendChild(el("p", { class: "small", attrs: { style: "margin-top:10px" } },
      el("span", { class: "kicker", text: label }), el("br"), el("span", { text: value }))));
    target.appendChild(card);
  }

  function renderKits(rows) {
    const target = $("#kit-list");
    if (!target) return;
    clear(target);
    state.kitReports = rows;
    if (!rows.length) {
      target.appendChild(el("p", { class: "muted small", text: "No kit analyses saved for this investigation." }));
      return;
    }
    rows.slice().reverse().forEach((kit) => {
      const details = el("details", { class: "kit-card" });
      details.appendChild(el("summary", { class: "mono small", text: `${kit.url || "kit"} · ${fmtDate(kit.created_at)}` }));
      details.appendChild(el("div", { class: "kit-grid", attrs: { style: "margin-top:10px" } },
        kitField("Kit SHA-256", kit.kit_sha256),
        kitField("Files", (kit.files || []).length),
        kitField("Exfil emails", (kit.exfil_emails || []).length),
        kitField("Telegram bots", (kit.telegram_bots || []).length),
        kitField("Webhooks", (kit.webhooks || []).length),
        kitField("Exposures", kit.credential_exposure_count)));
      if (kit.notes) details.appendChild(el("p", { class: "muted small", text: kit.notes }));
      target.appendChild(details);
    });
  }

  /* ---------------------------------------------------------------- tabs */
  function activateTab(name) {
    if (!name) return;
    state.activeTab = name;
    $$(".tab").forEach((button) => {
      const active = button.dataset.tab === name;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
    });
    $$(".tab-panel").forEach((panel) => {
      const active = panel.id === `tab-${name}`;
      panel.classList.toggle("active", active);
      panel.hidden = !active;
    });
    if (name === "graph" && state.graph) {
      const canvas = $("#graph-canvas");
      if (canvas && !canvas.firstChild) renderGraph(state.graph);
    }
  }

  /* ---------------------------------------------------------------- start */
  async function startInvestigation(event) {
    event.preventDefault();
    const errorBox = $("#start-error");
    hideError(errorBox);
    const seed = $("#seed").value.trim();
    if (!seed) { showError(errorBox, "Enter a seed indicator first."); return; }
    const button = $("#start-btn");
    if (button) { button.disabled = true; button.textContent = "Starting…"; }
    try {
      const payload = await api("/api/investigations", {
        method: "POST",
        body: JSON.stringify({
          seed,
          kind: $("#kind").value || null,
          run_sightings: $("#run-sightings").checked,
          reuse: true,
        }),
      });
      $("#seed").value = "";
      await openInvestigation(payload.investigation_id);
      await loadInvestigations();
    } catch (error) {
      showError(errorBox, error.message);
    } finally {
      if (button) { button.disabled = false; button.textContent = "Investigate"; }
    }
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
