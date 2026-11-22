// Analytics & Visitor Fingerprints Views
import {
  formatBytes,
  formatCompact,
  formatDateTime,
  formatMinute,
  renderAreaLineChart,
  renderBarList,
  renderDonutChart,
  renderGuardFunnel,
} from "../charts.js";
import { t } from "../i18n.js";
import { el, esc, openModal } from "../ui.js";

export function createAnalyticsViews({ api, store, navigate }) {
  let obsHeroMetric = "requests";
  let obsNode = "all";
  let obsSvc = "all";
  let obsWin = 0;

  let fpFilters = { q: "", ip: "", fp: "", node: "all", service: "all", verified: "all", risk: "all" };
  let fpData = null;

  /* ==================== ANALYTICS ==================== */

  function renderAnalyticsShell() {
    const root = el("tab-analytics");
    if (!root) return;
    const data = store.telemetry || {};
    const nodes = (data.available_nodes || []).slice().sort();
    const svcs = (data.available_services || []).slice().sort();

    root.innerHTML = `
      <div class="filter-bar">
        <label class="filter-inline">
          <span>Host</span>
          <select id="obs-node-filter">
            <option value="all">${esc(t("ana.all_nodes"))} (${nodes.length})</option>
            ${nodes.map((n) => `<option value="${esc(n)}" ${obsNode === n ? "selected" : ""}>${esc(n)}</option>`).join("")}
          </select>
        </label>
        <label class="filter-inline">
          <span>Service</span>
          <select id="obs-svc-filter">
            <option value="all">${esc(t("ana.all_services"))} (${svcs.length})</option>
            ${svcs.map((s) => `<option value="${esc(s)}" ${obsSvc === s ? "selected" : ""}>${esc(s)}</option>`).join("")}
          </select>
        </label>
        <label class="filter-inline">
          <span>Window</span>
          <select id="obs-window-filter">
            <option value="0" ${obsWin === 0 ? "selected" : ""}>All</option>
            <option value="300" ${obsWin === 300 ? "selected" : ""}>5m</option>
            <option value="900" ${obsWin === 900 ? "selected" : ""}>15m</option>
            <option value="3600" ${obsWin === 3600 ? "selected" : ""}>1h</option>
            <option value="21600" ${obsWin === 21600 ? "selected" : ""}>6h</option>
            <option value="86400" ${obsWin === 86400 ? "selected" : ""}>24h</option>
          </select>
        </label>
      </div>

      <div class="panel cf-hero-panel">
        <div class="cf-metric-tabs">
          <button type="button" class="cf-metric-tab ${obsHeroMetric === "requests" ? "active" : ""}" data-cf-metric="requests">
            <span class="cf-mt-label">Total Requests</span>
            <span id="cf-val-requests" class="cf-mt-val">0</span>
            <span id="cf-sub-requests" class="cf-mt-sub">-</span>
          </button>
          <button type="button" class="cf-metric-tab ${obsHeroMetric === "uv" ? "active" : ""}" data-cf-metric="uv">
            <span class="cf-mt-label">Unique Visitors</span>
            <span id="cf-val-uv" class="cf-mt-val">0</span>
            <span id="cf-sub-uv" class="cf-mt-sub">-</span>
          </button>
          <button type="button" class="cf-metric-tab ${obsHeroMetric === "bandwidth" ? "active" : ""}" data-cf-metric="bandwidth">
            <span class="cf-mt-label">Data Served</span>
            <span id="cf-val-bandwidth" class="cf-mt-val">0 B</span>
            <span id="cf-sub-bandwidth" class="cf-mt-sub">-</span>
          </button>
          <button type="button" class="cf-metric-tab ${obsHeroMetric === "guard" ? "active" : ""}" data-cf-metric="guard">
            <span class="cf-mt-label">Guard Mitigations</span>
            <span id="cf-val-guard" class="cf-mt-val">0</span>
            <span id="cf-sub-guard" class="cf-mt-sub">-</span>
          </button>
          <button type="button" class="cf-metric-tab ${obsHeroMetric === "latency" ? "active" : ""}" data-cf-metric="latency">
            <span class="cf-mt-label">Origin Latency (p95)</span>
            <span id="cf-val-latency" class="cf-mt-val">0 ms</span>
            <span id="cf-sub-latency" class="cf-mt-sub">-</span>
          </button>
        </div>
        <div id="obs-hero-chart" class="cf-hero-chart"></div>
      </div>

      <div class="dashboard-grid-2">
        <div class="panel"><div class="panel-header"><h3>Traffic by Service</h3></div><div id="obs-service-bars"></div></div>
        <div class="panel"><div class="panel-header"><h3>Traffic by Host</h3></div><div id="obs-node-bars"></div></div>
      </div>

      <div class="dashboard-grid-2">
        <div class="panel"><div class="panel-header"><h3>Guard Funnel</h3></div><div id="obs-guard-funnel"></div></div>
        <div class="panel"><div class="panel-header"><h3>Outcome Mix</h3></div><div id="obs-outcome-donut"></div></div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <h3>Client Fingerprints (Devices · Browsers · OS)</h3>
          <div class="btn-row">
            <span id="obs-fp-verified-badge" class="muted-sm"></span>
            <button type="button" id="btn-open-fp-explorer" class="btn sm">${esc(t("ana.fp_explorer"))}</button>
          </div>
        </div>
        <div id="obs-fp-breakdown" class="dashboard-grid-3" style="margin-bottom:0;"></div>
      </div>

      <details class="panel">
        <summary class="panel-summary">Raw Minute Buckets</summary>
        <div class="table-scroll" style="margin-top:12px;">
          <table class="table">
            <thead><tr><th>Time</th><th>Host</th><th>Role</th><th>Service</th><th>Req</th><th>UV</th><th>Err</th><th>429</th><th>PoW</th><th>Bytes</th><th>p50/p95/p99</th></tr></thead>
            <tbody id="stats-tbody"></tbody>
          </table>
        </div>
      </details>
    `;

    el("obs-node-filter")?.addEventListener("change", (ev) => { obsNode = ev.target.value; refreshAnalytics(); });
    el("obs-svc-filter")?.addEventListener("change", (ev) => { obsSvc = ev.target.value; refreshAnalytics(); });
    el("obs-window-filter")?.addEventListener("change", (ev) => { obsWin = Number(ev.target.value) || 0; refreshAnalytics(); });
    el("btn-open-fp-explorer")?.addEventListener("click", () => navigate("fingerprints"));
    root.querySelectorAll("[data-cf-metric]").forEach((btn) => {
      btn.addEventListener("click", () => {
        obsHeroMetric = btn.dataset.cfMetric;
        renderAnalyticsCharts();
      });
    });
  }

  function renderAnalyticsCharts() {
    const data = store.telemetry;
    if (!data) return;
    renderAnalyticsShell();
    const tr = data.traffic || {};
    const totalReq = Number(tr.total_requests) || 0;
    const totalUv = Math.round(Number(tr.uv_estimate) || 0);
    const totalErr = Number(tr.total_errors) || 0;
    const totalRl = Number(tr.total_rate_limited) || 0;
    const totalChI = Number(tr.total_challenges_issued) || 0;
    const totalChP = Number(tr.total_challenges_passed) || 0;
    const bytesIn = Number(tr.total_bytes_in) || 0;
    const bytesOut = Number(tr.total_bytes_out) || 0;
    const p50 = Number(tr.p50_ms) || 0;
    const p95 = Number(tr.p95_ms) || 0;
    const p99 = Number(tr.p99_ms) || 0;
    const errPct = totalReq > 0 ? ((totalErr / totalReq) * 100).toFixed(2) : "0.00";

    el("cf-val-requests").textContent = formatCompact(totalReq);
    el("cf-sub-requests").textContent = `${errPct}% errors · ${formatCompact(totalErr)} 5xx`;
    el("cf-val-uv").textContent = formatCompact(totalUv);
    el("cf-sub-uv").textContent = totalUv > 0 ? `${(totalReq / totalUv).toFixed(1)} req / visitor` : "HLL union";
    el("cf-val-bandwidth").textContent = formatBytes(bytesIn + bytesOut);
    el("cf-sub-bandwidth").textContent = `${formatBytes(bytesIn)} in · ${formatBytes(bytesOut)} out`;
    el("cf-val-guard").textContent = formatCompact(totalChI + totalRl);
    el("cf-sub-guard").textContent = `${formatCompact(totalChI)} PoW · ${formatCompact(totalRl)} 429`;
    el("cf-val-latency").textContent = `${p95.toFixed(1)} ms`;
    el("cf-sub-latency").textContent = `p50 ${p50.toFixed(1)}ms · p99 ${p99.toFixed(1)}ms`;

    const pts = data.timeseries || [];
    const labels = pts.map((p) => formatMinute(p.minute_epoch));
    const cfgs = {
      requests: { unit: "", series: [{ name: "Requests", color: "#4DA9D6", values: pts.map((p) => p.requests), area: true }, { name: "429", color: "#FAC800", values: pts.map((p) => p.rate_limited) }, { name: "5xx", color: "#C40233", values: pts.map((p) => p.errors) }] },
      uv: { unit: "", series: [{ name: "Unique Visitors", color: "#009F6B", values: pts.map((p) => Math.round(p.uv_estimate || 0)), area: true }, { name: "Requests", color: "#4DA9D6", values: pts.map((p) => p.requests), dashed: true }] },
      bandwidth: { unit: "bytes", series: [{ name: "Out", color: "#4DA9D6", values: pts.map((p) => p.bytes_out), area: true }, { name: "In", color: "#6A5ACD", values: pts.map((p) => p.bytes_in), area: true }] },
      guard: { unit: "", series: [{ name: "PoW Issued", color: "#6A5ACD", values: pts.map((p) => p.challenges_issued), area: true }, { name: "PoW Passed", color: "#009F6B", values: pts.map((p) => p.challenges_passed) }, { name: "429", color: "#FAC800", values: pts.map((p) => p.rate_limited) }] },
      latency: { unit: "ms", series: [{ name: "p99", color: "#C40233", values: pts.map((p) => p.p99_ms), dashed: true }, { name: "p95", color: "#FAC800", values: pts.map((p) => p.p95_ms) }, { name: "p50", color: "#009F6B", values: pts.map((p) => p.p50_ms), area: true }] },
    };
    const active = cfgs[obsHeroMetric] || cfgs.requests;
    renderAreaLineChart(el("obs-hero-chart"), { labels, height: 260, unit: active.unit, series: active.series });
    renderBarList(el("obs-service-bars"), data.service_breakdown || []);
    renderBarList(el("obs-node-bars"), data.node_breakdown || []);
    renderGuardFunnel(el("obs-guard-funnel"), tr);

    const cleanReqs = Math.max(0, totalReq - totalErr - totalRl - totalChI);
    renderDonutChart(el("obs-outcome-donut"), {
      centerValue: formatCompact(totalReq),
      centerLabel: "Requests",
      slices: [
        { label: "Clean / Passed", value: Math.min(totalReq, cleanReqs + totalChP), color: "#009F6B" },
        { label: "PoW Pending/Drop", value: Math.max(0, totalChI - totalChP), color: "#6A5ACD" },
        { label: "429", value: totalRl, color: "#FAC800" },
        { label: "5xx", value: totalErr, color: "#C40233" },
      ],
    });

    el("obs-fp-verified-badge").textContent = `${formatCompact(Number(data.client_fp_verified) || 0)} JS-verified`;
    const renderFpCol = (title, obj, color) => {
      const entries = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
      const maxVal = entries[0]?.[1] || 1;
      const tot = entries.reduce((a, [, v]) => a + v, 0) || 1;
      return `<div><div class="muted-sm" style="margin-bottom:8px;font-weight:700;">${esc(title)}</div>${
        entries.length
          ? entries.map(([k, v]) => `<div class="bar-item" style="margin-bottom:6px;"><div class="bar-item-head"><span>${esc(k)}</span><span>${formatCompact(v)} (${((v / tot) * 100).toFixed(0)}%)</span></div><div class="bar-track"><div class="bar-fill" style="width:${((v / maxVal) * 100).toFixed(1)}%;background:${color};"></div></div></div>`).join("")
          : '<div class="muted-sm">-</div>'
      }</div>`;
    };
    el("obs-fp-breakdown").innerHTML =
      renderFpCol("Devices", data.device_counts, "#4DA9D6") +
      renderFpCol("Browsers", data.browser_counts, "#009F6B") +
      renderFpCol("OS", data.os_counts, "#6A5ACD");

    el("stats-tbody").innerHTML =
      (data.summaries || [])
        .slice()
        .reverse()
        .map(
          (s) => `
        <tr>
          <td>${esc(formatDateTime(s.minute_epoch))}</td>
          <td>${esc(s.node_tag)}</td>
          <td><span class="role-chip ${esc(s.role || "ingress")}">${esc(s.role || "ingress")}</span></td>
          <td><code>${esc(s.service_tag)}</code></td>
          <td>${formatCompact(s.requests)}</td>
          <td>${Math.round(s.uv_estimate || 0)}</td>
          <td>${esc(s.errors)}</td>
          <td>${esc(s.rate_limited)}</td>
          <td>${esc(s.challenges_passed || 0)}/${esc(s.challenges_issued || 0)}</td>
          <td>${formatBytes(s.bytes_in || 0)} / ${formatBytes(s.bytes_out || 0)}</td>
          <td>${(s.p50_ms || 0).toFixed(1)} / ${(s.p95_ms || 0).toFixed(1)} / ${(s.p99_ms || 0).toFixed(1)}</td>
        </tr>`
        )
        .join("") || `<tr><td colspan="11" class="muted">No telemetry buckets</td></tr>`;
  }

  async function refreshAnalytics() {
    const qs = new URLSearchParams();
    if (obsNode !== "all") qs.set("node", obsNode);
    if (obsSvc !== "all") qs.set("service", obsSvc);
    if (obsWin > 0) qs.set("window_secs", String(obsWin));
    const data = await api(`/api/telemetry${qs.toString() ? `?${qs}` : ""}`);
    store.telemetry = data;
    renderAnalyticsCharts();
    return data;
  }

  /* ==================== FINGERPRINTS ==================== */

  function renderFingerprints() {
    const root = el("tab-fingerprints");
    if (!root) return;
    const data = fpData || {};
    const sum = data.summary || {};
    const nodes = (data.available_nodes || []).slice().sort();
    const svcs = (data.available_services || []).slice().sort();
    const items = data.items || [];

    root.innerHTML = `
      <div class="kpi-grid">
        <div class="kpi"><div class="kpi-label">Matched Visitors</div><div class="kpi-val">${formatCompact(sum.total_visitors || 0)}</div><div class="kpi-sub">${formatCompact(sum.unique_ips || 0)} unique IPs</div></div>
        <div class="kpi"><div class="kpi-label">JS-Verified FPs</div><div class="kpi-val">${formatCompact(sum.js_verified || 0)}</div><div class="kpi-sub">${formatCompact(sum.beacon_count || 0)} beacon · ${formatCompact(sum.pow_count || 0)} PoW</div></div>
        <div class="kpi"><div class="kpi-label">Unique Browser FPs</div><div class="kpi-val">${formatCompact(sum.unique_fps || 0)}</div><div class="kpi-sub">Distinct signatures</div></div>
        <div class="kpi"><div class="kpi-label">Bots &amp; Headless</div><div class="kpi-val">${sum.bots || 0} / ${sum.headless || 0}</div><div class="kpi-sub">Bot UA / Headless JS</div></div>
      </div>

      <div class="panel">
        <div class="fp-search-bar">
          <label><span>Universal Search</span><input id="fp-search-q" type="search" value="${esc(fpFilters.q)}" placeholder="Chrome, NVIDIA, example.com, IP, hash…" /></label>
          <label><span>IP / Prefix / HMAC</span><input id="fp-search-ip" type="search" value="${esc(fpFilters.ip)}" placeholder="203.0.113.5" /></label>
          <label><span>Browser FP / Canvas</span><input id="fp-search-fp" type="search" value="${esc(fpFilters.fp)}" placeholder="fp_hash" /></label>
          <div class="btn-row">
            <button type="button" id="btn-fp-search" class="btn primary">${esc(t("common.search"))}</button>
            <button type="button" id="btn-fp-clear" class="btn ghost">${esc(t("common.reset"))}</button>
          </div>
        </div>
        <div class="fp-filter-row">
          <div class="fp-chip-group">
            ${["all", "js", "beacon", "pow", "ua"].map((v) => `<button type="button" class="fp-chip ${fpFilters.verified === v ? "active" : ""}" data-fp-ver="${v}">${v.toUpperCase()}</button>`).join("")}
          </div>
          <div class="fp-chip-group">
            ${["all", "clean", "suspicious", "headless", "bot"].map((r) => `<button type="button" class="fp-chip ${fpFilters.risk === r ? "active" : ""}" data-fp-risk="${r}">${r.toUpperCase()}</button>`).join("")}
          </div>
          <div class="btn-row">
            <select id="fp-node-filter" class="select-sm">
              <option value="all">${esc(t("ana.all_nodes"))}</option>
              ${nodes.map((n) => `<option value="${esc(n)}" ${fpFilters.node === n ? "selected" : ""}>${esc(n)}</option>`).join("")}
            </select>
            <select id="fp-svc-filter" class="select-sm">
              <option value="all">${esc(t("ana.all_services"))}</option>
              ${svcs.map((s) => `<option value="${esc(s)}" ${fpFilters.service === s ? "selected" : ""}>${esc(s)}</option>`).join("")}
            </select>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <h3>Visitor &amp; Fingerprint Directory (${items.length})</h3>
          <span class="muted-sm">Click any row for full TLS, UA &amp; JS signals</span>
        </div>
        <div class="table-scroll" style="max-height:540px;">
          <table class="table">
            <thead><tr><th>IP / HMAC</th><th>Browser FP</th><th>Device · Browser · OS</th><th>JS Signals</th><th>Host / Service</th><th>Risk</th><th>Traffic</th><th>Last Seen</th></tr></thead>
            <tbody>
              ${
                items
                  .map((obs, idx) => {
                    const ipPrimary = obs.client_ip || obs.ip_prefix || "-";
                    const srcBadge = obs.js_verified ? (obs.fp_source === "pow" ? `<span class="pill ok">PoW</span>` : `<span class="pill info">Beacon</span>`) : `<span class="pill">UA</span>`;
                    const js = obs.js_fp;
                    const jsSum = js ? `${js.screen || "-"} · ${(js.webgl || js.platform || "-").slice(0, 28)}` : "-";
                    const riskCls = obs.is_headless || obs.is_bot || obs.suspicion_score >= 60 ? "err" : obs.suspicion_score >= 30 ? "warn" : "ok";
                    const riskLbl = obs.is_headless ? "HEADLESS" : obs.is_bot ? "BOT" : `Score ${Number(obs.suspicion_score) || 0}`;
                    return `
                  <tr class="fp-table-row" data-fp-idx="${idx}">
                    <td><div><strong>${esc(ipPrimary)}</strong></div><div class="muted-sm"><span class="fp-code">${esc(obs.ip_hmac)}</span></div></td>
                    <td><span class="fp-code">${esc(obs.fp_hash)}</span> ${srcBadge}</td>
                    <td><div><strong>${esc(obs.browser_family || "-")}</strong> · ${esc(obs.os_family || "-")}</div><div class="muted-sm">${esc(obs.device_type || "-")}</div></td>
                    <td><span class="muted-sm">${esc(jsSum)}</span></td>
                    <td><div><code>${esc(obs.service_tag)}</code></div><div class="muted-sm">${esc(obs.node_tag)}</div></td>
                    <td><span class="pill ${riskCls}">${esc(riskLbl)}</span></td>
                    <td><div><strong>${formatCompact(obs.request_count)}</strong></div><div class="muted-sm">${obs.challenge_count || 0} ch · ${obs.rate_limited_count || 0} 429</div></td>
                    <td>${esc(formatDateTime(obs.last_seen_ts))}</td>
                  </tr>`;
                  })
                  .join("") || `<tr><td colspan="8" class="muted">No visitor fingerprints match.</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    `;

    const triggerSearch = () => {
      fpFilters.q = el("fp-search-q")?.value.trim() || "";
      fpFilters.ip = el("fp-search-ip")?.value.trim() || "";
      fpFilters.fp = el("fp-search-fp")?.value.trim() || "";
      refreshFingerprints();
    };
    el("btn-fp-search")?.addEventListener("click", triggerSearch);
    el("btn-fp-clear")?.addEventListener("click", () => {
      fpFilters = { q: "", ip: "", fp: "", node: "all", service: "all", verified: "all", risk: "all" };
      refreshFingerprints();
    });
    ["fp-search-q", "fp-search-ip", "fp-search-fp"].forEach((id) => {
      el(id)?.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); triggerSearch(); } });
    });
    el("fp-node-filter")?.addEventListener("change", (ev) => { fpFilters.node = ev.target.value; refreshFingerprints(); });
    el("fp-svc-filter")?.addEventListener("change", (ev) => { fpFilters.service = ev.target.value; refreshFingerprints(); });
    root.querySelectorAll("[data-fp-ver]").forEach((b) => b.addEventListener("click", () => { fpFilters.verified = b.dataset.fpVer; refreshFingerprints(); }));
    root.querySelectorAll("[data-fp-risk]").forEach((b) => b.addEventListener("click", () => { fpFilters.risk = b.dataset.fpRisk; refreshFingerprints(); }));
    root.querySelectorAll("[data-fp-idx]").forEach((tr) => {
      tr.addEventListener("click", () => {
        const obs = items[Number(tr.dataset.fpIdx)];
        if (!obs) return;
        const js = obs.js_fp;
        openModal({
          title: `Fingerprint — ${obs.fp_hash}`,
          bodyHtml: `
            <div class="fp-detail-grid">
              <div class="fp-kv"><div class="fp-kv-lbl">IP / HMAC</div><div class="fp-kv-val">${esc(obs.client_ip || obs.ip_prefix || "-")}<br/><code>${esc(obs.ip_hmac)}</code></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Route</div><div class="fp-kv-val"><code>${esc(obs.service_tag)}</code> @ ${esc(obs.node_tag)}</div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Score &amp; TLS</div><div class="fp-kv-val">${Number(obs.suspicion_score) || 0}/100 · ciphers: ${Number(obs.tls_cipher_count) || 0}</div></div>
              ${js ? `<div class="fp-kv"><div class="fp-kv-lbl">WebGL / Screen</div><div class="fp-kv-val">${esc(js.webgl || "-")} · ${esc(js.screen || "-")}</div></div>` : ""}
            </div>
            <div class="fp-ua-box">${esc(obs.user_agent || "(empty)")}</div>`,
          actions: [{ label: t("common.close"), cls: "primary" }],
        });
      });
    });
  }

  async function refreshFingerprints() {
    const qs = new URLSearchParams();
    if (fpFilters.q) qs.set("q", fpFilters.q);
    if (fpFilters.ip) qs.set("ip", fpFilters.ip);
    if (fpFilters.fp) qs.set("fp", fpFilters.fp);
    if (fpFilters.node !== "all") qs.set("node", fpFilters.node);
    if (fpFilters.service !== "all") qs.set("service", fpFilters.service);
    if (fpFilters.verified !== "all") qs.set("verified", fpFilters.verified);
    if (fpFilters.risk !== "all") qs.set("risk", fpFilters.risk);
    const winSec = Number(el("sel-time-window")?.value || 0);
    if (winSec > 0) qs.set("window_secs", String(winSec));
    fpData = await api(`/api/fingerprints${qs.toString() ? `?${qs}` : ""}`);
    renderFingerprints();
    return fpData;
  }

  return {
    refreshAnalytics,
    renderAnalytics: renderAnalyticsCharts,
    refreshFingerprints,
    renderFingerprints,
  };
}
