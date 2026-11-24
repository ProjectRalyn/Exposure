// Analytics & Unified Logging (Access URL Explorer + Visitors & Fingerprints) Views
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

function downloadJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderPaginationBar(prefix, { total, offset, limit }) {
  const tot = Math.max(0, Number(total) || 0);
  const lim = Math.max(1, Number(limit) || 50);
  const off = Math.max(0, Number(offset) || 0);
  const page = Math.floor(off / lim) + 1;
  const totalPages = Math.max(1, Math.ceil(tot / lim));
  const start = tot === 0 ? 0 : Math.min(tot, off + 1);
  const end = Math.min(tot, off + lim);
  const atStart = off <= 0;
  const atEnd = off + lim >= tot;
  return `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-top:10px;">
      <div class="muted-sm">${esc(t("logs.page.showing", { start, end, total: tot }))}</div>
      <div class="btn-row">
        <label style="display:flex;align-items:center;gap:6px;">
          <span class="muted-sm">${esc(t("logs.page.per_page"))}</span>
          <select id="${prefix}-pg-limit" class="select-sm">
            ${[25, 50, 100].map((n) => `<option value="${n}" ${lim === n ? "selected" : ""}>${n}</option>`).join("")}
          </select>
        </label>
        <button type="button" id="${prefix}-pg-first" class="btn sm" ${atStart ? "disabled" : ""}>&laquo;</button>
        <button type="button" id="${prefix}-pg-prev" class="btn sm" ${atStart ? "disabled" : ""}>&lsaquo;</button>
        <span class="muted-sm">${esc(t("logs.page.of", { page, pages: totalPages }))}</span>
        <button type="button" id="${prefix}-pg-next" class="btn sm" ${atEnd ? "disabled" : ""}>&rsaquo;</button>
        <button type="button" id="${prefix}-pg-last" class="btn sm" ${atEnd ? "disabled" : ""}>&raquo;</button>
      </div>
    </div>
  `;
}

function wirePaginationBar(prefix, state, total, onChange) {
  const lim = Math.max(1, Number(state.limit) || 50);
  const tot = Math.max(0, Number(total) || 0);
  const lastOff = Math.max(0, (Math.max(1, Math.ceil(tot / lim)) - 1) * lim);
  el(`${prefix}-pg-limit`)?.addEventListener("change", (ev) => {
    state.limit = Number(ev.target.value) || 50;
    state.offset = 0;
    onChange();
  });
  el(`${prefix}-pg-first`)?.addEventListener("click", () => {
    state.offset = 0;
    onChange();
  });
  el(`${prefix}-pg-prev`)?.addEventListener("click", () => {
    state.offset = Math.max(0, (state.offset || 0) - lim);
    onChange();
  });
  el(`${prefix}-pg-next`)?.addEventListener("click", () => {
    if ((state.offset || 0) + lim < tot) {
      state.offset = (state.offset || 0) + lim;
      onChange();
    }
  });
  el(`${prefix}-pg-last`)?.addEventListener("click", () => {
    state.offset = lastOff;
    onChange();
  });
}

export function createAnalyticsViews({ api, store, navigate }) {
  let obsHeroMetric = "requests";
  let obsNode = "all";
  let obsSvc = "all";
  let obsWin = 0;
  let bucketPageState = { offset: 0, limit: 50 };

  let loggingSubTab = "access"; // access | visitors
  const defaultLogFilters = () => ({
    q: "",
    ip: "",
    host: "",
    node: "all",
    service: "all",
    role: "all",
    method: "all",
    status: "all",
    action: "all",
    country: "all",
    window_secs: 0,
    offset: 0,
    limit: 50,
  });
  let logFilters = defaultLogFilters();
  let logData = null;

  const defaultFpFilters = () => ({
    q: "",
    ip: "",
    fp: "",
    node: "all",
    service: "all",
    country: "all",
    verified: "all",
    risk: "all",
    offset: 0,
    limit: 50,
  });
  let fpFilters = defaultFpFilters();
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

      <div class="panel">
        <div class="panel-header">
          <h3>${esc(t("ana.svc_latency_title"))}</h3>
          <span class="muted-sm">${esc(t("ana.svc_latency_sub"))}</span>
        </div>
        <div class="table-scroll">
          <table class="table">
            <thead>
              <tr>
                <th>Service</th>
                <th>Requests</th>
                <th>UV</th>
                <th>5xx Err</th>
                <th>429</th>
                <th>Bytes (In / Out)</th>
                <th>p50</th>
                <th>p95</th>
                <th>p99</th>
                <th>Latency Spread</th>
                <th></th>
              </tr>
            </thead>
            <tbody id="obs-svc-latency-tbody"></tbody>
          </table>
        </div>
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
            <button type="button" id="btn-open-access-logs" class="btn sm">${esc(t("logging.tab.access"))} →</button>
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
        <div id="stats-pagination"></div>
      </details>
    `;

    el("obs-node-filter")?.addEventListener("change", (ev) => { obsNode = ev.target.value; bucketPageState.offset = 0; refreshAnalytics(); });
    el("obs-svc-filter")?.addEventListener("change", (ev) => { obsSvc = ev.target.value; bucketPageState.offset = 0; refreshAnalytics(); });
    el("obs-window-filter")?.addEventListener("change", (ev) => { obsWin = Number(ev.target.value) || 0; bucketPageState.offset = 0; refreshAnalytics(); });
    el("btn-open-access-logs")?.addEventListener("click", () => navigate("logging", { subTab: "access", service: obsSvc !== "all" ? obsSvc : undefined }));
    el("btn-open-fp-explorer")?.addEventListener("click", () => navigate("logging", { subTab: "visitors", service: obsSvc !== "all" ? obsSvc : undefined }));
    root.querySelectorAll("[data-cf-metric]").forEach((btn) => {
      btn.addEventListener("click", () => {
        obsHeroMetric = btn.dataset.cfMetric;
        renderAnalyticsCharts();
      });
    });
  }

  function renderAnalyticsCharts() {
    const data = store.telemetry;
    if (!data) {
      const root = el("tab-analytics");
      if (root) root.innerHTML = `<div class="panel muted">Loading telemetry…</div>`;
      return;
    }
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
    const cachedBytesOut = Number(tr.total_cached_bytes_out) || 0;
    const cachedPct = bytesOut > 0 ? ((cachedBytesOut / bytesOut) * 100).toFixed(1) : "0.0";
    const p50 = Number(tr.p50_ms) || 0;
    const p95 = Number(tr.p95_ms) || 0;
    const p99 = Number(tr.p99_ms) || 0;
    const errPct = totalReq > 0 ? ((totalErr / totalReq) * 100).toFixed(2) : "0.00";

    el("cf-val-requests").textContent = formatCompact(totalReq);
    el("cf-sub-requests").textContent = `${errPct}% errors · ${formatCompact(totalErr)} 5xx`;
    el("cf-val-uv").textContent = formatCompact(totalUv);
    el("cf-sub-uv").textContent = totalUv > 0 ? `${(totalReq / totalUv).toFixed(1)} req / visitor` : "HLL union";
    el("cf-val-bandwidth").textContent = formatBytes(bytesIn + bytesOut);
    el("cf-sub-bandwidth").textContent = `${formatBytes(cachedBytesOut)} cached (${cachedPct}%) · ${formatBytes(bytesIn)} in · ${formatBytes(bytesOut)} out`;
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

    const svcsList = data.service_breakdown || [];
    renderBarList(el("obs-service-bars"), svcsList);
    renderBarList(el("obs-node-bars"), data.node_breakdown || []);

    const maxP99 = Math.max(1, ...svcsList.map((s) => Number(s.p99_ms) || 0));
    const svcLatBody = el("obs-svc-latency-tbody");
    if (svcLatBody) {
      svcLatBody.innerHTML =
        svcsList
          .map((s) => {
            const req = Number(s.requests) || 0;
            const err = Number(s.errors) || 0;
            const sp50 = Number(s.p50_ms) || 0;
            const sp95 = Number(s.p95_ms) || 0;
            const sp99 = Number(s.p99_ms) || 0;
            const ePct = req > 0 ? ((err / req) * 100).toFixed(1) : "0.0";
            const eCls = err > 0 ? "err" : "ok";
            const barW = Math.max(3, Math.round((sp99 / maxP99) * 100));
            const barColor = sp99 >= 500 ? "#C40233" : sp99 >= 150 ? "#FAC800" : "#009F6B";
            return `
          <tr>
            <td><button type="button" class="btn sm ghost" data-obs-filter-svc="${esc(s.service_tag)}"><code>${esc(s.service_tag)}</code></button></td>
            <td><strong>${formatCompact(req)}</strong></td>
            <td>${formatCompact(Math.round(s.uv_estimate || 0))}</td>
            <td>${formatCompact(err)} <span class="pill ${eCls}">${ePct}%</span></td>
            <td>${formatCompact(s.rate_limited || 0)}</td>
            <td class="muted-sm">${formatBytes(s.bytes_in || 0)} / ${formatBytes(s.bytes_out || 0)}</td>
            <td><strong>${sp50.toFixed(1)}</strong> ms</td>
            <td>${sp95.toFixed(1)} ms</td>
            <td><span class="pill ${sp99 >= 500 ? "err" : sp99 >= 150 ? "warn" : "ok"}">${sp99.toFixed(1)} ms</span></td>
            <td style="min-width:110px;"><div class="bar-track"><div class="bar-fill" style="width:${barW}%;background:${barColor};"></div></div></td>
            <td><button type="button" class="btn sm" data-obs-svc-logs="${esc(s.service_tag)}">Logs →</button></td>
          </tr>`;
          })
          .join("") || `<tr><td colspan="11" class="muted">No service telemetry recorded</td></tr>`;

      svcLatBody.querySelectorAll("[data-obs-filter-svc]").forEach((btn) => {
        btn.addEventListener("click", () => {
          obsSvc = btn.dataset.obsFilterSvc;
          refreshAnalytics();
        });
      });
      svcLatBody.querySelectorAll("[data-obs-svc-logs]").forEach((btn) => {
        btn.addEventListener("click", () => {
          navigate("logging", { subTab: "access", service: btn.dataset.obsSvcLogs });
        });
      });
    }

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

    const allBuckets = (data.summaries || []).slice().reverse();
    if (bucketPageState.offset >= allBuckets.length) bucketPageState.offset = 0;
    const pagedBuckets = allBuckets.slice(
      bucketPageState.offset,
      bucketPageState.offset + bucketPageState.limit
    );
    el("stats-tbody").innerHTML =
      pagedBuckets
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
    const pgHost = el("stats-pagination");
    if (pgHost) {
      pgHost.innerHTML = renderPaginationBar("stats", {
        total: allBuckets.length,
        offset: bucketPageState.offset,
        limit: bucketPageState.limit,
      });
      wirePaginationBar("stats", bucketPageState, allBuckets.length, renderAnalyticsCharts);
    }
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

  /* ==================== UNIFIED LOGGING WORKSPACE ==================== */

  function renderLoggingSubtabsBar() {
    const logCnt = logData ? Number(logData.total_matched ?? (logData.items || []).length ?? 0) : null;
    const fpCnt = fpData ? Number(fpData.total_matched ?? (fpData.items || []).length ?? 0) : null;
    return `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${loggingSubTab === "access" ? "active" : ""}" data-log-sub="access">
            ${esc(t("logging.tab.access"))} ${logCnt != null ? `<span class="subtab-count">${logCnt}</span>` : ""}
          </button>
          <button type="button" class="subtab-btn ${loggingSubTab === "visitors" ? "active" : ""}" data-log-sub="visitors">
            ${esc(t("logging.tab.visitors"))} ${fpCnt != null ? `<span class="subtab-count">${fpCnt}</span>` : ""}
          </button>
        </div>
      </div>
    `;
  }

  function wireLoggingSubtabs(root) {
    root.querySelectorAll("[data-log-sub]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const next = btn.dataset.logSub;
        if (next === loggingSubTab) return;
        loggingSubTab = next;
        if (loggingSubTab === "access") {
          renderLogs();
          refreshLogs();
        } else {
          renderVisitors();
          refreshVisitors();
        }
      });
    });
  }

  function renderLogs() {
    const root = el("tab-logging");
    if (!root) return;
    const data = logData || {};
    const sum = data.summary || {};
    const prot = data.log_protection || {};
    const items = data.items || [];
    const topPaths = data.top_paths || [];
    const nodes = (data.available_nodes || []).slice().sort();
    const svcs = (data.available_services || []).slice().sort();
    const countries = (data.available_countries || []).slice().sort();
    const totalMatched = Number(data.total_matched ?? items.length) || 0;

    const actionPillCls = (act, status) => {
      if (act === "autoban" || act === "waf_block" || act === "evilpot" || act === "guard_reject" || act === "abuseipdb" || act === "geo_block" || act === "geo_evilpot" || status >= 500) return "err";
      if (act === "rate_limit" || act === "challenge" || act === "geo_challenge" || act === "waf_monitor" || act === "unmatched" || status >= 400) return "warn";
      if (act === "cache_hit" || act === "cache_stale" || act === "challenge_pass") return "info";
      return "ok";
    };

    root.innerHTML = `
      ${renderLoggingSubtabsBar()}
      <div class="kpi-grid">
        <div class="kpi"><div class="kpi-label">${esc(t("logs.kpi.requests"))}</div><div class="kpi-val">${formatCompact(sum.total_requests || 0)}</div><div class="kpi-sub">${formatCompact(sum.total_events || items.length)} events · ${formatCompact(sum.unique_ips || 0)} unique IPs</div></div>
        <div class="kpi"><div class="kpi-label">${esc(t("logs.kpi.blocked"))}</div><div class="kpi-val">${formatCompact(sum.blocked_requests || 0)}</div><div class="kpi-sub">cache hits: ${formatCompact(sum.cache_hits || 0)} · folded: ${formatCompact(sum.folded_requests || 0)}</div></div>
        <div class="kpi"><div class="kpi-label">${esc(t("logs.kpi.errors"))}</div><div class="kpi-val">${formatCompact(sum.error_5xx_requests || 0)}</div><div class="kpi-sub">${formatCompact(sum.unique_paths || 0)} unique URLs</div></div>
        <div class="kpi"><div class="kpi-label">${esc(t("logs.kpi.dos_shield"))}</div><div class="kpi-val">${formatCompact(prot.folded_records || 0)} / ${formatCompact(prot.dropped_records || 0)}</div><div class="kpi-sub">folded / dropped · ${formatCompact(prot.warn_suppressed || 0)} warns muted</div></div>
      </div>

      <div class="panel">
        <div class="fp-search-bar">
          <label><span>URL / Search</span><input id="log-search-q" type="search" value="${esc(logFilters.q)}" placeholder="${esc(t("logs.search_ph"))}" /></label>
          <label><span>IP / HMAC</span><input id="log-search-ip" type="search" value="${esc(logFilters.ip)}" placeholder="${esc(t("logs.ip_ph"))}" /></label>
          <label><span>Host</span><input id="log-search-host" type="search" value="${esc(logFilters.host)}" placeholder="${esc(t("logs.host_ph"))}" /></label>
          <div class="btn-row">
            <button type="button" id="btn-log-search" class="btn primary">${esc(t("common.search"))}</button>
            <button type="button" id="btn-log-clear" class="btn ghost">${esc(t("common.reset"))}</button>
            <button type="button" id="btn-log-export" class="btn sm">${esc(t("logging.export_json"))}</button>
          </div>
        </div>
        <div class="fp-filter-row">
          <div class="fp-chip-group">
            ${["all", "2xx", "3xx", "4xx", "5xx"].map((st) => `<button type="button" class="fp-chip ${logFilters.status === st ? "active" : ""}" data-log-st="${st}">${st.toUpperCase()}</button>`).join("")}
          </div>
          <div class="fp-chip-group">
            ${["all", "allow", "blocked", "waf_block", "evilpot", "autoban", "rate_limit", "geo_block", "geo_challenge", "geo_evilpot", "cache_hit", "unmatched"].map((a) => `<button type="button" class="fp-chip ${logFilters.action === a ? "active" : ""}" data-log-act="${a}">${esc(a)}</button>`).join("")}
          </div>
          <div class="btn-row">
            <select id="log-method-filter" class="select-sm">
              <option value="all" ${logFilters.method === "all" ? "selected" : ""}>All Methods</option>
              ${["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"].map((m) => `<option value="${m}" ${logFilters.method === m ? "selected" : ""}>${m}</option>`).join("")}
            </select>
            <select id="log-role-filter" class="select-sm">
              <option value="all" ${logFilters.role === "all" ? "selected" : ""}>All Roles</option>
              <option value="ingress" ${logFilters.role === "ingress" ? "selected" : ""}>ingress</option>
              <option value="egress" ${logFilters.role === "egress" ? "selected" : ""}>egress</option>
            </select>
            <select id="log-node-filter" class="select-sm">
              <option value="all">${esc(t("ana.all_nodes"))}</option>
              ${nodes.map((n) => `<option value="${esc(n)}" ${logFilters.node === n ? "selected" : ""}>${esc(n)}</option>`).join("")}
            </select>
            <select id="log-svc-filter" class="select-sm">
              <option value="all">${esc(t("ana.all_services"))}</option>
              ${svcs.map((s) => `<option value="${esc(s)}" ${logFilters.service === s ? "selected" : ""}>${esc(s)}</option>`).join("")}
            </select>
            <select id="log-country-filter" class="select-sm">
              <option value="all">${esc(t("logs.all_countries"))}</option>
              ${countries.map((c) => `<option value="${esc(c)}" ${logFilters.country === c ? "selected" : ""}>${esc(c)}</option>`).join("")}
            </select>
            <select id="log-window-filter" class="select-sm">
              <option value="0" ${logFilters.window_secs === 0 ? "selected" : ""}>Global Window</option>
              <option value="300" ${logFilters.window_secs === 300 ? "selected" : ""}>5m</option>
              <option value="900" ${logFilters.window_secs === 900 ? "selected" : ""}>15m</option>
              <option value="3600" ${logFilters.window_secs === 3600 ? "selected" : ""}>1h</option>
              <option value="86400" ${logFilters.window_secs === 86400 ? "selected" : ""}>24h</option>
            </select>
          </div>
        </div>
      </div>

      ${
        topPaths.length
          ? `<div class="panel">
              <div class="panel-header"><h3>${esc(t("logs.top_urls"))}</h3><span class="muted-sm">Click a path to filter</span></div>
              <div class="table-scroll">
                <table class="table">
                  <thead><tr><th>Host</th><th>Path</th><th>Hits</th><th>Blocked</th><th>5xx</th></tr></thead>
                  <tbody>
                    ${topPaths
                      .map(
                        (tp, i) => `
                      <tr class="fp-table-row" data-top-path-idx="${i}">
                        <td><code>${esc(tp.host || "-")}</code></td>
                        <td><span class="fp-code">${esc(tp.path || "/")}</span></td>
                        <td><strong>${formatCompact(tp.hits || 0)}</strong></td>
                        <td>${tp.blocked ? `<span class="pill warn">${formatCompact(tp.blocked)}</span>` : "0"}</td>
                        <td>${tp.errors_5xx ? `<span class="pill err">${formatCompact(tp.errors_5xx)}</span>` : "0"}</td>
                      </tr>`
                      )
                      .join("")}
                  </tbody>
                </table>
              </div>
            </div>`
          : ""
      }

      <div class="panel">
        <div class="panel-header">
          <h3>${esc(t("logs.explorer_title"))} (${totalMatched})</h3>
          <span class="muted-sm">Query strings redact secrets · Click row for full detail &amp; visitor correlation</span>
        </div>
        <div class="table-scroll">
          <table class="table">
            <thead>
              <tr>
                <th>${esc(t("logs.col.time"))}</th>
                <th>${esc(t("logs.col.method"))}</th>
                <th>${esc(t("logs.col.status"))}</th>
                <th>${esc(t("logs.col.url"))}</th>
                <th>${esc(t("logs.col.action"))}</th>
                <th>${esc(t("logs.col.client"))}</th>
                <th>${esc(t("logs.col.route"))}</th>
                <th>${esc(t("logs.col.perf"))}</th>
              </tr>
            </thead>
            <tbody>
              ${
                items
                  .map((r, idx) => {
                    const st = Number(r.status) || 0;
                    const stCls = st >= 500 ? "err" : st >= 400 ? "warn" : st >= 300 ? "info" : "ok";
                    const act = r.action || "allow";
                    const actCls = actionPillCls(act, st);
                    const repeat = Number(r.repeat_count) || 1;
                    const tsSec = Math.floor((Number(r.timestamp_ms) || 0) / 1000);
                    return `
                  <tr class="fp-table-row" data-log-idx="${idx}">
                    <td><div>${esc(formatDateTime(tsSec))}</div><div class="muted-sm">${esc(r.ray_id ? r.ray_id.slice(0, 12) : "-")}</div></td>
                    <td><div><strong>${esc(r.method || "-")}</strong></div><div class="muted-sm">${esc(r.scheme || "")}${r.protocol ? ` · ${esc(r.protocol)}` : ""}</div></td>
                    <td><span class="pill ${stCls}">${st}</span>${r.cache_status ? ` <span class="pill">${esc(r.cache_status)}</span>` : ""}</td>
                    <td style="max-width:340px;word-break:break-all;">
                      <div><strong>${esc(r.host || "-")}</strong></div>
                      <div><span class="fp-code">${esc(r.path || "/")}</span>${r.query ? `<span class="muted-sm">?${esc(r.query)}</span>` : ""}</div>
                    </td>
                    <td>
                      <div style="display:flex;flex-wrap:wrap;gap:4px;">
                        <span class="pill ${actCls}">${esc(act)}</span>
                        ${repeat > 1 ? `<span class="pill warn">&times;${repeat}</span>` : ""}
                      </div>
                      ${r.waf_category || r.error ? `<div class="muted-sm">${esc(r.waf_category || r.error || "")}</div>` : ""}
                    </td>
                    <td><div>${esc(r.raw_ip || "-")} ${r.client_country ? `<span class="pill info">${esc(r.client_country)}</span>` : ""}</div><div class="muted-sm"><span class="fp-code">${esc((r.ip_hmac || "").slice(0, 14))}</span></div></td>
                    <td><div><code>${esc(r.service_tag)}</code></div><div class="muted-sm">${esc(r.node_tag)} · ${esc(r.role)}</div></td>
                    <td><div>${(Number(r.latency_ms) || 0).toFixed(1)} ms</div><div class="muted-sm">${formatBytes(r.bytes_in || 0)} / ${formatBytes(r.bytes_out || 0)}</div></td>
                  </tr>`;
                  })
                  .join("") || `<tr><td colspan="8" class="muted">${esc(t("logs.empty"))}</td></tr>`
              }
            </tbody>
          </table>
        </div>
        ${renderPaginationBar("log", { total: totalMatched, offset: logFilters.offset, limit: logFilters.limit })}
      </div>
    `;

    wireLoggingSubtabs(root);
    wirePaginationBar("log", logFilters, totalMatched, refreshLogs);
    const triggerLogSearch = () => {
      logFilters.q = el("log-search-q")?.value.trim() || "";
      logFilters.ip = el("log-search-ip")?.value.trim() || "";
      logFilters.host = el("log-search-host")?.value.trim() || "";
      logFilters.method = el("log-method-filter")?.value || "all";
      logFilters.role = el("log-role-filter")?.value || "all";
      logFilters.node = el("log-node-filter")?.value || "all";
      logFilters.service = el("log-svc-filter")?.value || "all";
      logFilters.country = el("log-country-filter")?.value || "all";
      logFilters.window_secs = Number(el("log-window-filter")?.value || 0);
      logFilters.offset = 0;
      refreshLogs();
    };
    el("btn-log-search")?.addEventListener("click", triggerLogSearch);
    ["log-search-q", "log-search-ip", "log-search-host"].forEach((id) => {
      el(id)?.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") { ev.preventDefault(); triggerLogSearch(); }
      });
    });
    ["log-method-filter", "log-role-filter", "log-node-filter", "log-svc-filter", "log-country-filter", "log-window-filter"].forEach((id) => {
      el(id)?.addEventListener("change", triggerLogSearch);
    });
    el("btn-log-clear")?.addEventListener("click", () => {
      logFilters = defaultLogFilters();
      refreshLogs();
    });
    el("btn-log-export")?.addEventListener("click", () => {
      downloadJson("exposure-access-logs.json", items);
    });
    root.querySelectorAll("[data-log-st]").forEach((btn) => {
      btn.addEventListener("click", () => {
        logFilters.status = btn.dataset.logSt;
        logFilters.offset = 0;
        refreshLogs();
      });
    });
    root.querySelectorAll("[data-log-act]").forEach((btn) => {
      btn.addEventListener("click", () => {
        logFilters.action = btn.dataset.logAct;
        logFilters.offset = 0;
        refreshLogs();
      });
    });
    root.querySelectorAll("[data-top-path-idx]").forEach((row) => {
      row.addEventListener("click", () => {
        const tp = topPaths[Number(row.dataset.topPathIdx)];
        if (!tp) return;
        logFilters.q = tp.path || "";
        if (tp.host) logFilters.host = tp.host;
        logFilters.offset = 0;
        refreshLogs();
      });
    });
    root.querySelectorAll("[data-log-idx]").forEach((row) => {
      row.addEventListener("click", () => {
        const r = items[Number(row.dataset.logIdx)];
        if (!r) return;
        const tsSec = Math.floor((Number(r.timestamp_ms) || 0) / 1000);
        const ipKey = r.raw_ip || r.ip_hmac || "";
        const modalActions = [];
        if (ipKey) {
          modalActions.push({
            label: t("logging.cross.filter_ip"),
            cls: "ghost",
            onClick: () => {
              logFilters.ip = ipKey;
              logFilters.offset = 0;
              refreshLogs();
            },
          });
          modalActions.push({
            label: t("logging.cross.view_visitor"),
            cls: "ghost",
            onClick: () => {
              loggingSubTab = "visitors";
              fpFilters = { ...defaultFpFilters(), ip: ipKey };
              refreshVisitors();
            },
          });
        }
        if (r.path) {
          modalActions.push({
            label: t("logging.cross.filter_path"),
            cls: "ghost",
            onClick: () => {
              logFilters.q = r.path;
              logFilters.offset = 0;
              refreshLogs();
            },
          });
        }
        modalActions.push({ label: t("common.close"), cls: "primary" });

        openModal({
          title: `${r.method || "HTTP"} ${r.path || "/"} (${r.status || 0})`,
          bodyHtml: `
            <div class="fp-detail-grid">
              <div class="fp-kv"><div class="fp-kv-lbl">Ray ID · Time</div><div class="fp-kv-val"><code>${esc(r.ray_id || "-")}</code><br/><span class="muted-sm">${esc(formatDateTime(tsSec))}</span></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Host · Scheme · Proto</div><div class="fp-kv-val"><strong>${esc(r.host || "-")}</strong><br/><span class="muted-sm">${esc(r.scheme || "-")} · ${esc(r.protocol || "-")}</span></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Path</div><div class="fp-kv-val"><code>${esc(r.path || "/")}</code></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Query (Redacted)</div><div class="fp-kv-val"><code>${esc(r.query || "-")}</code></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Action · Cache · Repeat</div><div class="fp-kv-val"><strong>${esc(r.action || "allow")}</strong> · cache: ${esc(r.cache_status || "-")} · count: ${Number(r.repeat_count) || 1}</div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">WAF / Suspicion</div><div class="fp-kv-val">rule: ${esc(r.waf_rule_id != null ? String(r.waf_rule_id) : "-")} · cat: ${esc(r.waf_category || "-")}<br/><span class="muted-sm">suspicion: ${esc(r.suspicion_score != null ? String(r.suspicion_score) : "-")} · JA3: ${esc(r.tls_ja3 || "-")}</span></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Client IP / HMAC</div><div class="fp-kv-val">${esc(r.raw_ip || "-")} ${r.client_country ? `<span class="pill info">${esc(r.client_country)}</span>` : ""}<br/><code>${esc(r.ip_hmac || "-")}</code></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Node · Service · Perf</div><div class="fp-kv-val">${esc(r.node_tag)} (${esc(r.role)}) → <code>${esc(r.service_tag)}</code><br/><span class="muted-sm">${(Number(r.latency_ms) || 0).toFixed(2)} ms · in ${formatBytes(r.bytes_in || 0)} · out ${formatBytes(r.bytes_out || 0)}</span></div></div>
            </div>
            <div style="margin-top:8px;"><strong>Referer:</strong> <code>${esc(r.referer || "-")}</code></div>
            <div class="fp-ua-box" style="margin-top:8px;">${esc(r.user_agent || "(empty User-Agent)")}</div>
            ${r.error ? `<div class="fp-ua-box" style="margin-top:8px;color:var(--err,#ff6b6b);">Error: ${esc(r.error)}</div>` : ""}
          `,
          actions: modalActions,
        });
      });
    });
  }

  async function refreshLogs() {
    const qs = new URLSearchParams();
    if (logFilters.q) qs.set("q", logFilters.q);
    if (logFilters.ip) qs.set("ip", logFilters.ip);
    if (logFilters.host) qs.set("host", logFilters.host);
    if (logFilters.node !== "all") qs.set("node", logFilters.node);
    if (logFilters.service !== "all") qs.set("service", logFilters.service);
    if (logFilters.role !== "all") qs.set("role", logFilters.role);
    if (logFilters.method !== "all") qs.set("method", logFilters.method);
    if (logFilters.status !== "all") qs.set("status", logFilters.status);
    if (logFilters.action !== "all") qs.set("action", logFilters.action);
    if (logFilters.country && logFilters.country !== "all") qs.set("country", logFilters.country);
    qs.set("offset", String(logFilters.offset || 0));
    qs.set("limit", String(logFilters.limit || 50));
    const winSec = logFilters.window_secs > 0 ? logFilters.window_secs : Number(el("sel-time-window")?.value || 0);
    if (winSec > 0) qs.set("window_secs", String(winSec));
    logData = await api(`/api/logs${qs.toString() ? `?${qs}` : ""}`);
    if (loggingSubTab === "access") renderLogs();
    return logData;
  }

  function renderVisitors() {
    const root = el("tab-logging");
    if (!root) return;
    const data = fpData || {};
    const sum = data.summary || {};
    const nodes = (data.available_nodes || []).slice().sort();
    const svcs = (data.available_services || []).slice().sort();
    const countries = (data.available_countries || []).slice().sort();
    const items = data.items || [];
    const totalMatched = Number(data.total_matched ?? items.length) || 0;

    root.innerHTML = `
      ${renderLoggingSubtabsBar()}
      <div class="kpi-grid">
        <div class="kpi"><div class="kpi-label">Matched Visitors</div><div class="kpi-val">${formatCompact(sum.total_visitors || 0)}</div><div class="kpi-sub">${formatCompact(sum.unique_ips || 0)} unique IPs</div></div>
        <div class="kpi"><div class="kpi-label">JS-Verified FPs</div><div class="kpi-val">${formatCompact(sum.js_verified || 0)}</div><div class="kpi-sub">${formatCompact(sum.beacon_count || 0)} beacon · ${formatCompact(sum.pow_count || 0)} PoW</div></div>
        <div class="kpi"><div class="kpi-label">Unique Browser FPs</div><div class="kpi-val">${formatCompact(sum.unique_fps || 0)}</div><div class="kpi-sub">Distinct signatures</div></div>
        <div class="kpi"><div class="kpi-label">Bots · Headless · WebRTC Leaks</div><div class="kpi-val">${sum.bots || 0} / ${sum.headless || 0} / ${sum.webrtc_leaks || 0}</div><div class="kpi-sub">${sum.webrtc_lan_leaks || 0} LAN IP exposed</div></div>
      </div>

      <div class="panel">
        <div class="fp-search-bar">
          <label><span>Universal Search</span><input id="fp-search-q" type="search" value="${esc(fpFilters.q)}" placeholder="Chrome, NVIDIA, example.com, IP, leaked IP, hash…" /></label>
          <label><span>IP / Prefix / HMAC / WebRTC</span><input id="fp-search-ip" type="search" value="${esc(fpFilters.ip)}" placeholder="203.0.113.5" /></label>
          <label><span>Browser FP / Canvas</span><input id="fp-search-fp" type="search" value="${esc(fpFilters.fp)}" placeholder="fp_hash" /></label>
          <div class="btn-row">
            <button type="button" id="btn-fp-search" class="btn primary">${esc(t("common.search"))}</button>
            <button type="button" id="btn-fp-clear" class="btn ghost">${esc(t("common.reset"))}</button>
            <button type="button" id="btn-fp-export" class="btn sm">${esc(t("logging.export_json"))}</button>
          </div>
        </div>
        <div class="fp-filter-row">
          <div class="fp-chip-group">
            ${["all", "js", "beacon", "pow", "ua"].map((v) => `<button type="button" class="fp-chip ${fpFilters.verified === v ? "active" : ""}" data-fp-ver="${v}">${v.toUpperCase()}</button>`).join("")}
          </div>
          <div class="fp-chip-group">
            ${["all", "clean", "suspicious", "headless", "bot", "webrtc_leak"].map((r) => `<button type="button" class="fp-chip ${fpFilters.risk === r ? "active" : ""}" data-fp-risk="${r}">${r.toUpperCase()}</button>`).join("")}
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
            <select id="fp-country-filter" class="select-sm">
              <option value="all">${esc(t("logs.all_countries"))}</option>
              ${countries.map((c) => `<option value="${esc(c)}" ${fpFilters.country === c ? "selected" : ""}>${esc(c)}</option>`).join("")}
            </select>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <h3>Visitor &amp; Fingerprint Directory (${totalMatched})</h3>
          <span class="muted-sm">Click any row for TLS, UA, WebRTC leak &amp; JS signals</span>
        </div>
        <div class="table-scroll">
          <table class="table">
            <thead><tr><th>IP / HMAC</th><th>Browser FP</th><th>Device · Browser · OS</th><th>JS &amp; WebRTC Signals</th><th>Host / Service</th><th>Risk &amp; Leaks</th><th>Traffic</th><th>Last Seen</th></tr></thead>
            <tbody>
              ${
                items
                  .map((obs, idx) => {
                    const ipPrimary = obs.client_ip || obs.ip_prefix || "-";
                    const srcBadge = obs.js_verified ? (obs.fp_source === "pow" ? `<span class="pill ok">PoW</span>` : `<span class="pill info">Beacon</span>`) : `<span class="pill">UA</span>`;
                    const js = obs.js_fp;
                    const jsParts = [];
                    if (js) {
                      if (js.screen) jsParts.push(js.screen);
                      if (js.canvas_hash) jsParts.push(`cv:${js.canvas_hash}`);
                      if (js.audio_hash) jsParts.push(`au:${js.audio_hash}`);
                      if (js.fonts_count) jsParts.push(`ft:${js.fonts_count}`);
                      if (js.webgl) jsParts.push(js.webgl.slice(0, 22));
                      if (js.webrtc_public_ips?.length) jsParts.push(`rtc:${js.webrtc_public_ips[0]}`);
                    }
                    const jsSum = jsParts.length ? jsParts.join(" · ") : "-";
                    const riskCls = obs.is_headless || obs.is_bot || obs.suspicion_score >= 60 ? "err" : obs.suspicion_score >= 30 ? "warn" : "ok";
                    const riskLbl = obs.is_headless ? "HEADLESS" : obs.is_bot ? "BOT" : `${t("fp.server_score")} ${Number(obs.suspicion_score) || 0}`;
                    const abuseBadge = obs.abuse_score != null
                      ? `<span class="pill ${obs.abuse_score >= 75 ? "err" : obs.abuse_score >= 25 ? "warn" : "ok"}">Abuse ${Number(obs.abuse_score)}${obs.abuse_country ? ` · ${esc(obs.abuse_country)}` : ""}${obs.abuse_is_tor ? " · TOR" : ""}</span>`
                      : "";
                    const webrtcBadge = js?.webrtc_ip_mismatch
                      ? `<span class="pill err">${esc(t("fp.webrtc.leak_badge"))}</span>`
                      : js?.webrtc_local_ips?.length
                        ? `<span class="pill warn">${esc(t("fp.webrtc.lan_badge"))}</span>`
                        : js?.webrtc_mdns
                          ? `<span class="pill info">${esc(t("fp.webrtc.mdns_badge"))}</span>`
                          : "";
                    const ja3Line = obs.tls_ja3
                      ? `<div class="muted-sm">JA3: <span class="fp-code">${esc(obs.tls_ja3.slice(0, 12))}</span>${obs.tls_grease ? " · GREASE" : ""}</div>`
                      : "";
                    const geoBadge = obs.geo_country
                      ? `<span class="pill info">${esc(obs.geo_country)}${obs.geo_continent ? ` · ${esc(obs.geo_continent)}` : ""}</span>`
                      : "";
                    return `
                  <tr class="fp-table-row" data-fp-idx="${idx}">
                    <td><div><strong>${esc(ipPrimary)}</strong> ${geoBadge}</div><div class="muted-sm"><span class="fp-code">${esc(obs.ip_hmac)}</span></div></td>
                    <td><div><span class="fp-code">${esc(obs.fp_hash)}</span> ${srcBadge}</div>${ja3Line}</td>
                    <td><div><strong>${esc(obs.browser_family || "-")}</strong> · ${esc(obs.os_family || "-")}</div><div class="muted-sm">${esc(obs.device_type || "-")}</div></td>
                    <td><span class="muted-sm">${esc(jsSum)}</span></td>
                    <td><div><code>${esc(obs.service_tag)}</code></div><div class="muted-sm">${esc(obs.node_tag)}</div></td>
                    <td><div style="display:flex;flex-wrap:wrap;gap:4px;"><span class="pill ${riskCls}">${esc(riskLbl)}</span>${abuseBadge}${webrtcBadge}</div></td>
                    <td><div><strong>${formatCompact(obs.request_count)}</strong></div><div class="muted-sm">${obs.challenge_count || 0} ch · ${obs.rate_limited_count || 0} 429</div></td>
                    <td>${esc(formatDateTime(obs.last_seen_ts))}</td>
                  </tr>`;
                  })
                  .join("") || `<tr><td colspan="8" class="muted">No visitor fingerprints match.</td></tr>`
              }
            </tbody>
          </table>
        </div>
        ${renderPaginationBar("fp", { total: totalMatched, offset: fpFilters.offset, limit: fpFilters.limit })}
      </div>
    `;

    wireLoggingSubtabs(root);
    wirePaginationBar("fp", fpFilters, totalMatched, refreshVisitors);
    const triggerSearch = () => {
      fpFilters.q = el("fp-search-q")?.value.trim() || "";
      fpFilters.ip = el("fp-search-ip")?.value.trim() || "";
      fpFilters.fp = el("fp-search-fp")?.value.trim() || "";
      fpFilters.offset = 0;
      refreshVisitors();
    };
    el("btn-fp-search")?.addEventListener("click", triggerSearch);
    el("btn-fp-clear")?.addEventListener("click", () => {
      fpFilters = defaultFpFilters();
      refreshVisitors();
    });
    el("btn-fp-export")?.addEventListener("click", () => {
      downloadJson("exposure-visitor-fingerprints.json", items);
    });
    ["fp-search-q", "fp-search-ip", "fp-search-fp"].forEach((id) => {
      el(id)?.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); triggerSearch(); } });
    });
    el("fp-node-filter")?.addEventListener("change", (ev) => { fpFilters.node = ev.target.value; fpFilters.offset = 0; refreshVisitors(); });
    el("fp-svc-filter")?.addEventListener("change", (ev) => { fpFilters.service = ev.target.value; fpFilters.offset = 0; refreshVisitors(); });
    el("fp-country-filter")?.addEventListener("change", (ev) => { fpFilters.country = ev.target.value; fpFilters.offset = 0; refreshVisitors(); });
    root.querySelectorAll("[data-fp-ver]").forEach((b) => b.addEventListener("click", () => { fpFilters.verified = b.dataset.fpVer; fpFilters.offset = 0; refreshVisitors(); }));
    root.querySelectorAll("[data-fp-risk]").forEach((b) => b.addEventListener("click", () => { fpFilters.risk = b.dataset.fpRisk; fpFilters.offset = 0; refreshVisitors(); }));
    root.querySelectorAll("[data-fp-idx]").forEach((tr) => {
      tr.addEventListener("click", () => {
        const obs = items[Number(tr.dataset.fpIdx)];
        if (!obs) return;
        const js = obs.js_fp;
        const abuseHtml = obs.abuse_score != null
          ? `<span class="pill ${obs.abuse_score >= 75 ? "err" : obs.abuse_score >= 25 ? "warn" : "ok"}">${Number(obs.abuse_score)}/100</span>
             ${esc(obs.abuse_country || "-")} · ${esc(obs.abuse_isp || "-")}${obs.abuse_is_tor ? ` <span class="pill warn">TOR</span>` : ""}`
          : `<span class="muted">—</span>`;
        const tamperHtml = js?.tamper_flags?.length
          ? js.tamper_flags.map((f) => `<span class="pill err">${esc(f)}</span>`).join(" ")
          : `<span class="pill ok">none</span>`;

        let webrtcHtml = "";
        if (js) {
          const pubList = (js.webrtc_public_ips || []).map((ip) => `<code>${esc(ip)}</code>`).join(", ") || "-";
          const locList = (js.webrtc_local_ips || []).map((ip) => `<code>${esc(ip)}</code>`).join(", ") || "-";
          const verdictPill = js.webrtc_ip_mismatch
            ? `<span class="pill err">${esc(t("fp.webrtc.leak_badge"))}</span>`
            : js.webrtc_local_ips?.length
              ? `<span class="pill warn">${esc(t("fp.webrtc.lan_badge"))}</span>`
              : `<span class="pill ok">${esc(t("fp.webrtc.clean"))}</span>`;
          webrtcHtml = `
            <div style="font-size:12px;font-weight:700;margin:12px 0 6px;color:var(--accent);">${esc(t("fp.webrtc.title"))}</div>
            <div class="fp-detail-grid">
              <div class="fp-kv"><div class="fp-kv-lbl">Verdict &amp; Status</div><div class="fp-kv-val">${verdictPill} <span class="muted-sm">(${esc(js.webrtc_status || "-")}${js.webrtc_mdns ? " · mDNS" : ""})</span></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Public / Local ICE IPs</div><div class="fp-kv-val">pub: ${pubList}<br/>lan: ${locList}</div></div>
            </div>`;
        }

        const ipKey = obs.client_ip || obs.ip_hmac || "";
        const modalActions = [];
        if (ipKey) {
          modalActions.push({
            label: t("logging.cross.view_logs"),
            cls: "ghost",
            onClick: () => {
              loggingSubTab = "access";
              logFilters = { ...defaultLogFilters(), ip: ipKey };
              refreshLogs();
            },
          });
        }
        modalActions.push({ label: t("common.close"), cls: "primary" });

        openModal({
          title: `Fingerprint — ${obs.fp_hash}`,
          bodyHtml: `
            <div style="font-size:12px;font-weight:700;margin-bottom:6px;color:var(--accent);">${esc(t("fp.sec.server"))}</div>
            <div class="fp-detail-grid">
              <div class="fp-kv"><div class="fp-kv-lbl">IP / GeoIP / HMAC</div><div class="fp-kv-val">${esc(obs.client_ip || obs.ip_prefix || "-")} ${obs.geo_country ? `<span class="pill info">${esc(obs.geo_country)}${obs.geo_continent ? ` · ${esc(obs.geo_continent)}` : ""}</span>` : ""}<br/><code>${esc(obs.ip_hmac)}</code></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Route / Host</div><div class="fp-kv-val"><code>${esc(obs.service_tag)}</code> @ ${esc(obs.node_tag)}<br/><span class="muted-sm">${esc(obs.host || "-")}</span></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">${esc(t("fp.server_score"))}</div><div class="fp-kv-val"><strong>${Number(obs.suspicion_score) || 0}/100</strong> · bot:${obs.is_bot ? "yes" : "no"} · headless:${obs.is_headless ? "yes" : "no"}</div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">${esc(t("fp.tls_ja3"))}</div><div class="fp-kv-val"><code>${esc(obs.tls_ja3 || "-")}</code><br/><span class="muted-sm">ciphers: ${Number(obs.tls_cipher_count) || 0} · GREASE: ${obs.tls_grease ? "yes" : "no"}</span></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">${esc(t("fp.abuse_intel"))}</div><div class="fp-kv-val">${abuseHtml}</div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Traffic</div><div class="fp-kv-val">${formatCompact(obs.request_count)} req · ${obs.challenge_count || 0} PoW · ${obs.rate_limited_count || 0} 429</div></div>
            </div>
            <div class="fp-ua-box" style="margin-top:8px;">${esc(obs.user_agent || "(empty)")}</div>
            ${webrtcHtml}
            ${
              js
                ? `
              <div style="font-size:12px;font-weight:700;margin:12px 0 6px;color:var(--text-muted);">${esc(t("fp.sec.client"))}</div>
              <div class="fp-detail-grid">
                <div class="fp-kv"><div class="fp-kv-lbl">Canvas / Audio / Fonts</div><div class="fp-kv-val">cv: <code>${esc(js.canvas_hash || "-")}</code> · au: <code>${esc(js.audio_hash || "-")}</code><br/>fonts: <code>${esc(js.fonts_hash || "-")}</code> (${Number(js.fonts_count) || 0} detected)</div></div>
                <div class="fp-kv"><div class="fp-kv-lbl">WebGL GPU &amp; Extensions</div><div class="fp-kv-val">${esc(js.webgl || "-")}<br/><span class="muted-sm">vendor: ${esc(js.webgl_vendor || "-")} · ext: <code>${esc(js.webgl_ext_hash || "-")}</code> · maxTex: ${Number(js.webgl_max_tex) || 0}</span></div></div>
                <div class="fp-kv"><div class="fp-kv-lbl">Screen &amp; Media Prefs</div><div class="fp-kv-val">${esc(js.screen || "-")} (avail ${esc(js.avail_screen || "-")}) · DPR ${esc(js.dpr || "1")}<br/><span class="muted-sm">${esc(js.media_prefs || "-")}</span></div></div>
                <div class="fp-kv"><div class="fp-kv-lbl">Timezone &amp; Locale</div><div class="fp-kv-val">${esc(js.tz || "-")} (UTC offset ${Number(js.tz_offset) || 0}m)<br/><span class="muted-sm">intl: ${esc(js.intl_locale || "-")} · langs: ${esc(js.languages || js.lang || "-")}</span></div></div>
                <div class="fp-kv"><div class="fp-kv-lbl">Hardware &amp; UA-CH</div><div class="fp-kv-val">${Number(js.cores) || 0} cores · ${Number(js.mem) || 0} GB · touch:${Number(js.touch) || 0} · plugins:${Number(js.plugins_count) || 0} · voices:${Number(js.speech_voices) || 0}<br/><span class="muted-sm">${esc(js.ua_brands || js.platform || "-")}</span></div></div>
                <div class="fp-kv"><div class="fp-kv-lbl">Storage &amp; APIs / ${esc(t("fp.tamper_flags"))}</div><div class="fp-kv-val"><code>${esc(js.storage_flags || "-")}</code><br/><div style="margin-top:4px;">${tamperHtml}</div></div></div>
              </div>`
                : ""
            }`,
          actions: modalActions,
        });
      });
    });
  }

  async function refreshVisitors() {
    const qs = new URLSearchParams();
    if (fpFilters.q) qs.set("q", fpFilters.q);
    if (fpFilters.ip) qs.set("ip", fpFilters.ip);
    if (fpFilters.fp) qs.set("fp", fpFilters.fp);
    if (fpFilters.node !== "all") qs.set("node", fpFilters.node);
    if (fpFilters.service !== "all") qs.set("service", fpFilters.service);
    if (fpFilters.country && fpFilters.country !== "all") qs.set("country", fpFilters.country);
    if (fpFilters.verified !== "all") qs.set("verified", fpFilters.verified);
    if (fpFilters.risk !== "all") qs.set("risk", fpFilters.risk);
    qs.set("offset", String(fpFilters.offset || 0));
    qs.set("limit", String(fpFilters.limit || 50));
    const winSec = Number(el("sel-time-window")?.value || 0);
    if (winSec > 0) qs.set("window_secs", String(winSec));
    fpData = await api(`/api/fingerprints${qs.toString() ? `?${qs}` : ""}`);
    if (loggingSubTab === "visitors") renderVisitors();
    return fpData;
  }

  function renderLogging() {
    if (loggingSubTab === "visitors") renderVisitors();
    else renderLogs();
  }

  async function refreshLogging(opts = {}) {
    if (opts?.subTab === "visitors" || opts?.subTab === "access") {
      loggingSubTab = opts.subTab;
    }
    if (opts?.service) {
      if (loggingSubTab === "visitors") { fpFilters.service = opts.service; fpFilters.offset = 0; }
      else { logFilters.service = opts.service; logFilters.offset = 0; }
    }
    if (opts?.ip) {
      if (loggingSubTab === "visitors") { fpFilters.ip = opts.ip; fpFilters.offset = 0; }
      else { logFilters.ip = opts.ip; logFilters.offset = 0; }
    }
    if (opts?.q) {
      if (loggingSubTab === "visitors") { fpFilters.q = opts.q; fpFilters.offset = 0; }
      else { logFilters.q = opts.q; logFilters.offset = 0; }
    }
    if (loggingSubTab === "visitors") return refreshVisitors();
    return refreshLogs();
  }

  return {
    refreshAnalytics,
    renderAnalytics: renderAnalyticsCharts,
    refreshLogging,
    renderLogging,
    refreshFingerprints: refreshVisitors,
    renderFingerprints: renderVisitors,
  };
}
