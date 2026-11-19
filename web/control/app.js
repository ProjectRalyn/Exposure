import { createTopoEditor } from "./topo_editor.js";
import {
  formatBytes,
  formatCompact,
  formatDateTime,
  formatMinute,
  formatUptime,
  renderAreaLineChart,
  renderBarList,
  renderDonutChart,
  renderGuardFunnel,
  renderMiniTopo,
} from "./charts.js";

const state = {
  token: localStorage.getItem("exposure_token") || "",
  activeTab: "overview",
  obsHeroMetric: "requests", // requests | uv | bandwidth | guard | latency
  autoRefreshMs: 30000,
  refreshTimer: null,
  cache: {
    overview: null,
    nodesData: null,
    telemetry: null,
    audit: null,
    versions: [],
  },
};

const el = (id) => document.getElementById(id);

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function showToast(msg, isError = false) {
  const stack = el("toast-stack");
  if (!stack) return;
  const item = document.createElement("div");
  item.className = `toast-item ${isError ? "error" : ""}`;
  item.textContent = msg;
  stack.appendChild(item);
  setTimeout(() => {
    item.style.opacity = "0";
    item.style.transition = "opacity 0.2s";
    setTimeout(() => item.remove(), 220);
  }, 4000);
}

function openModal({ title, bodyHtml, actions = [] }) {
  el("modal-title").textContent = title;
  el("modal-body").innerHTML = bodyHtml;
  const foot = el("modal-footer");
  foot.innerHTML = "";
  for (const act of actions) {
    const btn = document.createElement("button");
    btn.className = `btn ${act.cls || ""}`;
    btn.textContent = act.label;
    btn.addEventListener("click", () => {
      if (act.onClick) act.onClick();
      if (act.close !== false) closeModal();
    });
    foot.appendChild(btn);
  }
  el("modal-backdrop").classList.remove("hidden");
}

function closeModal() {
  el("modal-backdrop").classList.add("hidden");
}

el("btn-modal-close")?.addEventListener("click", closeModal);
el("modal-backdrop")?.addEventListener("click", (ev) => {
  if (ev.target === el("modal-backdrop")) closeModal();
});

async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (state.token) headers["Authorization"] = `Bearer ${state.token}`;
  const resp = await fetch(path, { ...opts, headers });
  if (resp.status === 401) {
    logout();
    throw new Error("Session expired");
  }
  const text = await resp.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!resp.ok) {
    throw new Error((data && data.error) || text || `HTTP ${resp.status}`);
  }
  return data;
}

function logout() {
  state.token = "";
  localStorage.removeItem("exposure_token");
  stopAutoRefresh();
  el("app-view").classList.add("hidden");
  el("login-view").classList.remove("hidden");
}

function updateBootstrapBadge(bootTag) {
  const card = el("sidebar-bootstrap-status");
  if (!card) return;
  const connected = Boolean(bootTag);
  card.innerHTML = `
    <span class="live-dot ${connected ? "online" : "offline"}"></span>
    <div class="bootstrap-card-text">
      <div class="bootstrap-card-lbl">Bootstrap Link</div>
      <div class="bootstrap-card-val">${connected ? esc(bootTag) : "Disconnected"}</div>
    </div>`;
}

function updateTopbarTimestamp(iso) {
  const t = el("topbar-updated");
  if (!t) return;
  t.textContent = iso ? `Telemetry pulled: ${formatDateTime(iso)}` : `Updated ${formatDateTime(new Date().toISOString())}`;
}

function switchTab(tab, opts = {}) {
  state.activeTab = tab;
  document.querySelectorAll(".nav-item").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tab);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("hidden", p.id !== `tab-${tab}`);
  });
  const activeBtn = document.querySelector(`.nav-item[data-tab="${tab}"]`);
  el("page-title").textContent = activeBtn ? activeBtn.textContent : tab;
  refreshCurrentTab(opts);
}

function openNodeInTopology(nodeTag) {
  switchTab("topology", { focusNode: nodeTag });
}

/* ==================== OVERVIEW ==================== */

async function refreshOverview() {
  const winSec = Number(el("sel-time-window")?.value ?? 3600);
  const ov = await api(`/api/overview?window_secs=${winSec}`);
  state.cache.overview = ov;

  el("control-role-badge").textContent = (ov.role || "active").toUpperCase();
  updateBootstrapBadge(ov.bootstrap_node);
  updateTopbarTimestamp(ov.last_pulled_at);

  const tr = ov.traffic || {};
  const totalReq = Number(tr.total_requests) || 0;
  const totalErr = Number(tr.total_errors) || 0;
  const errPct = totalReq > 0 ? ((totalErr / totalReq) * 100).toFixed(2) : "0.00";

  el("kpi-nodes").textContent = `${ov.online_nodes ?? 0} / ${ov.node_count ?? 0}`;
  el("kpi-nodes-sub").textContent = `${ov.online_nodes ?? 0} online · ${(ov.node_count ?? 0) - (ov.online_nodes ?? 0)} offline`;

  el("kpi-links").textContent = `${ov.links_up ?? 0} / ${ov.links_degraded ?? 0} / ${ov.links_down ?? 0}`;
  el("kpi-links-sub").textContent = "UP / DEGRADED / DOWN";

  el("kpi-requests").textContent = formatCompact(totalReq);
  el("kpi-requests-sub").textContent = `${errPct}% error · ${formatCompact(tr.total_rate_limited || 0)} rate-limited`;

  el("kpi-uv").textContent = formatCompact(tr.uv_estimate || 0);
  el("kpi-uv-sub").textContent = `${formatBytes(tr.total_bytes_in || 0)} in · ${formatBytes(tr.total_bytes_out || 0)} out`;

  el("kpi-latency").textContent = `${(tr.p50_ms || 0).toFixed(1)} / ${(tr.p95_ms || 0).toFixed(1)} ms`;
  el("kpi-latency-sub").textContent = `p99: ${(tr.p99_ms || 0).toFixed(1)} ms`;

  const cs = ov.certificates_summary || {};
  el("kpi-certs").textContent = `#${ov.latest_sequence ?? 0}`;
  el("kpi-certs-sub").textContent = `${cs.valid ?? 0}/${cs.total ?? 0} valid certs · ${(ov.alerts || []).length} alerts`;

  // Traffic & Protection Trend Chart
  const ts = ov.timeseries || [];
  const labels = ts.map((b) => formatMinute(b.minute_epoch));
  renderAreaLineChart(el("ov-traffic-chart"), {
    labels,
    series: [
      { name: "Requests", color: "#4DA9D6", values: ts.map((b) => b.requests), area: true },
      { name: "Challenged", color: "#6A5ACD", values: ts.map((b) => b.challenges_issued) },
      { name: "Rate-Limited", color: "#FAC800", values: ts.map((b) => b.rate_limited) },
      { name: "Errors", color: "#C40233", values: ts.map((b) => b.errors) },
    ],
    emptyText: "No traffic telemetry yet — click Pull Telemetry to fetch from Maintainer",
  });

  // Latency Percentiles Chart
  renderAreaLineChart(el("ov-latency-chart"), {
    labels,
    unit: "ms",
    series: [
      { name: "p99", color: "#C40233", values: ts.map((b) => b.p99_ms), dashed: true },
      { name: "p95", color: "#FAC800", values: ts.map((b) => b.p95_ms) },
      { name: "p50", color: "#009F6B", values: ts.map((b) => b.p50_ms), area: true },
    ],
    emptyText: "No latency histogram buckets yet",
  });

  // Live Mesh Health Mini-Map
  renderMiniTopo(el("ov-mini-topo"), {
    spec: ov.spec,
    liveNodes: ov.nodes || [],
    liveLinks: ov.links || [],
    onNodeClick: (tag) => openNodeInTopology(tag),
  });

  // Link Status Donut
  const totalLinks = (ov.links_up || 0) + (ov.links_degraded || 0) + (ov.links_down || 0);
  renderDonutChart(el("ov-link-donut"), {
    centerValue: String(totalLinks),
    centerLabel: "Links",
    slices: [
      { label: "UP", value: ov.links_up || 0, color: "#009F6B" },
      { label: "DEGRADED", value: ov.links_degraded || 0, color: "#FAC800" },
      { label: "DOWN", value: ov.links_down || 0, color: "#C40233" },
    ],
  });

  // Top Services Bar Chart
  renderBarList(el("ov-top-services"), ov.service_breakdown || []);

  // Maintainer Health Strip
  renderMaintainerStrip(el("ov-maintainer-strip"), ov.maintainers || []);

  // Alerts table
  renderOverviewAlerts();
}

function renderMaintainerStrip(container, maintainers) {
  if (!container) return;
  if (!maintainers || !maintainers.length) {
    container.classList.add("hidden");
    container.innerHTML = "";
    return;
  }
  container.classList.remove("hidden");
  container.innerHTML = maintainers
    .map(
      (m) =>
        `<span class="maint-chip">Maintainer <b>${esc(m.maintainer_tag)}</b> · backlog <b>${m.segment_backlog}</b> · merge <b>${(m.merge_latency_ms || 0).toFixed(2)}ms</b></span>`
    )
    .join("");
}

function renderOverviewAlerts() {
  const ov = state.cache.overview;
  if (!ov) return;
  const sev = el("ov-alert-filter")?.value || "all";
  const rows = (ov.alerts || []).filter((a) => sev === "all" || a.severity === sev);
  el("alerts-tbody").innerHTML =
    rows
      .slice()
      .reverse()
      .slice(0, 50)
      .map(
        (a) => `
      <tr>
        <td>${esc(formatDateTime(a.timestamp))}</td>
        <td><code>${esc(a.source)}</code></td>
        <td><span class="pill ${a.severity === "error" ? "err" : "warn"}">${esc(a.severity)}</span></td>
        <td>${esc(a.message)}</td>
      </tr>`
      )
      .join("") || `<tr><td colspan="4" class="muted">No active alerts</td></tr>`;
}

el("ov-alert-filter")?.addEventListener("change", renderOverviewAlerts);

/* ==================== NODES & LINKS ==================== */

async function refreshNodes() {
  const data = await api("/api/nodes");
  state.cache.nodesData = data;
  updateBootstrapBadge(data.bootstrap_node);
  updateTopbarTimestamp(data.last_pulled_at);
  topoEditor.setLiveState(data.nodes || [], data.links || []);
  renderNodesTable();
  renderLinksTable();
}

function renderNodesTable() {
  const data = state.cache.nodesData;
  if (!data) return;
  const q = (el("nodes-search")?.value || "").trim().toLowerCase();
  const roleF = el("nodes-role-filter")?.value || "all";

  const nodes = (data.nodes || []).filter((n) => {
    if (q && !n.node_tag.toLowerCase().includes(q)) return false;
    if (roleF !== "all" && !(n.roles || []).includes(roleF)) return false;
    return true;
  });

  el("nodes-tbody").innerHTML =
    nodes
      .map((n) => {
        const rolePills = (n.roles || [])
          .map((r) => `<span class="role-chip ${esc(r)}">${esc(r)}</span>`)
          .join(" ");
        return `
      <tr>
        <td><strong>${esc(n.node_tag)}</strong></td>
        <td>${rolePills || '<span class="muted">-</span>'}</td>
        <td><code>${esc((n.pubkey_fingerprint || "").slice(0, 16) || "-")}</code></td>
        <td>${esc(formatUptime(n.uptime_secs))}</td>
        <td>#${esc(n.config_seq)}</td>
        <td>${esc(n.last_reload_status || "-")}</td>
        <td><span class="pill ${n.online ? "ok" : "err"}">${n.online ? "ONLINE" : "OFFLINE"}</span></td>
        <td>
          <div class="btn-row">
            <button class="btn sm" data-edit-node="${esc(n.node_tag)}">Inspect</button>
            <button class="btn sm primary" data-push-node="${esc(n.node_tag)}">Push Config</button>
          </div>
        </td>
      </tr>`;
      })
      .join("") || `<tr><td colspan="8" class="muted">No matching nodes</td></tr>`;

  el("nodes-tbody").querySelectorAll("[data-edit-node]").forEach((btn) => {
    btn.addEventListener("click", () => openNodeInTopology(btn.dataset.editNode));
  });
  el("nodes-tbody").querySelectorAll("[data-push-node]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/nodes/${encodeURIComponent(btn.dataset.pushNode)}/push`, { method: "POST" });
        showToast(`Pushed signed config to ${btn.dataset.pushNode}`);
        refreshNodes();
      } catch (e) { showToast(e.message, true); }
    });
  });
}

function renderLinksTable() {
  const data = state.cache.nodesData;
  if (!data) return;
  const q = (el("links-search")?.value || "").trim().toLowerCase();
  const stF = el("links-state-filter")?.value || "all";

  const links = (data.links || []).filter((l) => {
    if (stF !== "all" && l.state !== stF) return false;
    if (q && !`${l.node_tag} ${l.peer_tag} ${l.endpoint}`.toLowerCase().includes(q)) return false;
    return true;
  });

  el("links-tbody").innerHTML =
    links
      .map((l) => {
        const cls = l.state === "UP" ? "ok" : l.state === "DEGRADED" ? "warn" : "err";
        const rtt = l.rtt_ms != null ? Number(l.rtt_ms) : null;
        const rttPct = rtt != null ? Math.min(100, Math.round((rtt / 300) * 100)) : 0;
        const rttColor = rtt == null ? "#64748b" : rtt < 80 ? "#009F6B" : rtt < 200 ? "#FAC800" : "#C40233";
        const lossPct = Math.min(100, (l.loss_rate || 0) * 100);
        const lossColor = lossPct < 1 ? "#009F6B" : lossPct < 5 ? "#FAC800" : "#C40233";
        return `
      <tr>
        <td><strong>${esc(l.node_tag)}</strong></td>
        <td>${esc(l.peer_tag)}</td>
        <td><code>${esc(l.endpoint)}</code></td>
        <td><span class="pill ${cls}">${esc(l.state)}</span></td>
        <td>
          <div class="meter-cell">
            <div class="meter-bar"><div class="meter-fill" style="width:${rttPct}%;background:${rttColor}"></div></div>
            <span>${rtt != null ? `${rtt} ms` : "-"}</span>
          </div>
        </td>
        <td>
          <div class="meter-cell">
            <div class="meter-bar"><div class="meter-fill" style="width:${lossPct.toFixed(0)}%;background:${lossColor}"></div></div>
            <span>${lossPct.toFixed(1)}%</span>
          </div>
        </td>
      </tr>`;
      })
      .join("") || `<tr><td colspan="6" class="muted">No link telemetry yet</td></tr>`;
}

el("nodes-search")?.addEventListener("input", renderNodesTable);
el("nodes-role-filter")?.addEventListener("change", renderNodesTable);
el("links-search")?.addEventListener("input", renderLinksTable);
el("links-state-filter")?.addEventListener("change", renderLinksTable);

/* ==================== TOPOLOGY STUDIO ==================== */

const topoEditor = createTopoEditor({ api, showToast, el });

async function refreshTopology(opts = {}) {
  const topo = await api("/api/topology");
  if (!el("topology-editor").value || document.activeElement !== el("topology-editor")) {
    topoEditor.setFromServer(
      topo.yaml || "",
      topo.spec || { nodes: {}, links: [] },
      {
        paths: topo.paths || [],
        errors: topo.errors || [],
        warnings: topo.warnings || [],
        live_nodes: topo.live_nodes || [],
        live_links: topo.live_links || [],
      },
      Boolean(opts.force)
    );
  }
  if (opts.focusNode) {
    topoEditor.focusNode(opts.focusNode);
  }

  const versions = await api("/api/config-versions");
  state.cache.versions = versions.versions || [];
  el("versions-tbody").innerHTML =
    state.cache.versions
      .map(
        (v) => `
    <tr>
      <td><strong>#${esc(v.sequence)}</strong></td>
      <td>${esc(v.node_tag)}</td>
      <td>${esc(formatDateTime(v.created_at))}</td>
      <td><span class="pill ${v.status === "applied" ? "ok" : v.status === "failed" ? "err" : "warn"}">${esc(v.status)}</span></td>
      <td>
        <div class="btn-row">
          <button class="btn sm" data-preview-ver="${esc(v.id)}">Preview</button>
          <button class="btn sm danger" data-rollback="${esc(v.id)}">Rollback</button>
        </div>
      </td>
    </tr>`
      )
      .join("") || `<tr><td colspan="5" class="muted">No config history</td></tr>`;

  el("versions-tbody").querySelectorAll("[data-preview-ver]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const rec = state.cache.versions.find((v) => String(v.id) === btn.dataset.previewVer);
      if (!rec) return;
      let pretty = rec.config_json;
      try { pretty = JSON.stringify(JSON.parse(rec.config_json), null, 2); } catch {}
      openModal({
        title: `Config Snapshot #${rec.sequence} — ${rec.node_tag}`,
        bodyHtml: `<pre class="output-box" style="max-height:55vh;">${esc(pretty)}</pre>`,
        actions: [{ label: "Close" }],
      });
    });
  });

  el("versions-tbody").querySelectorAll("[data-rollback]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const rec = state.cache.versions.find((v) => String(v.id) === btn.dataset.rollback);
      if (!rec) return;
      openModal({
        title: `Confirm Rollback — ${rec.node_tag}`,
        bodyHtml: `<p>Push historical snapshot <b>#${rec.sequence}</b> (created ${esc(formatDateTime(rec.created_at))}) as a new signed revision to <code>${esc(rec.node_tag)}</code>?</p>`,
        actions: [
          { label: "Cancel", cls: "ghost" },
          {
            label: "Confirm Rollback",
            cls: "danger",
            onClick: async () => {
              try {
                await api(`/api/config-versions/${encodeURIComponent(rec.id)}/rollback`, { method: "POST" });
                showToast(`Rollback pushed to ${rec.node_tag}`);
                refreshTopology();
              } catch (e) { showToast(e.message, true); }
            },
          },
        ],
      });
    });
  });
}

async function validateTopologyNow() {
  try {
    const res = await api("/api/topology/validate", {
      method: "POST",
      body: JSON.stringify(topoEditor.getPayload(false)),
    });
    topoEditor.setValidationResult({
      errors: res.errors || [],
      warnings: res.warnings || [],
      paths: res.paths || [],
    });
    if (res.yaml) el("topology-editor").value = res.yaml;
    showToast(
      res.valid
        ? `Topology valid (${(res.paths || []).length} service route(s) verified)`
        : `Validation failed: ${(res.errors || []).length} error(s)`,
      !res.valid
    );
  } catch (e) {
    showToast(e.message, true);
  }
}

async function saveTopologyNow(push) {
  try {
    const res = await api("/api/topology", {
      method: "PUT",
      body: JSON.stringify(topoEditor.getPayload(push)),
    });
    topoEditor.setFromServer(
      res.yaml,
      res.spec,
      { paths: res.paths || [], errors: [], warnings: res.warnings || [] },
      true
    );
    if (push) {
      const errs = res.push_errors || [];
      if (errs.length) {
        showToast(`Saved & pushed ${res.pushed_count ?? 0} nodes (${errs.length} push errors)`, true);
        topoEditor.setValidationResult({ errors: errs, warnings: res.warnings || [], paths: res.paths || [] });
      } else {
        showToast(`Saved topology & pushed to ${res.pushed_count ?? 0} node(s)`);
      }
    } else {
      showToast("Topology draft saved to Control SQLite");
    }
    refreshTopology();
  } catch (e) {
    showToast(e.message, true);
  }
}

el("btn-validate-topo")?.addEventListener("click", validateTopologyNow);

el("btn-preflight-topo")?.addEventListener("click", async () => {
  try {
    showToast("Running node preflight connectivity checks…");
    const res = await api("/api/topology/preflight", {
      method: "POST",
      body: JSON.stringify(topoEditor.getPayload(false)),
    });
    const fails = [];
    const rowsHtml = (res.reports || [])
      .map((rep) => {
        const items = (rep.checks || [])
          .map((c) => {
            if (!c.ok) fails.push(`${rep.node_tag} [${c.target}]: ${c.detail}`);
            return `<tr>
              <td><code>${esc(rep.node_tag)}</code></td>
              <td><code>${esc(c.target)}</code></td>
              <td><span class="pill ${c.ok ? "ok" : "err"}">${c.ok ? "PASS" : "FAIL"}</span></td>
              <td>${esc(c.detail)}</td>
            </tr>`;
          })
          .join("");
        return items || `<tr><td><code>${esc(rep.node_tag)}</code></td><td>-</td><td><span class="pill ok">PASS</span></td><td>No checks</td></tr>`;
      })
      .join("");

    const bar = el("topo-validation-bar");
    if (bar) {
      bar.classList.remove("hidden", "ok", "err");
      if (res.all_ok) {
        bar.classList.add("ok");
        bar.textContent = `Preflight passed on ${(res.reports || []).length} node(s).`;
      } else {
        bar.classList.add("err");
        bar.textContent = `Preflight issues: ${fails.join(" | ")}`;
      }
    }

    openModal({
      title: res.all_ok ? "Preflight Report — All Checks Passed" : "Preflight Report — Issues Found",
      bodyHtml: `<div class="table-wrap"><table class="table">
        <thead><tr><th>Node</th><th>Target</th><th>Result</th><th>Detail</th></tr></thead>
        <tbody>${rowsHtml}</tbody>
      </table></div>`,
      actions: [{ label: "Close" }],
    });

    showToast(
      res.all_ok
        ? `Preflight OK (${(res.reports || []).length} nodes)`
        : "Preflight found connectivity/port issues",
      !res.all_ok
    );
  } catch (e) {
    showToast(e.message, true);
  }
});
el("btn-save-draft")?.addEventListener("click", () => saveTopologyNow(false));
el("btn-save-topo")?.addEventListener("click", () => saveTopologyNow(true));

/* ==================== ANALYTICS & CERTS ==================== */

async function refreshObservability() {
  const data = await api("/api/telemetry");
  state.cache.telemetry = data;
  updateTopbarTimestamp(data.last_pulled_at);

  const sums = data.summaries || [];
  const nodeSel = el("obs-node-filter");
  const svcSel = el("obs-svc-filter");
  const prevNode = nodeSel.value || "all";
  const prevSvc = svcSel.value || "all";

  const nodes = [...new Set(sums.map((s) => s.node_tag))].sort();
  const svcs = [...new Set(sums.map((s) => s.service_tag))].sort();

  nodeSel.innerHTML =
    `<option value="all">All Nodes (${nodes.length})</option>` +
    nodes.map((n) => `<option value="${esc(n)}" ${prevNode === n ? "selected" : ""}>${esc(n)}</option>`).join("");
  svcSel.innerHTML =
    `<option value="all">All Services (${svcs.length})</option>` +
    svcs.map((s) => `<option value="${esc(s)}" ${prevSvc === s ? "selected" : ""}>${esc(s)}</option>`).join("");

  renderMaintainerStrip(el("obs-maint-strip"), data.maintainers || []);
  renderObservabilityCharts();
  renderCertificatesCards(data.certificates || []);
}

function renderObservabilityCharts() {
  const data = state.cache.telemetry;
  if (!data) return;
  const nodeF = el("obs-node-filter")?.value || "all";
  const svcF = el("obs-svc-filter")?.value || "all";
  const winSec = Number(el("obs-window-filter")?.value || 0);
  const cutoff = winSec > 0 ? Math.floor(Date.now() / 1000) - winSec : 0;

  const filtered = (data.summaries || []).filter((s) => {
    if (nodeF !== "all" && s.node_tag !== nodeF) return false;
    if (svcF !== "all" && s.service_tag !== svcF) return false;
    if (cutoff > 0 && s.minute_epoch < cutoff) return false;
    return true;
  });

  // Group by minute, service, and node
  const byMin = new Map();
  const bySvc = new Map();
  const byNode = new Map();
  const agg = {
    total_requests: 0,
    total_uv: 0,
    total_errors: 0,
    total_rate_limited: 0,
    total_challenges_issued: 0,
    total_challenges_passed: 0,
    total_bytes_in: 0,
    total_bytes_out: 0,
    p50_sum: 0,
    p95_sum: 0,
    p99_sum: 0,
    n: 0,
  };

  for (const s of filtered) {
    agg.total_requests += s.requests || 0;
    agg.total_uv += s.uv_estimate || 0;
    agg.total_errors += s.errors || 0;
    agg.total_rate_limited += s.rate_limited || 0;
    agg.total_challenges_issued += s.challenges_issued || 0;
    agg.total_challenges_passed += s.challenges_passed || 0;
    agg.total_bytes_in += s.bytes_in || 0;
    agg.total_bytes_out += s.bytes_out || 0;
    agg.p50_sum += s.p50_ms || 0;
    agg.p95_sum += s.p95_ms || 0;
    agg.p99_sum += s.p99_ms || 0;
    agg.n += 1;

    let b = byMin.get(s.minute_epoch);
    if (!b) {
      b = {
        minute_epoch: s.minute_epoch,
        requests: 0, uv: 0, errors: 0, rl: 0, ch_i: 0, ch_p: 0, bytes_in: 0, bytes_out: 0,
        p50: 0, p95: 0, p99: 0, n: 0,
      };
      byMin.set(s.minute_epoch, b);
    }
    b.requests += s.requests || 0;
    b.uv += s.uv_estimate || 0;
    b.errors += s.errors || 0;
    b.rl += s.rate_limited || 0;
    b.ch_i += s.challenges_issued || 0;
    b.ch_p += s.challenges_passed || 0;
    b.bytes_in += s.bytes_in || 0;
    b.bytes_out += s.bytes_out || 0;
    b.p50 += s.p50_ms || 0;
    b.p95 += s.p95_ms || 0;
    b.p99 += s.p99_ms || 0;
    b.n += 1;

    const accumGroup = (map, key, field) => {
      let g = map.get(key);
      if (!g) {
        g = { [field]: key, requests: 0, errors: 0, p95_sum: 0, n: 0 };
        map.set(key, g);
      }
      g.requests += s.requests || 0;
      g.errors += s.errors || 0;
      g.p95_sum += s.p95_ms || 0;
      g.n += 1;
    };
    accumGroup(bySvc, s.service_tag, "service_tag");
    accumGroup(byNode, s.node_tag, "node_tag");
  }

  // Update Cloudflare Hero Metric Tabs
  const errPct = agg.total_requests > 0 ? ((agg.total_errors / agg.total_requests) * 100).toFixed(2) : "0.00";
  const avgP50 = agg.n ? agg.p50_sum / agg.n : 0;
  const avgP95 = agg.n ? agg.p95_sum / agg.n : 0;
  const avgP99 = agg.n ? agg.p99_sum / agg.n : 0;
  const totalBytes = agg.total_bytes_in + agg.total_bytes_out;
  const totalGuard = agg.total_challenges_issued + agg.total_rate_limited;

  if (el("cf-val-requests")) {
    el("cf-val-requests").textContent = formatCompact(agg.total_requests);
    el("cf-sub-requests").textContent = `${errPct}% errors · ${formatCompact(agg.total_errors)} 5xx`;
    el("cf-val-uv").textContent = formatCompact(agg.total_uv);
    el("cf-sub-uv").textContent =
      agg.total_uv > 0 ? `${(agg.total_requests / agg.total_uv).toFixed(1)} req / visitor` : "HyperLogLog union";
    el("cf-val-bandwidth").textContent = formatBytes(totalBytes);
    el("cf-sub-bandwidth").textContent = `${formatBytes(agg.total_bytes_in)} in · ${formatBytes(agg.total_bytes_out)} out`;
    el("cf-val-guard").textContent = formatCompact(totalGuard);
    el("cf-sub-guard").textContent = `${formatCompact(agg.total_challenges_issued)} PoW · ${formatCompact(agg.total_rate_limited)} 429`;
    el("cf-val-latency").textContent = `${avgP95.toFixed(1)} ms`;
    el("cf-sub-latency").textContent = `p50 ${avgP50.toFixed(1)}ms · p99 ${avgP99.toFixed(1)}ms`;
  }

  // Render full-width Cloudflare Hero Chart for active metric tab
  const pts = [...byMin.values()].sort((a, b) => a.minute_epoch - b.minute_epoch);
  const labels = pts.map((p) => formatMinute(p.minute_epoch));

  const heroConfigs = {
    requests: {
      unit: "",
      series: [
        { name: "Total Requests", color: "#4DA9D6", values: pts.map((p) => p.requests), area: true },
        { name: "Rate-Limited (429)", color: "#FAC800", values: pts.map((p) => p.rl) },
        { name: "Errors (5xx)", color: "#C40233", values: pts.map((p) => p.errors) },
      ],
    },
    uv: {
      unit: "",
      series: [
        { name: "Unique Visitors (HLL)", color: "#009F6B", values: pts.map((p) => Math.round(p.uv)), area: true },
        { name: "Requests", color: "#4DA9D6", values: pts.map((p) => p.requests), dashed: true },
      ],
    },
    bandwidth: {
      unit: "bytes",
      series: [
        { name: "Bytes Out (Served)", color: "#4DA9D6", values: pts.map((p) => p.bytes_out), area: true },
        { name: "Bytes In (Upload)", color: "#6A5ACD", values: pts.map((p) => p.bytes_in), area: true },
      ],
    },
    guard: {
      unit: "",
      series: [
        { name: "PoW Challenged", color: "#6A5ACD", values: pts.map((p) => p.ch_i), area: true },
        { name: "PoW Cleared", color: "#009F6B", values: pts.map((p) => p.ch_p) },
        { name: "Rate-Limited (429)", color: "#FAC800", values: pts.map((p) => p.rl) },
      ],
    },
    latency: {
      unit: "ms",
      series: [
        { name: "p99", color: "#C40233", values: pts.map((p) => p.p99 / p.n), dashed: true },
        { name: "p95", color: "#FAC800", values: pts.map((p) => p.p95 / p.n) },
        { name: "p50", color: "#009F6B", values: pts.map((p) => p.p50 / p.n), area: true },
      ],
    },
  };

  const activeCfg = heroConfigs[state.obsHeroMetric] || heroConfigs.requests;
  renderAreaLineChart(el("obs-hero-chart"), {
    labels,
    height: 265,
    unit: activeCfg.unit,
    series: activeCfg.series,
    emptyText: "No traffic telemetry pulled yet — click Pull Telemetry in topbar",
  });

  // Service & Node breakdown bar charts
  const svcList = [...bySvc.values()]
    .map((g) => ({ ...g, p95_ms: g.n ? g.p95_sum / g.n : 0 }))
    .sort((a, b) => b.requests - a.requests);
  const nodeList = [...byNode.values()]
    .map((g) => ({ ...g, p95_ms: g.n ? g.p95_sum / g.n : 0 }))
    .sort((a, b) => b.requests - a.requests);

  renderBarList(el("obs-service-bars"), svcList, "No service traffic in selected window");
  renderBarList(el("obs-node-bars"), nodeList, "No node traffic in selected window");
  renderGuardFunnel(el("obs-guard-funnel"), agg);

  const cleanReqs = Math.max(0, agg.total_requests - agg.total_errors - agg.total_rate_limited - agg.total_challenges_issued);
  renderDonutChart(el("obs-outcome-donut"), {
    centerValue: formatCompact(agg.total_requests),
    centerLabel: "Requests",
    slices: [
      { label: "Clean / Passed", value: cleanReqs + agg.total_challenges_passed, color: "#009F6B" },
      { label: "PoW Challenged", value: Math.max(0, agg.total_challenges_issued - agg.total_challenges_passed), color: "#6A5ACD" },
      { label: "Rate-Limited (429)", value: agg.total_rate_limited, color: "#FAC800" },
      { label: "Errors (5xx)", value: agg.total_errors, color: "#C40233" },
    ],
  });

  // Client Fingerprint Breakdown (Devices / Browsers / OS)
  const devMap = new Map();
  const brwMap = new Map();
  const osMap = new Map();
  let fpVerified = 0;
  for (const s of filtered) {
    fpVerified += s.client_fp_verified || 0;
    for (const [k, v] of Object.entries(s.device_counts || {})) devMap.set(k, (devMap.get(k) || 0) + v);
    for (const [k, v] of Object.entries(s.browser_counts || {})) brwMap.set(k, (brwMap.get(k) || 0) + v);
    for (const [k, v] of Object.entries(s.os_counts || {})) osMap.set(k, (osMap.get(k) || 0) + v);
  }
  const fpBadge = el("obs-fp-verified-badge");
  if (fpBadge) fpBadge.textContent = `${formatCompact(fpVerified)} JS-verified FP`;
  const fpBox = el("obs-fp-breakdown");
  if (fpBox) {
    const renderFpCol = (title, map, color) => {
      const entries = [...map.entries()].sort((a, b) => b[1] - a[1]);
      const maxVal = entries[0]?.[1] || 1;
      const tot = entries.reduce((a, [, v]) => a + v, 0) || 1;
      return `<div>
        <div class="muted-sm" style="margin-bottom:8px;font-weight:700;text-transform:uppercase;">${esc(title)}</div>
        ${entries.length
          ? entries
              .map(([k, v]) => `<div class="bar-item" style="margin-bottom:6px;">
                  <div class="bar-head"><span>${esc(k)}</span><span>${formatCompact(v)} (${((v / tot) * 100).toFixed(0)}%)</span></div>
                  <div class="bar-track"><div class="bar-fill" style="width:${((v / maxVal) * 100).toFixed(1)}%;background:${color};"></div></div>
                </div>`)
              .join("")
          : '<div class="muted-sm">No data yet</div>'}
      </div>`;
    };
    fpBox.innerHTML =
      renderFpCol("Devices", devMap, "#4DA9D6") +
      renderFpCol("Browsers", brwMap, "#009F6B") +
      renderFpCol("Operating Systems", osMap, "#6A5ACD");
  }

  // Raw detail table (collapsed by default inside <details>)
  el("stats-tbody").innerHTML =
    filtered
      .slice()
      .reverse()
      .map(
        (s) => `
      <tr>
        <td>${esc(formatDateTime(s.minute_epoch))}</td>
        <td>${esc(s.node_tag)}</td>
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
      .join("") || `<tr><td colspan="10" class="muted">No aggregated summaries match current filter</td></tr>`;
}

document.querySelectorAll("[data-cf-metric]").forEach((btn) => {
  btn.addEventListener("click", () => {
    state.obsHeroMetric = btn.dataset.cfMetric;
    document.querySelectorAll("[data-cf-metric]").forEach((b) => {
      b.classList.toggle("active", b.dataset.cfMetric === state.obsHeroMetric);
    });
    renderObservabilityCharts();
  });
});

function renderCertificatesCards(certs) {
  const grid = el("obs-certs-grid");
  if (!grid) return;
  if (!certs.length) {
    grid.innerHTML = `<div class="chart-empty">No SSL certificates tracked by Maintainer yet.</div>`;
    return;
  }
  const nowMs = Date.now();
  grid.innerHTML = certs
    .map((c) => {
      let daysLeft = null;
      if (c.expires_at) {
        const expMs = new Date(c.expires_at).getTime();
        if (!Number.isNaN(expMs)) daysLeft = Math.max(0, Math.round((expMs - nowMs) / 86_400_000));
      }
      const pct = daysLeft != null ? Math.min(100, Math.round((daysLeft / 90) * 100)) : 0;
      const barColor = daysLeft == null ? "#64748b" : daysLeft > 30 ? "#009F6B" : daysLeft > 10 ? "#FAC800" : "#C40233";
      const targets = (c.targets || []).map((t) => `<span class="role-chip ingress">${esc(t)}</span>`).join(" ");
      return `
        <div class="cert-card">
          <div class="cert-card-head">
            <span class="cert-domain">${esc(c.domain)}</span>
            <span class="pill ${c.status === "valid" ? "ok" : "warn"}">${esc(c.status)}</span>
          </div>
          <div class="cert-bar-track"><div class="cert-bar-fill" style="width:${pct}%;background:${barColor}"></div></div>
          <div class="muted-sm">
            ${daysLeft != null ? `<b>${daysLeft} days</b> remaining · ` : ""}Expires: ${esc(formatDateTime(c.expires_at))}
          </div>
          <div class="muted-sm">Last renewed: ${esc(formatDateTime(c.last_renewed))}</div>
          <div>${targets || '<span class="muted-sm">No target nodes</span>'}</div>
        </div>`;
    })
    .join("");
}

el("obs-node-filter")?.addEventListener("change", renderObservabilityCharts);
el("obs-svc-filter")?.addEventListener("change", renderObservabilityCharts);
el("obs-window-filter")?.addEventListener("change", renderObservabilityCharts);

/* ==================== ONBOARDING ==================== */

function updateOnboardingCliPreview() {
  const pre = el("enroll-cli-preview");
  if (!pre) return;
  const tag = el("enroll-tag")?.value.trim() || "node-new-1";
  const pass = el("enroll-passphrase")?.value.trim() || "<5-word-passphrase>";
  const mode = el("enroll-mode")?.value || "active";
  const addr = el("enroll-addr")?.value.trim() || "0.0.0.0:10802";
  if (mode === "listening") {
    pre.textContent =
      `# 1. Initialize listening node\n` +
      `exposure init-node --tag ${tag} --output ./${tag}.yaml --listen ${addr} --ingress\n\n` +
      `# 2. Start node with the generated one-time passphrase\n` +
      `exposure node --config ./${tag}.yaml --passphrase "${pass}"`;
  } else {
    pre.textContent =
      `# 1. Initialize active node pointing to bootstrap tunnel\n` +
      `exposure init-node --tag ${tag} --output ./${tag}.yaml --bootstrap <bootstrap-ip:10802> --egress\n\n` +
      `# 2. Start node (dials bootstrap and authenticates with Control)\n` +
      `exposure node --config ./${tag}.yaml --passphrase "${pass}"`;
  }
}

["enroll-tag", "enroll-passphrase", "enroll-mode", "enroll-addr"].forEach((id) => {
  el(id)?.addEventListener("input", updateOnboardingCliPreview);
  el(id)?.addEventListener("change", updateOnboardingCliPreview);
});

el("btn-copy-cli")?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(el("enroll-cli-preview").textContent);
    showToast("Copied CLI command to clipboard");
  } catch {
    showToast("Clipboard unavailable", true);
  }
});

async function refreshOnboarding() {
  updateOnboardingCliPreview();
  const data = await api("/api/passphrases");
  const nowSec = Math.floor(Date.now() / 1000);
  el("passphrases-tbody").innerHTML =
    (data.items || [])
      .map((p) => {
        const rem = (p.expires_ts || 0) - nowSec;
        const expText = p.revoked
          ? "Revoked"
          : rem > 0
          ? `${Math.floor(rem / 60)}m ${rem % 60}s left`
          : "Expired";
        return `
      <tr>
        <td><strong>${esc(p.node_tag)}</strong></td>
        <td>${esc(p.mode)}</td>
        <td>${esc(formatDateTime(p.expires_at))} <small class="muted">(${expText})</small></td>
        <td><span class="pill ${p.revoked || rem <= 0 ? "err" : "ok"}">${p.revoked ? "REVOKED" : rem <= 0 ? "EXPIRED" : "ACTIVE"}</span></td>
        <td>${p.revoked ? "-" : `<button class="btn sm danger" data-revoke="${esc(p.node_tag)}">Revoke</button>`}</td>
      </tr>`;
      })
      .join("") || `<tr><td colspan="5" class="muted">No passphrases registered</td></tr>`;

  el("passphrases-tbody").querySelectorAll("[data-revoke]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/passphrases/${encodeURIComponent(btn.dataset.revoke)}/revoke`, { method: "POST" });
        showToast(`Revoked passphrase for ${btn.dataset.revoke}`);
        refreshOnboarding();
      } catch (e) { showToast(e.message, true); }
    });
  });
}

el("enroll-form")?.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const hopsRaw = el("enroll-hops").value.trim();
    const hops = hopsRaw ? hopsRaw.split(",").map((s) => s.trim()).filter(Boolean) : [];
    await api("/api/passphrases", {
      method: "POST",
      body: JSON.stringify({
        node_tag: el("enroll-tag").value.trim(),
        passphrase: el("enroll-passphrase").value.trim(),
        mode: el("enroll-mode").value,
        address: el("enroll-addr").value.trim() || null,
        via_hops: hops,
      }),
    });
    showToast("Passphrase registered");
    el("enroll-form").reset();
    refreshOnboarding();
  } catch (e) { showToast(e.message, true); }
});

/* ==================== AUDIT LOG ==================== */

async function refreshAudit() {
  const data = await api("/api/audit");
  state.cache.audit = data.logs || [];
  renderAuditTable();
}

function renderAuditTable() {
  const logs = state.cache.audit || [];
  const q = (el("audit-search")?.value || "").trim().toLowerCase();
  const stF = el("audit-status-filter")?.value || "all";

  const filtered = logs.filter((l) => {
    if (stF === "ok" && !l.success) return false;
    if (stF === "fail" && l.success) return false;
    if (q && !`${l.actor} ${l.action} ${l.target} ${l.detail}`.toLowerCase().includes(q)) return false;
    return true;
  });

  el("audit-tbody").innerHTML =
    filtered
      .map(
        (l) => `
      <tr>
        <td>${esc(formatDateTime(l.created_at))}</td>
        <td>${esc(l.actor)}</td>
        <td><code>${esc(l.action)}</code></td>
        <td>${esc(l.target)}</td>
        <td><span class="pill ${l.success ? "ok" : "err"}">${l.success ? "OK" : "FAIL"}</span></td>
        <td>${esc(l.detail)}</td>
      </tr>`
      )
      .join("") || `<tr><td colspan="6" class="muted">No matching audit entries</td></tr>`;
}

el("audit-search")?.addEventListener("input", renderAuditTable);
el("audit-status-filter")?.addEventListener("change", renderAuditTable);

/* ==================== GLOBAL CONTROLS & AUTO REFRESH ==================== */

async function refreshCurrentTab(opts = {}) {
  try {
    if (state.activeTab === "overview") await refreshOverview();
    else if (state.activeTab === "nodes") await refreshNodes();
    else if (state.activeTab === "topology") await refreshTopology(opts);
    else if (state.activeTab === "onboarding") await refreshOnboarding();
    else if (state.activeTab === "observability") await refreshObservability();
    else if (state.activeTab === "audit") await refreshAudit();
  } catch (e) {
    showToast(e.message, true);
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  if (state.autoRefreshMs > 0 && state.token) {
    state.refreshTimer = setInterval(() => {
      // Never disrupt active editing in topology studio
      if (state.activeTab === "topology" && topoEditor.isDirty()) return;
      refreshCurrentTab();
    }, state.autoRefreshMs);
  }
}

function stopAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
}

el("sel-auto-refresh")?.addEventListener("change", (ev) => {
  state.autoRefreshMs = Number(ev.target.value) || 0;
  startAutoRefresh();
});

const savedWin = localStorage.getItem("exposure_time_window");
if (savedWin !== null && el("sel-time-window")) {
  el("sel-time-window").value = savedWin;
  if (el("obs-window-filter")) el("obs-window-filter").value = savedWin;
}

el("sel-time-window")?.addEventListener("change", (ev) => {
  const v = ev.target.value;
  localStorage.setItem("exposure_time_window", v);
  if (el("obs-window-filter")) el("obs-window-filter").value = v;
  refreshCurrentTab();
});

el("login-form")?.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  el("login-error").classList.add("hidden");
  try {
    const res = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: el("login-user").value.trim(),
        password: el("login-pass").value,
      }),
    });
    state.token = res.token;
    localStorage.setItem("exposure_token", res.token);
    el("login-view").classList.add("hidden");
    el("app-view").classList.remove("hidden");
    switchTab("overview");
    startAutoRefresh();
  } catch (e) {
    el("login-error").textContent = e.message;
    el("login-error").classList.remove("hidden");
  }
});

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

el("btn-logout")?.addEventListener("click", logout);
el("btn-refresh")?.addEventListener("click", () => refreshCurrentTab());

el("btn-discover")?.addEventListener("click", async () => {
  try {
    const r = await api("/api/discovery/run", { method: "POST" });
    showToast(`Discovery completed: ${r.discovered_nodes ?? 0} nodes reported`);
    refreshCurrentTab();
  } catch (e) { showToast(e.message, true); }
});

el("btn-pull-all")?.addEventListener("click", async () => {
  try {
    const r = await api("/api/telemetry/pull", { method: "POST" });
    showToast(`Pulled telemetry from ${r.pulled_sources ?? 0} source(s)`);
    refreshCurrentTab();
  } catch (e) { showToast(e.message, true); }
});

// Ctrl+S shortcut inside Topology Studio
window.addEventListener("keydown", (ev) => {
  if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "s" && state.activeTab === "topology" && state.token) {
    ev.preventDefault();
    saveTopologyNow(false);
  }
});

if (state.token) {
  el("login-view").classList.add("hidden");
  el("app-view").classList.remove("hidden");
  switchTab("overview");
  startAutoRefresh();
}
