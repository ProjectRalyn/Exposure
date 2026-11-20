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
  authenticated: false,
  activeTab: "overview",
  obsHeroMetric: "requests", // requests | uv | bandwidth | guard | latency
  fpFilters: {
    verified: "all",
    risk: "all",
  },
  autoRefreshMs: 30000,
  refreshTimer: null,
  cache: {
    overview: null,
    nodesData: null,
    telemetry: null,
    fingerprints: null,
    audit: null,
    versions: [],
  },
};

// Clear any legacy plaintext token left in localStorage by older builds.
try { localStorage.removeItem("exposure_token"); } catch {}

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

function shellQuote(v) {
  return `'${String(v ?? "").replace(/'/g, `'\\''`)}'`;
}

async function api(path, opts = {}) {
  const { skipLogoutOn401 = false, ...fetchOpts } = opts;
  const headers = Object.assign({ "Content-Type": "application/json" }, fetchOpts.headers || {});
  const resp = await fetch(path, {
    credentials: "same-origin",
    ...fetchOpts,
    headers,
  });
  if (resp.status === 401) {
    if (!skipLogoutOn401) resetToLogin();
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

function resetToLogin() {
  state.authenticated = false;
  stopAutoRefresh();
  if (el("login-pass")) el("login-pass").value = "";
  el("app-view").classList.add("hidden");
  el("login-view").classList.remove("hidden");
}

async function logout() {
  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  } catch {
    // ignore network errors during logout
  }
  resetToLogin();
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
        `<span class="maint-chip">Maintainer <b>${esc(m.maintainer_tag)}</b> · backlog <b>${Number(m.segment_backlog) || 0}</b> · merge <b>${(Number(m.merge_latency_ms) || 0).toFixed(2)}ms</b></span>`
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
        bodyHtml: `<p>Push historical snapshot <b>#${esc(rec.sequence)}</b> (created ${esc(formatDateTime(rec.created_at))}) as a new signed revision to <code>${esc(rec.node_tag)}</code>?</p>`,
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
  const nodeF = el("obs-node-filter")?.value || "all";
  const svcF = el("obs-svc-filter")?.value || "all";
  const winSec = Number(el("obs-window-filter")?.value || 0);
  const qs = new URLSearchParams();
  if (nodeF !== "all") qs.set("node", nodeF);
  if (svcF !== "all") qs.set("service", svcF);
  if (winSec > 0) qs.set("window_secs", String(winSec));

  const data = await api(`/api/telemetry${qs.toString() ? `?${qs}` : ""}`);
  state.cache.telemetry = data;
  updateTopbarTimestamp(data.last_pulled_at);

  const nodeSel = el("obs-node-filter");
  const svcSel = el("obs-svc-filter");
  const nodes = (data.available_nodes || []).slice().sort();
  const svcs = (data.available_services || []).slice().sort();

  nodeSel.innerHTML =
    `<option value="all">All Nodes (${nodes.length})</option>` +
    nodes.map((n) => `<option value="${esc(n)}" ${nodeF === n ? "selected" : ""}>${esc(n)}</option>`).join("");
  svcSel.innerHTML =
    `<option value="all">All Services (${svcs.length})</option>` +
    svcs.map((s) => `<option value="${esc(s)}" ${svcF === s ? "selected" : ""}>${esc(s)}</option>`).join("");

  renderMaintainerStrip(el("obs-maint-strip"), data.maintainers || []);
  renderObservabilityCharts();
  renderCertificatesCards(data.certificates || []);
}

function renderObservabilityCharts() {
  const data = state.cache.telemetry;
  if (!data) return;

  // Use true server-side HLL union & LatencyHistogram merge computed by Rust Control
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
  const totalBytes = bytesIn + bytesOut;
  const totalGuard = totalChI + totalRl;

  if (el("cf-val-requests")) {
    el("cf-val-requests").textContent = formatCompact(totalReq);
    el("cf-sub-requests").textContent = `${errPct}% errors · ${formatCompact(totalErr)} 5xx`;
    el("cf-val-uv").textContent = formatCompact(totalUv);
    el("cf-sub-uv").textContent =
      totalUv > 0 ? `${(totalReq / totalUv).toFixed(1)} req / visitor` : "Exact / HLL union";
    el("cf-val-bandwidth").textContent = formatBytes(totalBytes);
    el("cf-sub-bandwidth").textContent = `${formatBytes(bytesIn)} in · ${formatBytes(bytesOut)} out`;
    el("cf-val-guard").textContent = formatCompact(totalGuard);
    el("cf-sub-guard").textContent = `${formatCompact(totalChI)} PoW · ${formatCompact(totalRl)} 429`;
    el("cf-val-latency").textContent = `${p95.toFixed(1)} ms`;
    el("cf-sub-latency").textContent = `p50 ${p50.toFixed(1)}ms · p99 ${p99.toFixed(1)}ms`;
  }

  // Render full-width Cloudflare Hero Chart for active metric tab
  const pts = data.timeseries || [];
  const labels = pts.map((p) => formatMinute(p.minute_epoch));

  const heroConfigs = {
    requests: {
      unit: "",
      series: [
        { name: "Total Requests", color: "#4DA9D6", values: pts.map((p) => p.requests), area: true },
        { name: "Rate-Limited (429)", color: "#FAC800", values: pts.map((p) => p.rate_limited) },
        { name: "Errors (5xx)", color: "#C40233", values: pts.map((p) => p.errors) },
      ],
    },
    uv: {
      unit: "",
      series: [
        { name: "Unique Visitors (Exact/HLL)", color: "#009F6B", values: pts.map((p) => Math.round(p.uv_estimate || 0)), area: true },
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
        { name: "PoW Challenged", color: "#6A5ACD", values: pts.map((p) => p.challenges_issued), area: true },
        { name: "PoW Cleared", color: "#009F6B", values: pts.map((p) => p.challenges_passed) },
        { name: "Rate-Limited (429)", color: "#FAC800", values: pts.map((p) => p.rate_limited) },
      ],
    },
    latency: {
      unit: "ms",
      series: [
        { name: "p99", color: "#C40233", values: pts.map((p) => p.p99_ms), dashed: true },
        { name: "p95", color: "#FAC800", values: pts.map((p) => p.p95_ms) },
        { name: "p50", color: "#009F6B", values: pts.map((p) => p.p50_ms), area: true },
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

  renderBarList(el("obs-service-bars"), data.service_breakdown || [], "No service traffic in selected window");
  renderBarList(el("obs-node-bars"), data.node_breakdown || [], "No node traffic in selected window");
  renderGuardFunnel(el("obs-guard-funnel"), tr);

  const cleanReqs = Math.max(0, totalReq - totalErr - totalRl - totalChI);
  const cleanOrPassed = Math.min(totalReq, cleanReqs + totalChP);
  renderDonutChart(el("obs-outcome-donut"), {
    centerValue: formatCompact(totalReq),
    centerLabel: "Requests",
    slices: [
      { label: "Clean / Passed", value: cleanOrPassed, color: "#009F6B" },
      { label: "PoW Challenged", value: Math.max(0, totalChI - totalChP), color: "#6A5ACD" },
      { label: "Rate-Limited (429)", value: totalRl, color: "#FAC800" },
      { label: "Errors (5xx)", value: totalErr, color: "#C40233" },
    ],
  });

  // Client Fingerprint Breakdown (Devices / Browsers / OS)
  const devMap = new Map(Object.entries(data.device_counts || {}));
  const brwMap = new Map(Object.entries(data.browser_counts || {}));
  const osMap = new Map(Object.entries(data.os_counts || {}));
  const fpVerified = Number(data.client_fp_verified) || 0;
  const fpBadge = el("obs-fp-verified-badge");
  if (fpBadge) fpBadge.textContent = `${formatCompact(fpVerified)} JS-verified reqs`;
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
                  <div class="bar-item-head"><span>${esc(k)}</span><span>${formatCompact(v)} (${((v / tot) * 100).toFixed(0)}%)</span></div>
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
  const filtered = data.summaries || [];
  el("stats-tbody").innerHTML =
    filtered
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
      .join("") || `<tr><td colspan="11" class="muted">No aggregated summaries match current filter</td></tr>`;
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

el("btn-open-fp-explorer")?.addEventListener("click", () => switchTab("fingerprints"));

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

el("obs-node-filter")?.addEventListener("change", refreshObservability);
el("obs-svc-filter")?.addEventListener("change", refreshObservability);
el("obs-window-filter")?.addEventListener("change", refreshObservability);

/* ==================== FINGERPRINTS EXPLORER ==================== */

async function refreshFingerprints() {
  const qs = new URLSearchParams();
  const qVal = (el("fp-search-q")?.value || "").trim();
  const ipVal = (el("fp-search-ip")?.value || "").trim();
  const fpVal = (el("fp-search-fp")?.value || "").trim();
  const nodeF = el("fp-node-filter")?.value || "all";
  const svcF = el("fp-svc-filter")?.value || "all";
  const winSec = Number(el("sel-time-window")?.value || 0);

  if (qVal) qs.set("q", qVal);
  if (ipVal) qs.set("ip", ipVal);
  if (fpVal) qs.set("fp", fpVal);
  if (nodeF !== "all") qs.set("node", nodeF);
  if (svcF !== "all") qs.set("service", svcF);
  if (state.fpFilters.verified !== "all") qs.set("verified", state.fpFilters.verified);
  if (state.fpFilters.risk !== "all") qs.set("risk", state.fpFilters.risk);
  if (winSec > 0) qs.set("window_secs", String(winSec));

  const data = await api(`/api/fingerprints${qs.toString() ? `?${qs}` : ""}`);
  state.cache.fingerprints = data;
  updateTopbarTimestamp(data.last_pulled_at);

  const sum = data.summary || {};
  el("fp-kpi-total").textContent = formatCompact(sum.total_visitors || 0);
  el("fp-kpi-ips").textContent = `${formatCompact(sum.unique_ips || 0)} unique IPs`;
  el("fp-kpi-verified").textContent = formatCompact(sum.js_verified || 0);
  el("fp-kpi-sources").textContent = `${formatCompact(sum.beacon_count || 0)} beacon · ${formatCompact(sum.pow_count || 0)} PoW`;
  el("fp-kpi-unique-fp").textContent = formatCompact(sum.unique_fps || 0);
  el("fp-kpi-risk").textContent = `${sum.bots || 0} / ${sum.headless || 0}`;

  const nodes = (data.available_nodes || []).slice().sort();
  const svcs = (data.available_services || []).slice().sort();
  if (el("fp-node-filter")) {
    el("fp-node-filter").innerHTML =
      `<option value="all">All Nodes (${nodes.length})</option>` +
      nodes.map((n) => `<option value="${esc(n)}" ${nodeF === n ? "selected" : ""}>${esc(n)}</option>`).join("");
  }
  if (el("fp-svc-filter")) {
    el("fp-svc-filter").innerHTML =
      `<option value="all">All Services (${svcs.length})</option>` +
      svcs.map((s) => `<option value="${esc(s)}" ${svcF === s ? "selected" : ""}>${esc(s)}</option>`).join("");
  }

  const hint = el("fp-privacy-hint");
  if (hint) {
    hint.textContent = data.store_raw_ip_enabled
      ? "Raw IP storage is enabled (global_logger.store_raw_ip = true). You can search exact IPs, subnets, HMAC tags, and browser fingerprints."
      : "Privacy mode active (store_raw_ip = false): displaying /24 subnets & HMAC tags. Typing an exact IP in Search automatically matches via cluster IP HMAC.";
  }

  const items = data.items || [];
  if (el("fp-result-meta")) {
    el("fp-result-meta").textContent = `Showing ${items.length} of ${data.total_matched ?? items.length} observation(s) — click a row for details`;
  }

  const tbody = el("fp-tbody");
  tbody.innerHTML =
    items
      .map((obs, idx) => {
        const ipPrimary = obs.client_ip || obs.ip_prefix || "-";
        const srcBadge = obs.js_verified
          ? obs.fp_source === "pow"
            ? `<span class="pill ok">PoW JS</span>`
            : `<span class="pill info">Beacon JS</span>`
          : `<span class="pill">UA Only</span>`;
        const js = obs.js_fp;
        const jsSummary = js
          ? `${js.screen || "-"} · ${js.webgl ? js.webgl.slice(0, 32) : js.platform || "-"} · ${js.tz || "-"}`
          : "Pending passive JS beacon";
        const riskCls = obs.is_headless || obs.is_bot || obs.suspicion_score >= 60 ? "err" : obs.suspicion_score >= 30 ? "warn" : "ok";
        const riskLbl = obs.is_headless ? "HEADLESS" : obs.is_bot ? "BOT" : `Score ${Number(obs.suspicion_score) || 0}`;
        return `
      <tr class="fp-table-row" data-fp-idx="${idx}">
        <td>
          <div><strong>${esc(ipPrimary)}</strong></div>
          <div class="muted-sm"><span class="fp-code">${esc(obs.ip_hmac)}</span>${obs.client_ip && obs.ip_prefix ? ` · ${esc(obs.ip_prefix)}` : ""}</div>
        </td>
        <td>
          <div><span class="fp-code">${esc(obs.fp_hash)}</span> ${srcBadge}</div>
          ${js?.canvas_hash ? `<div class="muted-sm">canvas: <code>${esc(js.canvas_hash)}</code></div>` : ""}
        </td>
        <td>
          <div><strong>${esc(obs.browser_family || "-")}</strong> · ${esc(obs.os_family || "-")}</div>
          <div class="muted-sm">${esc(obs.device_type || "-")}</div>
        </td>
        <td><span class="muted-sm">${esc(jsSummary)}</span></td>
        <td>
          <div><code>${esc(obs.service_tag)}</code></div>
          <div class="muted-sm">${esc(obs.node_tag)}${obs.host ? ` · ${esc(obs.host)}` : ""}</div>
        </td>
        <td><span class="pill ${riskCls}">${esc(riskLbl)}</span></td>
        <td>
          <div><strong>${formatCompact(obs.request_count)}</strong> req</div>
          <div class="muted-sm">${obs.challenge_count || 0} ch · ${obs.rate_limited_count || 0} 429</div>
        </td>
        <td>${esc(formatDateTime(obs.last_seen_ts))}</td>
      </tr>`;
      })
      .join("") || `<tr><td colspan="8" class="muted">No visitor fingerprints match the current query.</td></tr>`;

  tbody.querySelectorAll("[data-fp-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const obs = items[Number(tr.dataset.fpIdx)];
      if (obs) openFingerprintDetailModal(obs);
    });
  });
}

function openFingerprintDetailModal(obs) {
  const js = obs.js_fp || null;
  const jsSection = js
    ? `<div class="inspector-sec" style="margin-bottom:12px;">
        <div class="inspector-sec-head"><span>Client JS Fingerprint (${esc(obs.fp_source || "beacon").toUpperCase()})</span></div>
        <div class="fp-detail-grid" style="margin-bottom:0;">
          <div class="fp-kv"><div class="fp-kv-lbl">WebGL Renderer</div><div class="fp-kv-val">${esc(js.webgl || "-")}</div></div>
          <div class="fp-kv"><div class="fp-kv-lbl">Canvas Hash</div><div class="fp-kv-val"><code>${esc(js.canvas_hash || "-")}</code></div></div>
          <div class="fp-kv"><div class="fp-kv-lbl">Platform / Screen / DPR</div><div class="fp-kv-val">${esc(js.platform || "-")} · ${esc(js.screen || "-")} @ ${esc(js.dpr || "1")}x</div></div>
          <div class="fp-kv"><div class="fp-kv-lbl">Timezone &amp; Language</div><div class="fp-kv-val">${esc(js.tz || "-")} · ${esc(js.lang || "-")}</div></div>
          <div class="fp-kv"><div class="fp-kv-lbl">Hardware (Cores · RAM · Touch)</div><div class="fp-kv-val">${Number(js.cores) || 0} cores · ${Number(js.mem) || 0} GB · ${Number(js.touch) || 0} touch</div></div>
          <div class="fp-kv"><div class="fp-kv-lbl">WebDriver / Plugins</div><div class="fp-kv-val">${js.webdriver ? '<span class="pill err">webdriver=true</span>' : '<span class="pill ok">webdriver=false</span>'} · ${Number(js.plugins_count) || 0} plugins</div></div>
        </div>
      </div>`
    : `<div class="muted-sm" style="margin-bottom:12px;">No client JS report captured yet for this visitor (only server-side HTTP/TLS headers observed).</div>`;

  const bodyHtml = `
    <div class="fp-detail-grid">
      <div class="fp-kv"><div class="fp-kv-lbl">Client IP / Subnet</div><div class="fp-kv-val">${esc(obs.client_ip || obs.ip_prefix || "-")}<br/><small class="muted">HMAC: <code>${esc(obs.ip_hmac)}</code></small></div></div>
      <div class="fp-kv"><div class="fp-kv-lbl">Fingerprint Hash</div><div class="fp-kv-val"><code>${esc(obs.fp_hash)}</code><br/><small class="muted">${obs.js_verified ? `JS Verified (${esc(obs.fp_source)})` : "Server UA Fallback"}</small></div></div>
      <div class="fp-kv"><div class="fp-kv-lbl">Classification</div><div class="fp-kv-val">${esc(obs.device_type)} · ${esc(obs.browser_family)} · ${esc(obs.os_family)}</div></div>
      <div class="fp-kv"><div class="fp-kv-lbl">Risk &amp; TLS Signals</div><div class="fp-kv-val">Score ${Number(obs.suspicion_score) || 0}/100 · ${obs.is_bot ? "Bot" : obs.is_headless ? "Headless" : "Normal"}<br/><small class="muted">TLS ciphers: ${Number(obs.tls_cipher_count) || 0} · ALPN: ${obs.tls_alpn ? "Yes" : "No"}</small></div></div>
      <div class="fp-kv"><div class="fp-kv-lbl">Route Context</div><div class="fp-kv-val"><code>${esc(obs.service_tag)}</code> @ ${esc(obs.node_tag)}<br/><small class="muted">Host: ${esc(obs.host || "-")}</small></div></div>
      <div class="fp-kv"><div class="fp-kv-lbl">Activity Window</div><div class="fp-kv-val">${formatCompact(obs.request_count)} req · ${obs.challenge_count || 0} ch · ${obs.rate_limited_count || 0} 429<br/><small class="muted">${esc(formatDateTime(obs.first_seen_ts))} → ${esc(formatDateTime(obs.last_seen_ts))}</small></div></div>
    </div>
    <div class="fp-kv-lbl" style="margin-bottom:4px;">User-Agent</div>
    <div class="fp-ua-box">${esc(obs.user_agent || "(empty)")}${obs.accept_language ? `\nAccept-Language: ${esc(obs.accept_language)}` : ""}</div>
    ${jsSection}
  `;

  openModal({
    title: `Fingerprint Inspector — ${obs.fp_hash}`,
    bodyHtml,
    actions: [
      {
        label: "Filter by this IP",
        onClick: () => {
          if (el("fp-search-ip")) el("fp-search-ip").value = obs.client_ip || obs.ip_hmac;
          refreshFingerprints();
        },
      },
      {
        label: "Filter by this FP",
        onClick: () => {
          if (el("fp-search-fp")) el("fp-search-fp").value = obs.fp_hash;
          refreshFingerprints();
        },
      },
      { label: "Close", cls: "primary" },
    ],
  });
}

el("btn-fp-search")?.addEventListener("click", refreshFingerprints);
el("btn-fp-clear")?.addEventListener("click", () => {
  if (el("fp-search-q")) el("fp-search-q").value = "";
  if (el("fp-search-ip")) el("fp-search-ip").value = "";
  if (el("fp-search-fp")) el("fp-search-fp").value = "";
  if (el("fp-node-filter")) el("fp-node-filter").value = "all";
  if (el("fp-svc-filter")) el("fp-svc-filter").value = "all";
  state.fpFilters.verified = "all";
  state.fpFilters.risk = "all";
  document.querySelectorAll("[data-fp-ver]").forEach((b) => b.classList.toggle("active", b.dataset.fpVer === "all"));
  document.querySelectorAll("[data-fp-risk]").forEach((b) => b.classList.toggle("active", b.dataset.fpRisk === "all"));
  refreshFingerprints();
});
["fp-search-q", "fp-search-ip", "fp-search-fp"].forEach((id) => {
  el(id)?.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      refreshFingerprints();
    }
  });
});
el("fp-node-filter")?.addEventListener("change", refreshFingerprints);
el("fp-svc-filter")?.addEventListener("change", refreshFingerprints);
document.querySelectorAll("[data-fp-ver]").forEach((btn) => {
  btn.addEventListener("click", () => {
    state.fpFilters.verified = btn.dataset.fpVer;
    document.querySelectorAll("[data-fp-ver]").forEach((b) => b.classList.toggle("active", b === btn));
    refreshFingerprints();
  });
});
document.querySelectorAll("[data-fp-risk]").forEach((btn) => {
  btn.addEventListener("click", () => {
    state.fpFilters.risk = btn.dataset.fpRisk;
    document.querySelectorAll("[data-fp-risk]").forEach((b) => b.classList.toggle("active", b === btn));
    refreshFingerprints();
  });
});

/* ==================== ONBOARDING ==================== */

function updateOnboardingCliPreview() {
  const pre = el("enroll-cli-preview");
  if (!pre) return;
  const tag = el("enroll-tag")?.value.trim() || "node-new-1";
  const pass = el("enroll-passphrase")?.value.trim() || "<one-time-passphrase>";
  const mode = el("enroll-mode")?.value || "active";
  const addr = el("enroll-addr")?.value.trim() || "0.0.0.0:10802";
  const cfgPath = `./${tag.replace(/[^A-Za-z0-9._-]/g, "_")}.yaml`;
  if (mode === "listening") {
    pre.textContent =
      `# 1. Initialize listening node\n` +
      `exposure init-node --tag ${shellQuote(tag)} --output ${shellQuote(cfgPath)} --listen ${shellQuote(addr)} --ingress\n\n` +
      `# 2. Start node with the generated one-time passphrase via environment variable\n` +
      `EXPOSURE_PASSPHRASE=${shellQuote(pass)} exposure node --config ${shellQuote(cfgPath)}`;
  } else {
    pre.textContent =
      `# 1. Initialize active node pointing to bootstrap tunnel\n` +
      `exposure init-node --tag ${shellQuote(tag)} --output ${shellQuote(cfgPath)} --bootstrap '<bootstrap-ip:10802>' --egress\n\n` +
      `# 2. Start node (dials bootstrap and authenticates with Control)\n` +
      `EXPOSURE_PASSPHRASE=${shellQuote(pass)} exposure node --config ${shellQuote(cfgPath)}`;
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
    else if (state.activeTab === "fingerprints") await refreshFingerprints();
    else if (state.activeTab === "audit") await refreshAudit();
  } catch (e) {
    showToast(e.message, true);
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  if (state.autoRefreshMs > 0 && state.authenticated) {
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
    await api("/api/auth/login", {
      method: "POST",
      skipLogoutOn401: true,
      body: JSON.stringify({
        username: el("login-user").value.trim(),
        password: el("login-pass").value,
      }),
    });
    el("login-pass").value = "";
    state.authenticated = true;
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

el("btn-logout")?.addEventListener("click", () => { logout(); });
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
  if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "s" && state.activeTab === "topology" && state.authenticated) {
    ev.preventDefault();
    saveTopologyNow(false);
  }
});

async function bootstrapSession() {
  try {
    await api("/api/auth/me", { method: "GET", skipLogoutOn401: true });
    state.authenticated = true;
    el("login-view").classList.add("hidden");
    el("app-view").classList.remove("hidden");
    switchTab("overview");
    startAutoRefresh();
  } catch {
    resetToLogin();
  }
}

bootstrapSession();
