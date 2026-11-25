// Overview NOC Dashboard View
import {
  formatBytes,
  formatCompact,
  formatDateTime,
  formatMinute,
  renderAreaLineChart,
  renderBarList,
  renderDonutChart,
  renderMiniTopo,
  themeColors,
} from "../charts.js";
import { t } from "../i18n.js";
import { el, esc } from "../ui.js";

export function createOverviewView({ api, store, navigate }) {
  let alertSeverity = "all";

  function renderShell() {
    const root = el("tab-overview");
    if (!root) return;
    root.innerHTML = `
      <div class="kpi-grid">
        <div class="kpi">
          <div class="kpi-label">${esc(t("ov.kpi.nodes"))}</div>
          <div id="kpi-nodes" class="kpi-val">0 / 0</div>
          <div id="kpi-nodes-sub" class="kpi-sub">-</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("ov.kpi.links"))}</div>
          <div id="kpi-links" class="kpi-val">0 / 0 / 0</div>
          <div id="kpi-links-sub" class="kpi-sub">UP / DEGRADED / DOWN</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("ov.kpi.requests"))}</div>
          <div id="kpi-requests" class="kpi-val">0</div>
          <div id="kpi-requests-sub" class="kpi-sub">-</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("ov.kpi.uv"))}</div>
          <div id="kpi-uv" class="kpi-val">0</div>
          <div id="kpi-uv-sub" class="kpi-sub">-</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("ov.kpi.latency"))}</div>
          <div id="kpi-latency" class="kpi-val">0 / 0 ms</div>
          <div id="kpi-latency-sub" class="kpi-sub">p99: 0.0 ms</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("ov.kpi.certs"))}</div>
          <div id="kpi-certs" class="kpi-val">#0</div>
          <div id="kpi-certs-sub" class="kpi-sub">-</div>
        </div>
      </div>

      <div class="dashboard-grid-2">
        <div class="panel">
          <div class="panel-header">
            <h3>${esc(t("ov.traffic_trend"))}</h3>
            <span class="muted-sm">${esc(t("ov.traffic_sub"))}</span>
          </div>
          <div id="ov-traffic-chart" class="chart-box"></div>
        </div>
        <div class="panel">
          <div class="panel-header">
            <h3>${esc(t("ov.latency_pct"))}</h3>
            <span class="muted-sm">${esc(t("ov.latency_sub"))}</span>
          </div>
          <div id="ov-latency-chart" class="chart-box"></div>
        </div>
      </div>

      <div class="dashboard-grid-3">
        <div class="panel span-2">
          <div class="panel-header">
            <h3>${esc(t("ov.mesh_map"))}</h3>
            <span class="muted-sm">${esc(t("ov.mesh_map_sub"))}</span>
          </div>
          <div id="ov-mini-topo" class="mini-topo-box"></div>
        </div>
        <div class="panel">
          <div class="panel-header">
            <h3>${esc(t("ov.link_mix"))}</h3>
          </div>
          <div id="ov-link-donut"></div>
        </div>
      </div>

      <div class="dashboard-grid-2">
        <div class="panel">
          <div class="panel-header">
            <h3>${esc(t("ov.top_services"))}</h3>
          </div>
          <div id="ov-top-services"></div>
        </div>
        <div class="panel">
          <div class="panel-header">
            <h3>${esc(t("ov.recent_alerts"))}</h3>
            <select id="ov-alert-filter" class="select-sm">
              <option value="all" ${alertSeverity === "all" ? "selected" : ""}>${esc(t("common.all"))}</option>
              <option value="error" ${alertSeverity === "error" ? "selected" : ""}>Error</option>
              <option value="warn" ${alertSeverity === "warn" ? "selected" : ""}>Warn</option>
            </select>
          </div>
          <div id="ov-maintainer-strip" class="maint-strip hidden"></div>
          <div class="table-scroll">
            <table class="table">
              <thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Message</th></tr></thead>
              <tbody id="alerts-tbody"></tbody>
            </table>
          </div>
        </div>
      </div>
    `;
    el("ov-alert-filter")?.addEventListener("change", (ev) => {
      alertSeverity = ev.target.value;
      renderAlerts();
    });
  }

  function renderAlerts() {
    const ov = store.overview;
    const tbody = el("alerts-tbody");
    if (!ov || !tbody) return;
    const rows = (ov.alerts || []).filter((a) => alertSeverity === "all" || a.severity === alertSeverity);
    tbody.innerHTML =
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
        .join("") || `<tr><td colspan="4" class="muted">${esc(t("ov.no_alerts"))}</td></tr>`;
  }

  function renderData() {
    const ov = store.overview;
    if (!ov) return;
    renderShell();

    const tr = ov.traffic || {};
    const totalReq = Number(tr.total_requests) || 0;
    const totalErr = Number(tr.total_errors) || 0;
    const errPct = totalReq > 0 ? ((totalErr / totalReq) * 100).toFixed(2) : "0.00";

    el("kpi-nodes").textContent = `${ov.online_nodes ?? 0} / ${ov.node_count ?? 0}`;
    el("kpi-nodes-sub").textContent = `${ov.online_nodes ?? 0} online · ${(ov.node_count ?? 0) - (ov.online_nodes ?? 0)} offline`;

    el("kpi-links").textContent = `${ov.links_up ?? 0} / ${ov.links_degraded ?? 0} / ${ov.links_down ?? 0}`;
    el("kpi-requests").textContent = formatCompact(totalReq);
    el("kpi-requests-sub").textContent = `${errPct}% 5xx · ${formatCompact(tr.total_blocked || 0)} blocked · ${formatCompact(tr.total_rate_limited || 0)} 429`;

    el("kpi-uv").textContent = formatCompact(tr.uv_estimate || 0);
    el("kpi-uv-sub").textContent = `${formatBytes(tr.total_bytes_in || 0)} in · ${formatBytes(tr.total_bytes_out || 0)} out`;

    el("kpi-latency").textContent = `${(tr.p50_ms || 0).toFixed(1)} / ${(tr.p95_ms || 0).toFixed(1)} ms`;
    el("kpi-latency-sub").textContent = `p99: ${(tr.p99_ms || 0).toFixed(1)} ms`;

    const cs = ov.certificates_summary || {};
    el("kpi-certs").textContent = `#${ov.latest_sequence ?? 0}`;
    el("kpi-certs-sub").textContent = `${cs.valid ?? 0}/${cs.total ?? 0} valid certs · ${(ov.alerts || []).length} alerts`;

    const tc = themeColors();
    const ts = ov.timeseries || [];
    const labels = ts.map((b) => formatMinute(b.minute_epoch));
    renderAreaLineChart(el("ov-traffic-chart"), {
      labels,
      series: [
        { name: "Requests", color: tc.accent, values: ts.map((b) => b.requests), area: true },
        { name: "Blocked", color: "#e07a3c", values: ts.map((b) => b.blocked || 0) },
        { name: "Challenged", color: tc.purple, values: ts.map((b) => b.challenges_issued) },
        { name: "Rate-Limited", color: tc.warn, values: ts.map((b) => b.rate_limited) },
        { name: "Errors", color: tc.danger, values: ts.map((b) => b.errors) },
      ],
    });

    renderAreaLineChart(el("ov-latency-chart"), {
      labels,
      unit: "ms",
      series: [
        { name: "p99", color: tc.danger, values: ts.map((b) => b.p99_ms), dashed: true },
        { name: "p95", color: tc.warn, values: ts.map((b) => b.p95_ms) },
        { name: "p50", color: tc.ok, values: ts.map((b) => b.p50_ms), area: true },
      ],
    });

    renderMiniTopo(el("ov-mini-topo"), {
      spec: ov.spec,
      liveNodes: ov.nodes || [],
      liveLinks: ov.links || [],
      onNodeClick: (tag) => navigate("topology", { focusNode: tag }),
    });

    const totalLinks = (ov.links_up || 0) + (ov.links_degraded || 0) + (ov.links_down || 0);
    renderDonutChart(el("ov-link-donut"), {
      centerValue: String(totalLinks),
      centerLabel: "Links",
      slices: [
        { label: "UP", value: ov.links_up || 0, color: tc.ok },
        { label: "DEGRADED", value: ov.links_degraded || 0, color: tc.warn },
        { label: "DOWN", value: ov.links_down || 0, color: tc.danger },
      ],
    });

    renderBarList(el("ov-top-services"), ov.service_breakdown || []);

    const mStrip = el("ov-maintainer-strip");
    const maints = ov.maintainers || [];
    if (mStrip) {
      if (maints.length) {
        mStrip.classList.remove("hidden");
        mStrip.innerHTML = maints
          .map(
            (m) =>
              `<span class="maint-chip">Maintainer <b>${esc(m.maintainer_tag)}</b> · backlog <b>${Number(m.segment_backlog) || 0}</b> · merge <b>${(Number(m.merge_latency_ms) || 0).toFixed(2)}ms</b></span>`
          )
          .join("");
      } else {
        mStrip.classList.add("hidden");
      }
    }
    renderAlerts();
  }

  async function refresh() {
    const winSec = Number(el("sel-time-window")?.value ?? 3600);
    const ov = await api(`/api/overview?window_secs=${winSec}`);
    store.overview = ov;
    if (!store.loaded && ov.spec) {
      store.setFromServer({ spec: ov.spec, live_nodes: ov.nodes, live_links: ov.links }, false);
    }
    renderData();
    return ov;
  }

  return { refresh, render: renderData };
}
