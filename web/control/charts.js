// Native SVG & HTML5 Visualization Engine for Exposure Control (Zero external deps)

export function formatCompact(n) {
  const num = Number(n) || 0;
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(2)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return String(Math.round(num));
}

export function formatBytes(bytes) {
  const b = Number(bytes) || 0;
  if (b >= 1024 ** 3) return `${(b / 1024 ** 3).toFixed(2)} GB`;
  if (b >= 1024 ** 2) return `${(b / 1024 ** 2).toFixed(2)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${b} B`;
}

export function formatMinute(epochSec) {
  if (!epochSec) return "-";
  const d = new Date(Number(epochSec) * 1000);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

export function formatDateTime(isoOrEpoch) {
  if (!isoOrEpoch) return "-";
  const d = typeof isoOrEpoch === "number" ? new Date(isoOrEpoch * 1000) : new Date(isoOrEpoch);
  if (Number.isNaN(d.getTime())) return String(isoOrEpoch);
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  const da = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${mo}-${da} ${hh}:${mm}:${ss}`;
}

export function formatUptime(secs) {
  if (secs == null) return "-";
  const s = Number(secs);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function safeColor(c, fallback = "#4DA9D6") {
  return typeof c === "string" && /^#[0-9a-fA-F]{3,8}$/.test(c) ? c : fallback;
}

function finiteVal(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function smoothPath(pts) {
  if (pts.length === 0) return "";
  if (pts.length === 1) return `M ${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
  let d = `M ${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[Math.max(0, i - 1)];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[Math.min(pts.length - 1, i + 2)];
    const cp1x = p1.x + (p2.x - p0.x) / 6;
    const cp1y = p1.y + (p2.y - p0.y) / 6;
    const cp2x = p2.x - (p3.x - p1.x) / 6;
    const cp2y = p2.y - (p3.y - p1.y) / 6;
    d += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;
  }
  return d;
}

/**
 * Interactive multi-series smooth SVG area/line/column chart with hover crosshair & tooltip.
 * Automatically renders clean rounded bars when there are <= 2 time buckets so sparse data
 * never degrades into an invisible single dot.
 * series: [{ name, color, values: number[], area?: boolean, dashed?: boolean }]
 */
export function renderAreaLineChart(
  container,
  { labels = [], series = [], unit = "", height = 220, emptyText = "No telemetry data yet" }
) {
  if (!container) return;
  if (!labels.length || !series.length || series.every((s) => s.values.length === 0)) {
    container.innerHTML = `<div class="chart-empty">${esc(emptyText)}</div>`;
    return;
  }

  const W = Math.max(640, Math.round(container.clientWidth || 840));
  const H = Math.max(height, 260);
  const padL = 54;
  const padR = 18;
  const padT = 18;
  const padB = 30;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  let rawMax = 1;
  for (const s of series) {
    for (const v of s.values) {
      const fv = finiteVal(v);
      if (fv > rawMax) rawMax = fv;
    }
  }
  const yMax = niceMax(rawMax);
  const ticks = 4;

  const isSparse = labels.length <= 2;
  const xAt = (i) =>
    isSparse
      ? padL + ((i + 0.5) / labels.length) * plotW
      : padL + (i / (labels.length - 1)) * plotW;
  const yAt = (v) => padT + plotH - (finiteVal(v) / yMax) * plotH;

  const uid = `cg_${Math.random().toString(36).slice(2, 8)}`;

  let defs = "";
  let gridSvg = "";
  for (let t = 0; t <= ticks; t++) {
    const val = (yMax / ticks) * t;
    const y = yAt(val);
    gridSvg += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" class="chart-grid" />`;
    const lbl =
      unit === "ms"
        ? `${val.toFixed(val < 10 ? 1 : 0)}`
        : unit === "bytes"
        ? formatBytes(val)
        : formatCompact(val);
    gridSvg += `<text x="${padL - 8}" y="${(y + 3.5).toFixed(1)}" text-anchor="end" class="chart-axis-text">${esc(lbl)}</text>`;
  }

  const labelStep = Math.max(1, Math.ceil(labels.length / 8));
  let xLabelsSvg = "";
  labels.forEach((lbl, i) => {
    if (i % labelStep === 0 || i === labels.length - 1) {
      xLabelsSvg += `<text x="${xAt(i).toFixed(1)}" y="${H - 8}" text-anchor="middle" class="chart-axis-text">${esc(lbl)}</text>`;
    }
  });

  let pathsSvg = "";
  if (isSparse) {
    // Render crisp grouped rounded bars for 1-2 minute buckets
    const groupW = Math.min(180, (plotW / labels.length) * 0.52);
    const barW = Math.max(16, Math.min(44, (groupW - (series.length - 1) * 6) / series.length));
    const totalGroup = barW * series.length + (series.length - 1) * 6;
    labels.forEach((_, li) => {
      const centerX = xAt(li);
      const startX = centerX - totalGroup / 2;
      series.forEach((s, si) => {
        const color = safeColor(s.color);
        const v = finiteVal(s.values[li]);
        const bx = startX + si * (barW + 6);
        const by = yAt(v);
        const bh = Math.max(v > 0 ? 4 : 0, padT + plotH - by);
        const gid = `${uid}_b_${si}`;
        if (li === 0) {
          defs += `
            <linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="${color}" stop-opacity="0.92" />
              <stop offset="100%" stop-color="${color}" stop-opacity="0.35" />
            </linearGradient>`;
        }
        pathsSvg += `<rect x="${bx.toFixed(1)}" y="${(padT + plotH - bh).toFixed(1)}" width="${barW.toFixed(1)}" height="${bh.toFixed(1)}" rx="5" fill="url(#${gid})" />`;
        if (v > 0) {
          const fv =
            unit === "ms"
              ? `${v.toFixed(1)}`
              : unit === "bytes"
              ? formatBytes(v)
              : formatCompact(v);
          pathsSvg += `<text x="${(bx + barW / 2).toFixed(1)}" y="${(padT + plotH - bh - 5).toFixed(1)}" text-anchor="middle" class="chart-axis-text" fill="${color}">${esc(fv)}</text>`;
        }
      });
    });
  } else {
    series.forEach((s, si) => {
      const color = safeColor(s.color);
      const pts = s.values.map((v, i) => ({ x: xAt(i), y: yAt(v) }));
      const lineD = smoothPath(pts);
      const gid = `${uid}_${si}`;
      if (s.area) {
        defs += `
          <linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="${color}" stop-opacity="0.34" />
            <stop offset="100%" stop-color="${color}" stop-opacity="0.02" />
          </linearGradient>`;
        const areaD = `${lineD} L ${pts[pts.length - 1].x.toFixed(1)} ${(padT + plotH).toFixed(1)} L ${pts[0].x.toFixed(1)} ${(padT + plotH).toFixed(1)} Z`;
        pathsSvg += `<path d="${areaD}" fill="url(#${gid})" />`;
      }
      pathsSvg += `<path d="${lineD}" fill="none" stroke="${color}" stroke-width="2.2" ${s.dashed ? 'stroke-dasharray="5 4"' : ""} stroke-linecap="round" />`;
      if (pts.length <= 28) {
        pts.forEach((p) => {
          pathsSvg += `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.8" fill="${color}" opacity="0.9" />`;
        });
      }
    });
  }

  const legendHtml = series
    .map(
      (s) =>
        `<span class="chart-legend-item"><i style="background:${safeColor(s.color)}"></i>${esc(s.name)}</span>`
    )
    .join("");

  container.innerHTML = `
    <div class="chart-legend">${legendHtml}</div>
    <div class="chart-svg-wrap" style="height:${H}px">
      <svg viewBox="0 0 ${W} ${H}" class="chart-svg" preserveAspectRatio="none">
        <defs>${defs}</defs>
        ${gridSvg}
        ${pathsSvg}
        ${xLabelsSvg}
        <line class="chart-crosshair hidden" x1="0" y1="${padT}" x2="0" y2="${padT + plotH}" />
        <rect class="chart-hit" x="${padL}" y="${padT}" width="${plotW}" height="${plotH}" fill="transparent" />
      </svg>
      <div class="chart-tooltip hidden"></div>
    </div>
  `;

  const wrap = container.querySelector(".chart-svg-wrap");
  const svg = container.querySelector(".chart-svg");
  const hit = container.querySelector(".chart-hit");
  const crosshair = container.querySelector(".chart-crosshair");
  const tooltip = container.querySelector(".chart-tooltip");

  hit.addEventListener("mousemove", (ev) => {
    const rect = svg.getBoundingClientRect();
    if (!rect.width) return;
    const relX = ((ev.clientX - rect.left) / rect.width) * W;
    const ratio = Math.max(0, Math.min(1, (relX - padL) / plotW));
    const idx = isSparse
      ? Math.min(labels.length - 1, Math.floor(ratio * labels.length))
      : Math.round(ratio * (labels.length - 1));
    const cx = xAt(idx);
    crosshair.setAttribute("x1", cx.toFixed(1));
    crosshair.setAttribute("x2", cx.toFixed(1));
    crosshair.classList.remove("hidden");

    const rows = series
      .map((s) => {
        const v = finiteVal(s.values[idx]);
        const fv =
          unit === "ms"
            ? `${v.toFixed(1)} ms`
            : unit === "bytes"
            ? formatBytes(v)
            : formatCompact(v);
        return `<div class="tt-row"><span><i style="background:${safeColor(s.color)}"></i>${esc(s.name)}</span><strong>${esc(fv)}</strong></div>`;
      })
      .join("");
    tooltip.innerHTML = `<div class="tt-title">${esc(labels[idx])}</div>${rows}`;
    tooltip.classList.remove("hidden");

    const wrapRect = wrap.getBoundingClientRect();
    const px = ev.clientX - wrapRect.left;
    const left = px > wrapRect.width * 0.62 ? Math.max(6, px - tooltip.offsetWidth - 12) : px + 12;
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `12px`;
  });

  hit.addEventListener("mouseleave", () => {
    crosshair.classList.add("hidden");
    tooltip.classList.add("hidden");
  });
}

function niceMax(val) {
  if (val <= 1) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(val)));
  const norm = val / exp;
  if (norm <= 1.2) return 1.2 * exp;
  if (norm <= 2) return 2 * exp;
  if (norm <= 5) return 5 * exp;
  return 10 * exp;
}

/**
 * Interactive SVG Donut Chart with legend.
 */
export function renderDonutChart(container, { slices = [], centerValue = "0", centerLabel = "Total" }) {
  if (!container) return;
  const total = slices.reduce((a, s) => a + (Number(s.value) || 0), 0);
  const r = 46;
  const c = 2 * Math.PI * r;
  let offset = 0;

  let rings = "";
  if (total === 0) {
    rings = `<circle cx="64" cy="64" r="${r}" fill="none" stroke="var(--border)" stroke-width="12" />`;
  } else {
    for (const s of slices) {
      const val = Number(s.value) || 0;
      if (val <= 0) continue;
      const frac = val / total;
      const dash = frac * c;
      rings += `<circle cx="64" cy="64" r="${r}" fill="none" stroke="${safeColor(s.color)}" stroke-width="12"
        stroke-dasharray="${dash.toFixed(2)} ${(c - dash).toFixed(2)}"
        stroke-dashoffset="${(-offset).toFixed(2)}"
        transform="rotate(-90 64 64)" />`;
      offset += dash;
    }
  }

  const legend = slices
    .map((s) => {
      const pct = total > 0 ? Math.round(((Number(s.value) || 0) / total) * 100) : 0;
      return `
        <div class="donut-legend-row">
          <span class="donut-legend-name"><i style="background:${safeColor(s.color)}"></i>${esc(s.label)}</span>
          <span class="donut-legend-val">${esc(s.value)} <small>(${pct}%)</small></span>
        </div>`;
    })
    .join("");

  container.innerHTML = `
    <div class="donut-wrap">
      <svg viewBox="0 0 128 128" class="donut-svg">
        ${rings}
        <text x="64" y="61" text-anchor="middle" class="donut-center-val">${esc(centerValue)}</text>
        <text x="64" y="77" text-anchor="middle" class="donut-center-lbl">${esc(centerLabel)}</text>
      </svg>
      <div class="donut-legend">${legend}</div>
    </div>
  `;
}

/**
 * Ranked horizontal bar breakdown (e.g., Top Services or Top Nodes).
 */
export function renderBarList(container, items = [], emptyText = "No traffic recorded") {
  if (!container) return;
  if (!items.length) {
    container.innerHTML = `<div class="chart-empty">${esc(emptyText)}</div>`;
    return;
  }
  const totalReqs = Math.max(1, items.reduce((a, i) => a + finiteVal(i.requests), 0));
  let maxVal = 1;
  for (const it of items) {
    const r = finiteVal(it.requests);
    if (r > maxVal) maxVal = r;
  }
  container.innerHTML = `<div class="bar-list">${items
    .slice(0, 8)
    .map((it) => {
      const label = it.service_tag || it.node_tag || it.label || "-";
      const req = finiteVal(it.requests);
      const err = finiteVal(it.errors);
      const p95 = finiteVal(it.p95_ms);
      const pct = Math.max(4, Math.round((req / maxVal) * 100));
      const share = ((req / totalReqs) * 100).toFixed(1);
      const errRate = req > 0 ? ((err / req) * 100).toFixed(1) : "0.0";
      const errCls = err > 0 ? "err" : "ok";
      return `
        <div class="bar-item">
          <div class="bar-item-head">
            <span class="bar-item-title"><code>${esc(label)}</code> <small class="muted">${share}%</small></span>
            <span class="bar-item-metrics">
              <strong>${formatCompact(req)}</strong> req
              · <span class="pill ${errCls}">${errRate}% err</span>
              · <span class="muted">p95 ${p95.toFixed(1)}ms</span>
            </span>
          </div>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        </div>`;
    })
    .join("")}</div>`;
}

/**
 * Visual Guard Protection Funnel.
 */
export function renderGuardFunnel(container, traffic) {
  if (!container) return;
  const total = finiteVal(traffic?.total_requests);
  const rl = finiteVal(traffic?.total_rate_limited);
  const chIssued = finiteVal(traffic?.total_challenges_issued);
  const chPassed = finiteVal(traffic?.total_challenges_passed);
  const errors = finiteVal(traffic?.total_errors);
  const clean = Math.max(0, total - rl - chIssued - errors);
  const cleanOrPassed = Math.min(total, clean + chPassed);

  const stages = [
    { label: "Total Requests", val: total, color: "#4DA9D6" },
    { label: "Clean / Passed", val: cleanOrPassed, color: "#009F6B" },
    { label: "PoW Challenged", val: chIssued, color: "#6A5ACD" },
    { label: "PoW Cleared", val: chPassed, color: "#00A3B8" },
    { label: "Rate-Limited (429)", val: rl, color: "#FAC800" },
    { label: "5xx / Backend Errors", val: errors, color: "#C40233" },
  ];

  const denom = Math.max(1, total);
  container.innerHTML = `<div class="funnel-list">${stages
    .map((s) => {
      const pct = total > 0 ? Math.min(100, (s.val / denom) * 100) : 0;
      return `
        <div class="funnel-row">
          <div class="funnel-lbl">${esc(s.label)}</div>
          <div class="funnel-track">
            <div class="funnel-bar" style="width:${Math.max(s.val > 0 ? 3 : 0, pct).toFixed(1)}%;background:${safeColor(s.color)}"></div>
          </div>
          <div class="funnel-val">${formatCompact(s.val)} <small>${pct.toFixed(1)}%</small></div>
        </div>`;
    })
    .join("")}</div>`;
}

/**
 * Interactive Live Mesh Health Mini-Map for Overview Dashboard.
 */
export function renderMiniTopo(container, { spec, liveNodes = [], liveLinks = [], onNodeClick }) {
  if (!container) return;
  const nodeMap = spec?.nodes && Object.keys(spec.nodes).length ? spec.nodes : {};
  const tags = Object.keys(nodeMap).length
    ? Object.keys(nodeMap)
    : liveNodes.map((n) => n.node_tag);

  if (!tags.length) {
    container.innerHTML = `<div class="chart-empty">No topology or registered nodes yet. Add nodes in Topology or run Discovery.</div>`;
    return;
  }

  const onlineByTag = new Map(liveNodes.map((n) => [n.node_tag, n]));
  const linkHealthByPair = new Map();
  for (const l of liveLinks) {
    linkHealthByPair.set(`${l.node_tag}->${l.peer_tag}`, l);
  }

  // Group into columns by role
  const cols = { ingress: [], relay: [], egress: [], maintainer: [], other: [] };
  for (const tag of tags) {
    const r = nodeMap[tag]?.roles || {};
    const liveRoles = onlineByTag.get(tag)?.roles || [];
    const has = (name) => Boolean(r[name] || liveRoles.includes(name));
    if (has("ingress")) cols.ingress.push(tag);
    else if (has("relay")) cols.relay.push(tag);
    else if (has("egress")) cols.egress.push(tag);
    else if (has("maintainer")) cols.maintainer.push(tag);
    else cols.other.push(tag);
  }
  const activeCols = [cols.ingress, cols.relay, cols.egress, cols.maintainer, cols.other].filter(
    (c) => c.length > 0
  );

  const W = 620;
  const H = 240;
  const colStep = W / (activeCols.length + 1);
  const pos = new Map();
  activeCols.forEach((col, ci) => {
    const rowStep = H / (col.length + 1);
    col.forEach((tag, ri) => {
      pos.set(tag, { x: colStep * (ci + 1), y: rowStep * (ri + 1) });
    });
  });

  const links = Array.isArray(spec?.links) ? spec.links : [];
  let edgesSvg = "";
  links.forEach((lk) => {
    const a = pos.get(lk.from);
    const b = pos.get(lk.to);
    if (!a || !b) return;
    const h = linkHealthByPair.get(`${lk.from}->${lk.peer_tag || lk.to}`) || linkHealthByPair.get(`${lk.to}->${lk.from}`);
    const st = h?.state || "UNKNOWN";
    const stroke =
      st === "UP" ? "#009F6B" : st === "DEGRADED" ? "#FAC800" : st === "DOWN" ? "#C40233" : "#4DA9D6";
    const dash = lk.mode === "tunnel" ? 'stroke-dasharray="5 4"' : "";
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2 - 12;
    edgesSvg += `<path d="M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}" fill="none" stroke="${stroke}" stroke-width="2" ${dash} opacity="0.85" />`;
    if (h?.rtt_ms != null && Number.isFinite(Number(h.rtt_ms))) {
      edgesSvg += `<text x="${mx}" y="${my - 2}" text-anchor="middle" class="mini-edge-lbl">${esc(Math.round(Number(h.rtt_ms)))}ms</text>`;
    }
  });

  let nodesSvg = "";
  for (const tag of tags) {
    const p = pos.get(tag);
    if (!p) continue;
    const live = onlineByTag.get(tag);
    const online = live?.online ?? false;
    const dotColor = online ? "#009F6B" : live ? "#C40233" : "#64748b";
    const r = nodeMap[tag]?.roles || {};
    const liveRoles = live?.roles || [];
    const roleLabel = ["ingress", "relay", "egress", "maintainer"]
      .filter((k) => r[k] || liveRoles.includes(k))
      .map((k) => k[0].toUpperCase())
      .join("/") || "N";
    nodesSvg += `
      <g class="mini-node" data-mini-node="${esc(tag)}" transform="translate(${p.x - 56}, ${p.y - 20})">
        <rect width="112" height="40" rx="0" fill="#0f172a" stroke="${online ? "#4DA9D6" : "#334155"}" stroke-width="1.4" />
        <circle cx="13" cy="14" r="4" fill="${dotColor}" />
        <text x="23" y="17" class="mini-node-title">${esc(tag.slice(0, 12))}</text>
        <text x="13" y="31" class="mini-node-sub">${esc(roleLabel)} · ${online ? "ONLINE" : live ? "OFFLINE" : "DRAFT"}</text>
      </g>`;
  }

  container.innerHTML = `<svg viewBox="0 0 ${W} ${H}" class="mini-topo-svg">${edgesSvg}${nodesSvg}</svg>`;
  container.querySelectorAll("[data-mini-node]").forEach((g) => {
    g.addEventListener("click", () => {
      if (onNodeClick) onNodeClick(g.dataset.miniNode);
    });
  });
}
