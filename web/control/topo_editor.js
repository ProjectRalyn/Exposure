// Pro-Grade Visual Topology Editor for Exposure Control (Vanilla H5/CSS/JS)

const POS_STORAGE_KEY = "exposure_topo_positions_v2";
const NODE_W = 224;
const NODE_DEFAULT_H = 104;
const GRID_STEP = 20;

function loadPositions() {
  try {
    return JSON.parse(localStorage.getItem(POS_STORAGE_KEY) || "{}");
  } catch {
    return {};
  }
}

function savePositions(pos) {
  try {
    localStorage.setItem(POS_STORAGE_KEY, JSON.stringify(pos));
  } catch {
    // ignore quota errors
  }
}

function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function isReservedKey(k) {
  return k === "__proto__" || k === "prototype" || k === "constructor";
}

function generateRandomSecretHex(bytes = 32) {
  const buf = new Uint8Array(bytes);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function defaultNodeSpec() {
  return {
    roles: { ingress: false, egress: false, relay: false, maintainer: false },
    link_listener: {
      listen_addr: "0.0.0.0:10802",
      allow_on_demand: true,
      allow_tunnel: true,
      allow_bootstrap: false,
    },
    maintainer_template: null,
    maintainer_hops: [],
    ingress: {
      listeners: [],
      rules: [],
      guards: {},
      rate_limit_buckets: {},
      tls_certs: [],
      clearance_secret: generateRandomSecretHex(32),
      cert_store_dir: null,
    },
    egress: { services: {} },
    relay: { rules: [] },
  };
}

function rolesFromAny(rawRoles) {
  const base = { ingress: false, egress: false, relay: false, maintainer: false };
  if (Array.isArray(rawRoles)) {
    for (const r of rawRoles) {
      if (Object.hasOwn(base, r)) base[r] = true;
    }
    return base;
  }
  if (rawRoles && typeof rawRoles === "object") {
    return {
      ingress: Boolean(rawRoles.ingress),
      egress: Boolean(rawRoles.egress),
      relay: Boolean(rawRoles.relay),
      maintainer: Boolean(rawRoles.maintainer),
    };
  }
  return base;
}

function sanitizeRecord(obj) {
  const out = {};
  if (obj && typeof obj === "object" && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj)) {
      if (!isReservedKey(k)) out[k] = v;
    }
  }
  return out;
}

function normalizeNode(n) {
  const base = defaultNodeSpec();
  const out = { ...base, ...(n || {}) };
  out.roles = rolesFromAny(n?.roles);
  out.ingress = { ...base.ingress, ...(n?.ingress || {}) };
  if (!out.ingress.clearance_secret) {
    out.ingress.clearance_secret = base.ingress.clearance_secret;
  }
  out.ingress.listeners = Array.isArray(out.ingress.listeners) ? out.ingress.listeners : [];
  out.ingress.rules = Array.isArray(out.ingress.rules) ? out.ingress.rules : [];
  out.ingress.guards = sanitizeRecord(out.ingress.guards);
  out.ingress.rate_limit_buckets = sanitizeRecord(out.ingress.rate_limit_buckets);
  out.ingress.tls_certs = Array.isArray(out.ingress.tls_certs) ? out.ingress.tls_certs : [];
  out.egress = { ...base.egress, ...(n?.egress || {}) };
  out.egress.services = sanitizeRecord(out.egress.services);
  out.relay = { ...base.relay, ...(n?.relay || {}) };
  out.relay.rules = Array.isArray(out.relay.rules) ? out.relay.rules : [];
  out.maintainer_hops = Array.isArray(n?.maintainer_hops) ? n.maintainer_hops : [];
  return out;
}

function defaultMaintainerTemplate() {
  return {
    is_primary_cert_manager: true,
    acme: {
      directory_url: "self-signed",
      contact_email: "",
      storage_dir: "./data/certs",
      providers: {},
      orders: [],
    },
  };
}

function normalizeSpec(raw) {
  const nodes = {};
  if (raw && raw.nodes && typeof raw.nodes === "object") {
    for (const [tag, n] of Object.entries(raw.nodes)) {
      if (isReservedKey(tag)) continue;
      nodes[tag] = normalizeNode(n);
    }
  }
  const links = Array.isArray(raw?.links)
    ? raw.links.map((l) => ({
        from: l.from || "",
        to: l.to || "",
        peer_tag: l.peer_tag || null,
        mode: l.mode || "on-demand",
        tunnel_direction: l.tunnel_direction || (l.mode === "tunnel" ? "outbound" : null),
        bidirectional: l.bidirectional ?? true,
        expected_client_addr: l.expected_client_addr || null,
        endpoints: Array.isArray(l.endpoints) ? l.endpoints : [],
        reverse_endpoints: Array.isArray(l.reverse_endpoints) ? l.reverse_endpoints : [],
      }))
    : [];
  const maintainer_templates = sanitizeRecord(
    raw?.maintainer_templates && typeof raw.maintainer_templates === "object"
      ? deepClone(raw.maintainer_templates)
      : {}
  );
  const global_logger = raw?.global_logger || null;
  return { nodes, links, maintainer_templates, global_logger };
}

function parseNum(raw, fallback, min = -Infinity, max = Infinity) {
  if (raw === "" || raw == null) return fallback;
  const n = Number(raw);
  if (Number.isNaN(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function shortestPathBFS(links, start, goal) {
  if (!start || !goal) return null;
  if (start === goal) return [start];
  const adj = new Map();
  const add = (a, b) => {
    if (!adj.has(a)) adj.set(a, new Set());
    adj.get(a).add(b);
  };
  for (const l of links) {
    if (!l.from || !l.to) continue;
    add(l.from, l.to);
    if (l.mode === "tunnel") {
      add(l.to, l.from);
    } else if (l.mode === "on-demand" && l.bidirectional !== false && (l.reverse_endpoints || []).length > 0) {
      add(l.to, l.from);
    }
  }
  const visited = new Set([start]);
  const q = [[start]];
  while (q.length) {
    const path = q.shift();
    const last = path[path.length - 1];
    for (const nb of adj.get(last) || []) {
      if (visited.has(nb)) continue;
      const next = [...path, nb];
      if (nb === goal) return next;
      visited.add(nb);
      q.push(next);
    }
  }
  return null;
}

/**
 * Compute intersection of ray from rect center toward target point with rect perimeter.
 */
function rectAnchor(rect, target) {
  const cx = rect.x + rect.w / 2;
  const cy = rect.y + rect.h / 2;
  const dx = target.x - cx;
  const dy = target.y - cy;
  if (Math.abs(dx) < 0.001 && Math.abs(dy) < 0.001) return { x: cx, y: cy };
  const hw = rect.w / 2 + 4;
  const hh = rect.h / 2 + 4;
  const sx = Math.abs(dx) > 0.001 ? hw / Math.abs(dx) : Infinity;
  const sy = Math.abs(dy) > 0.001 ? hh / Math.abs(dy) : Infinity;
  const t = Math.min(sx, sy);
  return { x: cx + dx * t, y: cy + dy * t };
}

export function createTopoEditor({ api, showToast, el, onDirtyChange }) {
  const editor = {
    spec: { nodes: {}, links: [], maintainer_templates: {}, global_logger: null },
    positions: loadPositions(),
    nodeHeights: {},
    selected: null, // { type: 'node', tag } | { type: 'link', index }
    inspectorTab: "general", // general | ingress | guard | egress | relay | maintainer
    mode: "visual", // visual | yaml
    connectMode: false,
    connectSource: null,
    // Viewport transform
    view: { tx: 30, ty: 30, scale: 1 },
    snapGrid: true,
    showLiveOverlay: true,
    // Interactive drags
    dragNode: null,
    panDrag: null,
    wireDrag: null, // { fromTag, curX, curY }
    suppressCanvasClick: false,
    // Live telemetry & validation overlays
    liveNodes: new Map(), // tag -> nodeRecord
    liveLinks: [],
    compiledPaths: [],
    validationErrors: [],
    validationWarnings: [],
    tracedService: "",
    // History & dirty state
    dirty: false,
    undoStack: [],
    redoStack: [],
  };

  function markDirty(recordHistory = true) {
    if (recordHistory) {
      editor.undoStack.push(deepClone(editor.spec));
      if (editor.undoStack.length > 40) editor.undoStack.shift();
      editor.redoStack = [];
    }
    editor.dirty = true;
    updateDirtyBadge();
    if (onDirtyChange) onDirtyChange(true);
  }

  function clearDirty() {
    editor.dirty = false;
    updateDirtyBadge();
    if (onDirtyChange) onDirtyChange(false);
  }

  function updateDirtyBadge() {
    const badge = el("topo-dirty-badge");
    if (badge) badge.classList.toggle("hidden", !editor.dirty);
    const uBtn = el("btn-topo-undo");
    const rBtn = el("btn-topo-redo");
    if (uBtn) uBtn.disabled = editor.undoStack.length === 0;
    if (rBtn) rBtn.disabled = editor.redoStack.length === 0;
  }

  function undo() {
    if (!editor.undoStack.length) return;
    editor.redoStack.push(deepClone(editor.spec));
    editor.spec = editor.undoStack.pop();
    editor.dirty = true;
    updateDirtyBadge();
    render();
    showToast("Undid topology change");
  }

  function redo() {
    if (!editor.redoStack.length) return;
    editor.undoStack.push(deepClone(editor.spec));
    editor.spec = editor.redoStack.pop();
    editor.dirty = true;
    updateDirtyBadge();
    render();
    showToast("Redid topology change");
  }

  function screenToWorld(clientX, clientY) {
    const rect = el("topo-canvas").getBoundingClientRect();
    return {
      x: (clientX - rect.left - editor.view.tx) / editor.view.scale,
      y: (clientY - rect.top - editor.view.ty) / editor.view.scale,
    };
  }

  function applyViewportTransform() {
    const vp = el("topo-viewport");
    if (vp) {
      vp.style.transform = `translate(${editor.view.tx}px, ${editor.view.ty}px) scale(${editor.view.scale})`;
    }
    const canvas = el("topo-canvas");
    if (canvas) {
      const sz = Math.max(10, GRID_STEP * editor.view.scale);
      canvas.style.backgroundSize = `${sz}px ${sz}px`;
      canvas.style.backgroundPosition = `${editor.view.tx}px ${editor.view.ty}px`;
    }
    const zoomLbl = el("topo-zoom-label");
    if (zoomLbl) zoomLbl.textContent = `${Math.round(editor.view.scale * 100)}%`;
    renderMinimap();
  }

  function ensurePositions() {
    const tags = Object.keys(editor.spec.nodes);
    let idx = 0;
    for (const tag of tags) {
      if (!editor.positions[tag]) {
        const col = idx % 3;
        const row = Math.floor(idx / 3);
        editor.positions[tag] = { x: 40 + col * 290, y: 40 + row * 190 };
      }
      idx++;
    }
    savePositions(editor.positions);
  }

  function autoLayout() {
    const tags = Object.keys(editor.spec.nodes);
    const cols = { ingress: [], relay: [], egress: [], maintainer: [], other: [] };
    for (const tag of tags) {
      const r = editor.spec.nodes[tag].roles || {};
      if (r.ingress) cols.ingress.push(tag);
      else if (r.relay) cols.relay.push(tag);
      else if (r.egress) cols.egress.push(tag);
      else if (r.maintainer) cols.maintainer.push(tag);
      else cols.other.push(tag);
    }
    const orderedCols = [cols.ingress, cols.relay, cols.egress, cols.maintainer, cols.other].filter(
      (c) => c.length > 0
    );
    orderedCols.forEach((colTags, ci) => {
      colTags.forEach((tag, ri) => {
        editor.positions[tag] = { x: 40 + ci * 310, y: 40 + ri * 190 };
      });
    });
    savePositions(editor.positions);
    render();
    fitToView();
  }

  function fitToView() {
    const tags = Object.keys(editor.spec.nodes);
    const canvas = el("topo-canvas");
    if (!canvas) return;
    if (!tags.length) {
      editor.view = { tx: 30, ty: 30, scale: 1 };
      applyViewportTransform();
      return;
    }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const tag of tags) {
      const p = editor.positions[tag] || { x: 40, y: 40 };
      const h = editor.nodeHeights[tag] || NODE_DEFAULT_H;
      minX = Math.min(minX, p.x);
      minY = Math.min(minY, p.y);
      maxX = Math.max(maxX, p.x + NODE_W);
      maxY = Math.max(maxY, p.y + h);
    }
    const pad = 64;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 50 || rect.height < 50) return;
    const contentW = Math.max(100, maxX - minX + pad * 2);
    const contentH = Math.max(100, maxY - minY + pad * 2);
    const scale = Math.max(0.4, Math.min(1.25, Math.min(rect.width / contentW, rect.height / contentH)));
    editor.view.scale = scale;
    editor.view.tx = (rect.width - (maxX - minX) * scale) / 2 - minX * scale;
    editor.view.ty = (rect.height - (maxY - minY) * scale) / 2 - minY * scale;
    applyViewportTransform();
  }

  function focusNodeOnCanvas(tag) {
    if (!editor.spec.nodes[tag]) return;
    const p = editor.positions[tag] || { x: 40, y: 40 };
    const h = editor.nodeHeights[tag] || NODE_DEFAULT_H;
    const canvas = el("topo-canvas");
    if (canvas) {
      const rect = canvas.getBoundingClientRect();
      editor.view.tx = rect.width / 2 - (p.x + NODE_W / 2) * editor.view.scale;
      editor.view.ty = rect.height / 2 - (p.y + h / 2) * editor.view.scale;
      applyViewportTransform();
    }
    editor.selected = { type: "node", tag };
    editor.inspectorTab = "general";
    render();
  }

  function nodeRect(tag) {
    const p = editor.positions[tag] || { x: 40, y: 40 };
    return { x: p.x, y: p.y, w: NODE_W, h: editor.nodeHeights[tag] || NODE_DEFAULT_H };
  }

  function findLiveLinkHealth(link) {
    const peerName = link.peer_tag || link.to;
    return (
      editor.liveLinks.find((l) => l.node_tag === link.from && l.peer_tag === peerName) ||
      editor.liveLinks.find((l) => l.node_tag === link.from && l.peer_tag === link.to) ||
      (link.mode === "tunnel"
        ? editor.liveLinks.find((l) => l.node_tag === link.to && l.peer_tag === link.from)
        : null)
    );
  }

  function getTracedSets() {
    if (!editor.tracedService) return null;
    const matching = editor.compiledPaths.filter((p) => p.service_tag === editor.tracedService);
    const nodes = new Set();
    const edgePairs = new Set();
    let hasErr = false;
    for (const p of matching) {
      if (!p.valid) hasErr = true;
      (p.hops || []).forEach((h, i) => {
        nodes.add(h);
        if (i + 1 < p.hops.length) {
          edgePairs.add(`${h}->${p.hops[i + 1]}`);
          edgePairs.add(`${p.hops[i + 1]}->${h}`);
        }
      });
    }
    return { nodes, edgePairs, hasErr };
  }

  function getErrorNodeSet() {
    const bad = new Set();
    for (const err of editor.validationErrors) {
      for (const tag of Object.keys(editor.spec.nodes)) {
        if (err.includes(`'${tag}'`)) bad.add(tag);
      }
    }
    return bad;
  }

  function refreshTracerDropdown() {
    const sel = el("topo-trace-select");
    if (!sel) return;
    const svcs = new Set();
    for (const n of Object.values(editor.spec.nodes)) {
      for (const r of n.ingress?.rules || []) if (r.service_tag) svcs.add(r.service_tag);
      for (const s of Object.keys(n.egress?.services || {})) svcs.add(s);
    }
    for (const p of editor.compiledPaths) if (p.service_tag) svcs.add(p.service_tag);
    const sorted = [...svcs].sort();
    if (editor.tracedService && !svcs.has(editor.tracedService)) editor.tracedService = "";
    sel.innerHTML =
      `<option value="">Trace Service: Off</option>` +
      sorted
        .map(
          (s) =>
            `<option value="${escapeHtml(s)}" ${editor.tracedService === s ? "selected" : ""}>Trace: ${escapeHtml(s)}</option>`
        )
        .join("");
  }

  function renderEdges() {
    const svg = el("topo-svg");
    if (!svg) return;
    const defs = svg.querySelector("defs");
    svg.innerHTML = "";
    if (defs) svg.appendChild(defs);

    const NS = "http://www.w3.org/2000/svg";
    const traced = getTracedSets();

    // Identify bidirectional on-demand pairs to merge them into a single visual edge
    const onDemandReverse = new Map();
    editor.spec.links.forEach((l, idx) => {
      if (l.mode === "on-demand") {
        const revIdx = editor.spec.links.findIndex(
          (o, j) => j !== idx && o.mode === "on-demand" && o.from === l.to && o.to === l.from
        );
        if (revIdx !== -1) onDemandReverse.set(idx, revIdx);
      }
    });

    // Detect remaining multi-edge pairs (e.g. parallel tunnel + on-demand) to separate curves
    const pairCount = new Map();
    editor.spec.links.forEach((l, idx) => {
      const revIdx = onDemandReverse.get(idx);
      if (revIdx !== undefined && idx > revIdx) return;
      const k = [l.from, l.to].sort().join("::");
      pairCount.set(k, (pairCount.get(k) || 0) + 1);
    });

    editor.spec.links.forEach((link, idx) => {
      if (!editor.spec.nodes[link.from] || !editor.spec.nodes[link.to]) return;
      const revIdx = onDemandReverse.get(idx);
      if (revIdx !== undefined && idx > revIdx) return;
      const isMergedBidirectional = revIdx !== undefined;

      const ra = nodeRect(link.from);
      const rb = nodeRect(link.to);
      const ca = { x: ra.x + ra.w / 2, y: ra.y + ra.h / 2 };
      const cb = { x: rb.x + rb.w / 2, y: rb.y + rb.h / 2 };

      const a = rectAnchor(ra, cb);
      const b = rectAnchor(rb, ca);

      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const len = Math.hypot(dx, dy) || 1;
      const nx = -dy / len;
      const ny = dx / len;
      const multi = (pairCount.get([link.from, link.to].sort().join("::")) || 1) > 1;
      const bend = multi ? 34 : 16;
      const cx = (a.x + b.x) / 2 + nx * bend;
      const cy = (a.y + b.y) / 2 + ny * bend;

      const isBidirectionalSingle = link.mode === "on-demand" && link.bidirectional !== false;
      const isBidirectional = isMergedBidirectional || isBidirectionalSingle;
      const isSel =
        editor.selected?.type === "link" &&
        (editor.selected.index === idx || (isMergedBidirectional && editor.selected.index === revIdx));
      const liveH = editor.showLiveOverlay ? findLiveLinkHealth(link) : null;
      const isTraced = traced
        ? traced.edgePairs.has(`${link.from}->${link.to}`) ||
          (isMergedBidirectional && traced.edgePairs.has(`${link.to}->${link.from}`))
        : false;
      const isDimmed = traced && !isTraced;

      // Wide transparent hit stroke for effortless clicking
      const hitPath = document.createElementNS(NS, "path");
      hitPath.setAttribute("d", `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`);
      hitPath.setAttribute("class", "topo-edge-hit");
      hitPath.addEventListener("mousedown", (ev) => {
        ev.stopPropagation();
      });
      hitPath.addEventListener("click", (ev) => {
        ev.stopPropagation();
        editor.selected = { type: "link", index: idx };
        render();
      });
      svg.appendChild(hitPath);

      const path = document.createElementNS(NS, "path");
      path.setAttribute("d", `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`);

      const classes = ["topo-edge"];
      if (link.mode === "tunnel") classes.push("tunnel");
      if (isSel) classes.push("selected");
      if (isTraced) classes.push(traced.hasErr ? "traced-err" : "traced-ok");
      if (isDimmed) classes.push("dimmed");
      if (liveH?.state === "DEGRADED") classes.push("state-degraded");
      if (liveH?.state === "DOWN") classes.push("state-down");
      path.setAttribute("class", classes.join(" "));

      let marker = link.mode === "tunnel" ? "arrow-tunnel" : "arrow-ondemand";
      if (isSel) marker = "arrow-selected";
      else if (isTraced) marker = traced.hasErr ? "arrow-danger" : "arrow-tunnel";
      else if (liveH?.state === "DOWN") marker = "arrow-danger";
      else if (liveH?.state === "DEGRADED") marker = "arrow-selected";
      path.setAttribute("marker-end", `url(#${marker})`);
      if (isBidirectional) {
        path.setAttribute("marker-start", `url(#${marker})`);
      }
      svg.appendChild(path);

      // Midpoint pill label
      const midX = 0.25 * a.x + 0.5 * cx + 0.25 * b.x;
      const midY = 0.25 * a.y + 0.5 * cy + 0.25 * b.y;
      const epCount = link.endpoints?.length || 0;
      const modeShort =
        link.mode === "tunnel"
          ? `tunnel:${link.tunnel_direction || "out"}`
          : isBidirectional
          ? "on-demand ↔"
          : "on-demand";
      const rttTxt = liveH?.rtt_ms != null ? ` · ${liveH.rtt_ms}ms` : "";
      const textStr = `${modeShort}${epCount > 1 ? ` ×${epCount}` : ""}${rttTxt}`;

      const g = document.createElementNS(NS, "g");
      g.setAttribute("class", `topo-edge-pill ${isSel ? "selected" : ""} ${isDimmed ? "dimmed" : ""}`);
      g.setAttribute("transform", `translate(${midX.toFixed(1)}, ${midY.toFixed(1)})`);
      const pillW = Math.max(66, textStr.length * 6.5 + 16);
      const rect = document.createElementNS(NS, "rect");
      rect.setAttribute("x", String(-pillW / 2));
      rect.setAttribute("y", "-10");
      rect.setAttribute("width", String(pillW));
      rect.setAttribute("height", "20");
      rect.setAttribute("rx", "10");
      g.appendChild(rect);

      if (liveH) {
        const dot = document.createElementNS(NS, "circle");
        dot.setAttribute("cx", String(-pillW / 2 + 9));
        dot.setAttribute("cy", "0");
        dot.setAttribute("r", "3");
        dot.setAttribute(
          "fill",
          liveH.state === "UP" ? "#009F6B" : liveH.state === "DEGRADED" ? "#FAC800" : "#C40233"
        );
        g.appendChild(dot);
      }

      const label = document.createElementNS(NS, "text");
      label.setAttribute("x", liveH ? "4" : "0");
      label.setAttribute("y", "3.5");
      label.setAttribute("text-anchor", "middle");
      label.setAttribute("class", "topo-edge-label");
      label.textContent = textStr;
      g.appendChild(label);

      g.addEventListener("mousedown", (ev) => {
        ev.stopPropagation();
      });
      g.addEventListener("click", (ev) => {
        ev.stopPropagation();
        editor.selected = { type: "link", index: idx };
        render();
      });
      svg.appendChild(g);
    });

    // Live rubber-band wire while dragging from a port
    if (editor.wireDrag && editor.spec.nodes[editor.wireDrag.fromTag]) {
      const ra = nodeRect(editor.wireDrag.fromTag);
      const target = { x: editor.wireDrag.curX, y: editor.wireDrag.curY };
      const a = rectAnchor(ra, target);
      const mx = (a.x + target.x) / 2;
      const wire = document.createElementNS(NS, "path");
      wire.setAttribute(
        "d",
        `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} C ${mx.toFixed(1)} ${a.y.toFixed(1)}, ${mx.toFixed(1)} ${target.y.toFixed(1)}, ${target.x.toFixed(1)} ${target.y.toFixed(1)}`
      );
      wire.setAttribute("class", "topo-wire-preview");
      wire.setAttribute("marker-end", "url(#arrow-selected)");
      svg.appendChild(wire);
    }
  }

  function renderNodes() {
    const layer = el("topo-nodes-layer");
    if (!layer) return;
    layer.innerHTML = "";

    const traced = getTracedSets();
    const errorNodes = getErrorNodeSet();

    for (const [tag, node] of Object.entries(editor.spec.nodes)) {
      const pos = editor.positions[tag] || { x: 40, y: 40 };
      const card = document.createElement("div");
      const isSel = editor.selected?.type === "node" && editor.selected.tag === tag;
      const isConnSrc = editor.connectMode && editor.connectSource === tag;
      const isTraced = traced ? traced.nodes.has(tag) : false;
      const isDimmed = traced && !isTraced;
      const hasErr = errorNodes.has(tag);
      const live = editor.liveNodes.get(tag);

      const classes = ["topo-node"];
      if (isSel) classes.push("selected");
      if (isConnSrc) classes.push("connect-src");
      if (isTraced) classes.push("traced");
      if (isDimmed) classes.push("dimmed");
      if (hasErr) classes.push("has-error");
      if (node.roles?.ingress) classes.push("accent-ingress");
      else if (node.roles?.relay) classes.push("accent-relay");
      else if (node.roles?.egress) classes.push("accent-egress");
      else if (node.roles?.maintainer) classes.push("accent-maintainer");

      card.className = classes.join(" ");
      card.dataset.nodeTag = tag;
      card.style.left = `${pos.x}px`;
      card.style.top = `${pos.y}px`;

      const roles = ["ingress", "egress", "relay", "maintainer"].filter((r) => node.roles?.[r]);
      const roleBadges = roles.map((r) => `<span class="role-chip ${r}">${r}</span>`).join("");

      const summary = [];
      if (node.link_listener?.listen_addr) summary.push(`link ${node.link_listener.listen_addr}`);
      if (node.roles?.ingress) {
        const lCount = node.ingress?.listeners?.length || 0;
        const rCount = node.ingress?.rules?.length || 0;
        const gCount = Object.keys(node.ingress?.guards || {}).length;
        summary.push(`in: ${lCount}L · ${rCount}R${gCount ? ` · ${gCount}G` : ""}`);
      }
      if (node.roles?.egress) {
        const svcs = Object.keys(node.egress?.services || {});
        summary.push(`out: ${svcs.length ? svcs.slice(0, 3).join(", ") : "0 svc"}`);
      }
      if (node.roles?.relay) {
        summary.push(`relay: ${node.relay?.rules?.length || 0} rule(s)`);
      }
      if (node.roles?.maintainer) {
        const tpl = editor.spec.maintainer_templates?.[node.maintainer_template || "default-maint"];
        const ord = tpl?.acme?.orders?.length || 0;
        summary.push(`maint: ${ord} cert order(s)`);
      }

      const statusDot = editor.showLiveOverlay
        ? live?.online
          ? `<span class="live-dot online" title="Online (seq #${Number(live.config_seq) || 0})"></span>`
          : live
          ? `<span class="live-dot offline" title="Offline"></span>`
          : `<span class="live-dot draft" title="Draft (not registered)"></span>`
        : "";

      card.innerHTML = `
        <div class="topo-node-head">
          <span class="topo-node-title-wrap">${statusDot}<span class="topo-node-title">${escapeHtml(tag)}</span></span>
          ${hasErr ? `<span class="node-err-badge" title="Has validation errors">!</span>` : ""}
        </div>
        <div class="topo-roles">${roleBadges || '<span class="role-chip">node</span>'}</div>
        <div class="topo-node-meta">${summary.map(escapeHtml).join("<br/>") || "No endpoints configured"}</div>
        <span class="node-port port-n" data-port="${escapeHtml(tag)}" title="Drag to connect link"></span>
        <span class="node-port port-s" data-port="${escapeHtml(tag)}" title="Drag to connect link"></span>
        <span class="node-port port-e" data-port="${escapeHtml(tag)}" title="Drag to connect link"></span>
        <span class="node-port port-w" data-port="${escapeHtml(tag)}" title="Drag to connect link"></span>
      `;

      // Port drag-to-connect!
      card.querySelectorAll(".node-port").forEach((port) => {
        port.addEventListener("mousedown", (ev) => {
          if (ev.button !== 0) return;
          ev.stopPropagation();
          const pt = screenToWorld(ev.clientX, ev.clientY);
          editor.wireDrag = { fromTag: tag, curX: pt.x, curY: pt.y };
          renderEdges();
        });
      });

      card.addEventListener("mouseup", (ev) => {
        if (editor.wireDrag && editor.wireDrag.fromTag !== tag) {
          ev.stopPropagation();
          const src = editor.wireDrag.fromTag;
          editor.wireDrag = null;
          createLinkBetween(src, tag);
        }
      });

      card.addEventListener("click", (ev) => {
        ev.stopPropagation();
      });

      card.addEventListener("mousedown", (ev) => {
        if (ev.button !== 0) return;
        if (ev.target.classList.contains("node-port")) return;
        ev.stopPropagation();
        ev.preventDefault();
        if (editor.connectMode) {
          handleConnectClick(tag);
          return;
        }
        const prevSelectedTag = editor.selected?.type === "node" ? editor.selected.tag : null;
        editor.selected = { type: "node", tag };
        if (prevSelectedTag !== tag) editor.inspectorTab = "general";

        const worldStart = screenToWorld(ev.clientX, ev.clientY);
        editor.dragNode = {
          tag,
          startWorldX: worldStart.x,
          startWorldY: worldStart.y,
          origX: pos.x,
          origY: pos.y,
          moved: false,
          selectionChanged: prevSelectedTag !== tag,
        };
        // Highlight selected card immediately without tearing down DOM mid-drag
        layer.querySelectorAll(".topo-node").forEach((c) => {
          c.classList.toggle("selected", c.dataset.nodeTag === tag);
        });
        renderEdges();
        if (prevSelectedTag !== tag) {
          renderInspector();
        }
      });

      layer.appendChild(card);
      // Measure actual rendered height for accurate perimeter anchoring
      editor.nodeHeights[tag] = card.offsetHeight || NODE_DEFAULT_H;
    }
  }

  function createLinkBetween(fromTag, toTag) {
    if (!fromTag || !toTag || fromTag === toTag) return;
    markDirty(true);
    const targetNode = editor.spec.nodes[toTag];
    const knownEp =
      editor.spec.links.find((l) => l.to === toTag && l.endpoints?.[0]?.address)?.endpoints[0].address ||
      editor.liveLinks.find((l) => l.peer_tag === toTag && l.endpoint && !l.endpoint.startsWith("127."))?.endpoint;
    const port = targetNode?.link_listener?.listen_addr?.split(":").pop() || "10802";
    const defaultAddr = knownEp || `<TARGET_IP>:${port}`;
    const fromNode = editor.spec.nodes[fromTag];
    const fromKnownEp =
      editor.spec.links.find((l) => l.to === fromTag && l.endpoints?.[0]?.address)?.endpoints[0].address ||
      editor.liveLinks.find((l) => l.peer_tag === fromTag && l.endpoint && !l.endpoint.startsWith("127."))?.endpoint;
    const fromPort = fromNode?.link_listener?.listen_addr?.split(":").pop() || "10802";
    const revAddr = fromKnownEp || `<${fromTag}_IP>:${fromPort}`;
    editor.spec.links.push({
      from: fromTag,
      to: toTag,
      peer_tag: null,
      mode: "on-demand",
      tunnel_direction: null,
      bidirectional: true,
      expected_client_addr: null,
      endpoints: [{ address: defaultAddr, priority: 10, weight: 100 }],
      reverse_endpoints: [{ address: revAddr, priority: 10, weight: 100 }],
    });
    editor.selected = { type: "link", index: editor.spec.links.length - 1 };
    editor.connectMode = false;
    editor.connectSource = null;
    el("topo-connect-hint")?.classList.add("hidden");
    el("btn-connect-mode")?.classList.remove("primary");
    render();
    showToast(`Linked ${fromTag} → ${toTag}`);
  }

  function handleConnectClick(tag) {
    if (!editor.connectSource) {
      editor.connectSource = tag;
      render();
      return;
    }
    if (editor.connectSource === tag) {
      editor.connectSource = null;
      render();
      return;
    }
    createLinkBetween(editor.connectSource, tag);
  }

  function renderMinimap() {
    const mm = el("topo-minimap");
    const canvas = el("topo-canvas");
    if (!mm || !canvas) return;
    const tags = Object.keys(editor.spec.nodes);
    if (!tags.length) {
      mm.innerHTML = "";
      return;
    }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const tag of tags) {
      const p = editor.positions[tag] || { x: 40, y: 40 };
      minX = Math.min(minX, p.x);
      minY = Math.min(minY, p.y);
      maxX = Math.max(maxX, p.x + NODE_W);
      maxY = Math.max(maxY, p.y + (editor.nodeHeights[tag] || NODE_DEFAULT_H));
    }
    minX -= 80;
    minY -= 80;
    maxX += 80;
    maxY += 80;
    const w = Math.max(300, maxX - minX);
    const h = Math.max(200, maxY - minY);
    const mw = 156;
    const mh = 96;
    const s = Math.min(mw / w, mh / h);
    const ox = (mw - w * s) / 2 - minX * s;
    const oy = (mh - h * s) / 2 - minY * s;

    let rects = "";
    for (const tag of tags) {
      const p = editor.positions[tag] || { x: 40, y: 40 };
      const isSel = editor.selected?.type === "node" && editor.selected.tag === tag;
      rects += `<rect x="${(p.x * s + ox).toFixed(1)}" y="${(p.y * s + oy).toFixed(1)}" width="${Math.max(5, NODE_W * s).toFixed(1)}" height="${Math.max(4, NODE_DEFAULT_H * s).toFixed(1)}" rx="0" fill="${isSel ? "#4DA9D6" : "#334155"}" />`;
    }

    const cr = canvas.getBoundingClientRect();
    const vx = (-editor.view.tx / editor.view.scale) * s + ox;
    const vy = (-editor.view.ty / editor.view.scale) * s + oy;
    const vw = (cr.width / editor.view.scale) * s;
    const vh = (cr.height / editor.view.scale) * s;

    mm.innerHTML = `<svg viewBox="0 0 ${mw} ${mh}" width="${mw}" height="${mh}">
      ${rects}
      <rect x="${vx.toFixed(1)}" y="${vy.toFixed(1)}" width="${Math.max(8, vw).toFixed(1)}" height="${Math.max(8, vh).toFixed(1)}" fill="rgba(56,189,248,0.12)" stroke="#4DA9D6" stroke-width="1" />
    </svg>`;
  }

  function renderValidationBar() {
    const bar = el("topo-validation-bar");
    if (!bar) return;
    const errs = editor.validationErrors || [];
    const warns = editor.validationWarnings || [];
    if (!errs.length && !warns.length) {
      bar.classList.remove("ok", "err");
      bar.classList.add("hidden");
      return;
    }
    bar.classList.remove("hidden", "ok", "err");
    const items = [
      ...errs.map((msg) => ({ kind: "err", msg })),
      ...warns.map((msg) => ({ kind: "warn", msg })),
    ];
    bar.innerHTML = `
      <div class="val-bar-head">
        <span>
          <span class="pill ${errs.length ? "err" : "ok"}">${errs.length} error(s)</span>
          <span class="pill warn">${warns.length} warning(s)</span>
          <small class="muted" style="margin-left:8px;">Click any item to focus the node on canvas</small>
        </span>
        <button id="btn-close-valbar" class="btn sm ghost">Dismiss</button>
      </div>
      <div class="val-items">
        ${items
          .map(
            (it, i) => `
          <button class="val-item ${it.kind}" data-val-idx="${i}">
            <span class="pill ${it.kind}">${it.kind === "err" ? "ERR" : "WARN"}</span>
            <span>${escapeHtml(it.msg)}</span>
          </button>`
          )
          .join("")}
      </div>
    `;
    bar.querySelector("#btn-close-valbar")?.addEventListener("click", () => {
      bar.classList.add("hidden");
    });
    bar.querySelectorAll("[data-val-idx]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const msg = items[Number(btn.dataset.valIdx)].msg;
        for (const tag of Object.keys(editor.spec.nodes)) {
          if (msg.includes(`'${tag}'`)) {
            focusNodeOnCanvas(tag);
            return;
          }
        }
      });
    });
  }

  function renderInspector() {
    const box = el("topo-inspector");
    if (!box) return;
    const prevScroll = box.scrollTop;

    if (!editor.selected) {
      const nodeTags = Object.keys(editor.spec.nodes);
      const nCount = nodeTags.length;
      const lCount = editor.spec.links.length;
      const pCount = editor.compiledPaths.length;
      const quickNodes = nodeTags
        .map((t) => {
          const roles = ["ingress", "relay", "egress", "maintainer"]
            .filter((r) => editor.spec.nodes[t]?.roles?.[r])
            .map((r) => `<span class="role-chip ${r}">${r[0].toUpperCase()}</span>`)
            .join("");
          return `<button type="button" class="quick-item" data-q-node="${escapeHtml(t)}"><span>${escapeHtml(t)}</span><span class="btn-row">${roles}</span></button>`;
        })
        .join("");
      const quickLinks = editor.spec.links
        .map(
          (l, i) =>
            `<button type="button" class="quick-item" data-q-link="${i}"><span>${escapeHtml(l.from)} → ${escapeHtml(l.to)}</span><span class="pill ${l.mode === "tunnel" ? "ok" : ""}">${escapeHtml(l.mode)}</span></button>`
        )
        .join("");

      box.innerHTML = `
        <div class="inspector-empty">
          <div class="inspector-empty-title">Topology Inspector</div>
          <p>Click a <b>node</b> or <b>link</b> on the canvas (or below) to configure it.</p>
          <div class="inspector-tips">
            <div><b>Drag node card</b> → move · <b>Drag port dot</b> → connect link</div>
            <div><b>Scroll wheel</b> → zoom · <b>Drag empty canvas</b> → pan</div>
            <div><b>Ctrl+Z / Ctrl+Y</b> → undo/redo · <b>Del</b> → delete · <b>F</b> → fit</div>
          </div>
          <div class="inspector-summary-pills">
            <span class="pill ok">${nCount} nodes</span>
            <span class="pill">${lCount} links</span>
            <span class="pill">${pCount} routes</span>
          </div>
        </div>
        ${
          nodeTags.length
            ? `<div class="inspector-sec">
                <div class="inspector-sec-head"><span>Nodes (${nCount})</span></div>
                <div class="quick-list">${quickNodes}</div>
              </div>`
            : ""
        }
        ${
          lCount
            ? `<div class="inspector-sec">
                <div class="inspector-sec-head"><span>Links (${lCount})</span></div>
                <div class="quick-list">${quickLinks}</div>
              </div>`
            : ""
        }`;
      box.querySelectorAll("[data-q-node]").forEach((b) =>
        b.addEventListener("click", () => focusNodeOnCanvas(b.dataset.qNode))
      );
      box.querySelectorAll("[data-q-link]").forEach((b) =>
        b.addEventListener("click", () => {
          editor.selected = { type: "link", index: Number(b.dataset.qLink) };
          render();
        })
      );
      return;
    }

    if (editor.selected.type === "node") {
      const tag = editor.selected.tag;
      const node = editor.spec.nodes[tag];
      if (!node) {
        editor.selected = null;
        renderInspector();
        return;
      }
      renderNodeInspector(box, tag, node);
    } else if (editor.selected.type === "link") {
      const idx = editor.selected.index;
      const link = editor.spec.links[idx];
      if (!link) {
        editor.selected = null;
        renderInspector();
        return;
      }
      renderLinkInspector(box, idx, link);
    }

    box.scrollTop = prevScroll;
  }

  function renderNodeInspector(box, tag, node) {
    const allTags = Object.keys(editor.spec.nodes);
    // Connected peer tags + self tag for smart Next Peer suggestions
    const connectedPeers = new Set([tag]);
    for (const l of editor.spec.links) {
      if (l.from === tag) connectedPeers.add(l.peer_tag || l.to);
      if (l.to === tag && l.mode === "tunnel") connectedPeers.add(l.from);
    }
    const peerOptions = [...new Set([...connectedPeers, ...allTags])]
      .map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t === tag ? `${t} (local egress)` : t)}</option>`)
      .join("");

    // Defined egress service tags across the whole topology for autocomplete
    const allServices = new Set();
    for (const n of Object.values(editor.spec.nodes)) {
      for (const s of Object.keys(n.egress?.services || {})) allServices.add(s);
    }
    const svcOptions = [...allServices]
      .sort()
      .map((s) => `<option value="${escapeHtml(s)}"></option>`)
      .join("");

    const ingressNodes = allTags.filter((t) => editor.spec.nodes[t]?.roles?.ingress);
    const maintainerNodes = allTags.filter((t) => editor.spec.nodes[t]?.roles?.maintainer);

    // Build role-aware tabs
    const tabs = [{ id: "general", label: "General", badge: "" }];
    if (node.roles.ingress) {
      const cnt = (node.ingress.listeners?.length || 0) + (node.ingress.rules?.length || 0);
      tabs.push({ id: "ingress", label: "Ingress", badge: cnt ? String(cnt) : "" });
      const gCnt = Object.keys(node.ingress.guards || {}).length + Object.keys(node.ingress.rate_limit_buckets || {}).length;
      tabs.push({ id: "guard", label: "Guard", badge: gCnt ? String(gCnt) : "" });
    }
    if (node.roles.egress) {
      const cnt = Object.keys(node.egress.services || {}).length;
      tabs.push({ id: "egress", label: "Egress", badge: cnt ? String(cnt) : "" });
    }
    if (node.roles.relay) {
      const cnt = node.relay.rules?.length || 0;
      tabs.push({ id: "relay", label: "Relay", badge: cnt ? String(cnt) : "" });
    }
    if (node.roles.maintainer) {
      tabs.push({ id: "maintainer", label: "Maintainer", badge: "" });
    }

    if (!tabs.some((t) => t.id === editor.inspectorTab)) {
      editor.inspectorTab = "general";
    }

    const tabsHtml = tabs
      .map(
        (t) =>
          `<button class="insp-tab ${editor.inspectorTab === t.id ? "active" : ""}" data-insp-tab="${t.id}">
            ${escapeHtml(t.label)}${t.badge ? `<span class="insp-badge">${t.badge}</span>` : ""}
          </button>`
      )
      .join("");

    let bodyHtml = "";
    if (editor.inspectorTab === "general") {
      bodyHtml = renderGeneralTab(tag, node, maintainerNodes);
    } else if (editor.inspectorTab === "ingress") {
      bodyHtml = renderIngressTab(node);
    } else if (editor.inspectorTab === "guard") {
      bodyHtml = renderGuardTab(node);
    } else if (editor.inspectorTab === "egress") {
      bodyHtml = renderEgressTab(node, ingressNodes);
    } else if (editor.inspectorTab === "relay") {
      bodyHtml = renderRelayTab(node);
    } else if (editor.inspectorTab === "maintainer") {
      bodyHtml = renderMaintainerTab(tag, node);
    }

    const live = editor.liveNodes.get(tag);
    const liveBadge = live
      ? `<span class="pill ${live.online ? "ok" : "err"}">${live.online ? `ONLINE · seq #${Number(live.config_seq) || 0}` : "OFFLINE"}</span>`
      : `<span class="pill">DRAFT</span>`;

    box.innerHTML = `
      <datalist id="peer-tags-list">${peerOptions}</datalist>
      <datalist id="service-tags-list">${svcOptions}</datalist>
      <div class="inspector-header">
        <div>
          <div class="inspector-title">${escapeHtml(tag)}</div>
          <div class="inspector-sub">${liveBadge}</div>
        </div>
        <div class="btn-row">
          <button id="btn-dup-node" class="btn sm" title="Duplicate Node">Clone</button>
          <button id="btn-del-node" class="btn sm danger">Delete</button>
        </div>
      </div>
      <div class="inspector-role-bar">
        <label class="role-toggle ${node.roles.ingress ? "on ingress" : ""}"><input type="checkbox" id="chk-role-ingress" ${node.roles.ingress ? "checked" : ""} />ingress</label>
        <label class="role-toggle ${node.roles.relay ? "on relay" : ""}"><input type="checkbox" id="chk-role-relay" ${node.roles.relay ? "checked" : ""} />relay</label>
        <label class="role-toggle ${node.roles.egress ? "on egress" : ""}"><input type="checkbox" id="chk-role-egress" ${node.roles.egress ? "checked" : ""} />egress</label>
        <label class="role-toggle ${node.roles.maintainer ? "on maintainer" : ""}"><input type="checkbox" id="chk-role-maintainer" ${node.roles.maintainer ? "checked" : ""} />maintainer</label>
      </div>
      <div class="insp-tabs">${tabsHtml}</div>
      <div class="insp-body">${bodyHtml}</div>
    `;

    // Tab switch
    box.querySelectorAll("[data-insp-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        editor.inspectorTab = btn.dataset.inspTab;
        renderInspector();
      });
    });

    // Header actions
    box.querySelector("#btn-del-node").addEventListener("click", () => {
      markDirty(true);
      delete editor.spec.nodes[tag];
      editor.spec.links = editor.spec.links.filter((l) => l.from !== tag && l.to !== tag);
      editor.selected = null;
      render();
    });

    box.querySelector("#btn-dup-node").addEventListener("click", () => {
      markDirty(true);
      let k = 2;
      let newTag = `${tag}-${k}`;
      while (editor.spec.nodes[newTag]) newTag = `${tag}-${++k}`;
      editor.spec.nodes[newTag] = deepClone(node);
      const p = editor.positions[tag] || { x: 40, y: 40 };
      editor.positions[newTag] = { x: p.x + 40, y: p.y + 40 };
      editor.selected = { type: "node", tag: newTag };
      savePositions(editor.positions);
      render();
    });

    ["ingress", "egress", "relay", "maintainer"].forEach((r) => {
      box.querySelector(`#chk-role-${r}`).addEventListener("change", (ev) => {
        markDirty(true);
        node.roles[r] = ev.target.checked;
        if (ev.target.checked) editor.inspectorTab = r;
        render();
      });
    });

    wireTabEvents(box, tag, node, maintainerNodes);
  }

  function renderGeneralTab(tag, node, maintainerNodes) {
    return `
      <div class="inspector-sec">
        <div class="inspector-sec-head"><span>Identity &amp; Mesh Listener</span></div>
        <label><span>Node Tag</span><input id="inp-node-tag" value="${escapeHtml(tag)}" /></label>
        <label><span>Link Listener Address (empty = outbound-only)</span>
          <input id="inp-link-listen" value="${escapeHtml(node.link_listener?.listen_addr || "")}" placeholder="0.0.0.0:10802" />
        </label>
        <div class="inspector-checks">
          <label class="check-inline"><input type="checkbox" id="chk-allow-ondemand" ${node.link_listener?.allow_on_demand !== false ? "checked" : ""} /> on-demand</label>
          <label class="check-inline"><input type="checkbox" id="chk-allow-tunnel" ${node.link_listener?.allow_tunnel !== false ? "checked" : ""} /> tunnel</label>
          <label class="check-inline"><input type="checkbox" id="chk-allow-boot" ${node.link_listener?.allow_bootstrap ? "checked" : ""} /> allow bootstrap</label>
        </div>
      </div>
      <div class="inspector-sec">
        <div class="inspector-sec-head">
          <span>Maintainer Telemetry Hop Table</span>
          ${maintainerNodes.length ? `<button id="btn-auto-mhops" class="btn sm">Auto Path</button>` : ""}
        </div>
        <label><span>Explicit Node Tag Hops (CSV)</span>
          <input id="inp-maint-hops" value="${escapeHtml((node.maintainer_hops || []).join(", "))}" placeholder="${escapeHtml(tag)}, relay-1, maintainer-1" />
        </label>
      </div>
    `;
  }

  function renderIngressTab(node) {
    const guardNames = Object.keys(node.ingress.guards || {});
    const listenersHtml = (node.ingress.listeners || [])
      .map(
        (l, i) => `
      <div class="subcard">
        <div class="subcard-head">
          <span>Listener #${i + 1}</span>
          <button class="btn sm danger" data-del-listener="${i}">Remove</button>
        </div>
        <div class="inspector-row">
          <label><span>Listen Addr</span><input data-l-addr="${i}" value="${escapeHtml(l.listen_addr || "")}" placeholder="0.0.0.0:8080" /></label>
          <label class="check-inline" style="align-self:end;padding-bottom:8px;">
            <input type="checkbox" data-l-tls="${i}" ${l.tls ? "checked" : ""} /> TLS (HTTPS + h2)
          </label>
        </div>
      </div>`
      )
      .join("");

    const rulesHtml = (node.ingress.rules || [])
      .map(
        (r, i) => `
      <div class="subcard">
        <div class="subcard-head">
          <span>Rule #${i + 1}${r.service_tag ? ` · ${escapeHtml(r.service_tag)}` : ""}</span>
          <button class="btn sm danger" data-del-irule="${i}">Remove</button>
        </div>
        <div class="inspector-row">
          <label><span>Rule Name</span><input data-ir-name="${i}" value="${escapeHtml(r.name || "")}" placeholder="web-main" /></label>
          <label><span>Service Tag</span><input list="service-tags-list" data-ir-svc="${i}" value="${escapeHtml(r.service_tag || "")}" placeholder="web@default" /></label>
        </div>
        <div class="inspector-row">
          <label><span>Match Host</span><input data-ir-host="${i}" value="${escapeHtml(r.match?.host || "")}" placeholder="*.example.com" /></label>
          <label><span>Next Peer</span><input list="peer-tags-list" data-ir-peer="${i}" value="${escapeHtml(r.next_peer || "")}" placeholder="relay-1 or self" /></label>
        </div>
        <div class="inspector-row">
          <label><span>URL Prefix</span><input data-ir-prefix="${i}" value="${escapeHtml(r.match?.url_prefix || "")}" placeholder="/api" /></label>
          <label><span>TLS SNI</span><input data-ir-sni="${i}" value="${escapeHtml(r.match?.sni || "")}" placeholder="example.com" /></label>
        </div>
        <div class="inspector-row">
          <label><span>Source CIDRs (CSV)</span><input data-ir-cidrs="${i}" value="${escapeHtml((r.match?.source_cidrs || []).join(", "))}" placeholder="203.0.113.0/24" /></label>
          <label><span>Guard Profile</span>
            <select data-ir-guard="${i}">
              <option value="">(none)</option>
              ${guardNames.map((g) => `<option value="${escapeHtml(g)}" ${r.guard === g ? "selected" : ""}>${escapeHtml(g)}</option>`).join("")}
            </select>
          </label>
        </div>
        <div class="inspector-checks">
          <label class="check-inline"><input type="checkbox" data-ir-intercept="${i}" ${r.intercept_errors ? "checked" : ""} /> Intercept Errors (429 / 5xx Exposure Page)</label>
        </div>
      </div>`
      )
      .join("");

    const tlsCertsHtml = (node.ingress.tls_certs || [])
      .map(
        (c, i) => `
      <div class="subcard">
        <div class="subcard-head">
          <span>Static Cert #${i + 1}</span>
          <button class="btn sm danger" data-del-cert="${i}">Remove</button>
        </div>
        <label><span>Domain</span><input data-ic-dom="${i}" value="${escapeHtml(c.domain || "")}" placeholder="example.com" /></label>
        <div class="inspector-row">
          <label><span>Cert Path</span><input data-ic-cert="${i}" value="${escapeHtml(c.cert_path || "")}" /></label>
          <label><span>Key Path</span><input data-ic-key="${i}" value="${escapeHtml(c.key_path || "")}" /></label>
        </div>
      </div>`
      )
      .join("");

    return `
      <div class="inspector-sec">
        <div class="inspector-sec-head">
          <span>Listeners (${node.ingress.listeners.length})</span>
          <button id="btn-add-listener" class="btn sm">+ Listener</button>
        </div>
        ${listenersHtml || '<div class="muted-sm">No ingress listeners yet.</div>'}
      </div>
      <div class="inspector-sec">
        <div class="inspector-sec-head">
          <span>Routing Rules (${node.ingress.rules.length})</span>
          <button id="btn-add-irule" class="btn sm">+ Rule</button>
        </div>
        ${rulesHtml || '<div class="muted-sm">No ingress routing rules yet.</div>'}
      </div>
      <div class="inspector-sec">
        <div class="inspector-sec-head">
          <span>TLS &amp; Clearance</span>
          <button id="btn-add-cert" class="btn sm">+ Static Cert</button>
        </div>
        <div class="inspector-row">
          <label><span>Cert Store Dir</span><input id="inp-cert-dir" value="${escapeHtml(node.ingress.cert_store_dir || "")}" placeholder="./data/ingress-certs" /></label>
          <label><span>Server Header</span>
            <select id="sel-server-hdr">
              <option value="nginx" ${(node.ingress.server_header || "nginx") === "nginx" ? "selected" : ""}>nginx (Disguised)</option>
              <option value="exposure" ${node.ingress.server_header === "exposure" ? "selected" : ""}>exposure</option>
            </select>
          </label>
          <label><span>Clearance Secret</span><input id="inp-clear-sec" type="password" autocomplete="off" spellcheck="false" value="${escapeHtml(node.ingress.clearance_secret || "")}" /></label>
        </div>
        ${tlsCertsHtml}
      </div>
    `;
  }

  function renderGuardTab(node) {
    const bucketNames = Object.keys(node.ingress.rate_limit_buckets || {});
    const bucketsHtml = Object.entries(node.ingress.rate_limit_buckets || {})
      .map(
        ([bName, b]) => `
      <div class="subcard">
        <div class="subcard-head">
          <span>Bucket: ${escapeHtml(bName)}</span>
          <button class="btn sm danger" data-del-bucket="${escapeHtml(bName)}">Remove</button>
        </div>
        <div class="inspector-row">
          <label><span>Name</span><input data-bk-name="${escapeHtml(bName)}" value="${escapeHtml(bName)}" /></label>
          <label><span>Capacity</span><input type="number" step="1" data-bk-cap="${escapeHtml(bName)}" value="${b.capacity ?? 60}" /></label>
        </div>
        <div class="inspector-row">
          <label><span>Refill / sec</span><input type="number" step="0.5" data-bk-refill="${escapeHtml(bName)}" value="${b.refill_per_sec ?? 10}" /></label>
          <label class="check-inline" style="align-self:end;padding-bottom:8px;">
            <input type="checkbox" data-bk-perip="${escapeHtml(bName)}" ${b.per_ip !== false ? "checked" : ""} /> Per-IP
          </label>
        </div>
      </div>`
      )
      .join("");

    const guardsHtml = Object.entries(node.ingress.guards || {})
      .map(([gName, g]) => {
        const boundRules = (node.ingress.rules || []).filter((r) => r.guard === gName).length;
        const totalRules = (node.ingress.rules || []).length;
        return `
      <div class="subcard">
        <div class="subcard-head">
          <span>Guard: ${escapeHtml(gName)} <span class="pill ${boundRules > 0 ? "ok" : "warn"}">${boundRules}/${totalRules} rules</span></span>
          <div class="btn-row">
            ${totalRules > 0 && boundRules < totalRules ? `<button class="btn sm" data-bind-guard-all="${escapeHtml(gName)}" title="Attach this guard to all ingress rules">Bind All Rules</button>` : ""}
            <button class="btn sm danger" data-del-guard="${escapeHtml(gName)}">Remove</button>
          </div>
        </div>
        <div class="inspector-row">
          <label><span>Profile Name</span><input data-gd-name="${escapeHtml(gName)}" value="${escapeHtml(gName)}" /></label>
          <label><span>Antibot Mode</span>
            <select data-gd-mode="${escapeHtml(gName)}">
              <option value="off" ${g.antibot === "off" ? "selected" : ""}>off (rate-limit/CIDR only)</option>
              <option value="silent" ${g.antibot === "silent" ? "selected" : ""}>silent (score block, no UI)</option>
              <option value="challenge" ${g.antibot === "challenge" ? "selected" : ""}>challenge (PoW on score ≥ threshold)</option>
              <option value="always" ${g.antibot === "always" ? "selected" : ""}>always (Under Attack / force PoW)</option>
            </select>
          </label>
        </div>
        <div class="inspector-row">
          <label><span>PoW Difficulty (bits)</span><input type="number" min="4" max="28" data-gd-pow="${escapeHtml(gName)}" value="${g.pow_difficulty ?? 16}" /></label>
          <label><span>Rate Limit Bucket</span>
            <select data-gd-bucket="${escapeHtml(gName)}">
              <option value="">(none)</option>
              ${bucketNames.map((b) => `<option value="${escapeHtml(b)}" ${g.rate_limit_bucket === b ? "selected" : ""}>${escapeHtml(b)}</option>`).join("")}
            </select>
          </label>
        </div>
        <div class="inspector-row">
          <label><span>Challenge Score (0 = all)</span><input type="number" min="0" max="100" data-gd-cthresh="${escapeHtml(gName)}" value="${g.challenge_threshold ?? 50}" /></label>
          <label><span>Reject Score (0 = off)</span><input type="number" min="0" max="100" data-gd-rthresh="${escapeHtml(gName)}" value="${g.reject_threshold ?? 85}" /></label>
        </div>
        <div class="inspector-row">
          <label><span>Allow CIDRs (CSV)</span><input data-gd-allow="${escapeHtml(gName)}" value="${escapeHtml((g.allow_cidrs || []).join(", "))}" /></label>
          <label><span>Deny CIDRs (CSV)</span><input data-gd-deny="${escapeHtml(gName)}" value="${escapeHtml((g.deny_cidrs || []).join(", "))}" /></label>
        </div>
        <div class="inspector-row">
          <label><span>Clearance TTL (s)</span><input type="number" min="10" data-gd-ttl="${escapeHtml(gName)}" value="${g.clearance_ttl_secs ?? 1800}" /></label>
          <label><span>API Bypass Headers</span><input data-gd-bypass="${escapeHtml(gName)}" value="${escapeHtml((g.api_bypass_headers || []).join(", "))}" placeholder="X-Api-Key" /></label>
        </div>
        <div class="inspector-checks">
          <label class="check-inline"><input type="checkbox" data-gd-ua="${escapeHtml(gName)}" ${g.bind_ua !== false ? "checked" : ""} /> Bind UA</label>
          <label class="check-inline"><input type="checkbox" data-gd-ip="${escapeHtml(gName)}" ${g.bind_ip_prefix ? "checked" : ""} /> Bind IP Prefix</label>
          <label class="check-inline"><input type="checkbox" data-gd-bots="${escapeHtml(gName)}" ${g.block_bots ? "checked" : ""} /> Block Bots</label>
          <label class="check-inline"><input type="checkbox" data-gd-headless="${escapeHtml(gName)}" ${g.block_headless ? "checked" : ""} /> Block Headless</label>
          <label class="check-inline"><input type="checkbox" data-gd-fp="${escapeHtml(gName)}" ${g.require_client_fp ? "checked" : ""} /> Require JS FP</label>
        </div>
      </div>`;
      })
      .join("");

    return `
      <div class="inspector-sec">
        <div class="inspector-sec-head">
          <span>Rate Limit Buckets</span>
          <button id="btn-add-bucket" class="btn sm">+ Bucket</button>
        </div>
        ${bucketsHtml || '<div class="muted-sm">No token buckets defined.</div>'}
      </div>
      <div class="inspector-sec">
        <div class="inspector-sec-head">
          <span>Guard Profiles</span>
          <button id="btn-add-guard" class="btn sm">+ Guard</button>
        </div>
        ${guardsHtml || '<div class="muted-sm">No guard profiles defined.</div>'}
      </div>
    `;
  }

  function renderEgressTab(node, ingressNodes) {
    const servicesHtml = Object.entries(node.egress.services || {})
      .map(([sTag, svc]) => {
        const allowSet = new Set(svc.allow_from || []);
        const chips = ingressNodes
          .map(
            (ig) =>
              `<button type="button" class="acl-chip ${allowSet.has(ig) ? "active" : ""}" data-acl-toggle="${escapeHtml(sTag)}" data-acl-node="${escapeHtml(ig)}">${escapeHtml(ig)}</button>`
          )
          .join("");
        return `
      <div class="subcard">
        <div class="subcard-head">
          <span>Service: ${escapeHtml(sTag)}</span>
          <button class="btn sm danger" data-del-esvc="${escapeHtml(sTag)}">Remove</button>
        </div>
        <div class="inspector-row">
          <label><span>Service Tag</span><input data-es-tag="${escapeHtml(sTag)}" value="${escapeHtml(sTag)}" /></label>
          <label><span>Backend Addr</span><input data-es-backend="${escapeHtml(sTag)}" value="${escapeHtml(svc.backend || "")}" placeholder="127.0.0.1:8080" /></label>
        </div>
        <div class="inspector-row">
          <label><span>Protocol</span>
            <select data-es-proto="${escapeHtml(sTag)}">
              <option value="auto" ${svc.protocol === "auto" ? "selected" : ""}>auto (h2/h1)</option>
              <option value="http1" ${svc.protocol === "http1" ? "selected" : ""}>http1</option>
              <option value="h2" ${svc.protocol === "h2" ? "selected" : ""}>h2</option>
            </select>
          </label>
          <label><span>Timeout (ms)</span><input type="number" data-es-timeout="${escapeHtml(sTag)}" value="${svc.timeout_ms ?? 15000}" /></label>
        </div>
        <label><span>Allow From Origin Node Tags (CSV)</span>
          <input data-es-allow="${escapeHtml(sTag)}" value="${escapeHtml((svc.allow_from || []).join(", "))}" placeholder="ingress-hk" />
        </label>
        ${chips ? `<div class="acl-chips-row"><span class="muted-sm">Quick ACL:</span>${chips}</div>` : ""}
        <div class="inspector-checks">
          <label class="check-inline"><input type="checkbox" data-es-tls="${escapeHtml(sTag)}" ${svc.tls ? "checked" : ""} /> Backend TLS</label>
          <label class="check-inline"><input type="checkbox" data-es-any="${escapeHtml(sTag)}" ${svc.allow_any_origin ? "checked" : ""} /> Allow Any Origin</label>
          <label class="check-inline"><input type="checkbox" data-es-intercept="${escapeHtml(sTag)}" ${svc.intercept_errors ? "checked" : ""} /> Intercept Errors (5xx Page)</label>
        </div>
        ${
          svc.tls
            ? `<div class="inspector-row">
                <label><span>CA Cert Path (optional PEM)</span><input data-es-ca="${escapeHtml(sTag)}" value="${escapeHtml(svc.ca_cert_path || "")}" placeholder="/etc/exposure/ca.pem" /></label>
                <label class="check-inline" style="align-self:end;padding-bottom:8px;">
                  <input type="checkbox" data-es-insecure="${escapeHtml(sTag)}" ${svc.insecure_skip_verify ? "checked" : ""} /> Allow Insecure Cert
                </label>
              </div>`
            : ""
        }
      </div>`;
      })
      .join("");

    return `
      <div class="inspector-sec">
        <div class="inspector-sec-head">
          <span>Egress Services (${Object.keys(node.egress.services || {}).length})</span>
          <button id="btn-add-esvc" class="btn sm">+ Service</button>
        </div>
        ${servicesHtml || '<div class="muted-sm">No egress services configured.</div>'}
      </div>
    `;
  }

  function renderRelayTab(node) {
    const relayHtml = (node.relay.rules || [])
      .map(
        (r, i) => `
      <div class="subcard">
        <div class="subcard-head">
          <span>Relay Rule #${i + 1}</span>
          <button class="btn sm danger" data-del-rrule="${i}">Remove</button>
        </div>
        <div class="inspector-row">
          <label><span>Service Tag</span><input list="service-tags-list" data-rr-svc="${i}" value="${escapeHtml(r.service_tag || "")}" /></label>
          <label><span>Next Peer</span><input list="peer-tags-list" data-rr-peer="${i}" value="${escapeHtml(r.next_peer || "")}" /></label>
        </div>
      </div>`
      )
      .join("");

    return `
      <div class="inspector-sec">
        <div class="inspector-sec-head">
          <span>Relay Forwarding Rules (${node.relay.rules.length})</span>
          <button id="btn-add-rrule" class="btn sm">+ Rule</button>
        </div>
        ${relayHtml || '<div class="muted-sm">No relay rules configured.</div>'}
      </div>
    `;
  }

  function renderMaintainerTab(tag, node) {
    const tplName = node.maintainer_template || "default-maint";
    const tpl = editor.spec.maintainer_templates[tplName];
    if (!tpl) {
      return `
        <div class="inspector-sec">
          <div class="inspector-sec-head">
            <span>Maintainer ACME &amp; SSL</span>
            <button id="btn-init-acme" class="btn sm primary">Enable ACME Template</button>
          </div>
          <div class="muted-sm">Enable an ACME template to manage DNS01 providers and automated SSL certificate distribution.</div>
        </div>`;
    }
    const acme = tpl.acme || { providers: {}, orders: [] };
    const providersHtml = Object.entries(acme.providers || {})
      .map(
        ([pName, p]) => `
      <div class="subcard">
        <div class="subcard-head">
          <span>DNS01: ${escapeHtml(pName)} (${escapeHtml(p.type || "cloudflare")})</span>
          <button class="btn sm danger" data-del-dns="${escapeHtml(pName)}">Remove</button>
        </div>
        ${
          p.type === "cloudflare"
            ? `<div class="inspector-row">
                <label><span>API Token</span><input type="password" autocomplete="off" spellcheck="false" data-dns-token="${escapeHtml(pName)}" value="${escapeHtml(p.api_token || "")}" /></label>
                <label><span>Zone ID</span><input data-dns-zone="${escapeHtml(pName)}" value="${escapeHtml(p.zone_id || "")}" /></label>
              </div>`
            : p.type === "webhook"
            ? `<div class="inspector-row">
                <label><span>Present URL</span><input data-dns-present="${escapeHtml(pName)}" value="${escapeHtml(p.present_url || "")}" /></label>
                <label><span>Cleanup URL</span><input data-dns-cleanup="${escapeHtml(pName)}" value="${escapeHtml(p.cleanup_url || "")}" /></label>
              </div>`
            : `<label><span>Exec Command</span><input data-dns-cmd="${escapeHtml(pName)}" value="${escapeHtml(p.command || "")}" /></label>`
        }
      </div>`
      )
      .join("");

    const ordersHtml = (acme.orders || [])
      .map(
        (o, i) => `
      <div class="subcard">
        <div class="subcard-head">
          <span>Cert Order #${i + 1}</span>
          <div class="btn-row">
            <button class="btn sm" data-auto-order-hops="${i}" title="Compute shortest hops from ${escapeHtml(tag)}">Auto Hops</button>
            <button class="btn sm danger" data-del-order="${i}">Remove</button>
          </div>
        </div>
        <div class="inspector-row">
          <label><span>Domain</span><input data-ord-dom="${i}" value="${escapeHtml(o.domain || "")}" placeholder="example.com" /></label>
          <label><span>DNS01 Provider</span><input data-ord-prov="${i}" value="${escapeHtml(o.provider || "")}" /></label>
        </div>
        <div class="inspector-row">
          <label><span>Target Nodes (CSV)</span><input data-ord-targets="${i}" value="${escapeHtml((o.target_nodes || []).join(", "))}" /></label>
          <label><span>Renew Before (days)</span><input type="number" data-ord-renew="${i}" value="${o.renew_before_days ?? 30}" /></label>
        </div>
      </div>`
      )
      .join("");

    return `
      <div class="inspector-sec">
        <div class="inspector-sec-head"><span>ACME Configuration</span></div>
        <div class="inspector-row">
          <label><span>Template Name</span><input id="inp-maint-tpl" value="${escapeHtml(tplName)}" /></label>
          <label class="check-inline" style="align-self:end;padding-bottom:8px;">
            <input type="checkbox" id="chk-primary-cm" ${tpl.is_primary_cert_manager ? "checked" : ""} /> Primary Cert Manager
          </label>
        </div>
        <div class="inspector-row">
          <label><span>Directory URL</span><input id="inp-acme-dir" value="${escapeHtml(acme.directory_url || "")}" /></label>
          <label><span>Contact Email</span><input id="inp-acme-email" value="${escapeHtml(acme.contact_email || "")}" /></label>
        </div>
        <div class="btn-row">
          <button id="btn-add-dns-cf" class="btn sm">+ Cloudflare</button>
          <button id="btn-add-dns-wh" class="btn sm">+ Webhook</button>
          <button id="btn-add-order" class="btn sm">+ Cert Order</button>
        </div>
        ${providersHtml}
        ${ordersHtml}
      </div>
    `;
  }

  function wireTabEvents(box, tag, node, maintainerNodes) {
    // General tab
    box.querySelector("#inp-node-tag")?.addEventListener("change", (ev) => {
      const newTag = ev.target.value.trim();
      if (!newTag || newTag === tag || isReservedKey(newTag) || Object.hasOwn(editor.spec.nodes, newTag)) {
        ev.target.value = tag;
        return;
      }
      markDirty(true);
      editor.spec.nodes[newTag] = editor.spec.nodes[tag];
      delete editor.spec.nodes[tag];
      editor.positions[newTag] = editor.positions[tag] || { x: 60, y: 60 };
      delete editor.positions[tag];
      editor.spec.links.forEach((l) => {
        if (l.from === tag) l.from = newTag;
        if (l.to === tag) l.to = newTag;
        if (l.peer_tag === tag) l.peer_tag = newTag;
      });
      for (const n of Object.values(editor.spec.nodes)) {
        if (Array.isArray(n.maintainer_hops)) {
          n.maintainer_hops = n.maintainer_hops.map((h) => (h === tag ? newTag : h));
        }
        for (const r of n.ingress?.rules || []) {
          if (r.next_peer === tag) r.next_peer = newTag;
        }
        for (const r of n.relay?.rules || []) {
          if (r.next_peer === tag) r.next_peer = newTag;
        }
        for (const svc of Object.values(n.egress?.services || {})) {
          if (Array.isArray(svc.allow_from)) {
            svc.allow_from = svc.allow_from.map((a) => (a === tag ? newTag : a));
          }
        }
      }
      for (const tpl of Object.values(editor.spec.maintainer_templates || {})) {
        for (const ord of tpl?.acme?.orders || []) {
          if (Array.isArray(ord.target_nodes)) {
            ord.target_nodes = ord.target_nodes.map((t) => (t === tag ? newTag : t));
          }
          if (ord.target_hops && typeof ord.target_hops === "object") {
            const nextHops = {};
            for (const [k, hops] of Object.entries(ord.target_hops)) {
              const nk = k === tag ? newTag : k;
              nextHops[nk] = Array.isArray(hops) ? hops.map((h) => (h === tag ? newTag : h)) : hops;
            }
            ord.target_hops = nextHops;
          }
        }
      }
      editor.selected = { type: "node", tag: newTag };
      savePositions(editor.positions);
      render();
    });

    const syncLinkListener = () => {
      markDirty(false);
      const addr = box.querySelector("#inp-link-listen").value.trim();
      if (!addr) {
        node.link_listener = null;
      } else {
        node.link_listener = {
          listen_addr: addr,
          allow_on_demand: box.querySelector("#chk-allow-ondemand").checked,
          allow_tunnel: box.querySelector("#chk-allow-tunnel").checked,
          allow_bootstrap: box.querySelector("#chk-allow-boot").checked,
        };
      }
      renderNodes();
      renderEdges();
    };
    box.querySelector("#inp-link-listen")?.addEventListener("input", syncLinkListener);
    box.querySelector("#chk-allow-ondemand")?.addEventListener("change", syncLinkListener);
    box.querySelector("#chk-allow-tunnel")?.addEventListener("change", syncLinkListener);
    box.querySelector("#chk-allow-boot")?.addEventListener("change", syncLinkListener);

    box.querySelector("#inp-maint-hops")?.addEventListener("input", (ev) => {
      markDirty(false);
      node.maintainer_hops = ev.target.value.split(",").map((s) => s.trim()).filter(Boolean);
    });
    box.querySelector("#btn-auto-mhops")?.addEventListener("click", () => {
      for (const m of maintainerNodes) {
        const path = shortestPathBFS(editor.spec.links, tag, m);
        if (path) {
          markDirty(true);
          node.maintainer_hops = path;
          renderInspector();
          showToast(`Computed hops: ${path.join(" → ")}`);
          return;
        }
      }
      showToast("No link path found to any Maintainer node", true);
    });

    // Ingress tab
    box.querySelector("#btn-add-listener")?.addEventListener("click", () => {
      markDirty(true);
      node.ingress.listeners.push({ listen_addr: "0.0.0.0:8080", tls: false });
      render();
    });
    box.querySelectorAll("[data-del-listener]").forEach((btn) =>
      btn.addEventListener("click", () => {
        markDirty(true);
        node.ingress.listeners.splice(Number(btn.dataset.delListener), 1);
        render();
      })
    );
    box.querySelectorAll("[data-l-addr]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        node.ingress.listeners[Number(inp.dataset.lAddr)].listen_addr = inp.value.trim();
        renderNodes();
      })
    );
    box.querySelectorAll("[data-l-tls]").forEach((chk) =>
      chk.addEventListener("change", () => {
        markDirty(false);
        node.ingress.listeners[Number(chk.dataset.lTls)].tls = chk.checked;
      })
    );

    box.querySelector("#btn-add-irule")?.addEventListener("click", () => {
      markDirty(true);
      node.ingress.rules.push({
        name: `rule-${node.ingress.rules.length + 1}`,
        match: {},
        service_tag: "",
        next_peer: "",
      });
      render();
    });
    box.querySelectorAll("[data-del-irule]").forEach((btn) =>
      btn.addEventListener("click", () => {
        markDirty(true);
        node.ingress.rules.splice(Number(btn.dataset.delIrule), 1);
        render();
      })
    );
    box.querySelectorAll("[data-ir-name]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        node.ingress.rules[Number(inp.dataset.irName)].name = inp.value.trim() || null;
      })
    );
    box.querySelectorAll("[data-ir-svc]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        node.ingress.rules[Number(inp.dataset.irSvc)].service_tag = inp.value.trim();
        refreshTracerDropdown();
      })
    );
    box.querySelectorAll("[data-ir-host]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        const r = node.ingress.rules[Number(inp.dataset.irHost)];
        r.match = r.match || {};
        const v = inp.value.trim();
        r.match.host = v && v !== "*" ? v : null;
      })
    );
    box.querySelectorAll("[data-ir-peer]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        node.ingress.rules[Number(inp.dataset.irPeer)].next_peer = inp.value.trim();
      })
    );
    box.querySelectorAll("[data-ir-prefix]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        const r = node.ingress.rules[Number(inp.dataset.irPrefix)];
        r.match = r.match || {};
        r.match.url_prefix = inp.value.trim() || null;
      })
    );
    box.querySelectorAll("[data-ir-sni]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        const r = node.ingress.rules[Number(inp.dataset.irSni)];
        r.match = r.match || {};
        r.match.sni = inp.value.trim() || null;
      })
    );
    box.querySelectorAll("[data-ir-cidrs]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        const r = node.ingress.rules[Number(inp.dataset.irCidrs)];
        r.match = r.match || {};
        r.match.source_cidrs = inp.value.split(",").map((s) => s.trim()).filter(Boolean);
      })
    );
    box.querySelectorAll("[data-ir-guard]").forEach((sel) =>
      sel.addEventListener("change", () => {
        markDirty(false);
        node.ingress.rules[Number(sel.dataset.irGuard)].guard = sel.value || null;
      })
    );
    box.querySelectorAll("[data-ir-intercept]").forEach((chk) =>
      chk.addEventListener("change", () => {
        markDirty(false);
        node.ingress.rules[Number(chk.dataset.irIntercept)].intercept_errors = chk.checked;
      })
    );
    box.querySelector("#inp-cert-dir")?.addEventListener("input", (ev) => {
      markDirty(false);
      node.ingress.cert_store_dir = ev.target.value.trim() || null;
    });
    box.querySelector("#sel-server-hdr")?.addEventListener("change", (ev) => {
      markDirty(false);
      node.ingress.server_header = ev.target.value;
    });
    box.querySelector("#inp-clear-sec")?.addEventListener("input", (ev) => {
      markDirty(false);
      node.ingress.clearance_secret = ev.target.value.trim();
    });
    box.querySelector("#btn-add-cert")?.addEventListener("click", () => {
      markDirty(true);
      node.ingress.tls_certs.push({ domain: "example.com", cert_path: "", key_path: "" });
      render();
    });
    box.querySelectorAll("[data-del-cert]").forEach((btn) =>
      btn.addEventListener("click", () => {
        markDirty(true);
        node.ingress.tls_certs.splice(Number(btn.dataset.delCert), 1);
        render();
      })
    );
    box.querySelectorAll("[data-ic-dom]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        node.ingress.tls_certs[Number(inp.dataset.icDom)].domain = inp.value.trim();
      })
    );
    box.querySelectorAll("[data-ic-cert]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        node.ingress.tls_certs[Number(inp.dataset.icCert)].cert_path = inp.value.trim();
      })
    );
    box.querySelectorAll("[data-ic-key]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        node.ingress.tls_certs[Number(inp.dataset.icKey)].key_path = inp.value.trim();
      })
    );

    // Guard tab
    box.querySelector("#btn-add-bucket")?.addEventListener("click", () => {
      markDirty(true);
      let name = "web-default", k = 1;
      while (node.ingress.rate_limit_buckets[name]) name = `bucket-${k++}`;
      node.ingress.rate_limit_buckets[name] = { capacity: 60, refill_per_sec: 10, per_ip: true };
      render();
    });
    box.querySelectorAll("[data-del-bucket]").forEach((btn) =>
      btn.addEventListener("click", () => {
        markDirty(true);
        const bName = btn.dataset.delBucket;
        delete node.ingress.rate_limit_buckets[bName];
        for (const g of Object.values(node.ingress.guards || {})) {
          if (g.rate_limit_bucket === bName) g.rate_limit_bucket = null;
        }
        render();
      })
    );
    box.querySelectorAll("[data-bk-name]").forEach((inp) =>
      inp.addEventListener("change", () => {
        const oldN = inp.dataset.bkName, newN = inp.value.trim();
        if (!newN || newN === oldN || isReservedKey(newN) || Object.hasOwn(node.ingress.rate_limit_buckets, newN)) {
          inp.value = oldN;
          return;
        }
        markDirty(true);
        node.ingress.rate_limit_buckets[newN] = node.ingress.rate_limit_buckets[oldN];
        delete node.ingress.rate_limit_buckets[oldN];
        for (const g of Object.values(node.ingress.guards || {})) {
          if (g.rate_limit_bucket === oldN) g.rate_limit_bucket = newN;
        }
        render();
      })
    );
    box.querySelectorAll("[data-bk-cap]").forEach((inp) =>
      inp.addEventListener("input", () => { markDirty(false); node.ingress.rate_limit_buckets[inp.dataset.bkCap].capacity = parseNum(inp.value, 60, 1); })
    );
    box.querySelectorAll("[data-bk-refill]").forEach((inp) =>
      inp.addEventListener("input", () => { markDirty(false); node.ingress.rate_limit_buckets[inp.dataset.bkRefill].refill_per_sec = parseNum(inp.value, 10, 0.01); })
    );
    box.querySelectorAll("[data-bk-perip]").forEach((chk) =>
      chk.addEventListener("change", () => { markDirty(false); node.ingress.rate_limit_buckets[chk.dataset.bkPerip].per_ip = chk.checked; })
    );

    box.querySelector("#btn-add-guard")?.addEventListener("click", () => {
      markDirty(true);
      let name = "standard", k = 1;
      while (node.ingress.guards[name]) name = `guard-${k++}`;
      node.ingress.guards[name] = {
        antibot: "challenge",
        rate_limit_bucket: Object.keys(node.ingress.rate_limit_buckets)[0] || null,
        allow_cidrs: [], deny_cidrs: [],
        challenge_threshold: 50, reject_threshold: 85,
        pow_difficulty: 16, clearance_ttl_secs: 1800,
        bind_ua: true, bind_ip_prefix: false, api_bypass_headers: [],
      };
      render();
    });
    box.querySelectorAll("[data-bind-guard-all]").forEach((btn) =>
      btn.addEventListener("click", () => {
        markDirty(true);
        const gName = btn.dataset.bindGuardAll;
        for (const r of node.ingress.rules || []) {
          r.guard = gName;
        }
        render();
        showToast(`Bound guard "${gName}" to all ${node.ingress.rules.length} ingress rule(s)`);
      })
    );
    box.querySelectorAll("[data-del-guard]").forEach((btn) =>
      btn.addEventListener("click", () => {
        markDirty(true);
        const gName = btn.dataset.delGuard;
        delete node.ingress.guards[gName];
        for (const r of node.ingress.rules || []) {
          if (r.guard === gName) r.guard = null;
        }
        render();
      })
    );
    box.querySelectorAll("[data-gd-name]").forEach((inp) =>
      inp.addEventListener("change", () => {
        const oldN = inp.dataset.gdName, newN = inp.value.trim();
        if (!newN || newN === oldN || isReservedKey(newN) || Object.hasOwn(node.ingress.guards, newN)) {
          inp.value = oldN;
          return;
        }
        markDirty(true);
        node.ingress.guards[newN] = node.ingress.guards[oldN];
        delete node.ingress.guards[oldN];
        // Keep ingress rules synced with renamed guard profile!
        for (const r of node.ingress.rules || []) {
          if (r.guard === oldN) r.guard = newN;
        }
        render();
      })
    );
    box.querySelectorAll("[data-gd-mode]").forEach((sel) => sel.addEventListener("change", () => { markDirty(false); node.ingress.guards[sel.dataset.gdMode].antibot = sel.value; }));
    box.querySelectorAll("[data-gd-pow]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.ingress.guards[inp.dataset.gdPow].pow_difficulty = parseNum(inp.value, 16, 4, 28); }));
    box.querySelectorAll("[data-gd-bucket]").forEach((sel) => sel.addEventListener("change", () => { markDirty(false); node.ingress.guards[sel.dataset.gdBucket].rate_limit_bucket = sel.value || null; }));
    box.querySelectorAll("[data-gd-cthresh]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.ingress.guards[inp.dataset.gdCthresh].challenge_threshold = parseNum(inp.value, 50, 0, 100); }));
    box.querySelectorAll("[data-gd-rthresh]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.ingress.guards[inp.dataset.gdRthresh].reject_threshold = parseNum(inp.value, 85, 0, 100); }));
    box.querySelectorAll("[data-gd-allow]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.ingress.guards[inp.dataset.gdAllow].allow_cidrs = inp.value.split(",").map((s) => s.trim()).filter(Boolean); }));
    box.querySelectorAll("[data-gd-deny]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.ingress.guards[inp.dataset.gdDeny].deny_cidrs = inp.value.split(",").map((s) => s.trim()).filter(Boolean); }));
    box.querySelectorAll("[data-gd-ttl]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.ingress.guards[inp.dataset.gdTtl].clearance_ttl_secs = parseNum(inp.value, 1800, 10, 86400 * 30); }));
    box.querySelectorAll("[data-gd-bypass]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.ingress.guards[inp.dataset.gdBypass].api_bypass_headers = inp.value.split(",").map((s) => s.trim()).filter(Boolean); }));
    box.querySelectorAll("[data-gd-ua]").forEach((chk) => chk.addEventListener("change", () => { markDirty(false); node.ingress.guards[chk.dataset.gdUa].bind_ua = chk.checked; }));
    box.querySelectorAll("[data-gd-ip]").forEach((chk) => chk.addEventListener("change", () => { markDirty(false); node.ingress.guards[chk.dataset.gdIp].bind_ip_prefix = chk.checked; }));
    box.querySelectorAll("[data-gd-bots]").forEach((chk) => chk.addEventListener("change", () => { markDirty(false); node.ingress.guards[chk.dataset.gdBots].block_bots = chk.checked; }));
    box.querySelectorAll("[data-gd-headless]").forEach((chk) => chk.addEventListener("change", () => { markDirty(false); node.ingress.guards[chk.dataset.gdHeadless].block_headless = chk.checked; }));
    box.querySelectorAll("[data-gd-fp]").forEach((chk) => chk.addEventListener("change", () => { markDirty(false); node.ingress.guards[chk.dataset.gdFp].require_client_fp = chk.checked; }));

    // Egress tab
    box.querySelector("#btn-add-esvc")?.addEventListener("click", () => {
      markDirty(true);
      let name = "svc", k = 1;
      while (node.egress.services[name]) name = `svc-${k++}`;
      node.egress.services[name] = {
        backend: "127.0.0.1:8080", protocol: "auto", tls: false,
        allow_from: [], allow_any_origin: false, timeout_ms: 15000,
      };
      render();
    });
    box.querySelectorAll("[data-del-esvc]").forEach((btn) =>
      btn.addEventListener("click", () => { markDirty(true); delete node.egress.services[btn.dataset.delEsvc]; render(); })
    );
    box.querySelectorAll("[data-es-tag]").forEach((inp) =>
      inp.addEventListener("change", () => {
        const oldTag = inp.dataset.esTag, newTag = inp.value.trim();
        if (!newTag || newTag === oldTag || isReservedKey(newTag) || Object.hasOwn(node.egress.services, newTag)) {
          inp.value = oldTag;
          return;
        }
        markDirty(true);
        node.egress.services[newTag] = node.egress.services[oldTag];
        delete node.egress.services[oldTag];
        render();
      })
    );
    box.querySelectorAll("[data-es-backend]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.egress.services[inp.dataset.esBackend].backend = inp.value.trim(); }));
    box.querySelectorAll("[data-es-proto]").forEach((sel) => sel.addEventListener("change", () => { markDirty(false); node.egress.services[sel.dataset.esProto].protocol = sel.value; }));
    box.querySelectorAll("[data-es-timeout]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.egress.services[inp.dataset.esTimeout].timeout_ms = parseNum(inp.value, 15000, 100); }));
    box.querySelectorAll("[data-es-allow]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.egress.services[inp.dataset.esAllow].allow_from = inp.value.split(",").map((s) => s.trim()).filter(Boolean); }));
    box.querySelectorAll("[data-es-tls]").forEach((chk) =>
      chk.addEventListener("change", () => {
        markDirty(true);
        node.egress.services[chk.dataset.esTls].tls = chk.checked;
        renderInspector();
      })
    );
    box.querySelectorAll("[data-es-ca]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        node.egress.services[inp.dataset.esCa].ca_cert_path = inp.value.trim() || null;
      })
    );
    box.querySelectorAll("[data-es-insecure]").forEach((chk) =>
      chk.addEventListener("change", () => {
        markDirty(false);
        node.egress.services[chk.dataset.esInsecure].insecure_skip_verify = chk.checked;
      })
    );
    box.querySelectorAll("[data-es-intercept]").forEach((chk) => chk.addEventListener("change", () => { markDirty(false); node.egress.services[chk.dataset.esIntercept].intercept_errors = chk.checked; }));
    box.querySelectorAll("[data-es-any]").forEach((chk) => chk.addEventListener("change", () => { markDirty(false); node.egress.services[chk.dataset.esAny].allow_any_origin = chk.checked; }));
    box.querySelectorAll("[data-acl-toggle]").forEach((btn) =>
      btn.addEventListener("click", () => {
        markDirty(true);
        const svc = node.egress.services[btn.dataset.aclToggle];
        const target = btn.dataset.aclNode;
        const set = new Set(svc.allow_from || []);
        if (set.has(target)) set.delete(target); else set.add(target);
        svc.allow_from = [...set];
        renderInspector();
      })
    );

    // Relay tab
    box.querySelector("#btn-add-rrule")?.addEventListener("click", () => {
      markDirty(true);
      node.relay.rules.push({ service_tag: "", next_peer: "" });
      render();
    });
    box.querySelectorAll("[data-del-rrule]").forEach((btn) =>
      btn.addEventListener("click", () => { markDirty(true); node.relay.rules.splice(Number(btn.dataset.delRrule), 1); render(); })
    );
    box.querySelectorAll("[data-rr-svc]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.relay.rules[Number(inp.dataset.rrSvc)].service_tag = inp.value.trim(); }));
    box.querySelectorAll("[data-rr-peer]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); node.relay.rules[Number(inp.dataset.rrPeer)].next_peer = inp.value.trim(); }));

    // Maintainer tab
    const tplName = node.maintainer_template || "default-maint";
    const tpl = editor.spec.maintainer_templates[tplName];
    box.querySelector("#btn-init-acme")?.addEventListener("click", () => {
      markDirty(true);
      node.maintainer_template = tplName;
      if (!editor.spec.maintainer_templates[tplName]) {
        editor.spec.maintainer_templates[tplName] = defaultMaintainerTemplate();
      }
      render();
    });
    box.querySelector("#inp-maint-tpl")?.addEventListener("change", (ev) => {
      const oldN = node.maintainer_template || "default-maint", newN = ev.target.value.trim();
      if (!newN || newN === oldN || isReservedKey(newN) || Object.hasOwn(editor.spec.maintainer_templates, newN)) {
        ev.target.value = oldN;
        return;
      }
      markDirty(true);
      editor.spec.maintainer_templates[newN] = editor.spec.maintainer_templates[oldN] || defaultMaintainerTemplate();
      delete editor.spec.maintainer_templates[oldN];
      for (const n of Object.values(editor.spec.nodes)) {
        if (n.maintainer_template === oldN) n.maintainer_template = newN;
      }
      node.maintainer_template = newN;
      render();
    });
    box.querySelector("#chk-primary-cm")?.addEventListener("change", (ev) => { if (tpl) { markDirty(false); tpl.is_primary_cert_manager = ev.target.checked; } });
    box.querySelector("#inp-acme-dir")?.addEventListener("input", (ev) => { if (tpl) { markDirty(false); tpl.acme.directory_url = ev.target.value.trim(); } });
    box.querySelector("#inp-acme-email")?.addEventListener("input", (ev) => { if (tpl) { markDirty(false); tpl.acme.contact_email = ev.target.value.trim(); } });
    box.querySelector("#btn-add-dns-cf")?.addEventListener("click", () => {
      if (!tpl) return;
      markDirty(true);
      let n = "cf", k = 1;
      while (tpl.acme.providers[n]) n = `cf-${k++}`;
      tpl.acme.providers[n] = { type: "cloudflare", api_token: "", zone_id: "" };
      render();
    });
    box.querySelector("#btn-add-dns-wh")?.addEventListener("click", () => {
      if (!tpl) return;
      markDirty(true);
      let n = "webhook", k = 1;
      while (tpl.acme.providers[n]) n = `webhook-${k++}`;
      tpl.acme.providers[n] = { type: "webhook", present_url: "", cleanup_url: "", auth_header: null };
      render();
    });
    box.querySelectorAll("[data-del-dns]").forEach((btn) => btn.addEventListener("click", () => { markDirty(true); delete tpl.acme.providers[btn.dataset.delDns]; render(); }));
    box.querySelectorAll("[data-dns-token]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); tpl.acme.providers[inp.dataset.dnsToken].api_token = inp.value.trim(); }));
    box.querySelectorAll("[data-dns-zone]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); tpl.acme.providers[inp.dataset.dnsZone].zone_id = inp.value.trim(); }));
    box.querySelectorAll("[data-dns-present]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); tpl.acme.providers[inp.dataset.dnsPresent].present_url = inp.value.trim(); }));
    box.querySelectorAll("[data-dns-cleanup]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); tpl.acme.providers[inp.dataset.dnsCleanup].cleanup_url = inp.value.trim(); }));
    box.querySelectorAll("[data-dns-cmd]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); tpl.acme.providers[inp.dataset.dnsCmd].command = inp.value.trim(); }));

    box.querySelector("#btn-add-order")?.addEventListener("click", () => {
      if (!tpl) return;
      markDirty(true);
      const firstProv = Object.keys(tpl.acme.providers)[0] || "cf";
      tpl.acme.orders.push({ domain: "example.com", provider: firstProv, target_nodes: [], target_hops: {}, renew_before_days: 30 });
      render();
    });
    box.querySelectorAll("[data-del-order]").forEach((btn) => btn.addEventListener("click", () => { markDirty(true); tpl.acme.orders.splice(Number(btn.dataset.delOrder), 1); render(); }));
    box.querySelectorAll("[data-ord-dom]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); tpl.acme.orders[Number(inp.dataset.ordDom)].domain = inp.value.trim(); }));
    box.querySelectorAll("[data-ord-prov]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); tpl.acme.orders[Number(inp.dataset.ordProv)].provider = inp.value.trim(); }));
    box.querySelectorAll("[data-ord-targets]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); tpl.acme.orders[Number(inp.dataset.ordTargets)].target_nodes = inp.value.split(",").map((s) => s.trim()).filter(Boolean); }));
    box.querySelectorAll("[data-ord-renew]").forEach((inp) => inp.addEventListener("input", () => { markDirty(false); tpl.acme.orders[Number(inp.dataset.ordRenew)].renew_before_days = parseNum(inp.value, 30, 1, 365); }));
    box.querySelectorAll("[data-auto-order-hops]").forEach((btn) =>
      btn.addEventListener("click", () => {
        const order = tpl.acme.orders[Number(btn.dataset.autoOrderHops)];
        if (!order) return;
        markDirty(true);
        order.target_hops = order.target_hops || {};
        let computed = 0;
        for (const t of order.target_nodes || []) {
          const p = shortestPathBFS(editor.spec.links, tag, t);
          if (p) {
            order.target_hops[t] = p;
            computed++;
          }
        }
        showToast(`Computed hop paths for ${computed}/${(order.target_nodes || []).length} target(s)`);
      })
    );
  }

  function renderLinkInspector(box, idx, link) {
    const liveH = findLiveLinkHealth(link);
    const liveHtml = liveH
      ? `<div class="live-link-strip">
          <span class="pill ${liveH.state === "UP" ? "ok" : liveH.state === "DEGRADED" ? "warn" : "err"}">${escapeHtml(liveH.state)}</span>
          <span>RTT: <b>${escapeHtml(liveH.rtt_ms ?? "-")} ms</b></span>
          <span>Loss: <b>${((Number(liveH.loss_rate) || 0) * 100).toFixed(1)}%</b></span>
        </div>`
      : "";

    const epsHtml = (link.endpoints || [])
      .map(
        (ep, i) => `
      <div class="subcard">
        <div class="subcard-head">
          <span>Endpoint #${i + 1}${Number(ep.weight) === 0 ? " (Backup)" : ""}</span>
          <button class="btn sm danger" data-del-ep="${i}">Remove</button>
        </div>
        <label><span>Address</span><input data-ep-addr="${i}" value="${escapeHtml(ep.address || "")}" placeholder="198.51.100.10:10802" /></label>
        <div class="inspector-row">
          <label><span>Priority (lower = higher)</span><input type="number" data-ep-prio="${i}" value="${ep.priority ?? 10}" /></label>
          <label><span>Weight (0 = backup)</span><input type="number" min="0" data-ep-weight="${i}" value="${ep.weight ?? 100}" /></label>
        </div>
      </div>`
      )
      .join("");

    box.innerHTML = `
      <div class="inspector-header">
        <div>
          <div class="inspector-title">${escapeHtml(link.from)} → ${escapeHtml(link.to)}</div>
          <div class="inspector-sub"><span class="pill ${link.mode === "tunnel" ? "ok" : ""}">${escapeHtml(link.mode)}</span></div>
        </div>
        <div class="btn-row">
          <button id="btn-swap-link" class="btn sm" title="Swap From/To">Swap ⇄</button>
          <button id="btn-del-link" class="btn sm danger">Delete</button>
        </div>
      </div>
      ${liveHtml}
      <div class="inspector-sec">
        <div class="inspector-sec-head"><span>Link Parameters</span></div>
        <div class="inspector-row">
          <label><span>Mode</span>
            <select id="sel-link-mode">
              <option value="on-demand" ${link.mode === "on-demand" ? "selected" : ""}>on-demand</option>
              <option value="tunnel" ${link.mode === "tunnel" ? "selected" : ""}>tunnel</option>
            </select>
          </label>
          <label><span>Tunnel Direction</span>
            <select id="sel-tunnel-dir" ${link.mode !== "tunnel" ? "disabled" : ""}>
              <option value="outbound" selected>outbound (from → to, use Swap ⇄ to reverse)</option>
            </select>
          </label>
        </div>
        <div class="inspector-row">
          <label><span>Peer Tag Alias (opt)</span><input id="inp-link-peertag" value="${escapeHtml(link.peer_tag || "")}" placeholder="${escapeHtml(link.to)}" /></label>
          <label><span>Expected Client Addr</span><input id="inp-link-caddr" value="${escapeHtml(link.expected_client_addr || "")}" placeholder="203.0.113.0/24" /></label>
        </div>
        ${
          link.mode === "on-demand"
            ? `<div class="inspector-checks">
                <label class="check-inline"><input type="checkbox" id="chk-link-bidir" ${link.bidirectional !== false ? "checked" : ""} /> Bidirectional (single-line ↔)</label>
              </div>`
            : ""
        }
      </div>
      <div class="inspector-sec">
        <div class="inspector-sec-head">
          <span>Endpoints (${link.endpoints.length})</span>
          <button id="btn-add-ep" class="btn sm">+ Endpoint</button>
        </div>
        ${epsHtml || '<div class="muted-sm">No endpoints (inbound tunnel receives connections).</div>'}
      </div>
      ${
        link.mode === "on-demand" && link.bidirectional !== false
          ? `<div class="inspector-sec">
              <div class="inspector-sec-head">
                <span>Reverse Endpoints: ${escapeHtml(link.to)} → ${escapeHtml(link.from)} (${(link.reverse_endpoints || []).length})</span>
                <button id="btn-add-rep" class="btn sm">+ Reverse EP</button>
              </div>
              ${(link.reverse_endpoints || [])
                .map(
                  (ep, i) => `
                <div class="subcard">
                  <div class="subcard-head">
                    <span>Reverse #${i + 1}</span>
                    <button class="btn sm danger" data-del-rep="${i}">Remove</button>
                  </div>
                  <label><span>Address</span><input data-rep-addr="${i}" value="${escapeHtml(ep.address || "")}" placeholder="172.16.20.111:10802" /></label>
                </div>`
                )
                .join("") || '<div class="muted-sm">Optional: add endpoint if target also dials back to source.</div>'}
            </div>`
          : ""
      }
    `;

    box.querySelector("#btn-del-link").addEventListener("click", () => {
      markDirty(true);
      editor.spec.links.splice(idx, 1);
      editor.selected = null;
      render();
    });
    box.querySelector("#btn-swap-link").addEventListener("click", () => {
      markDirty(true);
      const oldTo = link.to;
      const tmp = link.from;
      link.from = link.to;
      link.to = tmp;
      if (link.peer_tag === oldTo) {
        link.peer_tag = null;
      }
      if (link.mode === "on-demand" && link.bidirectional !== false) {
        const tmpEps = link.endpoints || [];
        link.endpoints = link.reverse_endpoints || [];
        link.reverse_endpoints = tmpEps;
      }
      render();
    });
    box.querySelector("#sel-link-mode").addEventListener("change", (ev) => {
      markDirty(true);
      link.mode = ev.target.value;
      if (link.mode === "tunnel" && !link.tunnel_direction) link.tunnel_direction = "outbound";
      if (link.mode !== "tunnel") link.tunnel_direction = null;
      render();
    });
    box.querySelector("#sel-tunnel-dir").addEventListener("change", (ev) => {
      markDirty(false);
      link.tunnel_direction = ev.target.value;
      renderEdges();
    });
    box.querySelector("#inp-link-peertag").addEventListener("input", (ev) => {
      markDirty(false);
      link.peer_tag = ev.target.value.trim() || null;
    });
    box.querySelector("#inp-link-caddr").addEventListener("input", (ev) => {
      markDirty(false);
      link.expected_client_addr = ev.target.value.trim() || null;
    });
    box.querySelector("#chk-link-bidir")?.addEventListener("change", (ev) => {
      markDirty(true);
      link.bidirectional = ev.target.checked;
      render();
    });
    box.querySelector("#btn-add-rep")?.addEventListener("click", () => {
      markDirty(true);
      link.reverse_endpoints = link.reverse_endpoints || [];
      link.reverse_endpoints.push({ address: "<SOURCE_IP>:10802", priority: 10, weight: 100 });
      render();
    });
    box.querySelectorAll("[data-del-rep]").forEach((btn) =>
      btn.addEventListener("click", () => {
        markDirty(true);
        link.reverse_endpoints.splice(Number(btn.dataset.delRep), 1);
        render();
      })
    );
    box.querySelectorAll("[data-rep-addr]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        link.reverse_endpoints[Number(inp.dataset.repAddr)].address = inp.value.trim();
      })
    );
    box.querySelector("#btn-add-ep").addEventListener("click", () => {
      markDirty(true);
      link.endpoints.push({ address: "127.0.0.1:10802", priority: 10, weight: 100 });
      render();
    });
    box.querySelectorAll("[data-del-ep]").forEach((btn) =>
      btn.addEventListener("click", () => {
        markDirty(true);
        link.endpoints.splice(Number(btn.dataset.delEp), 1);
        render();
      })
    );
    box.querySelectorAll("[data-ep-addr]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        link.endpoints[Number(inp.dataset.epAddr)].address = inp.value.trim();
        renderEdges();
      })
    );
    box.querySelectorAll("[data-ep-prio]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        link.endpoints[Number(inp.dataset.epPrio)].priority = parseNum(inp.value, 10, 0, 65535);
      })
    );
    box.querySelectorAll("[data-ep-weight]").forEach((inp) =>
      inp.addEventListener("input", () => {
        markDirty(false);
        const w = Number(inp.value);
        link.endpoints[Number(inp.dataset.epWeight)].weight = Number.isNaN(w) ? 100 : Math.max(0, w);
      })
    );
  }

  function render() {
    ensurePositions();
    renderNodes();
    renderEdges();
    renderInspector();
    refreshTracerDropdown();
    renderValidationBar();
    applyViewportTransform();
    updateDirtyBadge();
  }

  // Global mouse move / up for Node Drag, Canvas Pan, and Port Wire Drag
  window.addEventListener("mousemove", (ev) => {
    if (editor.wireDrag) {
      const pt = screenToWorld(ev.clientX, ev.clientY);
      editor.wireDrag.curX = pt.x;
      editor.wireDrag.curY = pt.y;
      renderEdges();
      return;
    }
    if (editor.panDrag) {
      const dx = ev.clientX - editor.panDrag.startX;
      const dy = ev.clientY - editor.panDrag.startY;
      if (Math.abs(dx) > 3 || Math.abs(dy) > 3) editor.panDrag.moved = true;
      editor.view.tx = editor.panDrag.origTx + dx;
      editor.view.ty = editor.panDrag.origTy + dy;
      applyViewportTransform();
      return;
    }
    if (editor.dragNode) {
      const d = editor.dragNode;
      const pt = screenToWorld(ev.clientX, ev.clientY);
      let nx = d.origX + (pt.x - d.startWorldX);
      let ny = d.origY + (pt.y - d.startWorldY);
      if (editor.snapGrid) {
        nx = Math.round(nx / GRID_STEP) * GRID_STEP;
        ny = Math.round(ny / GRID_STEP) * GRID_STEP;
      }
      if (Math.abs(nx - d.origX) > 2 || Math.abs(ny - d.origY) > 2) d.moved = true;
      editor.positions[d.tag] = { x: nx, y: ny };
      const card = el("topo-nodes-layer")?.querySelector(`[data-node-tag="${CSS.escape(d.tag)}"]`);
      if (card) {
        card.style.left = `${nx}px`;
        card.style.top = `${ny}px`;
      }
      renderEdges();
      renderMinimap();
    }
  });

  window.addEventListener("mouseup", () => {
    if (editor.wireDrag) {
      editor.wireDrag = null;
      renderEdges();
    }
    if (editor.panDrag) {
      if (editor.panDrag.moved) editor.suppressCanvasClick = true;
      editor.panDrag = null;
      el("topo-canvas")?.classList.remove("panning");
    }
    if (editor.dragNode) {
      if (editor.dragNode.moved) editor.suppressCanvasClick = true;
      savePositions(editor.positions);
      editor.dragNode = null;
    }
  });

  // Pan & Wheel Zoom on canvas
  const canvas = el("topo-canvas");
  canvas?.addEventListener("mousedown", (ev) => {
    if (ev.button !== 0 && ev.button !== 1) return;
    if (
      ev.target.closest(".topo-node") ||
      ev.target.closest(".topo-edge-hit") ||
      ev.target.closest(".topo-edge-pill") ||
      ev.target.closest(".topo-float-bar") ||
      ev.target.closest(".topo-minimap")
    ) {
      return;
    }
    editor.panDrag = {
      startX: ev.clientX,
      startY: ev.clientY,
      origTx: editor.view.tx,
      origTy: editor.view.ty,
      moved: false,
    };
    canvas.classList.add("panning");
  });

  canvas?.addEventListener(
    "wheel",
    (ev) => {
      ev.preventDefault();
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      const factor = ev.deltaY < 0 ? 1.1 : 0.91;
      const nextScale = Math.max(0.35, Math.min(2.2, editor.view.scale * factor));
      const ratio = nextScale / editor.view.scale;
      editor.view.tx = mx - (mx - editor.view.tx) * ratio;
      editor.view.ty = my - (my - editor.view.ty) * ratio;
      editor.view.scale = nextScale;
      applyViewportTransform();
    },
    { passive: false }
  );

  canvas?.addEventListener("click", (ev) => {
    if (editor.suppressCanvasClick) {
      editor.suppressCanvasClick = false;
      return;
    }
    if (
      ev.target.closest(".topo-node") ||
      ev.target.closest(".topo-edge-hit") ||
      ev.target.closest(".topo-edge-pill") ||
      ev.target.closest(".topo-float-bar") ||
      ev.target.closest(".topo-minimap")
    ) {
      return;
    }
    if (!editor.connectMode && editor.selected) {
      editor.selected = null;
      render();
    }
  });

  // Keyboard shortcuts (Undo, Redo, Escape, Delete, Fit)
  window.addEventListener("keydown", (ev) => {
    const topoPanel = el("tab-topology");
    if (!topoPanel || topoPanel.classList.contains("hidden") || editor.mode !== "visual") return;
    const isInput = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);

    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "z") {
      if (isInput) return;
      ev.preventDefault();
      if (ev.shiftKey) redo(); else undo();
      return;
    }
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "y") {
      if (isInput) return;
      ev.preventDefault();
      redo();
      return;
    }
    if (ev.key === "Escape") {
      if (editor.connectMode) {
        editor.connectMode = false;
        editor.connectSource = null;
        el("topo-connect-hint")?.classList.add("hidden");
        el("btn-connect-mode")?.classList.remove("primary");
        render();
      } else if (editor.tracedService) {
        editor.tracedService = "";
        render();
      }
      return;
    }
    if (!isInput && (ev.key === "Delete" || ev.key === "Backspace") && editor.selected) {
      ev.preventDefault();
      markDirty(true);
      if (editor.selected.type === "node") {
        const t = editor.selected.tag;
        delete editor.spec.nodes[t];
        editor.spec.links = editor.spec.links.filter((l) => l.from !== t && l.to !== t);
      } else if (editor.selected.type === "link") {
        editor.spec.links.splice(editor.selected.index, 1);
      }
      editor.selected = null;
      render();
    }
    if (!isInput && ev.key.toLowerCase() === "f") {
      fitToView();
    }
  });

  // Toolbar controls
  el("btn-connect-mode")?.addEventListener("click", () => {
    editor.connectMode = !editor.connectMode;
    editor.connectSource = null;
    el("topo-connect-hint")?.classList.toggle("hidden", !editor.connectMode);
    el("btn-connect-mode")?.classList.toggle("primary", editor.connectMode);
    render();
  });

  el("btn-auto-layout")?.addEventListener("click", autoLayout);
  el("btn-topo-undo")?.addEventListener("click", undo);
  el("btn-topo-redo")?.addEventListener("click", redo);

  el("btn-zoom-in")?.addEventListener("click", () => {
    editor.view.scale = Math.min(2.2, editor.view.scale * 1.18);
    applyViewportTransform();
  });
  el("btn-zoom-out")?.addEventListener("click", () => {
    editor.view.scale = Math.max(0.35, editor.view.scale / 1.18);
    applyViewportTransform();
  });
  el("btn-zoom-fit")?.addEventListener("click", fitToView);
  el("btn-toggle-grid")?.addEventListener("click", (ev) => {
    editor.snapGrid = !editor.snapGrid;
    ev.currentTarget.classList.toggle("active", editor.snapGrid);
  });
  el("btn-toggle-live")?.addEventListener("click", (ev) => {
    editor.showLiveOverlay = !editor.showLiveOverlay;
    ev.currentTarget.classList.toggle("active", editor.showLiveOverlay);
    renderNodes();
    renderEdges();
  });
  el("topo-trace-select")?.addEventListener("change", (ev) => {
    editor.tracedService = ev.target.value;
    renderNodes();
    renderEdges();
  });

  el("btn-import-nodes")?.addEventListener("click", async () => {
    try {
      const data = await api("/api/nodes");
      let added = 0;
      for (const n of data.nodes || []) {
        if (!n?.node_tag || isReservedKey(n.node_tag)) continue;
        editor.liveNodes.set(n.node_tag, n);
        if (!Object.hasOwn(editor.spec.nodes, n.node_tag)) {
          const spec = defaultNodeSpec();
          spec.roles = rolesFromAny(n.roles);
          editor.spec.nodes[n.node_tag] = spec;
          added++;
        }
      }
      if (added > 0) markDirty(true);
      autoLayout();
      showToast(`Imported ${added} new node(s) from live registry`);
    } catch (e) {
      showToast(e.message, true);
    }
  });

  el("btn-mode-visual")?.addEventListener("click", async () => {
    if (editor.mode === "visual") return;
    try {
      const res = await api("/api/topology/validate", {
        method: "POST",
        body: JSON.stringify({ yaml: el("topology-editor").value }),
      });
      if (!res?.spec) {
        const msg = (res?.errors && res.errors[0]) || "Invalid YAML syntax; fix errors before switching to Visual Graph";
        showToast(msg, true);
        return;
      }
      editor.spec = normalizeSpec(res.spec);
      if (res.paths) editor.compiledPaths = res.paths;
      editor.validationErrors = res.errors || [];
      editor.validationWarnings = res.warnings || [];
    } catch (e) {
      showToast(`YAML parse error: ${e.message}`, true);
      return;
    }
    editor.mode = "visual";
    el("topo-visual-wrap").classList.remove("hidden");
    el("topo-yaml-wrap").classList.add("hidden");
    el("btn-mode-visual").classList.add("primary");
    el("btn-mode-yaml").classList.remove("primary");
    render();
  });

  el("btn-mode-yaml")?.addEventListener("click", async () => {
    if (editor.mode === "yaml") return;
    try {
      const res = await api("/api/topology/validate", {
        method: "POST",
        body: JSON.stringify({ spec: editor.spec }),
      });
      if (res.yaml) el("topology-editor").value = res.yaml;
    } catch (e) {
      showToast(e.message, true);
    }
    editor.mode = "yaml";
    el("topo-visual-wrap").classList.add("hidden");
    el("topo-yaml-wrap").classList.remove("hidden");
    el("btn-mode-yaml").classList.add("primary");
    el("btn-mode-visual").classList.remove("primary");
  });

  return {
    isDirty() {
      return editor.dirty;
    },
    clearDirty,
    setLiveState(nodes = [], links = []) {
      editor.liveNodes = new Map((nodes || []).map((n) => [n.node_tag, n]));
      editor.liveLinks = links || [];
      if (editor.mode === "visual") {
        renderNodes();
        renderEdges();
      }
    },
    setValidationResult({ errors = [], warnings = [], paths = [] }) {
      editor.validationErrors = errors || [];
      editor.validationWarnings = warnings || [];
      if (Array.isArray(paths)) editor.compiledPaths = paths;
      render();
    },
    setFromServer(yaml, spec, meta = {}, force = false) {
      if (meta.live_nodes || meta.live_links) {
        editor.liveNodes = new Map((meta.live_nodes || []).map((n) => [n.node_tag, n]));
        editor.liveLinks = meta.live_links || [];
      }
      if (Array.isArray(meta.paths)) editor.compiledPaths = meta.paths;
      if (Array.isArray(meta.errors)) editor.validationErrors = meta.errors;
      if (Array.isArray(meta.warnings)) editor.validationWarnings = meta.warnings;

      // Protect unsaved visual edits from background refresh!
      if (!force && editor.dirty) {
        renderNodes();
        renderEdges();
        return;
      }
      el("topology-editor").value = yaml || "";
      editor.spec = normalizeSpec(spec);
      // Automatically surface onboarded/discovered live nodes on the graph
      for (const n of meta.live_nodes || []) {
        if (n?.node_tag && !isReservedKey(n.node_tag) && !Object.hasOwn(editor.spec.nodes, n.node_tag)) {
          const ns = defaultNodeSpec();
          ns.roles = rolesFromAny(n.roles);
          editor.spec.nodes[n.node_tag] = ns;
        }
      }
      clearDirty();
      render();
    },
    focusNode(tag) {
      focusNodeOnCanvas(tag);
    },
    fitToView,
    getPayload(push = false) {
      if (editor.mode === "yaml") {
        return { yaml: el("topology-editor").value, push };
      }
      return { spec: editor.spec, push };
    },
  };
}
