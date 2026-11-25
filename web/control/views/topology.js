// Pure Physical Mesh Topology Canvas & Service Route Tracer
import { themeColors } from "../charts.js";
import { t } from "../i18n.js";
import { resolveServiceTargetIngresses } from "../store.js";
import { el, esc, parseNum, showToast } from "../ui.js";

const POS_STORAGE_KEY = "exposure_topo_positions_v2";
const NODE_W = 224;
const NODE_DEFAULT_H = 104;
const GRID_STEP = 20;

function loadPositions() {
  try { return JSON.parse(localStorage.getItem(POS_STORAGE_KEY) || "{}"); } catch { return {}; }
}
function savePositions(pos) {
  try { localStorage.setItem(POS_STORAGE_KEY, JSON.stringify(pos)); } catch {}
}

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
  const k = Math.min(sx, sy);
  return { x: cx + dx * k, y: cy + dy * k };
}

export function createTopologyView({ store, navigate }) {
  const state = {
    positions: loadPositions(),
    nodeHeights: {},
    selected: null, // { type: 'node', tag } | { type: 'link', index }
    connectMode: false,
    connectSource: null,
    view: { tx: 30, ty: 30, scale: 1 },
    snapGrid: true,
    showLiveOverlay: true,
    tracedService: "",
    dragNode: null,
    panDrag: null,
    wireDrag: null,
    suppressCanvasClick: false,
    wiredGlobalEvents: false,
    shellRendered: false,
  };

  function ensureShell() {
    const root = el("tab-topology");
    if (!root) return;
    if (state.shellRendered && el("topo-canvas")) {
      updateToolbarLabels();
      return;
    }
    state.shellRendered = true;
    root.innerHTML = `
      <div class="panel topo-panel">
        <div class="topo-toolbar">
          <div class="btn-row">
            <button id="btn-topo-connect" class="btn sm">${esc(t("topo.connect"))}</button>
            <button id="btn-topo-auto-layout" class="btn sm">${esc(t("topo.auto_layout"))}</button>
            <div class="toolbar-sep"></div>
            <select id="topo-trace-select" class="select-sm" title="Highlight compiled service path">
              <option value="">${esc(t("topo.trace_off"))}</option>
            </select>
          </div>
          <div class="btn-row">
            <button id="btn-topo-go-hosts" class="btn sm">${esc(t("topo.open_host"))}</button>
            <button id="btn-topo-go-services" class="btn sm">${esc(t("topo.open_services"))}</button>
          </div>
        </div>

        <div class="topo-workspace">
          <div id="topo-canvas" class="topo-canvas">
            <div id="topo-viewport" class="topo-viewport">
              <svg id="topo-svg" class="topo-svg" viewBox="-4000 -4000 8000 8000">
                <defs>
                  <marker id="arrow-ondemand" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" style="fill:var(--accent)"></path>
                  </marker>
                  <marker id="arrow-tunnel" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" style="fill:var(--ok)"></path>
                  </marker>
                  <marker id="arrow-selected" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" style="fill:var(--warn)"></path>
                  </marker>
                  <marker id="arrow-danger" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" style="fill:var(--danger)"></path>
                  </marker>
                </defs>
              </svg>
              <div id="topo-nodes-layer" class="topo-nodes-layer"></div>
            </div>

            <div class="topo-float-bar">
              <button id="btn-zoom-out" class="btn sm">−</button>
              <span id="topo-zoom-label" class="zoom-lbl">100%</span>
              <button id="btn-zoom-in" class="btn sm">+</button>
              <button id="btn-zoom-fit" class="btn sm">${esc(t("topo.fit"))}</button>
              <button id="btn-toggle-grid" class="btn sm active">${esc(t("topo.grid"))}</button>
              <button id="btn-toggle-live" class="btn sm active">${esc(t("topo.live"))}</button>
            </div>
            <div id="topo-minimap" class="topo-minimap"></div>
            <div id="topo-connect-hint" class="topo-hint hidden">${esc(t("topo.connect_hint"))}</div>
          </div>
          <aside id="topo-inspector" class="topo-inspector"></aside>
        </div>
      </div>
    `;
    wireCanvasEvents();
  }

  function updateToolbarLabels() {
    if (el("btn-topo-connect")) el("btn-topo-connect").textContent = t("topo.connect");
    if (el("btn-topo-auto-layout")) el("btn-topo-auto-layout").textContent = t("topo.auto_layout");
    if (el("btn-topo-go-hosts")) el("btn-topo-go-hosts").textContent = t("topo.open_host");
    if (el("btn-topo-go-services")) el("btn-topo-go-services").textContent = t("topo.open_services");
    if (el("btn-zoom-fit")) el("btn-zoom-fit").textContent = t("topo.fit");
    if (el("btn-toggle-grid")) el("btn-toggle-grid").textContent = t("topo.grid");
    if (el("btn-toggle-live")) el("btn-toggle-live").textContent = t("topo.live");
    if (el("topo-connect-hint")) el("topo-connect-hint").textContent = t("topo.connect_hint");
  }

  function screenToWorld(clientX, clientY) {
    const rect = el("topo-canvas").getBoundingClientRect();
    return {
      x: (clientX - rect.left - state.view.tx) / state.view.scale,
      y: (clientY - rect.top - state.view.ty) / state.view.scale,
    };
  }

  function applyViewportTransform() {
    const vp = el("topo-viewport");
    if (vp) vp.style.transform = `translate(${state.view.tx}px, ${state.view.ty}px) scale(${state.view.scale})`;
    const canvas = el("topo-canvas");
    if (canvas) {
      const sz = Math.max(10, GRID_STEP * state.view.scale);
      canvas.style.backgroundSize = `${sz}px ${sz}px`;
      canvas.style.backgroundPosition = `${state.view.tx}px ${state.view.ty}px`;
    }
    if (el("topo-zoom-label")) el("topo-zoom-label").textContent = `${Math.round(state.view.scale * 100)}%`;
    renderMinimap();
  }

  function ensurePositions() {
    const tags = Object.keys(store.spec.nodes || {});
    let idx = 0;
    for (const tag of tags) {
      if (!state.positions[tag]) {
        state.positions[tag] = { x: 40 + (idx % 3) * 290, y: 40 + Math.floor(idx / 3) * 190 };
      }
      idx++;
    }
    savePositions(state.positions);
  }

  function autoLayout() {
    const tags = Object.keys(store.spec.nodes || {});
    const cols = { ingress: [], relay: [], egress: [], maintainer: [], other: [] };
    for (const tag of tags) {
      const r = store.spec.nodes[tag].roles || {};
      if (r.ingress) cols.ingress.push(tag);
      else if (r.relay) cols.relay.push(tag);
      else if (r.egress) cols.egress.push(tag);
      else if (r.maintainer) cols.maintainer.push(tag);
      else cols.other.push(tag);
    }
    const ordered = [cols.ingress, cols.relay, cols.egress, cols.maintainer, cols.other].filter((c) => c.length > 0);
    ordered.forEach((colTags, ci) => {
      colTags.forEach((tag, ri) => {
        state.positions[tag] = { x: 40 + ci * 310, y: 40 + ri * 190 };
      });
    });
    savePositions(state.positions);
    render();
    fitToView();
  }

  function fitToView() {
    const tags = Object.keys(store.spec.nodes || {});
    const canvas = el("topo-canvas");
    if (!canvas) return;
    if (!tags.length) {
      state.view = { tx: 30, ty: 30, scale: 1 };
      applyViewportTransform();
      return;
    }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const tag of tags) {
      const p = state.positions[tag] || { x: 40, y: 40 };
      const h = state.nodeHeights[tag] || NODE_DEFAULT_H;
      minX = Math.min(minX, p.x);
      minY = Math.min(minY, p.y);
      maxX = Math.max(maxX, p.x + NODE_W);
      maxY = Math.max(maxY, p.y + h);
    }
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 50 || rect.height < 50) return;
    const pad = 64;
    const scale = Math.max(0.4, Math.min(1.25, Math.min(rect.width / Math.max(100, maxX - minX + pad * 2), rect.height / Math.max(100, maxY - minY + pad * 2))));
    state.view.scale = scale;
    state.view.tx = (rect.width - (maxX - minX) * scale) / 2 - minX * scale;
    state.view.ty = (rect.height - (maxY - minY) * scale) / 2 - minY * scale;
    applyViewportTransform();
  }

  function focusNode(tag) {
    if (!store.spec.nodes?.[tag]) return;
    const p = state.positions[tag] || { x: 40, y: 40 };
    const h = state.nodeHeights[tag] || NODE_DEFAULT_H;
    const canvas = el("topo-canvas");
    if (canvas) {
      const rect = canvas.getBoundingClientRect();
      state.view.tx = rect.width / 2 - (p.x + NODE_W / 2) * state.view.scale;
      state.view.ty = rect.height / 2 - (p.y + h / 2) * state.view.scale;
      applyViewportTransform();
    }
    state.selected = { type: "node", tag };
    render();
  }

  function nodeRect(tag) {
    const p = state.positions[tag] || { x: 40, y: 40 };
    return { x: p.x, y: p.y, w: NODE_W, h: state.nodeHeights[tag] || NODE_DEFAULT_H };
  }

  function findLiveLinkHealth(link) {
    const peerName = link.peer_tag || link.to;
    const live = store.liveLinks || [];
    return (
      live.find((l) => l.node_tag === link.from && l.peer_tag === peerName) ||
      live.find((l) => l.node_tag === link.from && l.peer_tag === link.to) ||
      (link.mode === "tunnel" ? live.find((l) => l.node_tag === link.to && l.peer_tag === link.from) : null)
    );
  }

  function getTracedSets() {
    if (!state.tracedService) return null;
    const matching = (store.compiledPaths || []).filter((p) => p.service_tag === state.tracedService);
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

  function createLinkBetween(fromTag, toTag) {
    if (!fromTag || !toTag || fromTag === toTag) return;
    const toNode = store.spec.nodes[toTag];
    const fromNode = store.spec.nodes[fromTag];
    const targetListen = toNode?.link_listener?.listen_addr || "0.0.0.0:10802";
    const port = targetListen.includes(":") ? targetListen.split(":").pop() : "10802";
    const targetIp = toNode?.external_ips?.[0] || `${toTag}.internal`;
    const isTunnel = fromNode?.roles?.egress && !fromNode?.link_listener;
    let newIdx = 0;
    store.mutate((s) => {
      s.links.push({
        from: fromTag,
        to: toTag,
        peer_tag: null,
        mode: isTunnel ? "tunnel" : "on-demand",
        tunnel_direction: isTunnel ? "outbound" : null,
        bidirectional: false,
        expected_client_addr: null,
        endpoints: [{ address: `${targetIp}:${port}`, priority: 10, weight: 100 }],
        reverse_endpoints: [],
      });
      newIdx = s.links.length - 1;
    });
    state.selected = { type: "link", index: newIdx };
    showToast(`Created ${isTunnel ? "tunnel" : "on-demand"} link: ${fromTag} → ${toTag}`);
    render();
  }

  function refreshTracerDropdown() {
    const sel = el("topo-trace-select");
    if (!sel) return;
    const svcs = new Set(Object.keys(store.spec.services || {}));
    for (const n of Object.values(store.spec.nodes || {})) {
      for (const r of n.ingress?.rules || []) if (r.service_tag) svcs.add(r.service_tag);
      for (const s of Object.keys(n.egress?.services || {})) svcs.add(s);
    }
    const sorted = [...svcs].sort();
    sel.innerHTML =
      `<option value="">${esc(t("topo.trace_off"))}</option>` +
      sorted.map((s) => `<option value="${esc(s)}" ${state.tracedService === s ? "selected" : ""}>Trace: ${esc(s)}</option>`).join("");
  }

  function renderEdges() {
    const svg = el("topo-svg");
    if (!svg) return;
    const defs = svg.querySelector("defs");
    svg.innerHTML = "";
    if (defs) svg.appendChild(defs);
    const ns = "http://www.w3.org/2000/svg";
    const traced = getTracedSets();

    const pairGroups = new Map();
    (store.spec.links || []).forEach((l, i) => {
      const key = [l.from, l.to].sort().join("|");
      if (!pairGroups.has(key)) pairGroups.set(key, []);
      pairGroups.get(key).push(i);
    });

    (store.spec.links || []).forEach((link, idx) => {
      if (!store.spec.nodes[link.from] || !store.spec.nodes[link.to]) return;
      const rA = nodeRect(link.from);
      const rB = nodeRect(link.to);
      const cA = { x: rA.x + rA.w / 2, y: rA.y + rA.h / 2 };
      const cB = { x: rB.x + rB.w / 2, y: rB.y + rB.h / 2 };

      const siblings = pairGroups.get([link.from, link.to].sort().join("|")) || [idx];
      const sibPos = siblings.indexOf(idx);
      const curveOffset = siblings.length > 1 ? (sibPos - (siblings.length - 1) / 2) * 58 : 0;

      const dx = cB.x - cA.x;
      const dy = cB.y - cA.y;
      const len = Math.hypot(dx, dy) || 1;
      const nx = -dy / len;
      const ny = dx / len;
      const midCtrl = { x: (cA.x + cB.x) / 2 + nx * curveOffset, y: (cA.y + cB.y) / 2 + ny * curveOffset };
      const start = rectAnchor(rA, curveOffset ? midCtrl : cB);
      const end = rectAnchor(rB, curveOffset ? midCtrl : cA);
      const d = `M ${start.x.toFixed(1)} ${start.y.toFixed(1)} Q ${midCtrl.x.toFixed(1)} ${midCtrl.y.toFixed(1)} ${end.x.toFixed(1)} ${end.y.toFixed(1)}`;
      const labelPos = {
        x: 0.25 * start.x + 0.5 * midCtrl.x + 0.25 * end.x,
        y: 0.25 * start.y + 0.5 * midCtrl.y + 0.25 * end.y,
      };

      const isSelected = state.selected?.type === "link" && state.selected.index === idx;
      const isTraced = traced ? traced.edgePairs.has(`${link.from}->${link.to}`) : false;
      const isDimmed = traced && !isTraced && !isSelected;
      const liveH = state.showLiveOverlay ? findLiveLinkHealth(link) : null;

      const tc = themeColors();
      let stroke = link.mode === "tunnel" ? tc.ok : tc.accent;
      let marker = link.mode === "tunnel" ? "url(#arrow-tunnel)" : "url(#arrow-ondemand)";
      if (liveH?.state === "DOWN") { stroke = tc.danger; marker = "url(#arrow-danger)"; }
      else if (liveH?.state === "DEGRADED") { stroke = tc.warn; marker = "url(#arrow-selected)"; }
      if (isSelected) { stroke = tc.warn; marker = "url(#arrow-selected)"; }
      if (isTraced) { stroke = traced.hasErr ? tc.danger : tc.accent; }

      const isBidi = link.mode === "tunnel" || (link.mode === "on-demand" && link.bidirectional !== false && (link.reverse_endpoints || []).length > 0);

      const g = document.createElementNS(ns, "g");
      if (isDimmed) g.setAttribute("opacity", "0.22");

      const hit = document.createElementNS(ns, "path");
      hit.setAttribute("d", d);
      hit.setAttribute("stroke", "transparent");
      hit.setAttribute("stroke-width", "18");
      hit.setAttribute("fill", "none");
      hit.style.cursor = "pointer";
      hit.style.pointerEvents = "stroke";
      hit.addEventListener("click", (ev) => {
        ev.stopPropagation();
        state.selected = { type: "link", index: idx };
        render();
      });

      const vis = document.createElementNS(ns, "path");
      vis.setAttribute("d", d);
      vis.setAttribute("fill", "none");
      vis.setAttribute("stroke", stroke);
      vis.setAttribute("stroke-width", isSelected || isTraced ? "3.2" : "2.2");
      if (link.mode === "tunnel") vis.setAttribute("stroke-dasharray", "7 5");
      vis.setAttribute("marker-end", marker);
      if (isBidi) vis.setAttribute("marker-start", marker);
      if (isTraced) vis.classList.add("edge-traced");
      vis.style.pointerEvents = "none";

      let lblText = link.mode === "tunnel" ? "tunnel ⇄" : isBidi ? "on-demand ⇄" : "on-demand";
      if (liveH) {
        const rtt = liveH.rtt_ms != null ? `${liveH.rtt_ms}ms` : "";
        lblText = `${liveH.state}${rtt ? ` · ${rtt}` : ""}`;
      }
      const badgeW = Math.max(66, lblText.length * 6.5 + 14);
      const pill = document.createElementNS(ns, "rect");
      pill.setAttribute("x", (labelPos.x - badgeW / 2).toFixed(1));
      pill.setAttribute("y", (labelPos.y - 10).toFixed(1));
      pill.setAttribute("width", badgeW.toFixed(1));
      pill.setAttribute("height", "20");
      pill.setAttribute("rx", "10");
      pill.setAttribute("fill", isSelected ? "#1e293b" : "#0f172a");
      pill.setAttribute("stroke", stroke);
      pill.setAttribute("stroke-width", isSelected ? "1.6" : "1");
      pill.style.cursor = "pointer";
      pill.style.pointerEvents = "all";
      pill.addEventListener("click", (ev) => {
        ev.stopPropagation();
        state.selected = { type: "link", index: idx };
        render();
      });

      const txt = document.createElementNS(ns, "text");
      txt.setAttribute("x", labelPos.x.toFixed(1));
      txt.setAttribute("y", (labelPos.y + 3.5).toFixed(1));
      txt.setAttribute("text-anchor", "middle");
      txt.setAttribute("fill", isSelected ? tc.warn : tc.text);
      txt.setAttribute("font-size", "10.5");
      txt.setAttribute("font-weight", "600");
      txt.style.pointerEvents = "none";
      txt.textContent = lblText;

      g.appendChild(hit);
      g.appendChild(vis);
      g.appendChild(pill);
      g.appendChild(txt);
      svg.appendChild(g);
    });

    if (state.wireDrag) {
      const fromR = nodeRect(state.wireDrag.fromTag);
      const start = { x: fromR.x + fromR.w, y: fromR.y + fromR.h / 2 };
      const line = document.createElementNS(ns, "line");
      line.setAttribute("x1", start.x.toFixed(1));
      line.setAttribute("y1", start.y.toFixed(1));
      line.setAttribute("x2", state.wireDrag.curX.toFixed(1));
      line.setAttribute("y2", state.wireDrag.curY.toFixed(1));
      line.setAttribute("stroke", themeColors().warn);
      line.setAttribute("stroke-width", "2.5");
      line.setAttribute("stroke-dasharray", "6 4");
      svg.appendChild(line);
    }
  }

  function renderNodes() {
    const layer = el("topo-nodes-layer");
    if (!layer) return;
    ensurePositions();
    layer.innerHTML = "";
    const liveMap = store.liveNodeMap();
    const traced = getTracedSets();

    for (const [tag, node] of Object.entries(store.spec.nodes || {})) {
      const pos = state.positions[tag] || { x: 40, y: 40 };
      const live = liveMap.get(tag);
      const isSelected = state.selected?.type === "node" && state.selected.tag === tag;
      const isConnSrc = state.connectMode && state.connectSource === tag;
      const isTraced = traced ? traced.nodes.has(tag) : false;
      const isDimmed = traced && !isTraced && !isSelected;

      const card = document.createElement("div");
      card.className = `topo-node${isSelected ? " selected" : ""}${isConnSrc ? " connect-source" : ""}${isTraced ? " traced" : ""}${isDimmed ? " dimmed" : ""}`;
      card.dataset.nodeTag = tag;
      card.style.left = `${pos.x}px`;
      card.style.top = `${pos.y}px`;

      const roles = ["ingress", "relay", "egress", "maintainer"]
        .filter((r) => node.roles?.[r])
        .map((r) => `<span class="role-chip ${r}">${r}</span>`)
        .join("");

      const dotCls = !live ? "draft" : live.online ? "online" : "offline";
      const ipMeta = node.external_ips?.length ? node.external_ips[0] : node.link_listener?.listen_addr || "outbound";

      card.innerHTML = `
        <div class="topo-node-head">
          <div class="topo-node-title">
            <span class="live-dot ${dotCls}"></span>
            <span>${esc(tag)}</span>
          </div>
          <span class="topo-node-seq">${live ? `#${esc(live.config_seq)}` : "draft"}</span>
        </div>
        <div class="topo-node-roles">${roles || '<span class="muted-sm">no roles</span>'}</div>
        <div class="topo-node-meta">
          <span>${esc(ipMeta)}</span>
          <span>${live ? (live.online ? "ONLINE" : "OFFLINE") : "DRAFT"}</span>
        </div>
        <div class="topo-port out" title="Drag to link"></div>
      `;

      card.querySelector(".topo-port.out").addEventListener("mousedown", (ev) => {
        ev.stopPropagation();
        ev.preventDefault();
        const pt = screenToWorld(ev.clientX, ev.clientY);
        state.wireDrag = { fromTag: tag, curX: pt.x, curY: pt.y };
        renderEdges();
      });

      card.addEventListener("mousedown", (ev) => {
        if (ev.button !== 0 || ev.target.closest(".topo-port")) return;
        ev.stopPropagation();
        if (state.connectMode) {
          if (!state.connectSource) {
            state.connectSource = tag;
            renderNodes();
          } else if (state.connectSource === tag) {
            state.connectSource = null;
            renderNodes();
          } else {
            const src = state.connectSource;
            state.connectSource = null;
            state.connectMode = false;
            el("btn-topo-connect")?.classList.remove("primary");
            el("topo-connect-hint")?.classList.add("hidden");
            createLinkBetween(src, tag);
          }
          return;
        }
        const pt = screenToWorld(ev.clientX, ev.clientY);
        state.dragNode = { tag, startWorldX: pt.x, startWorldY: pt.y, origX: pos.x, origY: pos.y, moved: false };
      });

      card.addEventListener("click", (ev) => {
        ev.stopPropagation();
        if (state.connectMode || state.suppressCanvasClick) return;
        state.selected = { type: "node", tag };
        render();
      });

      layer.appendChild(card);
      state.nodeHeights[tag] = card.offsetHeight || NODE_DEFAULT_H;
    }
  }

  function renderMinimap() {
    const mm = el("topo-minimap");
    const canvas = el("topo-canvas");
    if (!mm || !canvas) return;
    const tags = Object.keys(store.spec.nodes || {});
    if (!tags.length) { mm.innerHTML = ""; return; }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const tag of tags) {
      const r = nodeRect(tag);
      minX = Math.min(minX, r.x); minY = Math.min(minY, r.y);
      maxX = Math.max(maxX, r.x + r.w); maxY = Math.max(maxY, r.y + r.h);
    }
    const pad = 60;
    const w = Math.max(300, maxX - minX + pad * 2);
    const h = Math.max(200, maxY - minY + pad * 2);
    const ox = minX - pad, oy = minY - pad;
    const mw = 152, mh = 96;
    const sc = Math.min(mw / w, mh / h);
    const mx = (x) => ((x - ox) * sc).toFixed(1);
    const my = (y) => ((y - oy) * sc).toFixed(1);

    const tc = themeColors();
    const edgesSvg = (store.spec.links || [])
      .filter((l) => store.spec.nodes[l.from] && store.spec.nodes[l.to])
      .map((l) => {
        const a = nodeRect(l.from), b = nodeRect(l.to);
        return `<line x1="${mx(a.x + a.w / 2)}" y1="${my(a.y + a.h / 2)}" x2="${mx(b.x + b.w / 2)}" y2="${my(b.y + b.h / 2)}" stroke="${l.mode === "tunnel" ? tc.ok : tc.accent}" stroke-width="1" opacity="0.7" />`;
      })
      .join("");
    const nodesSvg = tags
      .map((tag) => {
        const r = nodeRect(tag);
        const sel = state.selected?.type === "node" && state.selected.tag === tag;
        return `<rect x="${mx(r.x)}" y="${my(r.y)}" width="${Math.max(4, r.w * sc).toFixed(1)}" height="${Math.max(3, r.h * sc).toFixed(1)}" rx="2" fill="${sel ? tc.warn : tc.accent}" />`;
      })
      .join("");
    mm.innerHTML = `<svg width="${mw}" height="${mh}" viewBox="0 0 ${mw} ${mh}">${edgesSvg}${nodesSvg}</svg>`;
  }

  function renderInspector() {
    const box = el("topo-inspector");
    if (!box) return;
    if (!state.selected) {
      const nodeCnt = Object.keys(store.spec.nodes || {}).length;
      const linkCnt = (store.spec.links || []).length;
      const svcCnt = Object.keys(store.spec.services || {}).length;
      box.innerHTML = `
        <div class="inspector-empty">
          <h3>Mesh Topology</h3>
          <p class="muted-sm">${esc(t("topo.empty_inspector"))}</p>
          <div class="inspector-stats">
            <div><strong>${nodeCnt}</strong><span>Hosts</span></div>
            <div><strong>${linkCnt}</strong><span>Links</span></div>
            <div><strong>${svcCnt}</strong><span>Services</span></div>
          </div>
          <div class="btn-row" style="justify-content:center;margin-top:14px;">
            <button type="button" id="ins-go-hosts" class="btn sm">${esc(t("topo.open_host"))}</button>
            <button type="button" id="ins-go-svcs" class="btn sm primary">${esc(t("topo.open_services"))}</button>
          </div>
        </div>`;
      el("ins-go-hosts")?.addEventListener("click", () => navigate("hosts"));
      el("ins-go-svcs")?.addEventListener("click", () => navigate("services"));
      return;
    }

    if (state.selected.type === "node") {
      const tag = state.selected.tag;
      const node = store.spec.nodes?.[tag];
      if (!node) { state.selected = null; renderInspector(); return; }
      const live = store.liveNodeMap().get(tag);
      const adjLinks = (store.spec.links || [])
        .map((l, idx) => ({ l, idx }))
        .filter(({ l }) => l.from === tag || l.to === tag);
      const svcs = Object.entries(store.spec.services || {})
        .filter(([, s]) => s.egress?.node === tag || (node.roles?.ingress && resolveServiceTargetIngresses(store.spec, s).includes(tag)))
        .map(([n]) => n);

      box.innerHTML = `
        <div class="inspector-head">
          <div>
            <h3>${esc(tag)}</h3>
            <span class="pill ${live?.online ? "ok" : live ? "err" : "warn"}">${live ? (live.online ? "ONLINE" : "OFFLINE") : "DRAFT"}</span>
          </div>
          <button type="button" id="ins-edit-host" class="btn sm primary">${esc(t("topo.open_host"))}</button>
        </div>
        <div class="inspector-body">
          <div class="inspector-sec">
            <div class="inspector-sec-head"><span>${esc(t("topo.node_summary"))}</span></div>
            <div class="tag-list" style="margin-bottom:8px;">
              ${["ingress", "relay", "egress", "maintainer"].filter((r) => node.roles?.[r]).map((r) => `<span class="role-chip ${r}">${r}</span>`).join("") || '<span class="muted-sm">No roles</span>'}
            </div>
            <div class="muted-sm">External IPs: <code>${esc((node.external_ips || []).join(", ") || "-")}</code></div>
            <div class="muted-sm">Mesh Listener: <code>${esc(node.link_listener?.listen_addr || "outbound-only")}</code></div>
          </div>

          <div class="inspector-sec">
            <div class="inspector-sec-head"><span>Connected Mesh Links (${adjLinks.length})</span></div>
            ${
              adjLinks
                .map(
                  ({ l, idx }) => `
                <div class="diff-row" style="cursor:pointer;" data-ins-sel-link="${idx}">
                  <div><code>${esc(l.from)}</code> → <code>${esc(l.to)}</code></div>
                  <span class="pill">${esc(l.mode)}</span>
                </div>`
                )
                .join("") || `<div class="muted-sm">No mesh links connected. Use Connect mode or drag the right port to link.</div>`
            }
          </div>

          <div class="inspector-sec">
            <div class="inspector-sec-head">
              <span>Services (${svcs.length})</span>
              <button type="button" id="ins-edit-svcs" class="btn sm">${esc(t("topo.open_services"))}</button>
            </div>
            <div class="tag-list">
              ${svcs.map((s) => `<button type="button" class="acl-chip" data-ins-trace="${esc(s)}">${esc(s)}</button>`).join("") || '<span class="muted-sm">None</span>'}
            </div>
          </div>
        </div>
      `;
      el("ins-edit-host")?.addEventListener("click", () => navigate("hosts", { editHost: tag }));
      el("ins-edit-svcs")?.addEventListener("click", () => navigate("services"));
      box.querySelectorAll("[data-ins-sel-link]").forEach((row) => {
        row.addEventListener("click", () => {
          state.selected = { type: "link", index: Number(row.dataset.insSelLink) };
          render();
        });
      });
      box.querySelectorAll("[data-ins-trace]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.tracedService = btn.dataset.insTrace;
          render();
        });
      });
      return;
    }

    // Link Inspector
    const idx = state.selected.index;
    const link = store.spec.links?.[idx];
    if (!link) { state.selected = null; renderInspector(); return; }
    const renderEpList = (eps, kind) =>
      (eps || [])
        .map(
          (ep, i) => `
        <div class="subcard">
          <div class="subcard-head">
            <span>${kind === "fwd" ? "Endpoint" : "Reverse Endpoint"} #${i + 1}</span>
            <button type="button" class="btn sm danger" data-lk-del-ep="${kind}:${i}">×</button>
          </div>
          <label><span>Address (host:port)</span><input data-lk-ep-addr="${kind}:${i}" value="${esc(ep.address || "")}" /></label>
          <div class="inspector-row">
            <label><span>Priority</span><input type="number" data-lk-ep-prio="${kind}:${i}" value="${ep.priority ?? 10}" /></label>
            <label><span>Weight</span><input type="number" data-lk-ep-wt="${kind}:${i}" value="${ep.weight ?? 100}" /></label>
          </div>
        </div>`
        )
        .join("");

    box.innerHTML = `
      <div class="inspector-head">
        <div>
          <h3>${esc(t("topo.link_title"))}</h3>
          <div class="muted-sm"><code>${esc(link.from)}</code> → <code>${esc(link.to)}</code></div>
        </div>
        <button type="button" id="lk-del" class="btn sm danger">${esc(t("topo.delete_link"))}</button>
      </div>
      <div class="inspector-body">
        <div class="inspector-sec">
          <div class="inspector-row">
            <label><span>Link Mode</span>
              <select id="lk-mode">
                <option value="on-demand" ${link.mode === "on-demand" ? "selected" : ""}>on-demand</option>
                <option value="tunnel" ${link.mode === "tunnel" ? "selected" : ""}>tunnel (NAT outbound)</option>
              </select>
            </label>
            <label><span>Peer Tag (optional)</span>
              <input id="lk-ptag" value="${esc(link.peer_tag || "")}" placeholder="${esc(link.to)}" />
            </label>
          </div>
          ${
            link.mode === "on-demand"
              ? `<label class="check-inline" style="margin-top:6px;"><input type="checkbox" id="lk-bidi" ${link.bidirectional ? "checked" : ""} /> Bidirectional (requires reverse endpoints)</label>`
              : `<label style="margin-top:6px;"><span>Expected Client IP/CIDR (optional)</span><input id="lk-exp-ip" value="${esc(link.expected_client_addr || "")}" placeholder="203.0.113.5" /></label>`
          }
          <div class="btn-row" style="margin-top:8px;">
            <button type="button" id="lk-swap" class="btn sm">${esc(t("topo.reverse_dir"))}</button>
          </div>
        </div>

        <div class="inspector-sec">
          <div class="inspector-sec-head">
            <span>Forward Endpoints (${(link.endpoints || []).length})</span>
            <button type="button" id="lk-add-fwd" class="btn sm">+ Endpoint</button>
          </div>
          ${renderEpList(link.endpoints, "fwd") || '<div class="muted-sm">At least one dial endpoint required.</div>'}
        </div>

        ${
          link.mode === "on-demand" && link.bidirectional
            ? `<div class="inspector-sec">
                <div class="inspector-sec-head">
                  <span>Reverse Endpoints (${(link.reverse_endpoints || []).length})</span>
                  <button type="button" id="lk-add-rev" class="btn sm">+ Reverse EP</button>
                </div>
                ${renderEpList(link.reverse_endpoints, "rev") || '<div class="muted-sm">Specify address for target to dial source back.</div>'}
              </div>`
            : ""
        }
      </div>
    `;

    el("lk-del")?.addEventListener("click", () => {
      store.mutate((s) => { s.links.splice(idx, 1); });
      state.selected = null;
      render();
    });
    el("lk-swap")?.addEventListener("click", () => {
      store.mutate((s) => {
        const l = s.links[idx];
        [l.from, l.to] = [l.to, l.from];
        [l.endpoints, l.reverse_endpoints] = [l.reverse_endpoints || [], l.endpoints || []];
      });
      render();
    });
    el("lk-mode")?.addEventListener("change", (ev) => {
      store.mutate((s) => {
        s.links[idx].mode = ev.target.value;
        s.links[idx].tunnel_direction = ev.target.value === "tunnel" ? "outbound" : null;
      });
      render();
    });
    el("lk-ptag")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.links[idx].peer_tag = ev.target.value.trim() || null; }, false);
    });
    el("lk-bidi")?.addEventListener("change", (ev) => {
      store.mutate((s) => { s.links[idx].bidirectional = ev.target.checked; });
      render();
    });
    el("lk-exp-ip")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.links[idx].expected_client_addr = ev.target.value.trim() || null; }, false);
    });
    el("lk-add-fwd")?.addEventListener("click", () => {
      store.mutate((s) => { s.links[idx].endpoints.push({ address: `${link.to}.internal:10802`, priority: 10, weight: 100 }); });
      render();
    });
    el("lk-add-rev")?.addEventListener("click", () => {
      store.mutate((s) => {
        if (!s.links[idx].reverse_endpoints) s.links[idx].reverse_endpoints = [];
        s.links[idx].reverse_endpoints.push({ address: `${link.from}.internal:10802`, priority: 10, weight: 100 });
      });
      render();
    });
    const epListFor = (s, kind) => (kind === "fwd" ? s.links[idx].endpoints : s.links[idx].reverse_endpoints);
    box.querySelectorAll("[data-lk-del-ep]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const [kind, i] = btn.dataset.lkDelEp.split(":");
        store.mutate((s) => { epListFor(s, kind).splice(Number(i), 1); });
        render();
      });
    });
    box.querySelectorAll("[data-lk-ep-addr]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const [kind, i] = inp.dataset.lkEpAddr.split(":");
        store.mutate((s) => { epListFor(s, kind)[Number(i)].address = inp.value.trim(); }, false);
      });
    });
    box.querySelectorAll("[data-lk-ep-prio]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const [kind, i] = inp.dataset.lkEpPrio.split(":");
        store.mutate((s) => { epListFor(s, kind)[Number(i)].priority = parseNum(inp.value, 10, 0); }, false);
      });
    });
    box.querySelectorAll("[data-lk-ep-wt]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const [kind, i] = inp.dataset.lkEpWt.split(":");
        store.mutate((s) => { epListFor(s, kind)[Number(i)].weight = parseNum(inp.value, 100, 0); }, false);
      });
    });
  }

  function wireCanvasEvents() {
    el("btn-topo-connect")?.addEventListener("click", () => {
      state.connectMode = !state.connectMode;
      state.connectSource = null;
      el("btn-topo-connect")?.classList.toggle("primary", state.connectMode);
      el("topo-connect-hint")?.classList.toggle("hidden", !state.connectMode);
      renderNodes();
    });
    el("btn-topo-auto-layout")?.addEventListener("click", autoLayout);
    el("btn-topo-go-hosts")?.addEventListener("click", () => navigate("hosts"));
    el("btn-topo-go-services")?.addEventListener("click", () => navigate("services"));
    el("topo-trace-select")?.addEventListener("change", (ev) => {
      state.tracedService = ev.target.value;
      render();
    });

    el("btn-zoom-in")?.addEventListener("click", () => { state.view.scale = Math.min(2, state.view.scale * 1.15); applyViewportTransform(); });
    el("btn-zoom-out")?.addEventListener("click", () => { state.view.scale = Math.max(0.35, state.view.scale / 1.15); applyViewportTransform(); });
    el("btn-zoom-fit")?.addEventListener("click", fitToView);
    el("btn-toggle-grid")?.addEventListener("click", () => {
      state.snapGrid = !state.snapGrid;
      el("btn-toggle-grid")?.classList.toggle("active", state.snapGrid);
    });
    el("btn-toggle-live")?.addEventListener("click", () => {
      state.showLiveOverlay = !state.showLiveOverlay;
      el("btn-toggle-live")?.classList.toggle("active", state.showLiveOverlay);
      render();
    });

    const canvas = el("topo-canvas");
    canvas?.addEventListener("mousedown", (ev) => {
      if (ev.button !== 0 || ev.target.closest(".topo-node") || ev.target.closest(".topo-float-bar")) return;
      state.panDrag = { startX: ev.clientX, startY: ev.clientY, origTx: state.view.tx, origTy: state.view.ty, moved: false };
    });
    canvas?.addEventListener("click", () => {
      if (state.suppressCanvasClick) { state.suppressCanvasClick = false; return; }
      if (state.connectMode) return;
      state.selected = null;
      render();
    });
    canvas?.addEventListener("wheel", (ev) => {
      ev.preventDefault();
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      const factor = ev.deltaY < 0 ? 1.1 : 0.9;
      const nextScale = Math.max(0.35, Math.min(2.0, state.view.scale * factor));
      const ratio = nextScale / state.view.scale;
      state.view.tx = mx - (mx - state.view.tx) * ratio;
      state.view.ty = my - (my - state.view.ty) * ratio;
      state.view.scale = nextScale;
      applyViewportTransform();
    }, { passive: false });

    if (!state.wiredGlobalEvents) {
      state.wiredGlobalEvents = true;
      window.addEventListener("mousemove", (ev) => {
        if (state.dragNode) {
          const pt = screenToWorld(ev.clientX, ev.clientY);
          const dx = pt.x - state.dragNode.startWorldX;
          const dy = pt.y - state.dragNode.startWorldY;
          if (Math.hypot(dx, dy) > 3) state.dragNode.moved = true;
          let nx = state.dragNode.origX + dx;
          let ny = state.dragNode.origY + dy;
          if (state.snapGrid) {
            nx = Math.round(nx / GRID_STEP) * GRID_STEP;
            ny = Math.round(ny / GRID_STEP) * GRID_STEP;
          }
          state.positions[state.dragNode.tag] = { x: nx, y: ny };
          const card = el("topo-nodes-layer")?.querySelector(`[data-node-tag="${CSS.escape(state.dragNode.tag)}"]`);
          if (card) { card.style.left = `${nx}px`; card.style.top = `${ny}px`; }
          renderEdges();
          renderMinimap();
        } else if (state.panDrag) {
          const dx = ev.clientX - state.panDrag.startX;
          const dy = ev.clientY - state.panDrag.startY;
          if (Math.hypot(dx, dy) > 3) state.panDrag.moved = true;
          state.view.tx = state.panDrag.origTx + dx;
          state.view.ty = state.panDrag.origTy + dy;
          applyViewportTransform();
        } else if (state.wireDrag) {
          const pt = screenToWorld(ev.clientX, ev.clientY);
          state.wireDrag.curX = pt.x;
          state.wireDrag.curY = pt.y;
          renderEdges();
        }
      });

      window.addEventListener("mouseup", (ev) => {
        if (state.dragNode) {
          if (state.dragNode.moved) {
            savePositions(state.positions);
            state.suppressCanvasClick = true;
            setTimeout(() => { state.suppressCanvasClick = false; }, 0);
          }
          state.dragNode = null;
        }
        if (state.panDrag) {
          if (state.panDrag.moved) state.suppressCanvasClick = true;
          state.panDrag = null;
        }
        if (state.wireDrag) {
          const hit = document.elementFromPoint(ev.clientX, ev.clientY)?.closest?.(".topo-node");
          const from = state.wireDrag.fromTag;
          state.wireDrag = null;
          if (hit?.dataset?.nodeTag && hit.dataset.nodeTag !== from) {
            createLinkBetween(from, hit.dataset.nodeTag);
          } else {
            renderEdges();
          }
        }
      });

      window.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape" && state.connectMode) {
          state.connectMode = false;
          state.connectSource = null;
          el("btn-topo-connect")?.classList.remove("primary");
          el("topo-connect-hint")?.classList.add("hidden");
          renderNodes();
        }
      });
    }
  }

  function render() {
    ensureShell();
    refreshTracerDropdown();
    renderNodes();
    renderEdges();
    renderInspector();
    applyViewportTransform();
  }

  async function refresh(opts = {}) {
    if (!store.loaded) await store.loadTopology(false);
    if (opts.traceService != null) state.tracedService = opts.traceService;
    render();
    if (opts.focusNode) focusNode(opts.focusNode);
    else if (!opts.skipFit) setTimeout(fitToView, 20);
  }

  return { refresh, render, focusNode };
}
