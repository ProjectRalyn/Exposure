// Exposure Control Plane — Redesigned Modular App Coordinator
import { formatDateTime } from "./charts.js";
import { applyI18n, getAvailableLangs, getLang, onLangChange, setLang, t } from "./i18n.js";
import { createControlStore } from "./store.js";
import { closeDrawer, closeModal, el, esc, initOverlayControls, openModal, showToast } from "./ui.js";
import { createAnalyticsViews } from "./views/analytics.js";
import { createDomainsView } from "./views/domains.js";
import { createHostsView } from "./views/hosts.js";
import { createOverviewView } from "./views/overview.js";
import { createSecurityView } from "./views/security.js";
import { createServicesView } from "./views/services.js";
import { createSystemView } from "./views/system.js";
import { createTopologyView } from "./views/topology.js";

const CONFIG_TABS = new Set(["hosts", "services", "domains", "security", "topology", "system"]);
const VALID_TABS = new Set([
  "overview",
  "analytics",
  "logging",
  "hosts",
  "services",
  "domains",
  "security",
  "topology",
  "system",
]);
const LEGACY_TAB_MAP = {
  nodes: { tab: "hosts" },
  onboarding: { tab: "hosts", subTab: "onboarding" },
  observability: { tab: "analytics" },
  fingerprints: { tab: "logging", subTab: "visitors" },
  logs: { tab: "logging", subTab: "access" },
  audit: { tab: "logging", subTab: "audit" },
};

const appState = {
  authenticated: false,
  activeTab: "overview",
  autoRefreshMs: 30000,
  refreshTimer: null,
  heartbeatTimer: null,
};

const SIDEBAR_HEARTBEAT_MS = 30000;

try { localStorage.removeItem("exposure_token"); } catch {}

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
    throw new Error(t("Session expired"));
  }
  const text = await resp.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!resp.ok) {
    throw new Error((data && data.error) || text || `HTTP ${resp.status}`);
  }
  return data;
}

const store = createControlStore({ api });

function navigate(tab, opts = {}) {
  const normalized = typeof opts === "string" ? { subTab: opts } : opts;
  switchTab(tab, normalized);
}

function toLocalDatetimeInputValue(ms) {
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function getTimeRangeParams() {
  const val = el("sel-time-window")?.value ?? "3600";
  if (val === "custom") {
    const rawFrom = el("inp-time-from")?.value || localStorage.getItem("exposure_time_from") || "";
    const rawTo = el("inp-time-to")?.value || localStorage.getItem("exposure_time_to") || "";
    const fMs = rawFrom ? Date.parse(rawFrom) : NaN;
    const tMs = rawTo ? Date.parse(rawTo) : NaN;
    const from_ms = Number.isFinite(fMs) ? Math.floor(fMs) : Date.now() - 86400 * 1000;
    const to_ms = Number.isFinite(tMs) ? Math.floor(tMs) : Date.now();
    return {
      mode: "custom",
      from_ms,
      to_ms,
      window_secs: null,
      applyTo(qs) {
        qs.set("from_ms", String(from_ms));
        qs.set("to_ms", String(to_ms));
        return qs;
      },
    };
  }
  const win = Number(val);
  const window_secs = Number.isFinite(win) && win >= 0 ? win : 3600;
  return {
    mode: "preset",
    from_ms: null,
    to_ms: null,
    window_secs,
    applyTo(qs) {
      qs.set("window_secs", String(window_secs));
      return qs;
    },
  };
}

const overviewView = createOverviewView({ api, store, navigate, getTimeRangeParams });
const hostsView = createHostsView({ api, store, navigate });
const servicesView = createServicesView({ store, navigate });
const domainsView = createDomainsView({ api, store });
const securityView = createSecurityView({ api, store });
const topologyView = createTopologyView({ api, store, navigate });
const analyticsViews = createAnalyticsViews({ api, store, navigate, getTimeRangeParams });
const systemView = createSystemView({ api, store });

/* ==================== AUTH & SHELL STATE ==================== */

function resetToLogin(opts = {}) {
  appState.authenticated = false;
  stopAutoRefresh();
  stopHeartbeat();
  closeModal();
  closeDrawer();
  if (el("login-pass")) el("login-pass").value = "";
  el("login-error")?.classList.add("hidden");
  el("app-view")?.classList.add("hidden");
  el("login-view")?.classList.remove("hidden");
  document.title = "Exposure Control";
  if (opts.clearUrl && window.location.hash) {
    history.replaceState(null, "", window.location.pathname + window.location.search);
  }
}

async function logout() {
  const btn = el("btn-logout");
  if (btn) { btn.disabled = true; btn.textContent = t("Signing Out…"); }
  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin", cache: "no-store" });
  } catch {} finally {
    if (btn) { btn.disabled = false; btn.textContent = t("Sign Out"); }
  }
  resetToLogin({ clearUrl: true });
  showToast(t("Signed out safely"));
  el("login-pass")?.focus();
}

function updateBootstrapBadge(bootTag) {
  const card = el("sidebar-bootstrap-status");
  if (!card) return;
  const connected = Boolean(bootTag);
  card.innerHTML = `
    <span class="live-dot ${connected ? "online" : "offline"}"></span>
    <div class="bootstrap-card-text">
      <div class="bootstrap-card-lbl">${esc(t("Bootstrap Link"))}</div>
      <div class="bootstrap-card-val">${connected ? esc(bootTag) : esc(t("Disconnected"))}</div>
    </div>`;
}

function updateTopbarTimestamp(iso) {
  const elTime = el("topbar-updated");
  if (!elTime) return;
  elTime.textContent = iso
    ? t("Telemetry: {time}", { time: formatDateTime(iso) })
    : t("Updated {time}", { time: formatDateTime(new Date().toISOString()) });
}

/* ==================== GLOBAL DEPLOY BAR & VALIDATION STRIP ==================== */

function updateSidebarBadges() {
  const hostCnt = Object.keys(store.spec.nodes || {}).length;
  const svcCnt = Object.keys(store.spec.services || {}).length;
  const domCnt = Object.keys(store.spec.domains || {}).length;
  if (el("nav-badge-hosts")) el("nav-badge-hosts").textContent = String(hostCnt);
  if (el("nav-badge-services")) el("nav-badge-services").textContent = String(svcCnt);
  if (el("nav-badge-domains")) el("nav-badge-domains").textContent = String(domCnt);
}

function updateDeployBar() {
  const bar = el("global-deploy-bar");
  if (!bar) return;
  const showBar = store.dirty || CONFIG_TABS.has(appState.activeTab);
  bar.classList.toggle("hidden", !showBar);
  bar.classList.toggle("dirty", store.dirty);

  const changes = store.dirty ? store.computeDiff() : [];
  const pill = el("deploy-status-pill");
  if (pill) {
    pill.className = `pill ${store.dirty ? "warn" : "ok"}`;
    pill.textContent = store.dirty
      ? t("{count} pending change(s)", { count: Math.max(1, changes.length) })
      : t("All changes deployed");
  }
  if (el("btn-global-undo")) el("btn-global-undo").disabled = store.undoStack.length === 0;
  if (el("btn-global-redo")) el("btn-global-redo").disabled = store.redoStack.length === 0;
  el("btn-global-diff")?.classList.toggle("hidden", !store.dirty);
  el("btn-global-discard")?.classList.toggle("hidden", !store.dirty);

  updateValidationBar();
  updateSidebarBadges();
}

function updateValidationBar() {
  const bar = el("global-val-bar");
  if (!bar) return;
  const errs = store.errors || [];
  const warns = store.warnings || [];
  if (!errs.length && !warns.length) {
    bar.classList.add("hidden");
    return;
  }
  bar.classList.remove("hidden", "ok", "err", "warn");
  bar.classList.add(errs.length ? "err" : "warn");
  const lines = [
    ...errs.map((e) => `✖ ${e}`),
    ...warns.map((w) => `⚠ ${w}`),
  ];
  bar.innerHTML = `<div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start;">
    <div style="white-space:pre-wrap;">${esc(lines.join("\n"))}</div>
    <button type="button" id="btn-dismiss-val" class="btn sm ghost">✕</button>
  </div>`;
  el("btn-dismiss-val")?.addEventListener("click", () => {
    store.errors = [];
    store.warnings = [];
    bar.classList.add("hidden");
  });
}

store.subscribe((reason) => {
  updateDeployBar();
  if (reason === "undo" || reason === "redo" || reason === "discard") {
    renderActiveTabOnly();
  }
});

/* ==================== ROUTING & REFRESH ==================== */

function getRouteFromLocation() {
  const rawHash = (window.location.hash || "").replace(/^#\/?/, "").trim().toLowerCase();
  if (VALID_TABS.has(rawHash)) return { tab: rawHash };
  if (LEGACY_TAB_MAP[rawHash]) return LEGACY_TAB_MAP[rawHash];
  const qTab = new URLSearchParams(window.location.search).get("tab");
  if (qTab && VALID_TABS.has(qTab)) return { tab: qTab };
  return { tab: "overview" };
}

// Literal (not interpolated) so `pnpm i18n:extract` can discover the source strings.
function tabTitle(tab) {
  switch (tab) {
    case "overview": return t("Overview");
    case "analytics": return t("Analytics");
    case "logging": return t("Logging");
    case "hosts": return t("Hosts");
    case "services": return t("Services");
    case "domains": return t("Domains & DNS");
    case "security": return t("Security");
    case "topology": return t("Topology");
    case "system": return t("System");
    default: return t("Overview");
  }
}

function updatePageTitle() {
  const titleText = tabTitle(appState.activeTab);
  if (el("page-title")) el("page-title").textContent = titleText;
  document.title = `${titleText} · Exposure Control`;
}

function switchTab(tab, opts = {}) {
  const targetTab = VALID_TABS.has(tab) ? tab : "overview";
  appState.activeTab = targetTab;
  document.querySelectorAll(".nav-item").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === targetTab);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("hidden", p.id !== `tab-${targetTab}`);
  });
  updatePageTitle();
  updateDeployBar();

  if (!opts.skipHistory) {
    const targetHash = `#${targetTab}`;
    if (window.location.hash !== targetHash) {
      if (opts.replaceHistory) history.replaceState({ tab: targetTab }, "", targetHash);
      else history.pushState({ tab: targetTab }, "", targetHash);
    }
  }
  refreshCurrentTab(opts);
  // Tabs other than overview/hosts don't return cluster bootstrap state, so refresh the
  // sidebar badge independently instead of leaving it stale until the user opens Overview.
  if (targetTab !== "overview" && targetTab !== "hosts") sidebarHeartbeat();
}

function renderActiveTabOnly() {
  const tab = appState.activeTab;
  if (tab === "overview") overviewView.render();
  else if (tab === "hosts") hostsView.render();
  else if (tab === "services") servicesView.render();
  else if (tab === "domains") domainsView.render();
  else if (tab === "security") securityView.render();
  else if (tab === "topology") topologyView.render();
  else if (tab === "analytics") analyticsViews.renderAnalytics();
  else if (tab === "logging") analyticsViews.renderLogging();
  else if (tab === "system") systemView.render();
}

async function refreshCurrentTab(opts = {}) {
  try {
    const tab = appState.activeTab;
    if (tab === "overview") {
      const ov = await overviewView.refresh();
      if (ov) {
        if (el("control-role-badge")) el("control-role-badge").textContent = (ov.role || "active").toUpperCase();
        updateBootstrapBadge(ov.bootstrap_node);
        updateTopbarTimestamp(ov.last_pulled_at);
      }
    } else if (tab === "hosts") {
      const nd = await hostsView.refresh(opts);
      if (nd) {
        updateBootstrapBadge(nd.bootstrap_node);
        updateTopbarTimestamp(nd.last_pulled_at);
      }
    } else if (tab === "services") {
      await servicesView.refresh();
    } else if (tab === "domains") {
      await domainsView.refresh(opts);
    } else if (tab === "security") {
      await securityView.refresh(opts);
    } else if (tab === "topology") {
      await topologyView.refresh(opts);
    } else if (tab === "analytics") {
      const data = await analyticsViews.refreshAnalytics();
      if (data) updateTopbarTimestamp(data.last_pulled_at);
    } else if (tab === "logging") {
      const data = await analyticsViews.refreshLogging(opts);
      if (data) updateTopbarTimestamp(data.last_pulled_at);
    } else if (tab === "system") {
      await systemView.refresh(opts);
    }
    updateDeployBar();
  } catch (e) {
    showToast(e.message, true);
  }
}

/* ==================== GLOBAL DEPLOY ACTIONS ==================== */

async function handleValidate() {
  try {
    const res = await store.validate();
    showToast(
      res.valid
        ? t("Configuration valid ({paths} service route(s) verified)", { paths: (res.paths || []).length })
        : t("Validation failed: {count} error(s)", { count: (res.errors || []).length }),
      !res.valid
    );
    renderActiveTabOnly();
  } catch (e) {
    showToast(e.message, true);
  }
}

async function handlePreflight() {
  try {
    showToast(t("Running preflight connectivity checks across hosts…"));
    const res = await store.preflight();
    const rowsHtml = (res.reports || [])
      .map((rep) => {
        const items = (rep.checks || [])
          .map(
            (c) => `<tr>
              <td><code>${esc(rep.node_tag)}</code></td>
              <td><code>${esc(c.target)}</code></td>
              <td><span class="pill ${c.ok ? "ok" : "err"}">${c.ok ? "PASS" : "FAIL"}</span></td>
              <td>${esc(c.detail)}</td>
            </tr>`
          )
          .join("");
        return items || `<tr><td><code>${esc(rep.node_tag)}</code></td><td>-</td><td><span class="pill ok">PASS</span></td><td>OK</td></tr>`;
      })
      .join("");

    openModal({
      title: res.all_ok ? "Preflight — All Passed" : "Preflight — Issues Found",
      bodyHtml: `<div class="table-scroll"><table class="table"><thead><tr><th>Host</th><th>Target</th><th>Result</th><th>Detail</th></tr></thead><tbody>${rowsHtml}</tbody></table></div>`,
      actions: [{ label: t("Close"), cls: "primary" }],
    });
    showToast(
      res.all_ok ? t("Preflight passed on {count} host(s)", { count: (res.reports || []).length }) : t("Preflight found connectivity or port issues"),
      !res.all_ok
    );
  } catch (e) {
    showToast(e.message, true);
  }
}

async function handleDeploy(push, syncDns = false) {
  try {
    const res = await store.deploy({ push, syncDns });
    if (push) {
      const errs = res.push_errors || [];
      showToast(
        errs.length
          ? t("Deployed to {count} host(s) with {errors} push error(s)", { count: res.pushed_count ?? 0, errors: errs.length })
          : t("Deployed & pushed to {count} host(s)", { count: res.pushed_count ?? 0 }),
        errs.length > 0
      );
      if (syncDns && res.dns_sync_error) {
        showToast(`DNS sync error: ${res.dns_sync_error}`, true);
      } else if (syncDns && res.dns_sync_results) {
        showToast(`DNS synced (${res.dns_sync_results.length} domain(s))`);
      }
    } else {
      showToast(t("Draft saved to Control SQLite"));
    }
    renderActiveTabOnly();
  } catch (e) {
    showToast(e.message, true);
  }
}

function openDiffModal() {
  const changes = store.computeDiff();
  const bodyHtml = changes.length
    ? `<div class="diff-list">${changes
        .map(
          (c) => `
        <div class="diff-row">
          <div><span class="pill ${c.kind === "add" ? "ok" : c.kind === "remove" ? "err" : "warn"}">${esc(c.kind.toUpperCase())}</span> <strong>${esc(c.label)}</strong></div>
          <code>${esc(c.name)}</code>
        </div>`
        )
        .join("")}</div>`
    : `<p class="muted">${esc(t("No unsaved changes in draft."))}</p>`;

  openModal({
    title: t("Pending Draft Changes"),
    bodyHtml,
    actions: [
      { label: t("Close"), cls: "ghost" },
      { label: t("Deploy & Push"), cls: "primary", onClick: () => handleDeploy(true, false) },
    ],
  });
}

/* ==================== THEME, LANGUAGE & AUTO REFRESH ==================== */

const THEME_STORAGE_KEY = "exposure_theme";

function applyTheme(theme) {
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_STORAGE_KEY, next); } catch {}
  document.querySelectorAll(".theme-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.themeVal === next);
  });
  if (appState.authenticated) renderActiveTabOnly();
}

applyTheme((() => {
  try { return localStorage.getItem(THEME_STORAGE_KEY) || "dark"; } catch { return "dark"; }
})());

document.querySelectorAll(".theme-btn").forEach((btn) => {
  btn.addEventListener("click", () => applyTheme(btn.dataset.themeVal));
});

// Language pickers are rendered from the locale files on disk, so adding a new
// translation file is enough to expose it in both the login and topbar selectors.
function renderLangSelectors() {
  const langs = getAvailableLangs();
  const current = getLang();
  for (const id of ["sel-lang", "sel-lang-login"]) {
    const select = el(id);
    if (!select) continue;
    const signature = langs.map((l) => l.code).join("|");
    if (select.dataset.signature !== signature) {
      select.innerHTML = langs
        .map((l) => `<option value="${esc(l.code)}">${esc(l.name)}</option>`)
        .join("");
      select.dataset.signature = signature;
    }
    select.value = current;
  }
}

function syncLanguageUI() {
  const lang = getLang();
  document.documentElement.lang = lang;
  applyI18n(document);
  renderLangSelectors();
  updatePageTitle();
  updateDeployBar();
  if (appState.authenticated) renderActiveTabOnly();
}

onLangChange(syncLanguageUI);

for (const id of ["sel-lang", "sel-lang-login"]) {
  el(id)?.addEventListener("change", (ev) => setLang(ev.target.value));
}

// Views replace innerHTML wholesale, so translated text must be re-applied after every
// repaint. A debounced MutationObserver keeps this automatic: developers write plain
// English and never annotate nodes. API-driven regions are excluded inside applyI18n().
function observeI18nDom() {
  if (typeof MutationObserver === "undefined") return;
  const root = el("app-view") || document.body;
  if (!root) return;
  let queued = false;
  const flush = () => {
    queued = false;
    applyI18n(root);
  };
  new MutationObserver(() => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(flush);
  }).observe(root, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["placeholder", "title", "aria-label", "alt"],
  });
}
observeI18nDom();

function startAutoRefresh() {
  stopAutoRefresh();
  if (appState.autoRefreshMs > 0 && appState.authenticated) {
    appState.refreshTimer = setInterval(() => {
      if (store.dirty) return; // Never disrupt active draft editing
      refreshCurrentTab({ skipFit: true });
    }, appState.autoRefreshMs);
  }
}
function stopAutoRefresh() {
  if (appState.refreshTimer) { clearInterval(appState.refreshTimer); appState.refreshTimer = null; }
}

// Lightweight cluster heartbeat: keeps the sidebar "Bootstrap Link" card and the topbar
// "updated at" timestamp fresh no matter which tab is currently selected.
async function sidebarHeartbeat() {
  if (!appState.authenticated) return;
  try {
    const nd = await api("/api/nodes", { method: "GET" });
    updateBootstrapBadge(nd.bootstrap_node);
    if (nd.last_pulled_at) updateTopbarTimestamp(nd.last_pulled_at);
  } catch {
    /* transient network/auth errors are surfaced by the active tab refresh instead */
  }
}
function startHeartbeat() {
  stopHeartbeat();
  if (!appState.authenticated) return;
  sidebarHeartbeat();
  appState.heartbeatTimer = setInterval(sidebarHeartbeat, SIDEBAR_HEARTBEAT_MS);
}
function stopHeartbeat() {
  if (appState.heartbeatTimer) { clearInterval(appState.heartbeatTimer); appState.heartbeatTimer = null; }
}

/* ==================== WIRE GLOBAL EVENTS ==================== */

initOverlayControls();

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

el("btn-logout")?.addEventListener("click", logout);
el("btn-refresh")?.addEventListener("click", () => refreshCurrentTab());
el("btn-discover")?.addEventListener("click", async () => {
  try {
    const r = await api("/api/discovery/run", { method: "POST" });
    showToast(`Discovery completed: ${r.discovered_nodes ?? 0} host(s)`);
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

el("btn-global-undo")?.addEventListener("click", () => { if (store.undo()) showToast(t("Undo")); });
el("btn-global-redo")?.addEventListener("click", () => { if (store.redo()) showToast(t("Redo")); });
el("btn-global-diff")?.addEventListener("click", openDiffModal);
el("btn-global-discard")?.addEventListener("click", () => {
  openModal({
    title: t("Discard Draft"),
    bodyHtml: `<p>${esc(t("Discard Draft"))}?</p>`,
    actions: [
      { label: t("Cancel"), cls: "ghost" },
      { label: t("Confirm"), cls: "danger", onClick: () => { store.discardDraft(); showToast("Draft discarded"); } },
    ],
  });
});
el("btn-global-validate")?.addEventListener("click", handleValidate);
el("btn-global-preflight")?.addEventListener("click", handlePreflight);
el("btn-global-save-draft")?.addEventListener("click", () => handleDeploy(false, false));
el("btn-global-deploy")?.addEventListener("click", () => handleDeploy(true, false));
el("btn-global-deploy-dns")?.addEventListener("click", () => handleDeploy(true, true));

el("sel-auto-refresh")?.addEventListener("change", (ev) => {
  appState.autoRefreshMs = Number(ev.target.value) || 0;
  startAutoRefresh();
});
const savedWin = localStorage.getItem("exposure_time_window");
const savedFrom = localStorage.getItem("exposure_time_from");
const savedTo = localStorage.getItem("exposure_time_to");
function syncCustomTimeVisibility() {
  const isCustom = el("sel-time-window")?.value === "custom";
  el("time-custom-wrap")?.classList.toggle("hidden", !isCustom);
  if (isCustom) {
    if (el("inp-time-from") && !el("inp-time-from").value) {
      el("inp-time-from").value = savedFrom || toLocalDatetimeInputValue(Date.now() - 86400 * 1000);
    }
    if (el("inp-time-to") && !el("inp-time-to").value) {
      el("inp-time-to").value = savedTo || toLocalDatetimeInputValue(Date.now());
    }
  }
}
if (savedWin !== null && el("sel-time-window")) {
  const validOpt = Array.from(el("sel-time-window").options).some((o) => o.value === savedWin);
  el("sel-time-window").value = validOpt ? savedWin : "3600";
}
if (el("inp-time-from") && savedFrom) el("inp-time-from").value = savedFrom;
if (el("inp-time-to") && savedTo) el("inp-time-to").value = savedTo;
syncCustomTimeVisibility();

el("sel-time-window")?.addEventListener("change", (ev) => {
  localStorage.setItem("exposure_time_window", ev.target.value);
  syncCustomTimeVisibility();
  if (ev.target.value !== "custom") {
    refreshCurrentTab();
  }
});
el("btn-time-apply")?.addEventListener("click", () => {
  const f = el("inp-time-from")?.value || "";
  const tVal = el("inp-time-to")?.value || "";
  if (f) localStorage.setItem("exposure_time_from", f);
  if (tVal) localStorage.setItem("exposure_time_to", tVal);
  refreshCurrentTab();
});

window.addEventListener("keydown", (ev) => {
  if (!appState.authenticated) return;
  const tag = document.activeElement?.tagName;
  const inInput = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
  if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "s") {
    ev.preventDefault();
    if (store.dirty) handleDeploy(false, false);
  } else if (!inInput && (ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "z" && !ev.shiftKey) {
    if (store.undo()) { ev.preventDefault(); showToast(t("Undo")); }
  } else if (!inInput && (ev.ctrlKey || ev.metaKey) && (ev.key.toLowerCase() === "y" || (ev.shiftKey && ev.key.toLowerCase() === "z"))) {
    if (store.redo()) { ev.preventDefault(); showToast(t("Redo")); }
  }
});

el("login-form")?.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  el("login-error")?.classList.add("hidden");
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
    appState.authenticated = true;
    el("login-view")?.classList.add("hidden");
    el("app-view")?.classList.remove("hidden");
    await store.loadTopology(true).catch(() => {});
    const route = getRouteFromLocation();
    switchTab(route.tab, { subTab: route.subTab, replaceHistory: true });
    startAutoRefresh();
    startHeartbeat();
  } catch (e) {
    if (el("login-error")) {
      el("login-error").textContent = e.message;
      el("login-error").classList.remove("hidden");
    }
  }
});

window.addEventListener("hashchange", () => {
  if (!appState.authenticated) return;
  const route = getRouteFromLocation();
  if (route.tab !== appState.activeTab) switchTab(route.tab, { subTab: route.subTab, skipHistory: true });
});

async function bootstrapSession() {
  syncLanguageUI();
  try {
    await api("/api/auth/me", { method: "GET", skipLogoutOn401: true });
    appState.authenticated = true;
    el("login-view")?.classList.add("hidden");
    el("app-view")?.classList.remove("hidden");
    await store.loadTopology(true).catch(() => {});
    const route = getRouteFromLocation();
    switchTab(route.tab, { subTab: route.subTab, replaceHistory: true });
    startAutoRefresh();
    startHeartbeat();
  } catch {
    resetToLogin();
  }
}

bootstrapSession();
