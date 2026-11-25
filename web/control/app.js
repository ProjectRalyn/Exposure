// Exposure Control Plane — Redesigned Modular App Coordinator
import { formatDateTime } from "./charts.js";
import { applyStaticI18n, getLang, onLangChange, setLang, t } from "./i18n.js";
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
  audit: { tab: "system", subTab: "audit" },
};

const appState = {
  authenticated: false,
  activeTab: "overview",
  autoRefreshMs: 30000,
  refreshTimer: null,
};

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
    throw new Error(t("auth.session_expired"));
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
  switchTab(tab, opts);
}

const overviewView = createOverviewView({ api, store, navigate });
const hostsView = createHostsView({ api, store, navigate });
const servicesView = createServicesView({ store, navigate });
const domainsView = createDomainsView({ api, store });
const securityView = createSecurityView({ api, store });
const topologyView = createTopologyView({ store, navigate });
const analyticsViews = createAnalyticsViews({ api, store, navigate });
const systemView = createSystemView({ api, store });

/* ==================== AUTH & SHELL STATE ==================== */

function resetToLogin(opts = {}) {
  appState.authenticated = false;
  stopAutoRefresh();
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
  if (btn) { btn.disabled = true; btn.textContent = t("auth.signing_out"); }
  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin", cache: "no-store" });
  } catch {} finally {
    if (btn) { btn.disabled = false; btn.textContent = t("auth.signout"); }
  }
  resetToLogin({ clearUrl: true });
  showToast(t("auth.signed_out"));
  el("login-pass")?.focus();
}

function updateBootstrapBadge(bootTag) {
  const card = el("sidebar-bootstrap-status");
  if (!card) return;
  const connected = Boolean(bootTag);
  card.innerHTML = `
    <span class="live-dot ${connected ? "online" : "offline"}"></span>
    <div class="bootstrap-card-text">
      <div class="bootstrap-card-lbl">${esc(t("sidebar.bootstrap"))}</div>
      <div class="bootstrap-card-val">${connected ? esc(bootTag) : esc(t("sidebar.disconnected"))}</div>
    </div>`;
}

function updateTopbarTimestamp(iso) {
  const elTime = el("topbar-updated");
  if (!elTime) return;
  elTime.textContent = iso
    ? t("topbar.updated_telemetry", { time: formatDateTime(iso) })
    : t("topbar.updated_at", { time: formatDateTime(new Date().toISOString()) });
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
      ? t("deploy.pending", { count: Math.max(1, changes.length) })
      : t("deploy.clean");
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

function updatePageTitle() {
  const titleText = t(`nav.${appState.activeTab}`);
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
        ? t("deploy.validated_ok", { paths: (res.paths || []).length })
        : t("deploy.validated_err", { count: (res.errors || []).length }),
      !res.valid
    );
    renderActiveTabOnly();
  } catch (e) {
    showToast(e.message, true);
  }
}

async function handlePreflight() {
  try {
    showToast(t("deploy.preflight_running"));
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
      actions: [{ label: t("common.close"), cls: "primary" }],
    });
    showToast(
      res.all_ok ? t("deploy.preflight_ok", { count: (res.reports || []).length }) : t("deploy.preflight_fail"),
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
          ? t("deploy.pushed_partial", { count: res.pushed_count ?? 0, errors: errs.length })
          : t("deploy.pushed_ok", { count: res.pushed_count ?? 0 }),
        errs.length > 0
      );
      if (syncDns && res.dns_sync_error) {
        showToast(`DNS sync error: ${res.dns_sync_error}`, true);
      } else if (syncDns && res.dns_sync_results) {
        showToast(`DNS synced (${res.dns_sync_results.length} domain(s))`);
      }
    } else {
      showToast(t("deploy.saved_draft"));
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
    : `<p class="muted">${esc(t("deploy.no_changes"))}</p>`;

  openModal({
    title: t("deploy.diff_title"),
    bodyHtml,
    actions: [
      { label: t("common.close"), cls: "ghost" },
      { label: t("deploy.push_all"), cls: "primary", onClick: () => handleDeploy(true, false) },
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

function syncLanguageUI() {
  const lang = getLang();
  document.documentElement.lang = lang;
  applyStaticI18n(document);
  document.querySelectorAll(".lang-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.lang === lang);
  });
  if (el("btn-login-lang")) {
    el("btn-login-lang").textContent = lang === "zh-CN" ? "English" : "简体中文";
  }
  updatePageTitle();
  updateDeployBar();
  if (appState.authenticated) renderActiveTabOnly();
}

onLangChange(syncLanguageUI);

document.querySelectorAll(".lang-btn").forEach((btn) => {
  btn.addEventListener("click", () => setLang(btn.dataset.lang));
});
el("btn-login-lang")?.addEventListener("click", () => {
  setLang(getLang() === "zh-CN" ? "en" : "zh-CN");
});

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

el("btn-global-undo")?.addEventListener("click", () => { if (store.undo()) showToast(t("deploy.undo")); });
el("btn-global-redo")?.addEventListener("click", () => { if (store.redo()) showToast(t("deploy.redo")); });
el("btn-global-diff")?.addEventListener("click", openDiffModal);
el("btn-global-discard")?.addEventListener("click", () => {
  openModal({
    title: t("deploy.discard"),
    bodyHtml: `<p>${esc(t("deploy.discard"))}?</p>`,
    actions: [
      { label: t("common.cancel"), cls: "ghost" },
      { label: t("common.confirm"), cls: "danger", onClick: () => { store.discardDraft(); showToast("Draft discarded"); } },
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
if (savedWin !== null && el("sel-time-window")) el("sel-time-window").value = savedWin;
el("sel-time-window")?.addEventListener("change", (ev) => {
  localStorage.setItem("exposure_time_window", ev.target.value);
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
    if (store.undo()) { ev.preventDefault(); showToast(t("deploy.undo")); }
  } else if (!inInput && (ev.ctrlKey || ev.metaKey) && (ev.key.toLowerCase() === "y" || (ev.shiftKey && ev.key.toLowerCase() === "z"))) {
    if (store.redo()) { ev.preventDefault(); showToast(t("deploy.redo")); }
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
  } catch {
    resetToLogin();
  }
}

bootstrapSession();
