// System View — Cluster Defaults, Storage & Retention, Git-style Releases, Raw YAML Source
import { formatBytes, formatCompact, formatDateTime } from "../charts.js";
import { t } from "../i18n.js";
import {
  defaultLogProtectionConfig,
  defaultNodeCacheConfig,
  defaultTopologyDefaults,
} from "../store.js";
import {
  el,
  esc,
  generateRandomSecretHex,
  openModal,
  parseNum,
  renderBinSlider,
  showToast,
  wireBinSliders,
} from "../ui.js";

export function createSystemView({ api, store }) {
  let subTab = "defaults"; // defaults | storage | releases | yaml

  let storageData = null;
  let storageDraft = null;
  let storageBusy = false;
  let releasesData = null;
  let releasesBusy = false;

  function render() {
    const root = el("tab-system");
    if (!root) return;

    root.innerHTML = `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${subTab === "defaults" ? "active" : ""}" data-sys-sub="defaults">${esc(t("Cluster Defaults"))}</button>
          <button type="button" class="subtab-btn ${subTab === "storage" ? "active" : ""}" data-sys-sub="storage">${esc(t("Storage & Retention"))}</button>
          <button type="button" class="subtab-btn ${subTab === "releases" ? "active" : ""}" data-sys-sub="releases">
            ${esc(t("Releases"))} <span class="subtab-count">${(releasesData?.items || []).length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "yaml" ? "active" : ""}" data-sys-sub="yaml">${esc(t("YAML Source"))}</button>
        </div>
      </div>
      <div id="sys-sub-body"></div>
    `;

    root.querySelectorAll("[data-sys-sub]").forEach((btn) => {
      btn.addEventListener("click", () => {
        subTab = btn.dataset.sysSub;
        if (subTab === "storage") loadStorage();
        else if (subTab === "releases") loadReleases();
        render();
      });
    });

    const body = el("sys-sub-body");
    if (subTab === "defaults") renderDefaults(body);
    else if (subTab === "storage") renderStorage(body);
    else if (subTab === "releases") renderReleases(body);
    else renderYaml(body);
  }

  function renderDefaults(container) {
    const defs = store.spec.defaults || defaultTopologyDefaults();
    const ig = defs.ingress;
    if (!ig.cache) ig.cache = defaultNodeCacheConfig();
    const ca = ig.cache;
    const eg = defs.egress;
    const ll = defs.link_listener;
    const gl = store.spec.global_logger || {
      store_raw_ip: false,
      sample_rate: 1.0,
      segment: {
        flush_interval_secs: 30,
        max_batch_records: 500,
        max_batch_bytes: 1024 * 1024,
        max_disk_bytes: 512 * 1024 * 1024,
        retention_hours: 72,
        max_summaries: 50000,
        max_fingerprints: 20000,
        max_recent_logs: 2000,
      },
      protection: defaultLogProtectionConfig(),
    };
    const seg = gl.segment || {};
    const prot = { ...defaultLogProtectionConfig(), ...(gl.protection || {}) };
    const guardNames = Object.keys(store.spec.guard_templates || {});
    const bucketNames = Object.keys(store.spec.bucket_templates || {}).sort();
    const antibotNames = Object.keys(store.spec.antibot_templates || {}).sort();
    const wafNames = Object.keys(store.spec.waf_templates || {}).sort();

    container.innerHTML = `
      <div class="defaults-grid">
        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header"><h3>Ingress Defaults</h3></div>
          <div class="inspector-row">
            <label><span>Server Header</span>
              <select id="sd-ig-srv">
                <option value="nginx" ${(ig.server_header || "nginx") === "nginx" ? "selected" : ""}>nginx (Disguised)</option>
                <option value="exposure" ${ig.server_header === "exposure" ? "selected" : ""}>exposure</option>
              </select>
            </label>
            <label><span>Default Bucket Set</span>
              <select id="sd-ig-dbk">
                <option value="">(none)</option>
                ${bucketNames.map((b) => `<option value="${esc(b)}" ${ig.default_bucket === b ? "selected" : ""}>${esc(b)}</option>`).join("")}
              </select>
            </label>
          </div>
          <div class="inspector-row">
            <label><span>Default Antibot Set</span>
              <select id="sd-ig-dab">
                <option value="">(none)</option>
                ${antibotNames.map((a) => `<option value="${esc(a)}" ${ig.default_antibot === a ? "selected" : ""}>${esc(a)}</option>`).join("")}
              </select>
            </label>
            <label><span>Default WAF Set</span>
              <select id="sd-ig-dwf">
                <option value="">(none)</option>
                ${wafNames.map((w) => `<option value="${esc(w)}" ${ig.default_waf === w ? "selected" : ""}>${esc(w)}</option>`).join("")}
              </select>
            </label>
          </div>
          ${
            ig.default_guard
              ? `<label><span>Legacy Default Guard</span>
                  <select id="sd-ig-gd">
                    <option value="">(none — use modular sets)</option>
                    ${guardNames.map((g) => `<option value="${esc(g)}" ${ig.default_guard === g ? "selected" : ""}>${esc(g)}</option>`).join("")}
                  </select>
                </label>`
              : ""
          }
          <div class="inspector-row">
            <label><span>Cert Store Dir</span><input id="sd-ig-cdir" value="${esc(ig.cert_store_dir || "")}" placeholder="./data/ingress-certs" /></label>
            <label><span>JS FP TTL (s)</span><input id="sd-ig-ttl" type="number" min="60" value="${ig.js_fp_ttl_secs ?? 3600}" /></label>
          </div>
          <label><span>Shared Clearance Secret</span>
            <div style="display:flex;gap:6px;">
              <input id="sd-ig-sec" type="password" autocomplete="off" value="${esc(ig.clearance_secret || "")}" />
              <button type="button" id="sd-gen-sec" class="btn sm">${esc(t("Generate"))}</button>
            </div>
          </label>
          <div class="tri-stack" style="margin-top:8px;">
            ${renderBinSlider({ attrName: "data-sd-ig-bin", attrVal: "intercept_errors", label: "Intercept Errors (403 / 429 / 5xx)", val: ig.intercept_errors })}
            ${renderBinSlider({ attrName: "data-sd-ig-bin", attrVal: "js_fp_beacon", label: "Passive JS FP Beacon", val: ig.js_fp_beacon })}
          </div>
        </div>

        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header"><h3>Egress Defaults</h3></div>
          <div class="inspector-row">
            <label><span>Protocol</span>
              <select id="sd-eg-proto">
                <option value="auto" ${eg.protocol === "auto" ? "selected" : ""}>auto</option>
                <option value="http1" ${eg.protocol === "http1" ? "selected" : ""}>http1</option>
                <option value="h2" ${eg.protocol === "h2" ? "selected" : ""}>h2</option>
              </select>
            </label>
            <label><span>Timeout (ms)</span><input id="sd-eg-to" type="number" min="100" value="${eg.timeout_ms ?? 30000}" /></label>
          </div>
          <div class="tri-stack" style="margin-top:8px;">
            ${renderBinSlider({ attrName: "data-sd-eg-bin", attrVal: "tls", label: "Backend TLS", val: eg.tls })}
            ${renderBinSlider({ attrName: "data-sd-eg-bin", attrVal: "insecure_skip_verify", label: "Skip Backend Cert Verify", val: eg.insecure_skip_verify })}
            ${renderBinSlider({ attrName: "data-sd-eg-bin", attrVal: "allow_any_origin", label: "Allow Any Origin Node", val: eg.allow_any_origin })}
            ${renderBinSlider({ attrName: "data-sd-eg-bin", attrVal: "intercept_errors", label: "Intercept 5xx Errors", val: eg.intercept_errors })}
          </div>
        </div>

        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header"><h3>Mesh Listener &amp; Privacy Logger</h3></div>
          <div class="tri-stack">
            ${renderBinSlider({ attrName: "data-sd-ll-bin", attrVal: "allow_on_demand", label: "Allow On-Demand Links", val: ll.allow_on_demand })}
            ${renderBinSlider({ attrName: "data-sd-ll-bin", attrVal: "allow_tunnel", label: "Allow Reverse Tunnels", val: ll.allow_tunnel })}
            ${renderBinSlider({ attrName: "data-sd-ll-bin", attrVal: "allow_bootstrap", label: "Allow Bootstrap Onboarding", val: ll.allow_bootstrap })}
            ${renderBinSlider({ attrName: "data-sd-log-bin", attrVal: "store_raw_ip", label: "Store Raw Client IP in Fingerprints & Logs", val: Boolean(gl.store_raw_ip) })}
            ${renderBinSlider({ attrName: "data-sd-logp-bin", attrVal: "enabled", label: t("Enable Log DoS Protection"), sub: t("Token-bucket rate limit, byte ceiling & duplicate flood folding (metrics stay 100% exact)"), val: prot.enabled })}
            ${renderBinSlider({ attrName: "data-sd-logp-bin", attrVal: "log_query_string", label: t("Log Redacted URL Query Strings"), sub: t("Records sanitized URL ?query parameters while auto-redacting secret keys (token, password, key, auth)"), val: prot.log_query_string })}
            ${renderBinSlider({ attrName: "data-sd-logp-bin", attrVal: "access_log_stdout", label: t("Emit Stdout Access Logs"), val: prot.access_log_stdout })}
          </div>
          <div class="inspector-row" style="margin-top:8px;">
            <label><span>Sample Rate</span><input id="sd-log-sr" type="number" step="0.05" min="0.01" max="1" value="${gl.sample_rate ?? 1.0}" /></label>
            <label><span>${esc(t("Node Push Interval (s)"))}</span><input id="sd-log-flush" type="number" min="5" value="${seg.flush_interval_secs ?? 30}" /></label>
            <label><span>${esc(t("Early Flush Records"))}</span><input id="sd-log-brec" type="number" min="50" value="${seg.max_batch_records ?? 500}" /></label>
            <label><span>${esc(t("Early Flush Size (KiB)"))}</span><input id="sd-log-bkb" type="number" min="16" value="${Math.max(16, Math.round((seg.max_batch_bytes ?? 1048576) / 1024))}" /></label>
          </div>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("Maintainer Retention (h)"))}</span><input id="sd-log-ret" type="number" min="1" value="${seg.retention_hours ?? 72}" /></label>
            <label><span>${esc(t("Maintainer Max Disk (MiB)"))}</span><input id="sd-log-disk" type="number" min="16" value="${Math.max(16, Math.round((seg.max_disk_bytes ?? 536870912) / 1048576))}" /></label>
            <label><span>${esc(t("Max Summaries in Store"))}</span><input id="sd-log-maxsum" type="number" min="500" value="${seg.max_summaries ?? 50000}" /></label>
            <label><span>${esc(t("Max Fingerprints in Store"))}</span><input id="sd-log-maxfp" type="number" min="500" value="${seg.max_fingerprints ?? 20000}" /></label>
            <label><span>${esc(t("Recent URL Logs Cap"))}</span><input id="sd-log-maxrec" type="number" min="100" max="10000" value="${seg.max_recent_logs ?? 2000}" /></label>
          </div>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("Global Log Cap (rec/s)"))}</span><input id="sd-logp-rps" type="number" min="10" max="100000" value="${prot.max_records_per_sec ?? 500}" /></label>
            <label><span>${esc(t("Per-IP Log Cap (rec/s)"))}</span><input id="sd-logp-iprps" type="number" min="1" max="50000" value="${prot.max_per_ip_per_sec ?? 20}" /></label>
            <label><span>${esc(t("Log Byte Cap (MiB/min)"))}</span><input id="sd-logp-mbmin" type="number" min="1" max="512" value="${Math.max(1, Math.round((prot.max_bytes_per_min ?? 8388608) / 1048576))}" /></label>
            <label><span>${esc(t("Flood Fold Window (s)"))}</span><input id="sd-logp-dedup" type="number" min="0" max="300" value="${prot.dedup_window_secs ?? 10}" /></label>
            <label><span>${esc(t("Warn Log Cap (/s)"))}</span><input id="sd-logp-warn" type="number" min="1" max="1000" value="${prot.warn_rate_per_sec ?? 20}" /></label>
          </div>
        </div>

        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header"><h3>Edge HTTP Response Cache Defaults</h3></div>
          <div class="tri-stack" style="margin-bottom:8px;">
            ${renderBinSlider({ attrName: "data-sd-ca-bin", attrVal: "enabled", label: "Enable Edge Cache by Default", sub: "In-memory LRU cache on Ingress hosts (RFC 9111 Vary + ETag 304 + Stale-if-Error)", val: ca.enabled })}
            ${renderBinSlider({ attrName: "data-sd-ca-bin", attrVal: "respect_cache_control", label: "Respect Cache-Control Headers", sub: "Honor s-maxage / max-age / no-store / private (Set-Cookie is never cached)", val: ca.respect_cache_control })}
            ${renderBinSlider({ attrName: "data-sd-ca-bin", attrVal: "ignore_query_string", label: "Ignore Query String in Cache Key", val: ca.ignore_query_string })}
          </div>
          <div class="inspector-row">
            <label><span>Memory Budget (MiB)</span><input id="sd-ca-mem" type="number" min="1" value="${Math.round((ca.max_memory_bytes || 67108864) / 1048576)}" /></label>
            <label><span>Max Object (MiB)</span><input id="sd-ca-obj" type="number" min="1" value="${Math.max(1, Math.round((ca.max_object_bytes || 4194304) / 1048576))}" /></label>
            <label><span>Default TTL (s)</span><input id="sd-ca-ttl" type="number" min="0" value="${ca.default_ttl_secs ?? 60}" /></label>
            <label><span>Stale-if-Error (s)</span><input id="sd-ca-stale" type="number" min="0" value="${ca.stale_if_error_secs ?? 300}" /></label>
          </div>
          <label style="margin-top:8px;"><span>Bypass Cookie Prefixes (CSV)</span>
            <input id="sd-ca-ck" value="${esc((ca.bypass_cookie_prefixes || []).join(", "))}" placeholder="session=, auth_" />
          </label>
        </div>
      </div>
    `;

    el("sd-ig-srv")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.ingress.server_header = ev.target.value; }, false));
    el("sd-ig-dbk")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.ingress.default_bucket = ev.target.value || null; }, false));
    el("sd-ig-dab")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.ingress.default_antibot = ev.target.value || null; }, false));
    el("sd-ig-dwf")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.ingress.default_waf = ev.target.value || null; }, false));
    el("sd-ig-gd")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.ingress.default_guard = ev.target.value || null; }, false));
    el("sd-ig-cdir")?.addEventListener("input", (ev) => store.mutate((s) => { s.defaults.ingress.cert_store_dir = ev.target.value.trim() || null; }, false));
    el("sd-ig-ttl")?.addEventListener("input", (ev) => store.mutate((s) => { s.defaults.ingress.js_fp_ttl_secs = parseNum(ev.target.value, 3600, 60); }, false));
    el("sd-ig-sec")?.addEventListener("input", (ev) => store.mutate((s) => { s.defaults.ingress.clearance_secret = ev.target.value.trim(); }, false));
    el("sd-gen-sec")?.addEventListener("click", () => {
      store.mutate((s) => { s.defaults.ingress.clearance_secret = generateRandomSecretHex(32); });
      render();
      showToast("Generated cluster clearance secret");
    });
    wireBinSliders(container, "data-sd-ig-bin", (f, v) => store.mutate((s) => { s.defaults.ingress[f] = v; }, false));

    el("sd-eg-proto")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.egress.protocol = ev.target.value; }, false));
    el("sd-eg-to")?.addEventListener("input", (ev) => store.mutate((s) => { s.defaults.egress.timeout_ms = parseNum(ev.target.value, 30000, 100); }, false));
    wireBinSliders(container, "data-sd-eg-bin", (f, v) => store.mutate((s) => { s.defaults.egress[f] = v; }, false));

    wireBinSliders(container, "data-sd-ll-bin", (f, v) => store.mutate((s) => { s.defaults.link_listener[f] = v; }, false));
    const ensureGl = (s) => {
      if (!s.global_logger) {
        s.global_logger = {
          hmac_key: "",
          store_raw_ip: false,
          sample_rate: 1.0,
          hll_precision: 12,
          segment: {
            flush_interval_secs: 30,
            max_batch_records: 500,
            max_batch_bytes: 1024 * 1024,
            max_disk_bytes: 512 * 1024 * 1024,
            retention_hours: 72,
            max_summaries: 50000,
            max_fingerprints: 20000,
            max_recent_logs: 2000,
          },
          protection: defaultLogProtectionConfig(),
        };
      }
      if (!s.global_logger.segment) s.global_logger.segment = { retention_hours: 72, max_recent_logs: 2000 };
      if (!s.global_logger.protection) s.global_logger.protection = defaultLogProtectionConfig();
      return s.global_logger;
    };
    wireBinSliders(container, "data-sd-log-bin", (f, v) => store.mutate((s) => { ensureGl(s)[f] = v; }, false));
    wireBinSliders(container, "data-sd-logp-bin", (f, v) => store.mutate((s) => { ensureGl(s).protection[f] = v; }, false));
    el("sd-log-sr")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).sample_rate = parseNum(ev.target.value, 1.0, 0.01, 1.0); }, false));
    el("sd-log-flush")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).segment.flush_interval_secs = parseNum(ev.target.value, 30, 5); }, false));
    el("sd-log-brec")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).segment.max_batch_records = parseNum(ev.target.value, 500, 50); }, false));
    el("sd-log-bkb")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).segment.max_batch_bytes = parseNum(ev.target.value, 1024, 16) * 1024; }, false));
    el("sd-log-ret")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).segment.retention_hours = parseNum(ev.target.value, 72, 1); }, false));
    el("sd-log-disk")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).segment.max_disk_bytes = parseNum(ev.target.value, 512, 16) * 1048576; }, false));
    el("sd-log-maxsum")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).segment.max_summaries = parseNum(ev.target.value, 50000, 500); }, false));
    el("sd-log-maxfp")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).segment.max_fingerprints = parseNum(ev.target.value, 20000, 500); }, false));
    el("sd-log-maxrec")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).segment.max_recent_logs = parseNum(ev.target.value, 2000, 100, 10000); }, false));
    el("sd-logp-rps")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).protection.max_records_per_sec = parseNum(ev.target.value, 500, 10, 100000); }, false));
    el("sd-logp-iprps")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).protection.max_per_ip_per_sec = parseNum(ev.target.value, 20, 1, 50000); }, false));
    el("sd-logp-mbmin")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).protection.max_bytes_per_min = parseNum(ev.target.value, 8, 1, 512) * 1048576; }, false));
    el("sd-logp-dedup")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).protection.dedup_window_secs = parseNum(ev.target.value, 10, 0, 300); }, false));
    el("sd-logp-warn")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).protection.warn_rate_per_sec = parseNum(ev.target.value, 20, 1, 1000); }, false));

    const ensureCa = (s) => {
      if (!s.defaults.ingress.cache) s.defaults.ingress.cache = defaultNodeCacheConfig();
      return s.defaults.ingress.cache;
    };
    wireBinSliders(container, "data-sd-ca-bin", (f, v) => store.mutate((s) => { ensureCa(s)[f] = v; }, false));
    el("sd-ca-mem")?.addEventListener("input", (ev) => store.mutate((s) => { ensureCa(s).max_memory_bytes = parseNum(ev.target.value, 64, 1, 16384) * 1048576; }, false));
    el("sd-ca-obj")?.addEventListener("input", (ev) => store.mutate((s) => { ensureCa(s).max_object_bytes = parseNum(ev.target.value, 4, 1, 512) * 1048576; }, false));
    el("sd-ca-ttl")?.addEventListener("input", (ev) => store.mutate((s) => { ensureCa(s).default_ttl_secs = parseNum(ev.target.value, 60, 0); }, false));
    el("sd-ca-stale")?.addEventListener("input", (ev) => store.mutate((s) => { ensureCa(s).stale_if_error_secs = parseNum(ev.target.value, 300, 0); }, false));
    el("sd-ca-ck")?.addEventListener("input", (ev) => store.mutate((s) => { ensureCa(s).bypass_cookie_prefixes = ev.target.value.split(",").map((x) => x.trim()).filter(Boolean); }, false));
  }

  /* ==================== STORAGE & RETENTION ==================== */

  async function loadStorage() {
    try {
      storageData = await api("/api/storage/retention");
      storageDraft = {
        control: JSON.parse(JSON.stringify(storageData.control_retention || {})),
        maintainer: JSON.parse(JSON.stringify(storageData.maintainer_retention || {})),
      };
      if (subTab === "storage") render();
    } catch (e) {
      showToast(e.message, true);
    }
  }

  function renderStorage(container) {
    if (!storageData) {
      container.innerHTML = `<div class="panel muted">Loading storage stats…</div>`;
      loadStorage();
      return;
    }
    const c = storageDraft?.control || storageData.control_retention || {};
    const m = storageDraft?.maintainer || storageData.maintainer_retention || {};
    const cs = storageData.control_stats || {};
    const maintStats = storageData.maintainer_stats || [];

    const num = (attr, key, val, min = 0, extra = "") =>
      `<label><span>${esc(attr)}</span><input type="number" min="${min}" data-${extra || "cret"}="${key}" value="${esc(val ?? "")}" /></label>`;
    const mret = (label, key, val, min = 0) =>
      `<label><span>${esc(label)}</span><input type="number" min="${min}" data-mret="${key}" value="${esc(val ?? "")}" /></label>`;

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h3>Control Plane Storage</h3>
          <span class="muted-sm">SQLite live usage · ${formatBytes((cs.db_bytes || 0) + (cs.wal_bytes || 0))}</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:12px;">
          <div class="kpi"><div class="kpi-label">DB</div><div class="kpi-val">${formatBytes(cs.db_bytes || 0)}</div><div class="kpi-sub">WAL ${formatBytes(cs.wal_bytes || 0)}</div></div>
          <div class="kpi"><div class="kpi-label">Releases</div><div class="kpi-val">${formatCompact(cs.config_releases_rows || 0)}</div><div class="kpi-sub">legacy versions: ${formatCompact(cs.config_versions_rows || 0)}</div></div>
          <div class="kpi"><div class="kpi-label">Audit Logs</div><div class="kpi-val">${formatCompact(cs.audit_logs_rows || 0)}</div><div class="kpi-sub">Nodes: ${formatCompact(cs.nodes_rows || 0)}</div></div>
          <div class="kpi"><div class="kpi-label">Last Cleanup</div><div class="kpi-val" style="font-size:14px;">${esc(cs.last_cleanup_at ? formatDateTime(cs.last_cleanup_at) : "never")}</div><div class="kpi-sub">interval: ${esc(c.control_cleanup_interval_mins ?? 60)}m</div></div>
        </div>
        <div class="inspector-row">
          ${num("Releases retention (days, 0 = off)", "config_releases_retention_days", c.config_releases_retention_days, 0)}
          ${num("Releases max count", "config_releases_max_count", c.config_releases_max_count, 1)}
          ${num("Audit logs retention (days)", "audit_logs_retention_days", c.audit_logs_retention_days, 0)}
          ${num("Audit logs max rows", "audit_logs_max_rows", c.audit_logs_max_rows, 1)}
        </div>
        <div class="inspector-row">
          ${num("Expired passphrase retention (hours)", "expired_passphrases_retention_hours", c.expired_passphrases_retention_hours, 0)}
          ${num("Cleanup interval (mins)", "control_cleanup_interval_mins", c.control_cleanup_interval_mins, 1)}
        </div>
        <div class="btn-row" style="margin-top:12px;">
          <button type="button" id="btn-storage-save" class="btn primary" ${storageBusy ? "disabled" : ""}>Save &amp; Push</button>
          <button type="button" id="btn-storage-cleanup" class="btn" ${storageBusy ? "disabled" : ""}>Run Cleanup Now</button>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <h3>Maintainer Storage &amp; Retention</h3>
          <span class="muted-sm">Hot-reloaded to every Maintainer via a signed topology release</span>
        </div>
        <div class="table-scroll" style="margin-bottom:12px;">
          <table class="table">
            <thead><tr><th>Maintainer</th><th>DB</th><th>WAL</th><th>Access</th><th>Summaries</th><th>Fingerprints</th><th>Evilpot</th><th>Bans</th><th>Alerts</th></tr></thead>
            <tbody>
              ${
                maintStats
                  .map(
                    (s) => `
                <tr>
                  <td><code>${esc(s.maintainer_tag || "-")}</code></td>
                  <td>${formatBytes(s.db_bytes || 0)}</td>
                  <td>${formatBytes(s.wal_bytes || 0)}</td>
                  <td>${formatCompact(s.access_logs_rows || 0)}</td>
                  <td>${formatCompact(s.minute_summaries_rows || 0)}</td>
                  <td>${formatCompact(s.fingerprints_rows || 0)}</td>
                  <td>${formatCompact(s.evilpot_sessions_rows || 0)} / ${formatCompact(s.evilpot_events_rows || 0)}</td>
                  <td>${formatCompact(s.ban_records_rows || 0)}</td>
                  <td>${formatCompact(s.alerts_rows || 0)}</td>
                </tr>`
                  )
                  .join("") || `<tr><td colspan="9" class="muted">${esc(t("No Maintainer storage stats reported yet"))}</td></tr>`
              }
            </tbody>
          </table>
        </div>
        <div class="inspector-row">
          ${mret("Access logs retention (hours)", "access_logs_retention_hours", m.access_logs_retention_hours, 0)}
          ${mret("Access logs max rows", "access_logs_max_rows", m.access_logs_max_rows, 1)}
          ${mret("Stats retention (days)", "stats_retention_days", m.stats_retention_days, 0)}
          ${mret("Max minute summaries", "max_summaries", m.max_summaries, 1)}
        </div>
        <div class="inspector-row">
          ${mret("Fingerprint retention (days)", "fingerprints_retention_days", m.fingerprints_retention_days, 0)}
          ${mret("Max fingerprints", "max_fingerprints", m.max_fingerprints, 1)}
          ${mret("Evilpot retention (days)", "evilpot_retention_days", m.evilpot_retention_days, 0)}
          ${mret("Max evilpot events", "evilpot_max_events", m.evilpot_max_events, 1)}
          ${mret("Max evilpot sessions", "evilpot_max_sessions", m.evilpot_max_sessions, 1)}
        </div>
        <div class="inspector-row">
          ${mret("Ban history retention (days)", "bans_retention_days", m.bans_retention_days, 0)}
          ${mret("Max ban rows", "bans_max_rows", m.bans_max_rows, 1)}
          ${mret("Alert retention (days)", "alerts_retention_days", m.alerts_retention_days, 0)}
          ${mret("Max alert rows", "alerts_max_rows", m.alerts_max_rows, 1)}
        </div>
        <div class="inspector-row">
          <label><span>Max DB size (MiB)</span><input type="number" min="16" data-mret-mib="max_db_bytes" value="${esc(m.max_db_bytes ? Math.round(m.max_db_bytes / 1048576) : 1024)}" /></label>
          ${mret("Cleanup interval (mins)", "cleanup_interval_mins", m.cleanup_interval_mins, 1)}
        </div>
      </div>
    `;

    const collect = () => {
      const nextControl = {};
      container.querySelectorAll("[data-cret]").forEach((inp) => {
        nextControl[inp.dataset.cret] = parseNum(inp.value, 0, 0);
      });
      const nextMaint = {};
      container.querySelectorAll("[data-mret]").forEach((inp) => {
        nextMaint[inp.dataset.mret] = parseNum(inp.value, 0, 0);
      });
      const mib = container.querySelector("[data-mret-mib]");
      if (mib) nextMaint.max_db_bytes = parseNum(mib.value, 1024, 16) * 1048576;
      return { control_retention: nextControl, maintainer_retention: nextMaint };
    };

    el("btn-storage-save")?.addEventListener("click", async () => {
      if (storageBusy) return;
      storageBusy = true;
      try {
        const payload = { ...collect(), push: true };
        const res = await api("/api/storage/retention", { method: "PUT", body: JSON.stringify(payload) });
        if ((res.push_errors || []).length) {
          showToast(`Saved, but ${res.push_errors.length} node(s) failed to apply`, true);
        } else {
          showToast(res.release?.revision ? `Saved · release ${res.release.revision}` : "Retention policy saved");
        }
        await loadStorage();
      } catch (e) {
        showToast(e.message, true);
      } finally {
        storageBusy = false;
        render();
      }
    });
    el("btn-storage-cleanup")?.addEventListener("click", async () => {
      if (storageBusy) return;
      storageBusy = true;
      try {
        const res = await api("/api/storage/cleanup", { method: "POST" });
        const cc = res.control_cleanup || {};
        const maint = (res.maintainer_cleanups || []).filter((x) => x.ok).length;
        showToast(`Cleanup done · ${cc.deleted_audit_logs ?? 0} audit rows, ${cc.deleted_releases ?? 0} releases, ${maint} maintainer(s)`);
        await loadStorage();
      } catch (e) {
        showToast(e.message, true);
      } finally {
        storageBusy = false;
        render();
      }
    });
  }

  /* ==================== GIT-STYLE RELEASES ==================== */

  async function loadReleases() {
    try {
      releasesData = await api("/api/config-releases?limit=100");
      if (subTab === "releases") render();
    } catch (e) {
      showToast(e.message, true);
    }
  }

  function renderReleases(container) {
    const data = releasesData || {};
    const list = data.releases || [];
    const latestRev = data.latest_revision || "";
    if (!releasesData) {
      container.innerHTML = `<div class="panel muted">Loading releases…</div>`;
      loadReleases();
      return;
    }

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h3>Global Releases (${list.length})</h3>
          <div class="btn-row">
            <span class="muted-sm">Latest <code>${esc(latestRev || "-")}</code></span>
            <button type="button" id="btn-releases-refresh" class="btn sm">Refresh</button>
          </div>
        </div>
        <div class="table-scroll">
          <table class="table">
            <thead><tr><th>Revision</th><th>Seq</th><th>Parent</th><th>Time</th><th>Actor</th><th>Trigger</th><th>Nodes</th><th>Actions</th></tr></thead>
            <tbody>
              ${
                list
                  .map((r) => {
                    const nodes = r.nodes || [];
                    const applied = nodes.filter((n) => n.status === "applied").length;
                    const failed = nodes.filter((n) => n.status === "failed").length;
                    const pill = failed
                      ? `<span class="pill err">${applied}/${nodes.length} applied</span>`
                      : applied === nodes.length && nodes.length
                      ? `<span class="pill ok">${applied}/${nodes.length} applied</span>`
                      : `<span class="pill warn">${applied}/${nodes.length} applied</span>`;
                    return `
                <tr>
                  <td><span class="rev-badge">${esc(r.revision)}</span>${r.revision === latestRev ? ` <span class="pill ok">latest</span>` : ""}</td>
                  <td>#${esc(r.release_seq)}</td>
                  <td>${r.parent_revision ? `<span class="rev-badge">${esc(r.parent_revision)}</span>` : "—"}</td>
                  <td class="muted-sm">${esc(formatDateTime(r.created_at))}</td>
                  <td>${esc(r.pushed_by || "-")}</td>
                  <td class="muted-sm">${esc(r.trigger_kind || "-")}</td>
                  <td>
                    <details>
                      <summary class="muted-sm" style="cursor:pointer;">${pill}</summary>
                      <div style="margin-top:6px;display:flex;flex-direction:column;gap:3px;">
                        ${
                          nodes
                            .map(
                              (n) => `<span class="muted-sm"><code>${esc(n.node_tag)}</code> · <span class="pill ${n.status === "applied" ? "ok" : n.status === "failed" ? "err" : "warn"}">${esc(n.status)}</span>${n.error ? ` · ${esc(n.error)}` : ""}</span>`
                            )
                            .join("") || `<span class="muted-sm">no per-node records</span>`
                        }
                      </div>
                    </details>
                  </td>
                  <td>
                    <div class="btn-row">
                      <button type="button" class="btn sm" data-rel-details="${esc(r.revision)}">Details</button>
                      <button type="button" class="btn sm danger" data-rel-rb="${esc(r.revision)}" ${releasesBusy || r.revision === latestRev ? "disabled" : ""}>Rollback</button>
                    </div>
                  </td>
                </tr>`;
                  })
                  .join("") || `<tr><td colspan="8" class="muted">${esc(t("No releases yet — deploy a topology to create the first one"))}</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    `;

    el("btn-releases-refresh")?.addEventListener("click", loadReleases);
    container.querySelectorAll("[data-rel-details]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const rec = list.find((r) => r.revision === btn.dataset.relDetails);
        if (!rec) return;
        const rows = (rec.nodes || [])
          .map((n) => `<tr><td><code>${esc(n.node_tag)}</code></td><td><span class="pill ${n.status === "applied" ? "ok" : n.status === "failed" ? "err" : "warn"}">${esc(n.status)}</span></td><td class="muted-sm">${esc(n.updated_at || "-")}</td><td>${esc(n.error || "-")}</td></tr>`)
          .join("");
        openModal({
          title: `Release ${rec.revision} (#${rec.release_seq})`,
          bodyHtml: `
            <div class="fp-detail-grid">
              <div class="fp-kv"><div class="fp-kv-lbl">Full Hash</div><div class="fp-kv-val"><code style="word-break:break-all;">${esc(rec.revision_full)}</code></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Parent / Trigger</div><div class="fp-kv-val">${esc(rec.parent_revision || "—")} · ${esc(rec.trigger_kind || "-")}</div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Actor / Time</div><div class="fp-kv-val">${esc(rec.pushed_by || "-")} · ${esc(formatDateTime(rec.created_at))}</div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">CRS Version</div><div class="fp-kv-val"><code>${esc(rec.crs_version || "-")}</code></div></div>
            </div>
            <p class="muted-sm" style="margin-top:8px;">${esc(rec.message || "")}</p>
            <div class="table-scroll" style="margin-top:8px;">
              <table class="table">
                <thead><tr><th>Node</th><th>Status</th><th>Updated</th><th>Error</th></tr></thead>
                <tbody>${rows || `<tr><td colspan="4" class="muted">no per-node records</td></tr>`}</tbody>
              </table>
            </div>`,
          actions: [{ label: t("Close") }],
        });
      });
    });
    container.querySelectorAll("[data-rel-rb]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const rev = btn.dataset.relRb;
        openModal({
          title: `Rollback to ${rev}`,
          bodyHtml: `<p>Create a new forward release that reverts the cluster to <span class="rev-badge">${esc(rev)}</span>?</p><p class="muted-sm">This pushes a brand-new globally-signed release to every node.</p>`,
          actions: [
            { label: t("Cancel"), cls: "ghost" },
            {
              label: "Rollback",
              cls: "danger",
              onClick: async () => {
                releasesBusy = true;
                try {
                  const res = await api(`/api/config-releases/${encodeURIComponent(rev)}/rollback`, { method: "POST" });
                  showToast(`Rolled back as ${res.revision}`);
                  await loadReleases();
                } catch (e) {
                  showToast(e.message, true);
                } finally {
                  releasesBusy = false;
                  render();
                }
              },
            },
          ],
        });
      });
    });
  }

  function renderYaml(container) {
    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3>${esc(t("YAML Source"))}</h3>
            <div class="muted-sm">${esc(t("Advanced raw TopologySpec YAML editor. Changes here sync with all visual tabs when applied."))}</div>
          </div>
          <div class="btn-row">
            <button type="button" id="btn-yaml-sync-from-draft" class="btn sm">Refresh from Draft</button>
            <button type="button" id="btn-yaml-apply" class="btn sm primary">${esc(t("Parse & Apply YAML to Draft"))}</button>
          </div>
        </div>
        <textarea id="sys-yaml-editor" class="code-editor" spellcheck="false">${esc(store.yaml || "")}</textarea>
      </div>
    `;

    el("btn-yaml-sync-from-draft")?.addEventListener("click", async () => {
      try {
        const res = await store.validate(null);
        if (el("sys-yaml-editor")) el("sys-yaml-editor").value = res.yaml || store.yaml;
        showToast("Synced YAML from current draft");
      } catch (e) { showToast(e.message, true); }
    });
    el("btn-yaml-apply")?.addEventListener("click", async () => {
      try {
        const raw = el("sys-yaml-editor")?.value || "";
        const res = await store.validate(raw);
        showToast(res.valid ? "Parsed YAML & applied to draft" : `Parsed with ${(res.errors || []).length} error(s)`, !res.valid);
      } catch (e) { showToast(e.message, true); }
    });
  }

  async function refresh(opts = {}) {
    if (opts.subTab) subTab = opts.subTab;
    if (!store.loaded) await store.loadTopology(false);
    if (subTab === "storage") await loadStorage();
    else if (subTab === "releases") await loadReleases();
    else if (subTab === "yaml" && store.dirty) {
      try { await store.validate(null); } catch {}
    }
    render();
  }

  return { refresh, render };
}
