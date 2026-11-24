// System View — Cluster Defaults, Config Versions & Rollback, Audit Log, Raw YAML Source
import { formatDateTime } from "../charts.js";
import { t } from "../i18n.js";
import {
  defaultAbuseIpDbConfig,
  defaultEvilpotConfig,
  defaultLogProtectionConfig,
  defaultNodeCacheConfig,
  defaultTopologyDefaults,
  defaultWafConfig,
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
  let subTab = "defaults"; // defaults | versions | audit | yaml
  let auditSearch = "";
  let auditStatus = "all";
  let abuseTestIp = "118.25.6.39";
  let abuseTestResult = null;
  let abuseTesting = false;

  function render() {
    const root = el("tab-system");
    if (!root) return;

    root.innerHTML = `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${subTab === "defaults" ? "active" : ""}" data-sys-sub="defaults">${esc(t("sys.tab.defaults"))}</button>
          <button type="button" class="subtab-btn ${subTab === "versions" ? "active" : ""}" data-sys-sub="versions">
            ${esc(t("sys.tab.versions"))} <span class="subtab-count">${(store.versions || []).length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "audit" ? "active" : ""}" data-sys-sub="audit">${esc(t("sys.tab.audit"))}</button>
          <button type="button" class="subtab-btn ${subTab === "yaml" ? "active" : ""}" data-sys-sub="yaml">${esc(t("sys.tab.yaml"))}</button>
        </div>
      </div>
      <div id="sys-sub-body"></div>
    `;

    root.querySelectorAll("[data-sys-sub]").forEach((btn) => {
      btn.addEventListener("click", () => {
        subTab = btn.dataset.sysSub;
        if (subTab === "versions") loadVersions();
        else if (subTab === "audit") loadAudit();
        render();
      });
    });

    const body = el("sys-sub-body");
    if (subTab === "defaults") renderDefaults(body);
    else if (subTab === "versions") renderVersions(body);
    else if (subTab === "audit") renderAudit(body);
    else renderYaml(body);
  }

  function renderDefaults(container) {
    const defs = store.spec.defaults || defaultTopologyDefaults();
    const ig = defs.ingress;
    if (!ig.cache) ig.cache = defaultNodeCacheConfig();
    if (!ig.evilpot) ig.evilpot = defaultEvilpotConfig();
    if (!ig.abuseipdb) ig.abuseipdb = defaultAbuseIpDbConfig();
    const ca = ig.cache;
    const ep = ig.evilpot;
    const ab = ig.abuseipdb;
    const gd = defs.guard;
    if (!gd.waf) gd.waf = defaultWafConfig();
    const dwaf = gd.waf;
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
    const bucketNames = Object.keys(store.spec.bucket_templates || {});

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
            <label><span>Default Guard Template</span>
              <select id="sd-ig-gd">
                <option value="">(none)</option>
                ${guardNames.map((g) => `<option value="${esc(g)}" ${ig.default_guard === g ? "selected" : ""}>${esc(g)}</option>`).join("")}
              </select>
            </label>
          </div>
          <div class="inspector-row">
            <label><span>Cert Store Dir</span><input id="sd-ig-cdir" value="${esc(ig.cert_store_dir || "")}" placeholder="./data/ingress-certs" /></label>
            <label><span>JS FP TTL (s)</span><input id="sd-ig-ttl" type="number" min="60" value="${ig.js_fp_ttl_secs ?? 3600}" /></label>
          </div>
          <label><span>Shared Clearance Secret</span>
            <div style="display:flex;gap:6px;">
              <input id="sd-ig-sec" type="password" autocomplete="off" value="${esc(ig.clearance_secret || "")}" />
              <button type="button" id="sd-gen-sec" class="btn sm">${esc(t("common.generate"))}</button>
            </div>
          </label>
          <div class="tri-stack" style="margin-top:8px;">
            ${renderBinSlider({ attrName: "data-sd-ig-bin", attrVal: "intercept_errors", label: "Intercept Errors (429 / 5xx)", val: ig.intercept_errors })}
            ${renderBinSlider({ attrName: "data-sd-ig-bin", attrVal: "js_fp_beacon", label: "Passive JS FP Beacon", val: ig.js_fp_beacon })}
          </div>
        </div>

        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header"><h3>Guard Defaults</h3></div>
          <div class="inspector-row">
            <label><span>Antibot Mode</span>
              <select id="sd-gd-mode">
                <option value="off" ${gd.antibot === "off" ? "selected" : ""}>off</option>
                <option value="silent" ${gd.antibot === "silent" ? "selected" : ""}>silent</option>
                <option value="challenge" ${gd.antibot === "challenge" ? "selected" : ""}>challenge</option>
                <option value="always" ${gd.antibot === "always" ? "selected" : ""}>always</option>
              </select>
            </label>
            <label><span>Default Bucket</span>
              <select id="sd-gd-bk">
                <option value="">(none)</option>
                ${bucketNames.map((b) => `<option value="${esc(b)}" ${gd.rate_limit_bucket === b ? "selected" : ""}>${esc(b)}</option>`).join("")}
              </select>
            </label>
          </div>
          <div class="inspector-row">
            <label><span>Challenge Score</span><input id="sd-gd-ct" type="number" min="0" max="100" value="${gd.challenge_threshold ?? 50}" /></label>
            <label><span>Reject Score</span><input id="sd-gd-rt" type="number" min="0" max="100" value="${gd.reject_threshold ?? 85}" /></label>
            <label><span>PoW Bits</span><input id="sd-gd-pow" type="number" min="4" max="28" value="${gd.pow_difficulty ?? 16}" /></label>
            <label><span>Clearance TTL</span><input id="sd-gd-ttl" type="number" min="10" value="${gd.clearance_ttl_secs ?? 600}" /></label>
          </div>
          <div class="tri-stack" style="margin-top:8px;">
            ${renderBinSlider({ attrName: "data-sd-gd-bin", attrVal: "bind_ua", label: "Bind User-Agent", val: gd.bind_ua })}
            ${renderBinSlider({ attrName: "data-sd-gd-bin", attrVal: "bind_ip_prefix", label: "Bind Client IP", val: gd.bind_ip_prefix })}
            ${renderBinSlider({ attrName: "data-sd-gd-bin", attrVal: "block_bots", label: "Block Known Bots", val: gd.block_bots })}
            ${renderBinSlider({ attrName: "data-sd-gd-bin", attrVal: "block_headless", label: "Block Headless Browsers", val: gd.block_headless })}
          </div>
          <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">
            <div class="inspector-row">
              <label><span>${esc(t("waf.mode"))}</span>
                <select id="sd-waf-mode">
                  <option value="off" ${dwaf.mode === "off" ? "selected" : ""}>${esc(t("waf.mode.off"))}</option>
                  <option value="monitor" ${dwaf.mode === "monitor" ? "selected" : ""}>${esc(t("waf.mode.monitor"))}</option>
                  <option value="block" ${dwaf.mode === "block" ? "selected" : ""}>${esc(t("waf.mode.block"))}</option>
                  <option value="evilpot" ${dwaf.mode === "evilpot" ? "selected" : ""}>${esc(t("waf.mode.evilpot"))}</option>
                </select>
              </label>
              <label><span>${esc(t("waf.min_conf"))}</span><input id="sd-waf-conf" type="number" step="0.05" min="0.1" max="1" value="${dwaf.min_confidence ?? 0.65}" /></label>
              <label><span>${esc(t("waf.max_body_kb"))}</span><input id="sd-waf-bodykb" type="number" min="0" max="256" value="${Math.round((dwaf.max_body_bytes ?? 32768) / 1024)}" /></label>
              <label><span>${esc(t("waf.crs.paranoia"))}</span>
                <select id="sd-waf-pl">
                  ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${(dwaf.crs_paranoia_level || 1) === pl ? "selected" : ""}>PL${pl}</option>`).join("")}
                </select>
              </label>
            </div>
            <div class="tri-stack" style="margin-top:6px;">
              ${renderBinSlider({ attrName: "data-sd-waf-bin", attrVal: "inspect_headers", label: t("waf.inspect_headers"), val: dwaf.inspect_headers !== false })}
              ${renderBinSlider({ attrName: "data-sd-waf-bin", attrVal: "inspect_body", label: t("waf.inspect_body"), val: dwaf.inspect_body !== false })}
              ${renderBinSlider({ attrName: "data-sd-waf-bin", attrVal: "crs_enabled", label: t("waf.crs.enabled"), val: dwaf.crs_enabled !== false })}
            </div>
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
            ${renderBinSlider({ attrName: "data-sd-logp-bin", attrVal: "enabled", label: t("log.prot_enable"), sub: t("log.prot_enable_sub"), val: prot.enabled })}
            ${renderBinSlider({ attrName: "data-sd-logp-bin", attrVal: "log_query_string", label: t("log.prot_query"), sub: t("log.prot_query_sub"), val: prot.log_query_string })}
            ${renderBinSlider({ attrName: "data-sd-logp-bin", attrVal: "access_log_stdout", label: t("log.prot_stdout"), val: prot.access_log_stdout })}
          </div>
          <div class="inspector-row" style="margin-top:8px;">
            <label><span>Sample Rate</span><input id="sd-log-sr" type="number" step="0.05" min="0.01" max="1" value="${gl.sample_rate ?? 1.0}" /></label>
            <label><span>${esc(t("log.flush_secs"))}</span><input id="sd-log-flush" type="number" min="5" value="${seg.flush_interval_secs ?? 30}" /></label>
            <label><span>${esc(t("log.max_batch_rec"))}</span><input id="sd-log-brec" type="number" min="50" value="${seg.max_batch_records ?? 500}" /></label>
            <label><span>${esc(t("log.max_batch_kb"))}</span><input id="sd-log-bkb" type="number" min="16" value="${Math.max(16, Math.round((seg.max_batch_bytes ?? 1048576) / 1024))}" /></label>
          </div>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("log.retention_h"))}</span><input id="sd-log-ret" type="number" min="1" value="${seg.retention_hours ?? 72}" /></label>
            <label><span>${esc(t("log.max_disk_mb"))}</span><input id="sd-log-disk" type="number" min="16" value="${Math.max(16, Math.round((seg.max_disk_bytes ?? 536870912) / 1048576))}" /></label>
            <label><span>${esc(t("log.max_summaries"))}</span><input id="sd-log-maxsum" type="number" min="500" value="${seg.max_summaries ?? 50000}" /></label>
            <label><span>${esc(t("log.max_fps"))}</span><input id="sd-log-maxfp" type="number" min="500" value="${seg.max_fingerprints ?? 20000}" /></label>
            <label><span>${esc(t("log.max_recent"))}</span><input id="sd-log-maxrec" type="number" min="100" max="10000" value="${seg.max_recent_logs ?? 2000}" /></label>
          </div>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("log.prot_rps"))}</span><input id="sd-logp-rps" type="number" min="10" max="100000" value="${prot.max_records_per_sec ?? 500}" /></label>
            <label><span>${esc(t("log.prot_iprps"))}</span><input id="sd-logp-iprps" type="number" min="1" max="50000" value="${prot.max_per_ip_per_sec ?? 20}" /></label>
            <label><span>${esc(t("log.prot_mbmin"))}</span><input id="sd-logp-mbmin" type="number" min="1" max="512" value="${Math.max(1, Math.round((prot.max_bytes_per_min ?? 8388608) / 1048576))}" /></label>
            <label><span>${esc(t("log.prot_dedup"))}</span><input id="sd-logp-dedup" type="number" min="0" max="300" value="${prot.dedup_window_secs ?? 10}" /></label>
            <label><span>${esc(t("log.prot_warn"))}</span><input id="sd-logp-warn" type="number" min="1" max="1000" value="${prot.warn_rate_per_sec ?? 20}" /></label>
          </div>
        </div>

        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header"><h3>${esc(t("abuse.title"))}</h3></div>
          <div class="tri-stack" style="margin-bottom:8px;">
            ${renderBinSlider({ attrName: "data-sd-ab-bin", attrVal: "enabled", label: t("abuse.enable"), sub: t("abuse.enable_sub"), val: ab.enabled })}
          </div>
          <div class="inspector-row">
            <label style="flex:1.5;"><span>${esc(t("abuse.api_key"))}</span>
              <input id="sd-ab-key" type="password" autocomplete="off" value="${esc(ab.api_key || "")}" placeholder="AbuseIPDB v2 API Key" />
            </label>
            <label><span>${esc(t("abuse.test_ip"))}</span>
              <div style="display:flex;gap:6px;">
                <input id="sd-ab-test-ip" value="${esc(abuseTestIp)}" placeholder="118.25.6.39" />
                <button type="button" id="sd-ab-test-btn" class="btn sm primary" ${abuseTesting ? "disabled" : ""}>${esc(abuseTesting ? t("abuse.testing") : t("abuse.test_btn"))}</button>
              </div>
            </label>
          </div>
          ${
            abuseTestResult
              ? `<div class="muted-sm" style="margin:6px 0;padding:6px 8px;border-radius:6px;background:var(--bg-elev);">
                  ${
                    abuseTestResult.error
                      ? `<span class="pill err">ERR</span> ${esc(abuseTestResult.error)}`
                      : `<span class="pill ${abuseTestResult.abuse_confidence_score >= 50 ? "err" : abuseTestResult.abuse_confidence_score >= 25 ? "warn" : "ok"}">Score ${esc(abuseTestResult.abuse_confidence_score)}/100</span>
                         <code>${esc(abuseTestResult.ip_address)}</code> · ${esc(abuseTestResult.country_code || "-")} · ${esc(abuseTestResult.isp || "-")} · reports: ${esc(abuseTestResult.total_reports)}${abuseTestResult.is_tor ? ` <span class="pill warn">TOR</span>` : ""}`
                  }
                </div>`
              : ""
          }
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("abuse.action"))}</span>
              <select id="sd-ab-act">
                <option value="off" ${ab.high_risk_action === "off" ? "selected" : ""}>${esc(t("abuse.action.off"))}</option>
                <option value="monitor" ${ab.high_risk_action === "monitor" ? "selected" : ""}>${esc(t("abuse.action.monitor"))}</option>
                <option value="challenge" ${ab.high_risk_action === "challenge" ? "selected" : ""}>${esc(t("abuse.action.challenge"))}</option>
                <option value="block" ${(ab.high_risk_action || "block") === "block" ? "selected" : ""}>${esc(t("abuse.action.block"))}</option>
                <option value="evilpot" ${ab.high_risk_action === "evilpot" ? "selected" : ""}>${esc(t("abuse.action.evilpot"))}</option>
              </select>
            </label>
            <label><span>${esc(t("abuse.challenge_th"))}</span><input id="sd-ab-ch" type="number" min="0" max="100" value="${ab.challenge_threshold ?? 25}" /></label>
            <label><span>${esc(t("abuse.block_th"))}</span><input id="sd-ab-blk" type="number" min="0" max="100" value="${ab.block_threshold ?? 75}" /></label>
          </div>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("abuse.max_age"))}</span><input id="sd-ab-age" type="number" min="1" max="365" value="${ab.max_age_days ?? 90}" /></label>
            <label><span>${esc(t("abuse.cache_ttl"))}</span><input id="sd-ab-ttl" type="number" min="60" value="${ab.cache_ttl_secs ?? 21600}" /></label>
            <label><span>${esc(t("abuse.daily_limit"))}</span><input id="sd-ab-cap" type="number" min="10" value="${ab.max_daily_lookups ?? 900}" /></label>
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

        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header"><h3>${esc(t("ep.defaults.title"))}</h3></div>
          <div class="inspector-row">
            <label><span>${esc(t("ep.defaults.rotation"))}</span><input id="sd-ep-rot" type="number" min="60" value="${ep.rotation_interval_secs ?? 300}" /></label>
            <label><span>${esc(t("ep.defaults.slots"))}</span><input id="sd-ep-slots" type="number" min="1" max="32" value="${ep.persona_slots ?? 16}" /></label>
            <label><span>${esc(t("ep.defaults.tarpit_conns"))}</span><input id="sd-ep-tconns" type="number" min="1" max="256" value="${ep.max_tarpit_connections ?? 256}" /></label>
          </div>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("ep.defaults.drip_bps"))}</span><input id="sd-ep-drip" type="number" min="16" max="16384" value="${ep.tarpit_drip_bytes_per_sec ?? 256}" /></label>
            <label><span>${esc(t("ep.defaults.sqli_delay"))}</span><input id="sd-ep-sqli" type="number" min="100" max="5000" value="${ep.sqli_time_delay_ms ?? 2500}" /></label>
            <label><span>${esc(t("ep.defaults.max_sessions"))}</span><input id="sd-ep-maxs" type="number" min="16" max="4096" value="${ep.max_tracked_sessions ?? 2048}" /></label>
          </div>
          <label style="margin-top:8px;"><span>${esc(t("ep.defaults.canary_url"))}</span>
            <input id="sd-ep-curl" value="${esc(ep.canary_webhook_url || "")}" placeholder="https://canary.internal.example.com/t" />
          </label>
        </div>
      </div>
    `;

    el("sd-ig-srv")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.ingress.server_header = ev.target.value; }, false));
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

    el("sd-gd-mode")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.guard.antibot = ev.target.value; }, false));
    el("sd-gd-bk")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.guard.rate_limit_bucket = ev.target.value || null; }, false));
    el("sd-gd-ct")?.addEventListener("input", (ev) => store.mutate((s) => { s.defaults.guard.challenge_threshold = parseNum(ev.target.value, 50, 0, 100); }, false));
    el("sd-gd-rt")?.addEventListener("input", (ev) => store.mutate((s) => { s.defaults.guard.reject_threshold = parseNum(ev.target.value, 85, 0, 100); }, false));
    el("sd-gd-pow")?.addEventListener("input", (ev) => store.mutate((s) => { s.defaults.guard.pow_difficulty = parseNum(ev.target.value, 16, 4, 28); }, false));
    el("sd-gd-ttl")?.addEventListener("input", (ev) => store.mutate((s) => { s.defaults.guard.clearance_ttl_secs = parseNum(ev.target.value, 600, 10); }, false));
    wireBinSliders(container, "data-sd-gd-bin", (f, v) => store.mutate((s) => { s.defaults.guard[f] = v; }, false));
    const ensureWaf = (s) => {
      if (!s.defaults.guard.waf) s.defaults.guard.waf = defaultWafConfig();
      return s.defaults.guard.waf;
    };
    el("sd-waf-mode")?.addEventListener("change", (ev) => store.mutate((s) => { ensureWaf(s).mode = ev.target.value; }, false));
    el("sd-waf-conf")?.addEventListener("input", (ev) => store.mutate((s) => { ensureWaf(s).min_confidence = parseNum(ev.target.value, 0.65, 0.1, 1.0); }, false));
    el("sd-waf-bodykb")?.addEventListener("input", (ev) => store.mutate((s) => { ensureWaf(s).max_body_bytes = parseNum(ev.target.value, 32, 0, 256) * 1024; }, false));
    el("sd-waf-pl")?.addEventListener("change", (ev) => store.mutate((s) => { ensureWaf(s).crs_paranoia_level = parseNum(ev.target.value, 1, 1, 4); }, false));
    wireBinSliders(container, "data-sd-waf-bin", (f, v) => store.mutate((s) => { ensureWaf(s)[f] = v; }, false));

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

    const ensureAb = (s) => {
      if (!s.defaults.ingress.abuseipdb) s.defaults.ingress.abuseipdb = defaultAbuseIpDbConfig();
      return s.defaults.ingress.abuseipdb;
    };
    wireBinSliders(container, "data-sd-ab-bin", (f, v) => store.mutate((s) => { ensureAb(s)[f] = v; }, false));
    el("sd-ab-key")?.addEventListener("input", (ev) => store.mutate((s) => { ensureAb(s).api_key = ev.target.value.trim(); }, false));
    el("sd-ab-test-ip")?.addEventListener("input", (ev) => { abuseTestIp = ev.target.value.trim(); });
    el("sd-ab-act")?.addEventListener("change", (ev) => store.mutate((s) => { ensureAb(s).high_risk_action = ev.target.value; }, false));
    el("sd-ab-ch")?.addEventListener("input", (ev) => store.mutate((s) => { ensureAb(s).challenge_threshold = parseNum(ev.target.value, 25, 0, 100); }, false));
    el("sd-ab-blk")?.addEventListener("input", (ev) => store.mutate((s) => { ensureAb(s).block_threshold = parseNum(ev.target.value, 75, 0, 100); }, false));
    el("sd-ab-age")?.addEventListener("input", (ev) => store.mutate((s) => { ensureAb(s).max_age_days = parseNum(ev.target.value, 90, 1, 365); }, false));
    el("sd-ab-ttl")?.addEventListener("input", (ev) => store.mutate((s) => { ensureAb(s).cache_ttl_secs = parseNum(ev.target.value, 21600, 60); }, false));
    el("sd-ab-cap")?.addEventListener("input", (ev) => store.mutate((s) => { ensureAb(s).max_daily_lookups = parseNum(ev.target.value, 900, 10); }, false));
    el("sd-ab-test-btn")?.addEventListener("click", async () => {
      if (abuseTesting) return;
      abuseTesting = true;
      abuseTestResult = null;
      render();
      try {
        const curAb = store.spec.defaults?.ingress?.abuseipdb || defaultAbuseIpDbConfig();
        abuseTestResult = await api("/api/security/abuseipdb/test", {
          method: "POST",
          body: JSON.stringify({
            api_key: curAb.api_key || "",
            ip: abuseTestIp || "118.25.6.39",
            max_age_days: curAb.max_age_days || 90,
          }),
        });
      } catch (e) {
        abuseTestResult = { error: e.message };
      } finally {
        abuseTesting = false;
        if (subTab === "defaults") render();
      }
    });

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

    const ensureEp = (s) => {
      if (!s.defaults.ingress.evilpot) s.defaults.ingress.evilpot = defaultEvilpotConfig();
      return s.defaults.ingress.evilpot;
    };
    el("sd-ep-rot")?.addEventListener("input", (ev) => store.mutate((s) => { ensureEp(s).rotation_interval_secs = parseNum(ev.target.value, 300, 60); }, false));
    el("sd-ep-slots")?.addEventListener("input", (ev) => store.mutate((s) => { ensureEp(s).persona_slots = parseNum(ev.target.value, 16, 1, 32); }, false));
    el("sd-ep-tconns")?.addEventListener("input", (ev) => store.mutate((s) => { ensureEp(s).max_tarpit_connections = parseNum(ev.target.value, 256, 1, 256); }, false));
    el("sd-ep-drip")?.addEventListener("input", (ev) => store.mutate((s) => { ensureEp(s).tarpit_drip_bytes_per_sec = parseNum(ev.target.value, 256, 16, 16384); }, false));
    el("sd-ep-sqli")?.addEventListener("input", (ev) => store.mutate((s) => { ensureEp(s).sqli_time_delay_ms = parseNum(ev.target.value, 2500, 100, 5000); }, false));
    el("sd-ep-maxs")?.addEventListener("input", (ev) => store.mutate((s) => { ensureEp(s).max_tracked_sessions = parseNum(ev.target.value, 2048, 16, 4096); }, false));
    el("sd-ep-curl")?.addEventListener("input", (ev) => store.mutate((s) => { ensureEp(s).canary_webhook_url = ev.target.value.trim().slice(0, 256); }, false));
  }

  async function loadVersions() {
    try {
      const data = await api("/api/config-versions");
      store.versions = data.versions || [];
      if (subTab === "versions") render();
    } catch (e) {
      showToast(e.message, true);
    }
  }

  function renderVersions(container) {
    const list = store.versions || [];
    container.innerHTML = `
      <div class="panel">
        <div class="panel-header"><h3>${esc(t("sys.tab.versions"))} (${list.length})</h3></div>
        <div class="table-scroll">
          <table class="table">
            <thead><tr><th>Seq</th><th>Host Tag</th><th>Created</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              ${
                list
                  .map(
                    (v) => `
                  <tr>
                    <td><strong>#${esc(v.sequence)}</strong></td>
                    <td><code>${esc(v.node_tag)}</code></td>
                    <td>${esc(formatDateTime(v.created_at))}</td>
                    <td><span class="pill ${v.status === "applied" ? "ok" : v.status === "failed" ? "err" : "warn"}">${esc(v.status)}</span></td>
                    <td>
                      <div class="btn-row">
                        <button type="button" class="btn sm" data-ver-prev="${esc(v.id)}">Preview</button>
                        <button type="button" class="btn sm danger" data-ver-rb="${esc(v.id)}">Rollback</button>
                      </div>
                    </td>
                  </tr>`
                  )
                  .join("") || `<tr><td colspan="5" class="muted">No config history</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    `;

    container.querySelectorAll("[data-ver-prev]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const rec = list.find((v) => String(v.id) === btn.dataset.verPrev);
        if (!rec) return;
        let pretty = rec.config_json;
        try { pretty = JSON.stringify(JSON.parse(rec.config_json), null, 2); } catch {}
        openModal({
          title: `Snapshot #${rec.sequence} — ${rec.node_tag}`,
          bodyHtml: `<pre class="output-box" style="max-height:55vh;">${esc(pretty)}</pre>`,
          actions: [{ label: t("common.close") }],
        });
      });
    });

    container.querySelectorAll("[data-ver-rb]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const rec = list.find((v) => String(v.id) === btn.dataset.verRb);
        if (!rec) return;
        openModal({
          title: `Confirm Rollback — ${rec.node_tag}`,
          bodyHtml: `<p>Push snapshot <b>#${esc(rec.sequence)}</b> as a new signed revision to <code>${esc(rec.node_tag)}</code>?</p>`,
          actions: [
            { label: t("common.cancel"), cls: "ghost" },
            {
              label: "Confirm Rollback",
              cls: "danger",
              onClick: async () => {
                try {
                  await api(`/api/config-versions/${encodeURIComponent(rec.id)}/rollback`, { method: "POST" });
                  showToast(`Rollback pushed to ${rec.node_tag}`);
                  loadVersions();
                } catch (e) { showToast(e.message, true); }
              },
            },
          ],
        });
      });
    });
  }

  async function loadAudit() {
    try {
      const data = await api("/api/audit");
      store.audit = data.logs || [];
      if (subTab === "audit") render();
    } catch (e) {
      showToast(e.message, true);
    }
  }

  function renderAudit(container) {
    const filtered = (store.audit || []).filter((l) => {
      if (auditStatus === "ok" && !l.success) return false;
      if (auditStatus === "fail" && l.success) return false;
      if (auditSearch && !`${l.actor} ${l.action} ${l.target} ${l.detail}`.toLowerCase().includes(auditSearch.toLowerCase())) return false;
      return true;
    });

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h3>${esc(t("sys.tab.audit"))} (${filtered.length})</h3>
          <div class="btn-row">
            <input id="sys-aud-q" class="input-sm" type="search" value="${esc(auditSearch)}" placeholder="${esc(t("common.search"))}" />
            <select id="sys-aud-st" class="select-sm">
              <option value="all" ${auditStatus === "all" ? "selected" : ""}>All</option>
              <option value="ok" ${auditStatus === "ok" ? "selected" : ""}>OK</option>
              <option value="fail" ${auditStatus === "fail" ? "selected" : ""}>Failed</option>
            </select>
          </div>
        </div>
        <div class="table-scroll">
          <table class="table">
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Detail</th></tr></thead>
            <tbody>
              ${
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
                  .join("") || `<tr><td colspan="6" class="muted">No audit entries</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    `;
    el("sys-aud-q")?.addEventListener("input", (ev) => { auditSearch = ev.target.value; render(); el("sys-aud-q")?.focus(); });
    el("sys-aud-st")?.addEventListener("change", (ev) => { auditStatus = ev.target.value; render(); });
  }

  function renderYaml(container) {
    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3>${esc(t("sys.tab.yaml"))}</h3>
            <div class="muted-sm">${esc(t("sys.yaml_hint"))}</div>
          </div>
          <div class="btn-row">
            <button type="button" id="btn-yaml-sync-from-draft" class="btn sm">Refresh from Draft</button>
            <button type="button" id="btn-yaml-apply" class="btn sm primary">${esc(t("sys.yaml_apply"))}</button>
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
    if (subTab === "versions") await loadVersions();
    else if (subTab === "audit") await loadAudit();
    else if (subTab === "yaml" && store.dirty) {
      try { await store.validate(null); } catch {}
    }
    render();
  }

  return { refresh, render };
}
