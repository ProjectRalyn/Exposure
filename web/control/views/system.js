// System View — Cluster Defaults, Config Versions & Rollback, Audit Log, Raw YAML Source
import { formatDateTime } from "../charts.js";
import { t } from "../i18n.js";
import { defaultTopologyDefaults } from "../store.js";
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
    const gd = defs.guard;
    const eg = defs.egress;
    const ll = defs.link_listener;
    const gl = store.spec.global_logger || { store_raw_ip: false, sample_rate: 1.0, segment: { retention_hours: 72 } };
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
            ${renderBinSlider({ attrName: "data-sd-log-bin", attrVal: "store_raw_ip", label: "Store Raw Client IP in Fingerprints", val: Boolean(gl.store_raw_ip) })}
          </div>
          <div class="inspector-row" style="margin-top:8px;">
            <label><span>Sample Rate</span><input id="sd-log-sr" type="number" step="0.05" min="0.01" max="1" value="${gl.sample_rate ?? 1.0}" /></label>
            <label><span>Retention (hours)</span><input id="sd-log-ret" type="number" min="1" value="${gl.segment?.retention_hours ?? 72}" /></label>
          </div>
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

    el("sd-eg-proto")?.addEventListener("change", (ev) => store.mutate((s) => { s.defaults.egress.protocol = ev.target.value; }, false));
    el("sd-eg-to")?.addEventListener("input", (ev) => store.mutate((s) => { s.defaults.egress.timeout_ms = parseNum(ev.target.value, 30000, 100); }, false));
    wireBinSliders(container, "data-sd-eg-bin", (f, v) => store.mutate((s) => { s.defaults.egress[f] = v; }, false));

    wireBinSliders(container, "data-sd-ll-bin", (f, v) => store.mutate((s) => { s.defaults.link_listener[f] = v; }, false));
    const ensureGl = (s) => {
      if (!s.global_logger) s.global_logger = { hmac_key: "", store_raw_ip: false, sample_rate: 1.0, hll_precision: 12, segment: { retention_hours: 72 } };
      if (!s.global_logger.segment) s.global_logger.segment = { retention_hours: 72 };
      return s.global_logger;
    };
    wireBinSliders(container, "data-sd-log-bin", (f, v) => store.mutate((s) => { ensureGl(s)[f] = v; }, false));
    el("sd-log-sr")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).sample_rate = parseNum(ev.target.value, 1.0, 0.01, 1.0); }, false));
    el("sd-log-ret")?.addEventListener("input", (ev) => store.mutate((s) => { ensureGl(s).segment.retention_hours = parseNum(ev.target.value, 72, 1); }, false));
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
