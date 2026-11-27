// Security View — Buckets, Antibot & GeoIP Region-Targeting, Pure OWASP CRS WAF, GeoIP DB, Pages
import { formatDateTime } from "../charts.js";
import { t } from "../i18n.js";
import {
  defaultAbuseIpDbConfig,
  defaultAntibotProfile,
  defaultEvilpotConfig,
  defaultGeoIpConfig,
  defaultGeoPolicyConfig,
  defaultTopologyDefaults,
  defaultWafConfig,
  GEO_RULE_ACTIONS,
  isReservedKey,
  normalizeCrsUpdateConfig,
  WAF_CATEGORIES,
} from "../store.js";
import {
  el,
  esc,
  openModal,
  parseNum,
  renderBinSlider,
  renderTriSlider,
  showToast,
  wireBinSliders,
  wireTriSliders,
} from "../ui.js";

// Literal t() calls (instead of `t(\`waf.cat.${c}\`)`) so `pnpm i18n:extract` can see them.
function wafCategoryLabel(cat) {
  switch (cat) {
    case "sql-injection": return t("SQLi");
    case "xss": return t("XSS");
    case "path-traversal": return t("Path Traversal");
    case "command-injection": return t("Cmd Injection");
    case "nosql-injection": return t("NoSQLi");
    case "ssrf": return t("SSRF");
    case "ssti": return t("SSTI / Code");
    case "xxe": return t("XXE / XML");
    case "ldap-injection": return t("LDAPi");
    case "crlf-injection": return t("CRLF");
    case "deserialization": return t("JNDI / Deser");
    case "buffer-overflow": return t("Overflow");
    default: return cat;
  }
}

const QUICK_GEO_TOKENS = [
  "CN",
  "HK",
  "TW",
  "JP",
  "SG",
  "US",
  "GB",
  "DE",
  "FR",
  "RU",
  "BR",
  "IN",
  "CONTINENT:AS",
  "CONTINENT:EU",
  "CONTINENT:NA",
  "CONTINENT:SA",
  "CONTINENT:AF",
  "CONTINENT:OC",
];

export function createSecurityView({ api, store }) {
  let subTab = "buckets"; // buckets | antibot | waf | intel | geoip | pages
  let setScope = "cluster"; // "cluster" | <ingress-node-tag>
  let previewMode = "error"; // error | challenge

  let wafRulesData = null;
  let wafRulesLoading = false;
  let wafSyncing = false;
  let wafSearch = "";
  let wafPlFilter = "all"; // all | 1 | 2 | 3 | 4
  let wafStatusFilter = "all"; // all | on | off

  let geoipData = null;
  let geoipLoading = false;
  let geoipSyncing = false;
  let geoLookupResult = null;
  let geoQuickTargetBySet = {}; // scope:setName -> "deny" | "allow"
  let geoPanelOpenBySet = {}; // scope:setName -> boolean

  let abuseTestIp = "118.25.6.39";
  let abuseTestResult = null;
  let abuseTesting = false;

  function ingressNodes() {
    return Object.entries(store.spec.nodes || {})
      .filter(([, n]) => n.roles?.ingress)
      .sort(([a], [b]) => a.localeCompare(b));
  }

  function validateScope() {
    if (setScope !== "cluster") {
      const n = store.spec.nodes?.[setScope];
      if (!n || !n.roles?.ingress) setScope = "cluster";
    }
  }

  function getSetConfig(kind) {
    validateScope();
    const mapKey = kind === "bucket" ? "rate_limit_buckets" : kind === "antibot" ? "antibot_sets" : "waf_sets";
    const tplKey = kind === "bucket" ? "bucket_templates" : kind === "antibot" ? "antibot_templates" : "waf_templates";
    const defField = kind === "bucket" ? "default_bucket" : kind === "antibot" ? "default_antibot" : "default_waf";
    const isNodeScope = setScope !== "cluster";

    const getMap = (spec) => {
      if (!isNodeScope) {
        if (!spec[tplKey]) spec[tplKey] = {};
        return spec[tplKey];
      }
      const ig = spec.nodes?.[setScope]?.ingress;
      if (!ig) return {};
      if (!ig[mapKey]) ig[mapKey] = {};
      return ig[mapKey];
    };

    return { mapKey, tplKey, defField, isNodeScope, getMap };
  }

  function listKeysForNode(kind, nodeTag = null) {
    const tplKey = kind === "bucket" ? "bucket_templates" : kind === "antibot" ? "antibot_templates" : "waf_templates";
    const mapKey = kind === "bucket" ? "rate_limit_buckets" : kind === "antibot" ? "antibot_sets" : "waf_sets";
    const clusterKeys = Object.keys(store.spec[tplKey] || {});
    if (!nodeTag) return clusterKeys.sort();
    const nodeKeys = Object.keys(store.spec.nodes?.[nodeTag]?.ingress?.[mapKey] || {});
    return [...new Set([...clusterKeys, ...nodeKeys])].sort();
  }

  function countSetUsage(kind) {
    const field = kind; // "bucket" | "antibot" | "waf"
    const defField = `default_${kind}`;
    const counts = {};
    const clusterDef = store.spec.defaults?.ingress?.[defField];

    for (const svc of Object.values(store.spec.services || {})) {
      if (svc.enabled === false) continue;
      if (svc[field]) counts[svc[field]] = (counts[svc[field]] || 0) + 1;
      for (const ov of Object.values(svc.ingress?.overrides || {})) {
        if (ov?.[field]) counts[ov[field]] = (counts[ov[field]] || 0) + 1;
      }
    }
    if (clusterDef) counts[clusterDef] = (counts[clusterDef] || 0) + 1;
    for (const [, n] of ingressNodes()) {
      const nd = n.ingress?.[defField];
      if (nd) counts[nd] = (counts[nd] || 0) + 1;
      for (const r of n.ingress?.rules || []) {
        if (r[field]) counts[r[field]] = (counts[r[field]] || 0) + 1;
      }
    }
    return counts;
  }

  function hasLegacyGuards() {
    if (Object.keys(store.spec.guard_templates || {}).length > 0) return true;
    if (store.spec.defaults?.ingress?.default_guard) return true;
    for (const svc of Object.values(store.spec.services || {})) {
      if (svc.guard) return true;
      for (const ov of Object.values(svc.ingress?.overrides || {})) {
        if (ov?.guard) return true;
      }
    }
    for (const n of Object.values(store.spec.nodes || {})) {
      if (n.ingress?.default_guard) return true;
      if (Object.keys(n.ingress?.guards || {}).length > 0) return true;
      for (const r of n.ingress?.rules || []) {
        if (r.guard) return true;
      }
    }
    return false;
  }

  function splitLegacyGuardIntoSets(name, g, abTarget, wafTarget) {
    const hasAb =
      (g.antibot && g.antibot !== "off") ||
      (g.allow_cidrs || []).length > 0 ||
      (g.deny_cidrs || []).length > 0 ||
      (g.api_bypass_headers || []).length > 0 ||
      g.bind_ua != null ||
      g.bind_ip_prefix != null ||
      g.block_bots != null ||
      g.browser_only != null ||
      g.block_headless != null ||
      g.require_client_fp != null ||
      g.js_fp_beacon != null ||
      g.geo?.enabled;

    let antibotName = null;
    if (hasAb) {
      let abKey = name;
      if (abTarget[abKey]) abKey = `${name}-ab`;
      const copy = { ...defaultAntibotProfile(), ...g };
      delete copy.rate_limit_bucket;
      delete copy.waf;
      abTarget[abKey] = copy;
      antibotName = abKey;
    }

    let wafName = null;
    if (g.waf && g.waf.mode && g.waf.mode !== "off") {
      let wKey = name;
      if (wafTarget[wKey]) wKey = `${name}-waf`;
      wafTarget[wKey] = { ...defaultWafConfig(), ...g.waf };
      wafName = wKey;
    }

    return {
      bucket: g.rate_limit_bucket || null,
      antibot: antibotName,
      waf: wafName,
    };
  }

  function migrateLegacyGuards() {
    store.mutate((s) => {
      if (!s.antibot_templates) s.antibot_templates = {};
      if (!s.waf_templates) s.waf_templates = {};
      const gMap = {};
      for (const [gName, g] of Object.entries(s.guard_templates || {})) {
        gMap[gName] = splitLegacyGuardIntoSets(gName, g, s.antibot_templates, s.waf_templates);
      }
      const applyMapping = (holder, legacyField = "guard") => {
        const gName = holder?.[legacyField];
        if (!gName) return;
        const m = gMap[gName];
        if (m) {
          if (!holder.bucket && m.bucket) holder.bucket = m.bucket;
          if (!holder.antibot && m.antibot) holder.antibot = m.antibot;
          if (!holder.waf && m.waf) holder.waf = m.waf;
        }
        holder[legacyField] = null;
      };
      if (s.defaults?.ingress?.default_guard) {
        const m = gMap[s.defaults.ingress.default_guard];
        if (m) {
          if (!s.defaults.ingress.default_bucket && m.bucket) s.defaults.ingress.default_bucket = m.bucket;
          if (!s.defaults.ingress.default_antibot && m.antibot) s.defaults.ingress.default_antibot = m.antibot;
          if (!s.defaults.ingress.default_waf && m.waf) s.defaults.ingress.default_waf = m.waf;
        }
        s.defaults.ingress.default_guard = null;
      }
      for (const svc of Object.values(s.services || {})) {
        applyMapping(svc, "guard");
        for (const ov of Object.values(svc.ingress?.overrides || {})) applyMapping(ov, "guard");
      }
      for (const n of Object.values(s.nodes || {})) {
        if (!n.ingress) continue;
        const localMap = { ...gMap };
        if (!n.ingress.antibot_sets) n.ingress.antibot_sets = {};
        if (!n.ingress.waf_sets) n.ingress.waf_sets = {};
        for (const [lgName, lg] of Object.entries(n.ingress.guards || {})) {
          localMap[lgName] = splitLegacyGuardIntoSets(
            lgName,
            lg,
            n.ingress.antibot_sets,
            n.ingress.waf_sets
          );
        }
        if (n.ingress.default_guard) {
          const lm = localMap[n.ingress.default_guard];
          if (lm) {
            if (!n.ingress.default_bucket && lm.bucket) n.ingress.default_bucket = lm.bucket;
            if (!n.ingress.default_antibot && lm.antibot) n.ingress.default_antibot = lm.antibot;
            if (!n.ingress.default_waf && lm.waf) n.ingress.default_waf = lm.waf;
          }
          n.ingress.default_guard = null;
        }
        for (const r of n.ingress.rules || []) {
          const rm = r.guard ? localMap[r.guard] : null;
          if (rm) {
            if (!r.bucket && rm.bucket) r.bucket = rm.bucket;
            if (!r.antibot && rm.antibot) r.antibot = rm.antibot;
            if (!r.waf && rm.waf) r.waf = rm.waf;
          }
          r.guard = null;
        }
        n.ingress.guards = {};
      }
      s.guard_templates = {};
    });
    render();
    showToast(t("Migrated legacy guards into Bucket / Antibot / WAF sets in draft"));
  }

  function isValidSetName(name) {
    return typeof name === "string" && /^[A-Za-z0-9._-]{1,64}$/.test(name) && !isReservedKey(name);
  }

  function tryRenameSet(inp, cfg, kind, dataKey) {
    const oldN = inp.dataset[dataKey];
    const newN = inp.value.trim();
    const cur = cfg.getMap(store.spec);
    if (!newN || newN === oldN) {
      inp.value = oldN;
      return;
    }
    if (!isValidSetName(newN)) {
      inp.value = oldN;
      showToast(t("Invalid name (use 1-64 letters, digits, ., _, -)"), true);
      return;
    }
    if (cur[newN]) {
      inp.value = oldN;
      return;
    }
    store.mutate((s) => {
      const m = cfg.getMap(s);
      m[newN] = m[oldN];
      delete m[oldN];
      renameSetReferences(s, kind, oldN, newN);
    });
    render();
  }

  function renameSetReferences(s, kind, oldN, newN) {
    const defField = `default_${kind}`;
    if (s.defaults?.ingress?.[defField] === oldN) s.defaults.ingress[defField] = newN;
    for (const svc of Object.values(s.services || {})) {
      if (svc[kind] === oldN) svc[kind] = newN;
      for (const ov of Object.values(svc.ingress?.overrides || {})) {
        if (ov?.[kind] === oldN) ov[kind] = newN;
      }
    }
    for (const n of Object.values(s.nodes || {})) {
      if (!n.ingress) continue;
      if (n.ingress[defField] === oldN) n.ingress[defField] = newN;
      for (const r of n.ingress.rules || []) {
        if (r[kind] === oldN) r[kind] = newN;
      }
    }
  }

  function renderLegacyMigrationBanner() {
    if (!hasLegacyGuards()) return "";
    const gCount = Object.keys(store.spec.guard_templates || {}).length;
    return `
      <div class="panel" style="border-color:var(--warn);margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
        <div>
          <strong style="color:var(--warn);">${esc(t("Legacy Guard Policies Detected"))}</strong>
          <div class="muted-sm">${esc(t("{count} legacy monolithic guard profile(s) can be cleanly split into modular Bucket / Antibot / WAF sets.", { count: gCount }))}</div>
        </div>
        <button type="button" id="btn-sec-migrate-guards" class="btn sm primary">${esc(t("Migrate to Modular Sets"))}</button>
      </div>
    `;
  }

  function wireLegacyMigrationBanner() {
    el("btn-sec-migrate-guards")?.addEventListener("click", migrateLegacyGuards);
  }

  function renderScopeAndAssignmentCard(kind, titleKey) {
    validateScope();
    const ingNodes = ingressNodes();
    const defField = `default_${kind}`;
    const clusterOpts = listKeysForNode(kind, null);
    const clusterDef = store.spec.defaults?.ingress?.[defField] || "";
    const mapKey = kind === "bucket" ? "rate_limit_buckets" : kind === "antibot" ? "antibot_sets" : "waf_sets";

    return `
      <div class="panel" style="margin-bottom:14px;">
        <div class="panel-header" style="margin-bottom:10px;">
          <h3>${esc(t(titleKey))}</h3>
          <div class="btn-row">
            <label style="flex-direction:row;align-items:center;gap:6px;">
              <span class="muted-sm">${esc(t("Edit Scope"))}</span>
              <select id="sec-set-scope" class="select-sm" style="width:auto;min-width:170px;">
                <option value="cluster" ${setScope === "cluster" ? "selected" : ""}>${esc(t("Cluster Templates"))}</option>
                ${ingNodes
                  .map(([tag, n]) => {
                    const cnt = Object.keys(n.ingress?.[mapKey] || {}).length;
                    return `<option value="${esc(tag)}" ${setScope === tag ? "selected" : ""}>${esc(tag)} (${cnt})</option>`;
                  })
                  .join("")}
              </select>
            </label>
          </div>
        </div>
        <div class="inspector-row" style="margin-bottom:${ingNodes.length ? "10px" : "0"};">
          <label>
            <span>${esc(t("Cluster Default Set"))}</span>
            <select id="sec-def-cluster-${esc(kind)}">
              <option value="">${esc(t("(none)"))}</option>
              ${clusterOpts.map((k) => `<option value="${esc(k)}" ${clusterDef === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
            </select>
          </label>
          <div style="display:flex;align-items:end;">
            <div class="muted-sm">${esc(t("Configure sets globally or per-Ingress node; override individually on any Service."))}</div>
          </div>
        </div>
        ${
          ingNodes.length
            ? `
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px;">
            ${ingNodes
              .map(([tag, n]) => {
                const val = n.ingress?.[defField] || "";
                const opts = listKeysForNode(kind, tag);
                const localCnt = Object.keys(n.ingress?.[mapKey] || {}).length;
                return `
                  <label style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:8px 10px;">
                    <span style="display:flex;justify-content:space-between;align-items:center;gap:6px;">
                      <code>${esc(tag)}</code>
                      ${localCnt ? `<span class="pill info">${localCnt} local</span>` : `<span class="muted-sm">cluster</span>`}
                    </span>
                    <select data-sec-node-def="${esc(tag)}">
                      <option value="">(${esc(t("Inherit Cluster"))}: ${esc(clusterDef || t("(none)"))})</option>
                      ${opts.map((k) => `<option value="${esc(k)}" ${val === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
                    </select>
                  </label>
                `;
              })
              .join("")}
          </div>`
            : `<div class="muted-sm">${esc(t("No Ingress nodes defined yet."))}</div>`
        }
      </div>
    `;
  }

  function wireScopeAndAssignmentCard(container, kind) {
    const defField = `default_${kind}`;
    el("sec-set-scope")?.addEventListener("change", (ev) => {
      setScope = ev.target.value || "cluster";
      render();
    });
    el(`sec-def-cluster-${kind}`)?.addEventListener("change", (ev) => {
      store.mutate((s) => {
        if (!s.defaults) s.defaults = defaultTopologyDefaults();
        if (!s.defaults.ingress) s.defaults.ingress = defaultTopologyDefaults().ingress;
        s.defaults.ingress[defField] = ev.target.value || null;
      });
      render();
    });
    container.querySelectorAll("[data-sec-node-def]").forEach((sel) => {
      sel.addEventListener("change", () => {
        const tag = sel.dataset.secNodeDef;
        store.mutate((s) => {
          if (s.nodes?.[tag]?.ingress) s.nodes[tag].ingress[defField] = sel.value || null;
        }, false);
      });
    });
  }

  function renderBucketsSubTab(container) {
    const cfg = getSetConfig("bucket");
    const bucketMap = cfg.getMap(store.spec);
    const bucketKeys = Object.keys(bucketMap).sort();
    const usage = countSetUsage("bucket");

    const cardsHtml = bucketKeys
      .map((bName) => {
        const b = bucketMap[bName];
        const used = usage[bName] || 0;
        return `
          <div class="subcard">
            <div class="subcard-head">
              <div style="display:flex;gap:8px;align-items:center;flex:1;flex-wrap:wrap;">
                <input class="inline-name" data-bk-rename="${esc(bName)}" value="${esc(bName)}" />
                <span class="pill ${used > 0 ? "ok" : ""}">Used: ${used}</span>
              </div>
              <button type="button" class="btn sm danger" data-bk-del="${esc(bName)}">${esc(t("Remove"))}</button>
            </div>
            <div class="inspector-row">
              <label><span>Burst Capacity (tokens)</span><input type="number" min="1" data-bk-cap="${esc(bName)}" value="${b.capacity ?? 60}" /></label>
              <label><span>Refill Rate (req/sec)</span><input type="number" step="0.5" min="0.1" data-bk-refill="${esc(bName)}" value="${b.refill_per_sec ?? 10}" /></label>
            </div>
            ${renderTriSlider({ attrName: `data-bk-tri-${bName}`, attrVal: "per_ip", label: "Per-IP Bucket Isolation", val: b.per_ip, inherited: true })}
          </div>`;
      })
      .join("");

    container.innerHTML = `
      ${renderLegacyMigrationBanner()}
      ${renderScopeAndAssignmentCard("bucket", "Per-Ingress Bucket Set Assignment")}
      ${
        cardsHtml
          ? `<div class="tpl-card-grid">${cardsHtml}</div>`
          : `<div class="empty-state-box"><p>${esc(t("No rate-limit bucket sets in this scope yet."))}</p></div>`
      }
    `;

    wireLegacyMigrationBanner();
    wireScopeAndAssignmentCard(container, "bucket");

    el("btn-sec-add-bucket")?.addEventListener("click", () => {
      store.mutate((s) => {
        const m = cfg.getMap(s);
        let name = "web-default";
        let k = 1;
        while (m[name]) name = `bucket-${k++}`;
        m[name] = { capacity: 120, refill_per_sec: 20, per_ip: null };
      });
      render();
    });

    container.querySelectorAll("[data-bk-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const bName = btn.dataset.bkDel;
        store.mutate((s) => {
          delete cfg.getMap(s)[bName];
          renameSetReferences(s, "bucket", bName, null);
        });
        render();
      });
    });

    container.querySelectorAll("[data-bk-rename]").forEach((inp) => {
      inp.addEventListener("change", () => tryRenameSet(inp, cfg, "bucket", "bkRename"));
    });

    container.querySelectorAll("[data-bk-cap]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          cfg.getMap(s)[inp.dataset.bkCap].capacity = parseNum(inp.value, 60, 1);
        }, false);
      });
    });
    container.querySelectorAll("[data-bk-refill]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          cfg.getMap(s)[inp.dataset.bkRefill].refill_per_sec = parseNum(inp.value, 10, 0.1);
        }, false);
      });
    });
    for (const bName of bucketKeys) {
      wireTriSliders(container, `data-bk-tri-${bName}`, (field, val) => {
        store.mutate((s) => {
          cfg.getMap(s)[bName][field] = val;
        }, false);
      });
    }
  }

  function renderGeoPolicySection(abName, geo) {
    const g = geo || defaultGeoPolicyConfig();
    const stateKey = `${setScope}:${abName}`;
    const isOpen = geoPanelOpenBySet[stateKey] ?? Boolean(g.enabled || g.allow_regions?.length || g.deny_regions?.length || g.rules?.length);
    const quickMode = geoQuickTargetBySet[stateKey] || "deny";
    const activeDeny = new Set(g.deny_regions || []);
    const activeAllow = new Set(g.allow_regions || []);
    const rules = g.rules || [];

    return `
      <div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border);">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <strong style="font-size:12px;letter-spacing:.03em;">${esc(t("GeoIP Region-Targeting"))}</strong>
            ${g.enabled ? `<span class="pill ok">${esc(t("Enabled"))}</span>` : `<span class="pill">${esc(t("Disabled"))}</span>`}
            ${rules.length ? `<span class="pill info">${rules.length} rules</span>` : ""}
          </div>
          <button type="button" class="btn sm ghost" data-ab-geo-toggle="${esc(abName)}">${isOpen ? "▾" : "▸"} ${esc(t("Regions & Rules"))}</button>
        </div>
        ${
          !isOpen
            ? ""
            : `
          <div style="display:flex;flex-direction:column;gap:8px;padding:10px;background:var(--bg);border:1px solid var(--border);border-radius:8px;">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
              <div style="flex:1;min-width:190px;">
                ${renderBinSlider({ attrName: `data-ab-geo-bin-${abName}`, attrVal: "enabled", label: t("Enable GeoIP Region Policy"), val: Boolean(g.enabled) })}
              </div>
              <div class="btn-row">
                <span class="muted-sm">${esc(t("Chip adds to"))}:</span>
                <button type="button" class="btn sm ${quickMode === "deny" ? "primary" : "ghost"}" data-ab-geo-qtarget="${esc(abName)}" data-qval="deny">${esc(t("Deny List"))}</button>
                <button type="button" class="btn sm ${quickMode === "allow" ? "primary" : "ghost"}" data-ab-geo-qtarget="${esc(abName)}" data-qval="allow">${esc(t("Allow List"))}</button>
              </div>
            </div>
            <div>
              <div class="muted-sm" style="margin-bottom:4px;">${esc(t("Quick-Pick Country / Continent Codes (click to toggle)"))}</div>
              <div style="display:flex;flex-wrap:wrap;gap:4px;">
                ${QUICK_GEO_TOKENS.map((tok) => {
                  const inTarget = quickMode === "deny" ? activeDeny.has(tok) : activeAllow.has(tok);
                  return `<button type="button" class="btn sm ${inTarget ? (quickMode === "deny" ? "danger" : "primary") : "ghost"}" data-ab-geo-chip="${esc(abName)}" data-tok="${esc(tok)}">${esc(tok)}</button>`;
                }).join("")}
              </div>
            </div>
            <div class="inspector-row">
              <label><span>${esc(t("Allow Regions CSV (non-matching trigger Deny Action if non-empty)"))}</span><input data-ab-geo-csv="${esc(abName)}" data-gk="allow_regions" value="${esc((g.allow_regions || []).join(", "))}" placeholder="CN, HK, CONTINENT:AS" /></label>
              <label><span>${esc(t("Deny Regions CSV (e.g. CN, RU, CONTINENT:AF)"))}</span><input data-ab-geo-csv="${esc(abName)}" data-gk="deny_regions" value="${esc((g.deny_regions || []).join(", "))}" placeholder="RU, CONTINENT:AF" /></label>
            </div>
            <div class="inspector-row">
              <label><span>${esc(t("Deny Action"))}</span>
                <select data-ab-geo-act="${esc(abName)}" data-gk="deny_action">
                  ${GEO_RULE_ACTIONS.map((a) => `<option value="${a}" ${g.deny_action === a ? "selected" : ""}>${a}</option>`).join("")}
                </select>
              </label>
              <label><span>${esc(t("Default Action"))}</span>
                <select data-ab-geo-act="${esc(abName)}" data-gk="default_action">
                  ${GEO_RULE_ACTIONS.map((a) => `<option value="${a}" ${g.default_action === a ? "selected" : ""}>${a}</option>`).join("")}
                </select>
              </label>
              <label><span>${esc(t("Unknown / Unallocated IP Action"))}</span>
                <select data-ab-geo-act="${esc(abName)}" data-gk="unknown_action">
                  ${GEO_RULE_ACTIONS.map((a) => `<option value="${a}" ${g.unknown_action === a ? "selected" : ""}>${a}</option>`).join("")}
                </select>
              </label>
            </div>
            <div style="margin-top:4px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <span class="muted-sm"><strong>${esc(t("Ordered Region Override Rules"))}</strong> (${rules.length})</span>
                <button type="button" class="btn sm" data-ab-geo-add-rule="${esc(abName)}">+ ${esc(t("Add Rule"))}</button>
              </div>
              ${
                rules.length
                  ? `<div style="display:flex;flex-direction:column;gap:6px;">
                      ${rules
                        .map(
                          (r, idx) => `
                        <div style="display:grid;grid-template-columns:1.5fr 1fr 0.7fr 1.2fr auto;gap:6px;align-items:center;">
                          <input data-ab-geor-reg="${esc(abName)}" data-ridx="${idx}" value="${esc((r.regions || []).join(", "))}" placeholder="CN, US, CONTINENT:EU" />
                          <select data-ab-geor-act="${esc(abName)}" data-ridx="${idx}">
                            ${GEO_RULE_ACTIONS.map((a) => `<option value="${a}" ${r.action === a ? "selected" : ""}>${a}</option>`).join("")}
                          </select>
                          <input type="number" min="-50" max="100" title="Suspicion boost (-50..100)" data-ab-geor-boost="${esc(abName)}" data-ridx="${idx}" value="${r.suspicion_boost ?? 0}" />
                          <input data-ab-geor-note="${esc(abName)}" data-ridx="${idx}" value="${esc(r.note || "")}" placeholder="note" />
                          <button type="button" class="btn sm danger" data-ab-geor-del="${esc(abName)}" data-ridx="${idx}">×</button>
                        </div>`
                        )
                        .join("")}
                    </div>`
                  : `<div class="muted-sm">${esc(t("No per-region override rules yet."))}</div>`
              }
            </div>
          </div>`
        }
      </div>
    `;
  }

  function renderAntibotSubTab(container) {
    const gDefs = store.spec.defaults?.guard || defaultTopologyDefaults().guard;
    const cfg = getSetConfig("antibot");
    const abMap = cfg.getMap(store.spec);
    const abKeys = Object.keys(abMap).sort();
    const usage = countSetUsage("antibot");

    const cardsHtml = abKeys
      .map((abName) => {
        const ab = abMap[abName];
        const used = usage[abName] || 0;
        const isUnderAttack = ab.antibot === "always";
        return `
          <div class="subcard">
            <div class="subcard-head">
              <div style="display:flex;gap:8px;align-items:center;flex:1;flex-wrap:wrap;">
                <input class="inline-name" data-ab-rename="${esc(abName)}" value="${esc(abName)}" />
                <span class="pill ${used > 0 ? "ok" : ""}">Used: ${used}</span>
                ${isUnderAttack ? `<span class="pill err">UNDER ATTACK</span>` : `<span class="pill">${esc(ab.antibot || "off")}</span>`}
                ${ab.geo?.enabled ? `<span class="pill info">GeoIP</span>` : ""}
              </div>
              <div class="btn-row">
                <button type="button" class="btn sm ${isUnderAttack ? "danger" : ""}" data-ab-ua="${esc(abName)}">⚡ ${isUnderAttack ? "Exit Attack" : "Under Attack"}</button>
                <button type="button" class="btn sm danger" data-ab-del="${esc(abName)}">${esc(t("Remove"))}</button>
              </div>
            </div>
            <div class="inspector-row">
              <label><span>Antibot Mode</span>
                <select data-ab-mode="${esc(abName)}">
                  <option value="off" ${ab.antibot === "off" ? "selected" : ""}>off</option>
                  <option value="silent" ${ab.antibot === "silent" ? "selected" : ""}>silent</option>
                  <option value="challenge" ${ab.antibot === "challenge" ? "selected" : ""}>challenge</option>
                  <option value="always" ${ab.antibot === "always" ? "selected" : ""}>always (Under Attack)</option>
                </select>
              </label>
              <label><span>JS FP TTL (s, optional)</span><input type="number" min="30" placeholder="${esc(store.spec.defaults?.ingress?.js_fp_ttl_secs ?? 3600)}" data-ab-optnum="${esc(abName)}" data-ab-k="js_fp_ttl_secs" value="${ab.js_fp_ttl_secs ?? ""}" /></label>
            </div>
            <div class="inspector-row">
              <label><span>Challenge Score</span><input type="number" min="0" max="100" data-ab-num="${esc(abName)}" data-ab-k="challenge_threshold" value="${ab.challenge_threshold ?? 35}" /></label>
              <label><span>Reject Score</span><input type="number" min="0" max="100" data-ab-num="${esc(abName)}" data-ab-k="reject_threshold" value="${ab.reject_threshold ?? 80}" /></label>
              <label><span>PoW Bits</span><input type="number" min="4" max="28" data-ab-num="${esc(abName)}" data-ab-k="pow_difficulty" value="${ab.pow_difficulty ?? 18}" /></label>
              <label><span>Clearance TTL (s)</span><input type="number" min="10" data-ab-num="${esc(abName)}" data-ab-k="clearance_ttl_secs" value="${ab.clearance_ttl_secs ?? 3600}" /></label>
            </div>
            <div class="inspector-row">
              <label><span>Allow CIDRs (CSV)</span><input data-ab-csv="${esc(abName)}" data-ab-k="allow_cidrs" value="${esc((ab.allow_cidrs || []).join(", "))}" placeholder="10.0.0.0/8" /></label>
              <label><span>Deny CIDRs (CSV)</span><input data-ab-csv="${esc(abName)}" data-ab-k="deny_cidrs" value="${esc((ab.deny_cidrs || []).join(", "))}" placeholder="198.51.100.0/24" /></label>
            </div>
            <label><span>API Bypass Headers (one per line: <code>X-Api-Key: secret</code>)</span>
              <textarea rows="2" data-ab-lines="${esc(abName)}" placeholder="X-Api-Key: secret">${esc((ab.api_bypass_headers || []).join("\n"))}</textarea>
            </label>
            <div class="tri-stack">
              ${renderTriSlider({ attrName: `data-ab-tri-${abName}`, attrVal: "bind_ua", label: "Bind User-Agent", val: ab.bind_ua, inherited: gDefs.bind_ua })}
              ${renderTriSlider({ attrName: `data-ab-tri-${abName}`, attrVal: "bind_ip_prefix", label: "Bind Client IP", val: ab.bind_ip_prefix, inherited: gDefs.bind_ip_prefix })}
              ${renderTriSlider({ attrName: `data-ab-tri-${abName}`, attrVal: "block_bots", label: "Block Known Bots", val: ab.block_bots, inherited: gDefs.block_bots })}
              ${renderTriSlider({ attrName: `data-ab-tri-${abName}`, attrVal: "browser_only", label: "Browser-Only Strict Mode", val: ab.browser_only, inherited: gDefs.browser_only })}
              ${renderTriSlider({ attrName: `data-ab-tri-${abName}`, attrVal: "block_headless", label: "Block Headless Browsers", val: ab.block_headless, inherited: gDefs.block_headless })}
              ${renderTriSlider({ attrName: `data-ab-tri-${abName}`, attrVal: "require_client_fp", label: "Require Verified JS FP", val: ab.require_client_fp, inherited: gDefs.require_client_fp })}
              ${renderTriSlider({ attrName: `data-ab-tri-${abName}`, attrVal: "js_fp_beacon", label: "Passive JS FP Beacon", val: ab.js_fp_beacon, inherited: gDefs.js_fp_beacon })}
            </div>
            ${renderGeoPolicySection(abName, ab.geo)}
          </div>`;
      })
      .join("");

    container.innerHTML = `
      ${renderLegacyMigrationBanner()}
      ${renderScopeAndAssignmentCard("antibot", "Per-Ingress Antibot Set Assignment")}
      ${
        cardsHtml
          ? `<div class="tpl-card-grid">${cardsHtml}</div>`
          : `<div class="empty-state-box"><p>${esc(t("No Antibot / Geo policy sets in this scope yet."))}</p></div>`
      }
    `;

    wireLegacyMigrationBanner();
    wireScopeAndAssignmentCard(container, "antibot");

    el("btn-sec-add-antibot")?.addEventListener("click", () => {
      store.mutate((s) => {
        const m = cfg.getMap(s);
        let name = "web-challenge";
        let k = 1;
        while (m[name]) name = `antibot-${k++}`;
        m[name] = defaultAntibotProfile(gDefs);
      });
      render();
    });

    const ensureGeo = (s, abName) => {
      const ab = cfg.getMap(s)[abName];
      if (!ab.geo) ab.geo = defaultGeoPolicyConfig();
      return ab.geo;
    };

    container.querySelectorAll("[data-ab-ua]").forEach((btn) => {
      btn.addEventListener("click", () => {
        store.mutate((s) => {
          const ab = cfg.getMap(s)[btn.dataset.abUa];
          ab.antibot = ab.antibot === "always" ? "challenge" : "always";
        });
        render();
      });
    });

    container.querySelectorAll("[data-ab-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const abName = btn.dataset.abDel;
        store.mutate((s) => {
          delete cfg.getMap(s)[abName];
          renameSetReferences(s, "antibot", abName, null);
        });
        render();
      });
    });

    container.querySelectorAll("[data-ab-rename]").forEach((inp) => {
      inp.addEventListener("change", () => tryRenameSet(inp, cfg, "antibot", "abRename"));
    });

    container.querySelectorAll("[data-ab-mode]").forEach((sel) => {
      sel.addEventListener("change", () => {
        store.mutate((s) => {
          cfg.getMap(s)[sel.dataset.abMode].antibot = sel.value;
        });
        render();
      });
    });

    container.querySelectorAll("[data-ab-num]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          cfg.getMap(s)[inp.dataset.abNum][inp.dataset.abK] = parseNum(inp.value, 0, 0);
        }, false);
      });
    });

    container.querySelectorAll("[data-ab-optnum]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const raw = inp.value.trim();
        store.mutate((s) => {
          cfg.getMap(s)[inp.dataset.abOptnum][inp.dataset.abK] = raw ? parseNum(raw, 3600, 30) : null;
        }, false);
      });
    });

    container.querySelectorAll("[data-ab-csv]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          cfg.getMap(s)[inp.dataset.abCsv][inp.dataset.abK] = inp.value
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean);
        }, false);
      });
    });

    container.querySelectorAll("[data-ab-lines]").forEach((ta) => {
      ta.addEventListener("input", () => {
        store.mutate((s) => {
          cfg.getMap(s)[ta.dataset.abLines].api_bypass_headers = ta.value
            .split("\n")
            .map((x) => x.trim())
            .filter(Boolean);
        }, false);
      });
    });

    for (const abName of abKeys) {
      wireTriSliders(container, `data-ab-tri-${abName}`, (field, val) => {
        store.mutate((s) => {
          cfg.getMap(s)[abName][field] = val;
        }, false);
      });
      wireBinSliders(container, `data-ab-geo-bin-${abName}`, (field, val) => {
        store.mutate((s) => {
          ensureGeo(s, abName)[field] = val;
        });
        render();
      });
    }

    container.querySelectorAll("[data-ab-geo-toggle]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const k = `${setScope}:${btn.dataset.abGeoToggle}`;
        const curGeo = abMap[btn.dataset.abGeoToggle]?.geo;
        const curOpen = geoPanelOpenBySet[k] ?? Boolean(curGeo?.enabled || curGeo?.allow_regions?.length || curGeo?.deny_regions?.length || curGeo?.rules?.length);
        geoPanelOpenBySet[k] = !curOpen;
        render();
      });
    });

    container.querySelectorAll("[data-ab-geo-qtarget]").forEach((btn) => {
      btn.addEventListener("click", () => {
        geoQuickTargetBySet[`${setScope}:${btn.dataset.abGeoQtarget}`] = btn.dataset.qval;
        render();
      });
    });

    container.querySelectorAll("[data-ab-geo-chip]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const abName = btn.dataset.abGeoChip;
        const tok = btn.dataset.tok;
        const mode = geoQuickTargetBySet[`${setScope}:${abName}`] || "deny";
        const field = mode === "allow" ? "allow_regions" : "deny_regions";
        store.mutate((s) => {
          const g = ensureGeo(s, abName);
          const arr = Array.isArray(g[field]) ? [...g[field]] : [];
          const idx = arr.indexOf(tok);
          if (idx >= 0) arr.splice(idx, 1);
          else arr.push(tok);
          g[field] = arr;
        });
        render();
      });
    });

    container.querySelectorAll("[data-ab-geo-csv]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const abName = inp.dataset.abGeoCsv;
        const gk = inp.dataset.gk;
        store.mutate((s) => {
          ensureGeo(s, abName)[gk] = [
            ...new Set(
              inp.value
                .split(",")
                .map((x) => x.trim().toUpperCase())
                .filter(Boolean)
            ),
          ];
        }, false);
      });
    });

    container.querySelectorAll("[data-ab-geo-act]").forEach((sel) => {
      sel.addEventListener("change", () => {
        store.mutate((s) => {
          ensureGeo(s, sel.dataset.abGeoAct)[sel.dataset.gk] = sel.value;
        }, false);
      });
    });

    container.querySelectorAll("[data-ab-geo-add-rule]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const abName = btn.dataset.abGeoAddRule;
        geoPanelOpenBySet[`${setScope}:${abName}`] = true;
        store.mutate((s) => {
          const g = ensureGeo(s, abName);
          if (!Array.isArray(g.rules)) g.rules = [];
          g.rules.push({ regions: ["CN"], action: "allow", suspicion_boost: 0, note: null });
        });
        render();
      });
    });

    container.querySelectorAll("[data-ab-geor-reg]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const idx = Number(inp.dataset.ridx);
        store.mutate((s) => {
          const r = ensureGeo(s, inp.dataset.abGeorReg).rules?.[idx];
          if (r) {
            r.regions = inp.value
              .split(",")
              .map((x) => x.trim().toUpperCase())
              .filter(Boolean);
          }
        }, false);
      });
    });

    container.querySelectorAll("[data-ab-geor-act]").forEach((sel) => {
      sel.addEventListener("change", () => {
        const idx = Number(sel.dataset.ridx);
        store.mutate((s) => {
          const r = ensureGeo(s, sel.dataset.abGeorAct).rules?.[idx];
          if (r) r.action = sel.value;
        }, false);
      });
    });

    container.querySelectorAll("[data-ab-geor-boost]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const idx = Number(inp.dataset.ridx);
        store.mutate((s) => {
          const r = ensureGeo(s, inp.dataset.abGeorBoost).rules?.[idx];
          if (r) r.suspicion_boost = parseNum(inp.value, 0, -50, 100);
        }, false);
      });
    });

    container.querySelectorAll("[data-ab-geor-note]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const idx = Number(inp.dataset.ridx);
        store.mutate((s) => {
          const r = ensureGeo(s, inp.dataset.abGeorNote).rules?.[idx];
          if (r) r.note = inp.value.trim() || null;
        }, false);
      });
    });

    container.querySelectorAll("[data-ab-geor-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.ridx);
        store.mutate((s) => {
          const rules = ensureGeo(s, btn.dataset.abGeorDel).rules;
          if (Array.isArray(rules)) rules.splice(idx, 1);
        });
        render();
      });
    });
  }

  async function loadWafRules() {
    if (wafRulesLoading) return;
    wafRulesLoading = true;
    try {
      wafRulesData = await api("/api/waf/rules");
    } catch (e) {
      showToast(e.message, true);
    } finally {
      wafRulesLoading = false;
      if (subTab === "waf") render();
    }
  }

  async function triggerCrsSync() {
    if (wafSyncing) return;
    wafSyncing = true;
    render();
    try {
      const res = await api("/api/waf/crs/sync", { method: "POST" });
      showToast(t("Synced OWASP CRS {version} ({count} active rules)", { version: res.version || "latest", count: res.rules_count ?? 0 }));
      await loadWafRules();
    } catch (e) {
      showToast(e.message, true);
    } finally {
      wafSyncing = false;
      if (subTab === "waf") render();
    }
  }

  function renderWafSubTab(container) {
    const cfg = getSetConfig("waf");
    const wafMap = cfg.getMap(store.spec);
    const wafKeys = Object.keys(wafMap).sort();
    const usage = countSetUsage("waf");

    const ensureCrs = (s) => {
      if (!s.defaults) s.defaults = defaultTopologyDefaults();
      if (!s.defaults.ingress) s.defaults.ingress = defaultTopologyDefaults().ingress;
      if (!s.defaults.ingress.crs) s.defaults.ingress.crs = normalizeCrsUpdateConfig();
      return s.defaults.ingress.crs;
    };
    const crsCfg = store.spec.defaults?.ingress?.crs || normalizeCrsUpdateConfig();
    const disabledSet = new Set((crsCfg.disabled_rule_ids || []).map(Number));
    const meta = wafRulesData?.crs_meta || {};
    const allRules = wafRulesData?.crs_rules || wafRulesData?.rules || [];

    const q = wafSearch.trim().toLowerCase();
    const filtered = allRules.filter((r) => {
      if (wafPlFilter !== "all" && Number(r.paranoia_level || 1) !== Number(wafPlFilter)) return false;
      const isOff = disabledSet.has(Number(r.id));
      if (wafStatusFilter === "on" && isOff) return false;
      if (wafStatusFilter === "off" && !isOff) return false;
      if (q) {
        const hay = `${r.id} ${r.category || ""} ${r.msg || ""} ${r.pattern || ""} ${r.file || ""} ${(r.tags || []).join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const sevPill = (sev) => {
      const s = String(sev || "CRITICAL").toUpperCase();
      const cls = s === "CRITICAL" ? "err" : s === "ERROR" ? "warn" : "info";
      return `<span class="pill ${cls}">${esc(s)}</span>`;
    };

    const wafCardsHtml = wafKeys
      .map((wName) => {
        const w = wafMap[wName];
        const used = usage[wName] || 0;
        const activeCats = w.categories || [];
        return `
          <div class="subcard">
            <div class="subcard-head">
              <div style="display:flex;gap:8px;align-items:center;flex:1;flex-wrap:wrap;">
                <input class="inline-name" data-ws-rename="${esc(wName)}" value="${esc(wName)}" />
                <span class="pill ${used > 0 ? "ok" : ""}">Used: ${used}</span>
                ${w.mode === "block" ? `<span class="pill err">BLOCK</span>` : w.mode === "evilpot" ? `<span class="pill warn">EVILPOT</span>` : w.mode === "monitor" ? `<span class="pill info">MONITOR</span>` : `<span class="pill">OFF</span>`}
              </div>
              <button type="button" class="btn sm danger" data-ws-del="${esc(wName)}">${esc(t("Remove"))}</button>
            </div>
            <div class="inspector-row">
              <label><span>${esc(t("WAF Mode"))}</span>
                <select data-ws-mode="${esc(wName)}">
                  <option value="off" ${w.mode === "off" ? "selected" : ""}>${esc(t("Off"))}</option>
                  <option value="monitor" ${w.mode === "monitor" ? "selected" : ""}>${esc(t("Monitor (Log Only)"))}</option>
                  <option value="block" ${w.mode === "block" ? "selected" : ""}>${esc(t("Block (403 Forbidden)"))}</option>
                  <option value="evilpot" ${w.mode === "evilpot" ? "selected" : ""}>${esc(t("Evilpot (Honeypot & Behavior Analysis)"))}</option>
                </select>
              </label>
              <label><span>${esc(t("CRS Paranoia Level"))}</span>
                <select data-ws-pl="${esc(wName)}">
                  ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${(w.crs_paranoia_level || 1) === pl ? "selected" : ""}>PL${pl}</option>`).join("")}
                </select>
              </label>
              <label><span>${esc(t("Max Body Inspection (KiB)"))}</span>
                <input type="number" min="0" max="256" data-ws-bodykb="${esc(wName)}" value="${Math.round((w.max_body_bytes ?? 32768) / 1024)}" />
              </label>
            </div>
            <div class="tri-stack" style="margin-top:6px;">
              ${renderBinSlider({ attrName: `data-ws-bin-${wName}`, attrVal: "inspect_headers", label: t("Inspect Headers (UA / Referer / Cookie)"), val: w.inspect_headers !== false })}
              ${renderBinSlider({ attrName: `data-ws-bin-${wName}`, attrVal: "inspect_body", label: t("Inspect Text / JSON / Form Bodies"), val: w.inspect_body !== false })}
            </div>
            <div class="inspector-row" style="margin-top:6px;">
              <label><span>${esc(t("Exempt Path Prefixes (CSV)"))}</span>
                <input data-ws-exempt="${esc(wName)}" value="${esc((w.exempt_paths || []).join(", "))}" placeholder="/api/webhooks/, /cms/" />
              </label>
              <label><span>${esc(t("Disabled CRS Rule IDs (CSV)"))}</span>
                <input data-ws-disids="${esc(wName)}" value="${esc((w.disabled_rule_ids || []).join(", "))}" placeholder="942100, 932100" />
              </label>
            </div>
            <div style="margin-top:6px;">
              <div class="muted" style="font-size:11px;margin-bottom:5px;">${esc(activeCats.length ? t("Attack Categories (empty = all 12)") : t("All 12 OWASP CRS Categories"))}</div>
              <div style="display:flex;flex-wrap:wrap;gap:4px;">
                <button type="button" class="btn sm ${activeCats.length === 0 ? "primary" : "ghost"}" data-ws-cat-all="${esc(wName)}">${esc(t("All"))}</button>
                ${WAF_CATEGORIES.map((c) => {
                  const on = activeCats.includes(c);
                  return `<button type="button" class="btn sm ${on ? "primary" : "ghost"}" data-ws-cat="${esc(wName)}" data-waf-c="${esc(c)}">${esc(wafCategoryLabel(c))}</button>`;
                }).join("")}
              </div>
            </div>
          </div>`;
      })
      .join("");

    container.innerHTML = `
      ${renderLegacyMigrationBanner()}
      ${renderScopeAndAssignmentCard("waf", "Per-Ingress WAF Set Assignment")}
      ${
        wafCardsHtml
          ? `<div class="tpl-card-grid" style="margin-bottom:16px;">${wafCardsHtml}</div>`
          : `<div class="empty-state-box" style="margin-bottom:16px;"><p>${esc(t("No OWASP CRS WAF sets in this scope yet."))}</p></div>`
      }

      <div class="kpi-grid" style="margin-bottom:14px;">
        <div class="kpi">
          <div class="kpi-label">${esc(t("Active CRS Version"))}</div>
          <div class="kpi-val" style="font-size:18px;">${esc(meta.version || (wafRulesLoading ? "…" : "builtin"))}</div>
          <div class="kpi-sub"><a href="https://coreruleset.org/" target="_blank" rel="noopener noreferrer" style="color:var(--accent);">coreruleset.org</a></div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("Active Rules"))}</div>
          <div class="kpi-val">${Math.max(0, allRules.length - disabledSet.size)} / ${allRules.length}</div>
          <div class="kpi-sub">${esc(t("Pure OWASP CRS Linear-Time Engine"))}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("PCRE-only Skipped"))}</div>
          <div class="kpi-val">${meta.skipped_pcre ?? 0}</div>
          <div class="kpi-sub">Linear-time ReDoS-safe Rust regex</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("Last Synced"))}</div>
          <div class="kpi-val" style="font-size:15px;">${esc(meta.updated_at ? formatDateTime(meta.updated_at) : "—")}</div>
          <div class="kpi-sub">${disabledSet.size} globally disabled</div>
        </div>
      </div>

      <div class="panel" style="margin-bottom:14px;">
        <div class="inspector-row" style="align-items:end;">
          <div style="flex:1.4;">
            ${renderBinSlider({ attrName: "data-crs-bin", attrVal: "auto_update", label: t("Auto-Update OWASP CRS"), val: crsCfg.auto_update !== false })}
          </div>
          <label><span>${esc(t("Update Interval (hours)"))}</span>
            <input id="crs-interval-h" type="number" min="1" max="720" value="${crsCfg.update_interval_hours ?? 24}" />
          </label>
          <label><span>${esc(t("CRS Paranoia Level"))}</span>
            <select id="crs-default-pl">
              ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${(crsCfg.paranoia_level || 1) === pl ? "selected" : ""}>PL${pl}</option>`).join("")}
            </select>
          </label>
        </div>
        <div class="muted-sm" style="margin-top:8px;">${esc(t("Toggling rules updates cluster CRS defaults in draft — deploy to push changes to Ingress nodes."))}</div>
      </div>

      <div class="panel">
        <div class="fp-search-bar" style="margin-bottom:10px;">
          <label style="flex:2;"><span>${esc(t("Search…"))}</span>
            <input id="waf-rule-search" type="search" value="${esc(wafSearch)}" placeholder="${esc(t("Search rule ID, message, category, regex…"))}" />
          </label>
          <label><span>${esc(t("PL"))}</span>
            <select id="waf-rule-pl">
              <option value="all" ${wafPlFilter === "all" ? "selected" : ""}>${esc(t("All"))}</option>
              ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${String(wafPlFilter) === String(pl) ? "selected" : ""}>PL${pl}</option>`).join("")}
            </select>
          </label>
          <label><span>${esc(t("Enabled"))}</span>
            <select id="waf-rule-status">
              <option value="all" ${wafStatusFilter === "all" ? "selected" : ""}>${esc(t("All Status"))}</option>
              <option value="on" ${wafStatusFilter === "on" ? "selected" : ""}>${esc(t("Enabled"))}</option>
              <option value="off" ${wafStatusFilter === "off" ? "selected" : ""}>${esc(t("Disabled"))}</option>
            </select>
          </label>
        </div>

        <div class="table-scroll">
          <table class="table">
            <thead>
              <tr>
                <th>${esc(t("Rule ID"))}</th>
                <th>${esc(t("PL"))}</th>
                <th>${esc(t("Category"))}</th>
                <th>${esc(t("Severity"))}</th>
                <th>${esc(t("Description / Pattern"))}</th>
                <th>${esc(t("Enabled"))}</th>
              </tr>
            </thead>
            <tbody>
              ${
                filtered
                  .slice(0, 300)
                  .map((r, idx) => {
                    const isEnabled = !disabledSet.has(Number(r.id));
                    return `
                  <tr class="fp-table-row" data-waf-rule-idx="${idx}" style="${isEnabled ? "" : "opacity:0.55;"}">
                    <td><code>${esc(r.id)}</code></td>
                    <td><span class="pill">PL${Number(r.paranoia_level) || 1}</span></td>
                    <td><code>${esc(r.category || "-")}</code></td>
                    <td>${sevPill(r.severity)}</td>
                    <td style="max-width:440px;">
                      <div><strong>${esc(r.msg || "(unnamed rule)")}</strong></div>
                      <div class="muted-sm" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><code>${esc((r.pattern || "").slice(0, 120))}</code></div>
                    </td>
                    <td data-waf-toggle-cell="1">
                      <button type="button" class="btn sm ${isEnabled ? "primary" : "ghost"}" data-waf-rule-toggle="${esc(r.id)}">
                        ${esc(isEnabled ? t("Enabled") : t("Disabled"))}
                      </button>
                    </td>
                  </tr>`;
                  })
                  .join("") || `<tr><td colspan="6" class="muted">${wafRulesLoading ? "Loading…" : "No OWASP CRS rules match filter."}</td></tr>`
              }
            </tbody>
          </table>
        </div>
        ${filtered.length > 300 ? `<div class="muted-sm" style="margin-top:6px;">Showing first 300 of ${filtered.length} matching rules — refine search to inspect others.</div>` : ""}
      </div>
    `;

    wireLegacyMigrationBanner();
    wireScopeAndAssignmentCard(container, "waf");
    el("btn-sec-crs-sync")?.addEventListener("click", triggerCrsSync);

    el("btn-sec-add-waf")?.addEventListener("click", () => {
      store.mutate((s) => {
        const m = cfg.getMap(s);
        let name = "web-crs";
        let k = 1;
        while (m[name]) name = `waf-${k++}`;
        const w = defaultWafConfig();
        w.mode = "block";
        m[name] = w;
      });
      render();
    });

    container.querySelectorAll("[data-ws-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const wName = btn.dataset.wsDel;
        store.mutate((s) => {
          delete cfg.getMap(s)[wName];
          renameSetReferences(s, "waf", wName, null);
        });
        render();
      });
    });

    container.querySelectorAll("[data-ws-rename]").forEach((inp) => {
      inp.addEventListener("change", () => tryRenameSet(inp, cfg, "waf", "wsRename"));
    });

    container.querySelectorAll("[data-ws-mode]").forEach((sel) => {
      sel.addEventListener("change", () => {
        store.mutate((s) => {
          cfg.getMap(s)[sel.dataset.wsMode].mode = sel.value;
        });
        render();
      });
    });

    container.querySelectorAll("[data-ws-pl]").forEach((sel) => {
      sel.addEventListener("change", () => {
        store.mutate((s) => {
          cfg.getMap(s)[sel.dataset.wsPl].crs_paranoia_level = parseNum(sel.value, 1, 1, 4);
        }, false);
      });
    });

    container.querySelectorAll("[data-ws-bodykb]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          cfg.getMap(s)[inp.dataset.wsBodykb].max_body_bytes = parseNum(inp.value, 32, 0, 256) * 1024;
        }, false);
      });
    });

    for (const wName of wafKeys) {
      wireBinSliders(container, `data-ws-bin-${wName}`, (field, val) => {
        store.mutate((s) => {
          cfg.getMap(s)[wName][field] = val;
        }, false);
      });
    }

    container.querySelectorAll("[data-ws-exempt]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          cfg.getMap(s)[inp.dataset.wsExempt].exempt_paths = inp.value
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean);
        }, false);
      });
    });

    container.querySelectorAll("[data-ws-disids]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          cfg.getMap(s)[inp.dataset.wsDisids].disabled_rule_ids = [
            ...new Set(
              inp.value
                .split(",")
                .map((x) => Number(x.trim()))
                .filter((n) => Number.isInteger(n) && n > 0)
            ),
          ];
        }, false);
      });
    });

    container.querySelectorAll("[data-ws-cat-all]").forEach((btn) => {
      btn.addEventListener("click", () => {
        store.mutate((s) => {
          cfg.getMap(s)[btn.dataset.wsCatAll].categories = [];
        });
        render();
      });
    });

    container.querySelectorAll("[data-ws-cat]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const wName = btn.dataset.wsCat;
        const cat = btn.dataset.wafC;
        store.mutate((s) => {
          const w = cfg.getMap(s)[wName];
          const list = Array.isArray(w.categories) ? [...w.categories] : [];
          const idx = list.indexOf(cat);
          if (idx >= 0) list.splice(idx, 1);
          else list.push(cat);
          w.categories = list;
        });
        render();
      });
    });

    wireBinSliders(container, "data-crs-bin", (f, v) => {
      store.mutate((s) => {
        ensureCrs(s)[f] = v;
      }, false);
    });
    el("crs-interval-h")?.addEventListener("input", (ev) => {
      store.mutate((s) => {
        ensureCrs(s).update_interval_hours = parseNum(ev.target.value, 24, 1, 720);
      }, false);
    });
    el("crs-default-pl")?.addEventListener("change", (ev) => {
      store.mutate((s) => {
        ensureCrs(s).paranoia_level = parseNum(ev.target.value, 1, 1, 4);
      }, false);
    });
    el("waf-rule-search")?.addEventListener("input", (ev) => {
      wafSearch = ev.target.value;
      render();
    });
    el("waf-rule-pl")?.addEventListener("change", (ev) => {
      wafPlFilter = ev.target.value;
      render();
    });
    el("waf-rule-status")?.addEventListener("change", (ev) => {
      wafStatusFilter = ev.target.value;
      render();
    });

    container.querySelectorAll("[data-waf-rule-toggle]").forEach((btn) => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const id = Number(btn.dataset.wafRuleToggle);
        store.mutate((s) => {
          const c = ensureCrs(s);
          const list = Array.isArray(c.disabled_rule_ids) ? c.disabled_rule_ids.map(Number) : [];
          const idx = list.indexOf(id);
          if (idx >= 0) list.splice(idx, 1);
          else list.push(id);
          c.disabled_rule_ids = list.sort((a, b) => a - b);
        });
        render();
      });
    });

    container.querySelectorAll("[data-waf-rule-idx]").forEach((tr) => {
      tr.addEventListener("click", (ev) => {
        if (ev.target.closest("[data-waf-toggle-cell]")) return;
        const r = filtered[Number(tr.dataset.wafRuleIdx)];
        if (!r) return;
        openModal({
          title: `OWASP CRS Rule #${r.id}`,
          bodyHtml: `
            <div class="fp-detail-grid">
              <div class="fp-kv"><div class="fp-kv-lbl">Category / PL / Severity</div><div class="fp-kv-val"><code>${esc(r.category)}</code> · PL${Number(r.paranoia_level) || 1} · ${esc(r.severity)}</div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Source File</div><div class="fp-kv-val"><code>${esc(r.file || "-")}</code></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Operator</div><div class="fp-kv-val"><code>@${esc(r.operator || "rx")}</code></div></div>
              <div class="fp-kv"><div class="fp-kv-lbl">Targets</div><div class="fp-kv-val"><code>${esc((r.targets || []).join(", ") || "-")}</code></div></div>
            </div>
            <div style="margin-top:10px;"><strong>${esc(r.msg || "")}</strong></div>
            <div class="muted-sm" style="margin-top:8px;">Pattern</div>
            <pre class="output-box" style="max-height:180px;white-space:pre-wrap;word-break:break-all;">${esc(r.pattern || "")}</pre>
            ${r.tags?.length ? `<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:4px;">${r.tags.map((tg) => `<span class="pill">${esc(tg)}</span>`).join("")}</div>` : ""}`,
          actions: [{ label: t("Close"), cls: "primary" }],
        });
      });
    });
  }

  async function loadGeoIpStatus() {
    if (!api) return;
    geoipLoading = true;
    try {
      geoipData = await api("/api/security/geoip/status");
    } catch (e) {
      showToast(e.message, true);
    } finally {
      geoipLoading = false;
      if (subTab === "geoip") render();
    }
  }

  async function syncGeoIp(nodeTag = null, force = true) {
    if (!api || geoipSyncing) return;
    geoipSyncing = true;
    render();
    try {
      const res = await api("/api/security/geoip/sync", {
        method: "POST",
        body: JSON.stringify({ node_tag: nodeTag || null, force }),
      });
      const okCnt = (res.nodes || []).filter((n) => n.ok).length;
      showToast(t("GeoIP synced on {ok}/{total} Ingress node(s)", { ok: okCnt, total: (res.nodes || []).length }));
      await loadGeoIpStatus();
    } catch (e) {
      showToast(e.message, true);
    } finally {
      geoipSyncing = false;
      if (subTab === "geoip") render();
    }
  }

  function renderGeoIpSubTab(container) {
    const ensureGeoIp = (s) => {
      if (!s.defaults) s.defaults = defaultTopologyDefaults();
      if (!s.defaults.ingress) s.defaults.ingress = defaultTopologyDefaults().ingress;
      if (!s.defaults.ingress.geoip) s.defaults.ingress.geoip = defaultGeoIpConfig();
      return s.defaults.ingress.geoip;
    };
    const gcfg = store.spec.defaults?.ingress?.geoip || defaultGeoIpConfig();
    const sum = geoipData?.summary || { total_ingress_nodes: 0, loaded_nodes: 0, max_ipv4_ranges: 0, max_ipv6_ranges: 0 };
    const nodes = geoipData?.nodes || [];
    const ingNodes = ingressNodes();

    container.innerHTML = `
      <div class="kpi-grid" style="margin-bottom:14px;">
        <div class="kpi"><div class="kpi-label">${esc(t("Nodes Loaded"))}</div><div class="kpi-val">${esc(sum.loaded_nodes)} / ${esc(sum.total_ingress_nodes)}</div><div class="kpi-sub">CC0 IP-to-Country DB</div></div>
        <div class="kpi"><div class="kpi-label">IPv4 Ranges</div><div class="kpi-val">${esc((sum.max_ipv4_ranges || 0).toLocaleString())}</div><div class="kpi-sub">O(log N) binary search</div></div>
        <div class="kpi"><div class="kpi-label">IPv6 Ranges</div><div class="kpi-val">${esc((sum.max_ipv6_ranges || 0).toLocaleString())}</div><div class="kpi-sub">Dual-stack lookup</div></div>
        <div class="kpi"><div class="kpi-label">${esc(t("Telemetry Updated"))}</div><div class="kpi-val" style="font-size:15px;">${geoipData?.last_pulled_at ? esc(formatDateTime(geoipData.last_pulled_at)) : (geoipLoading ? "…" : "—")}</div><div class="kpi-sub">${esc(t("Persisted geoip.bin disk cache"))}</div></div>
      </div>

      <div class="panel" style="margin-bottom:14px;">
        <div class="panel-header"><h3>${esc(t("Cluster GeoIP Auto-Pull Settings (CC0 Free DB)"))}</h3><span class="muted-sm">${esc(t("Toggling rules updates cluster CRS defaults in draft — deploy to push changes to Ingress nodes."))}</span></div>
        <div class="tri-stack" style="margin-bottom:10px;">
          ${renderBinSlider({ attrName: "data-geoip-bin", attrVal: "enabled", label: t("Enable Local GeoIP Engine on Ingress Nodes"), val: gcfg.enabled !== false })}
          ${renderBinSlider({ attrName: "data-geoip-bin", attrVal: "auto_update", label: t("Background Auto-Update"), val: gcfg.auto_update !== false })}
        </div>
        <div class="inspector-row">
          <label><span>${esc(t("Refresh Interval (hours, 6–720)"))}</span><input id="geoip-interval" type="number" min="6" max="720" value="${gcfg.update_interval_hours ?? 168}" /></label>
          <label><span>${esc(t("Optional Cache Dir Override"))}</span><input id="geoip-cache-dir" value="${esc(gcfg.cache_dir || "")}" placeholder="(default: <segment_dir>/geoip)" /></label>
        </div>
        <div class="inspector-row">
          <label><span>Custom IPv4 CSV HTTPS URL</span><input id="geoip-v4-url" value="${esc(gcfg.ipv4_url || "")}" placeholder="(default built-in CC0 mirrors)" /></label>
          <label><span>Custom IPv6 CSV HTTPS URL</span><input id="geoip-v6-url" value="${esc(gcfg.ipv6_url || "")}" placeholder="(default built-in CC0 mirrors)" /></label>
        </div>
      </div>

      <div class="panel" style="margin-bottom:14px;">
        <div class="panel-header"><h3>${esc(t("Live Node GeoIP Lookup Tester"))}</h3></div>
        <div class="fp-search-bar" style="margin-bottom:0;">
          <label style="flex:1.4;"><span>IP Address</span><input id="geoip-test-ip" placeholder="1.1.1.1 / 114.114.114.114 / 2001:4860:4860::8888" /></label>
          <label><span>Ingress Node</span>
            <select id="geoip-test-node">
              <option value="all">${esc(t("Auto (First Loaded Ingress)"))}</option>
              ${ingNodes.map(([tag]) => `<option value="${esc(tag)}">${esc(tag)}</option>`).join("")}
            </select>
          </label>
          <div class="btn-row"><button type="button" id="btn-geoip-lookup" class="btn primary">${esc(t("Lookup IP"))}</button></div>
        </div>
        ${
          geoLookupResult
            ? `<div style="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                <span class="pill ${geoLookupResult.ok ? "ok" : "err"}">${esc(geoLookupResult.node_tag || "-")}</span>
                <code>${esc(geoLookupResult.ip)}</code>
                ${geoLookupResult.country ? `<span class="pill info">${esc(geoLookupResult.country)} · ${esc(geoLookupResult.continent || "-")}</span>` : `<span class="pill warn">${geoLookupResult.is_private ? "Private / Loopback" : "Unknown / Unloaded"}</span>`}
                ${geoLookupResult.error ? `<span class="pill err">${esc(geoLookupResult.error)}</span>` : ""}
              </div>`
            : ""
        }
      </div>

      <div class="panel">
        <div class="panel-header"><h3>${esc(t("Per-Ingress GeoIP Database Status"))}</h3></div>
        <div class="table-scroll">
          <table class="table">
            <thead><tr><th>Node</th><th>State</th><th>IPv4</th><th>IPv6</th><th>Updated</th><th>Source / Error</th><th>Action</th></tr></thead>
            <tbody>
              ${
                nodes
                  .map(
                    (n) => `
                  <tr>
                    <td><code>${esc(n.node_tag)}</code></td>
                    <td>${n.loaded ? `<span class="pill ok">Loaded</span>` : n.enabled ? `<span class="pill warn">Pending</span>` : `<span class="pill">Disabled</span>`}</td>
                    <td>${esc((n.ipv4_ranges || 0).toLocaleString())}</td>
                    <td>${esc((n.ipv6_ranges || 0).toLocaleString())}</td>
                    <td style="white-space:nowrap;">${n.updated_at ? esc(formatDateTime(n.updated_at)) : "—"}</td>
                    <td style="max-width:300px;word-break:break-all;">
                      ${n.source ? `<div class="muted-sm"><code>${esc(n.source)}</code></div>` : ""}
                      ${n.last_error ? `<div style="color:var(--err);font-size:11px;">${esc(n.last_error)}</div>` : ""}
                    </td>
                    <td><button type="button" class="btn sm" data-geoip-node-sync="${esc(n.node_tag)}" ${geoipSyncing ? "disabled" : ""}>Sync</button></td>
                  </tr>`
                  )
                  .join("") || `<tr><td colspan="7" class="muted">${geoipLoading ? "Loading…" : "No ingress GeoIP status reported yet."}</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    `;

    el("btn-sec-geoip-sync")?.addEventListener("click", () => syncGeoIp(null, true));
    container.querySelectorAll("[data-geoip-node-sync]").forEach((btn) => {
      btn.addEventListener("click", () => syncGeoIp(btn.dataset.geoipNodeSync, true));
    });
    wireBinSliders(container, "data-geoip-bin", (f, v) => {
      store.mutate((s) => {
        ensureGeoIp(s)[f] = v;
      }, false);
    });
    el("geoip-interval")?.addEventListener("input", (ev) => {
      store.mutate((s) => {
        ensureGeoIp(s).update_interval_hours = parseNum(ev.target.value, 168, 6, 720);
      }, false);
    });
    el("geoip-cache-dir")?.addEventListener("input", (ev) => {
      store.mutate((s) => {
        ensureGeoIp(s).cache_dir = ev.target.value.trim() || null;
      }, false);
    });
    el("geoip-v4-url")?.addEventListener("input", (ev) => {
      store.mutate((s) => {
        ensureGeoIp(s).ipv4_url = ev.target.value.trim() || null;
      }, false);
    });
    el("geoip-v6-url")?.addEventListener("input", (ev) => {
      store.mutate((s) => {
        ensureGeoIp(s).ipv6_url = ev.target.value.trim() || null;
      }, false);
    });
    el("btn-geoip-lookup")?.addEventListener("click", async () => {
      const ip = el("geoip-test-ip")?.value.trim();
      const node = el("geoip-test-node")?.value || "all";
      if (!ip) {
        showToast("Enter an IP address first", true);
        return;
      }
      try {
        geoLookupResult = await api(`/api/security/geoip/lookup?ip=${encodeURIComponent(ip)}&node=${encodeURIComponent(node)}`);
        render();
      } catch (e) {
        showToast(e.message, true);
      }
    });
  }

  // Built-in page fallbacks (mirror crates/exposure-core/src/assets.rs + web/challenge/*):
  // monospace, one hairline rule, no card chrome — the semi-immersive portal / SSO language.
  // The illustration is inlined only in the real pages; the sandboxed preview omits it.
  const BUILTIN_PAGE_CSS =
    ":root{color-scheme:light dark;--bg:#ffffff;--text:#1a1a1a;--line:#1a1a1a;--muted:#6a6a6a;--soft:#f2f2f2;--track:#e4e4e4;--accent:#C40233;--accent-ink:#ffffff;--danger:#c40233}" +
    "@media (prefers-color-scheme:dark){:root{--bg:#121212;--text:#ededed;--line:#5a5a5a;--muted:#8c8c8c;--soft:#1e1e1e;--track:#2b2b2b;--danger:#e0737c}}" +
    ".page.is-429{--accent:#9A6A00;--accent-ink:#ffffff}" +
    ".page.is-4xx{--accent:#C40233;--accent-ink:#ffffff}" +
    ".page.is-5xx{--accent:#7E0C1A;--accent-ink:#ffffff}" +
    "@media (prefers-color-scheme:dark){.page.is-429{--accent:#DCA93F;--accent-ink:#121212}.page.is-4xx{--accent:#E4595F;--accent-ink:#121212}.page.is-5xx{--accent:#C2606A;--accent-ink:#121212}}" +
    "*{box-sizing:border-box}" +
    "body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:ui-monospace,'Sarasa Mono SC','Cascadia Code',Menlo,Consolas,monospace;font-size:14px;line-height:1.5}" +
    ".page{position:relative;min-height:100vh;display:flex;align-items:center;padding:64px min(9vw,120px)}" +
    ".col{position:relative;z-index:1;width:min(520px,100%)}" +
    ".tag{display:inline-block;padding:4px 9px;background:var(--accent);color:var(--accent-ink);font-size:10px;font-weight:900;letter-spacing:.2em;text-transform:uppercase}" +
    "h1{margin:12px 0 0;font-size:clamp(22px,4.6vw,40px);line-height:1.05;font-weight:900;text-transform:uppercase;letter-spacing:.01em}" +
    ".rule{height:1px;margin:22px 0 0;background:var(--line);opacity:.5}" +
    ".detail{margin:20px 0 0;max-width:42ch;color:var(--muted);font-size:15px;line-height:1.7}" +
    ".meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px 28px;margin:32px 0 0;padding:0}" +
    ".meta div{display:flex;flex-direction:column;gap:3px}" +
    ".meta dt{margin:0;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}" +
    ".meta dd{margin:0;font-size:13px;font-weight:900}" +
    ".retry{display:flex;align-items:center;gap:14px;margin:26px 0 0}" +
    ".retry span{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);white-space:nowrap}" +
    ".retry i{position:relative;flex:1;height:6px;background:var(--track);overflow:hidden}" +
    ".retry i::after{content:'';position:absolute;top:0;bottom:0;left:0;background:var(--accent);animation:load var(--d,12s) linear forwards}" +
    "@keyframes load{from{width:0}to{width:100%}}" +
    ".foot{display:flex;justify-content:space-between;gap:16px;margin:52px 0 0;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);opacity:.75}" +
    ".track{position:relative;height:6px;margin:26px 0 0;background:var(--track);overflow:hidden}" +
    ".bar{width:15%;height:100%;background:var(--accent)}" +
    ".error{margin:20px 0 0;max-width:42ch;color:var(--danger);font-size:12px;line-height:1.6;word-break:break-word}" +
    ".hidden{display:none}" +
    "@media (max-width:980px){.page{align-items:flex-start;padding:52px 24px 0}.foot{margin-top:36px}}";

  // Custom pages are node-local files, so the panel can only preview the built-in templates.
  function buildPreviewHtml() {
    if (previewMode === "error") {
      const tpl = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><meta name="color-scheme" content="light dark"/><title>{{status}} {{title}}</title><style>${BUILTIN_PAGE_CSS}</style></head><body><main class="page is-429"><section class="col"><div class="tag">HTTP {{status}}</div><h1>{{title}}</h1><div class="rule"></div><p class="detail">{{detail}}</p>{{retry_note}}<div class="foot"><span>Exposure Edge</span><span>Ray {{ray_id}}</span></div></section></main></body></html>`;
      return tpl
        .replaceAll("{{status}}", "429")
        .replaceAll("{{title}}", "Too Many Requests")
        .replaceAll("{{detail}}", "Rate limit exceeded on edge guard. Please wait a moment and retry.")
        .replaceAll("{{ray_id}}", "exp-preview-8f91c2a0")
        .replaceAll("{{retry_after}}", "12")
        .replaceAll("{{accent}}", "#9A6A00")
        .replaceAll(
          "{{retry_note}}",
          `<dl class="meta"><div><dt>Status</dt><dd>429</dd></div><div><dt>Retry after</dt><dd>12s</dd></div></dl><div class="retry"><span>Auto-retry</span><i style="--d:12000ms"></i></div>`
        );
    }
    const css =
      BUILTIN_PAGE_CSS.replace(
        "--accent:#C40233;--accent-ink:#ffffff;--danger:#c40233}",
        "--accent:#3c7499;--accent-ink:#ffffff;--danger:#c40233}"
      ) + "@media (prefers-color-scheme:dark){:root{--accent:#8fb9d6;--accent-ink:#121212}}";
    return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><meta name="color-scheme" content="light dark"/><title>Security Check</title><style>${css}</style></head><body><main class="page"><section class="col"><div class="tag">Security Check</div><h1>Verifying your browser</h1><div class="rule"></div><p id="status-text" class="detail">Running a lightweight proof-of-work check before forwarding your request.</p><div class="track"><div id="progress-bar" class="bar" style="width:62%"></div></div><dl class="meta"><div><dt>Difficulty</dt><dd id="meta-difficulty">18 bits</dd></div><div><dt>Hashes</dt><dd id="meta-hashes">131072</dd></div></dl><p id="error-text" class="error hidden"></p><div class="foot"><span>Exposure Edge</span><span>PoW / SHA-256</span></div></section></main></body></html>`;
  }

  function renderPagesSubTab(container) {
    const pages = store.spec.defaults?.pages || { error: null, pow: null };
    container.innerHTML = `
      <div class="page-editor-grid">
        <div class="panel" style="display:flex;flex-direction:column;gap:12px;margin-bottom:0;">
          <p style="margin:0;font-size:12px;color:var(--muted);">${esc(t("Each node reads these single-file HTML pages from its own filesystem when the config is applied. Leave empty for the built-in page; a missing or unreadable file falls back to it with a warning."))}</p>
          <label><span>${esc(t("Custom Intercept Error Page (single-file HTML path)"))}</span>
            <input id="pg-err-path" type="text" spellcheck="false" placeholder="/etc/exposure/pages/error.html" value="${esc(pages.error || "")}" />
          </label>
          <label><span>${esc(t("Custom PoW Challenge Page (single-file HTML path)"))}</span>
            <input id="pg-pow-path" type="text" spellcheck="false" placeholder="/etc/exposure/pages/pow.html" value="${esc(pages.pow || "")}" />
          </label>
        </div>
        <div class="panel" style="display:flex;flex-direction:column;gap:10px;margin-bottom:0;">
          <div class="panel-header" style="margin-bottom:0;">
            <h3>${esc(t("Live Preview (Sandboxed)"))}</h3>
            <div class="seg-group">
              <button type="button" class="btn sm ${previewMode === "error" ? "primary" : ""}" data-pg-prev="error">429 Error</button>
              <button type="button" class="btn sm ${previewMode === "challenge" ? "primary" : ""}" data-pg-prev="challenge">PoW Page</button>
            </div>
          </div>
          <iframe id="pg-preview-iframe" class="page-preview-frame" sandbox="" title="Custom Page Preview"></iframe>
        </div>
      </div>
    `;

    const refreshFrame = () => {
      const fr = el("pg-preview-iframe");
      if (fr) fr.srcdoc = buildPreviewHtml();
    };
    refreshFrame();

    container.querySelectorAll("[data-pg-prev]").forEach((btn) => {
      btn.addEventListener("click", () => {
        previewMode = btn.dataset.pgPrev;
        render();
      });
    });

    el("pg-err-path")?.addEventListener("input", (ev) => {
      const v = ev.target.value.trim();
      store.mutate((s) => { s.defaults.pages.error = v ? v : null; }, false);
    });
    el("pg-pow-path")?.addEventListener("input", (ev) => {
      const v = ev.target.value.trim();
      store.mutate((s) => { s.defaults.pages.pow = v ? v : null; }, false);
    });

    el("btn-sec-reset-pages")?.addEventListener("click", () => {
      store.mutate((s) => {
        s.defaults.pages = { error: null, pow: null };
      });
      render();
      showToast("Reset custom pages to built-in defaults");
    });
  }

  /* ---------- Threat Intel & Honeypot (cluster ingress defaults) ---------- */

  function renderThreatIntelSubTab(container) {
    const defs = store.spec.defaults || defaultTopologyDefaults();
    const ig = defs.ingress;
    if (!ig.abuseipdb) ig.abuseipdb = defaultAbuseIpDbConfig();
    if (!ig.evilpot) ig.evilpot = defaultEvilpotConfig();
    const ab = ig.abuseipdb;
    const ep = ig.evilpot;

    container.innerHTML = `
      <div class="defaults-grid">
        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header"><h3>${esc(t("AbuseIPDB IP Reputation"))}</h3></div>
          <div class="tri-stack" style="margin-bottom:8px;">
            ${renderBinSlider({ attrName: "data-sd-ab-bin", attrVal: "enabled", label: t("Enable AbuseIPDB Automatic IP Scoring"), sub: t("Queries AbuseIPDB v2 with your own API key; high abuse scores raise server suspicion or trigger automatic mitigation"), val: ab.enabled })}
          </div>
          <div class="inspector-row">
            <label style="flex:1.5;"><span>${esc(t("AbuseIPDB API Key"))}</span>
              <input id="sd-ab-key" type="password" autocomplete="off" value="${esc(ab.api_key || "")}" placeholder="AbuseIPDB v2 API Key" />
            </label>
            <label><span>${esc(t("Test IP Address"))}</span>
              <div style="display:flex;gap:6px;">
                <input id="sd-ab-test-ip" value="${esc(abuseTestIp)}" placeholder="118.25.6.39" />
                <button type="button" id="sd-ab-test-btn" class="btn sm primary" ${abuseTesting ? "disabled" : ""}>${esc(abuseTesting ? t("Testing…") : t("Test Key"))}</button>
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
            <label><span>${esc(t("High-Risk Action (≥ Block Score)"))}</span>
              <select id="sd-ab-act">
                <option value="off" ${ab.high_risk_action === "off" ? "selected" : ""}>${esc(t("off — Score Only"))}</option>
                <option value="monitor" ${ab.high_risk_action === "monitor" ? "selected" : ""}>${esc(t("monitor — Log Only"))}</option>
                <option value="challenge" ${ab.high_risk_action === "challenge" ? "selected" : ""}>${esc(t("challenge — Force PoW"))}</option>
                <option value="block" ${(ab.high_risk_action || "block") === "block" ? "selected" : ""}>${esc(t("block — HTTP 403"))}</option>
                <option value="evilpot" ${ab.high_risk_action === "evilpot" ? "selected" : ""}>${esc(t("evilpot — Divert to Honeypot"))}</option>
              </select>
            </label>
            <label><span>${esc(t("Challenge Score (0-100)"))}</span><input id="sd-ab-ch" type="number" min="0" max="100" value="${ab.challenge_threshold ?? 25}" /></label>
            <label><span>${esc(t("Block Score (0-100)"))}</span><input id="sd-ab-blk" type="number" min="0" max="100" value="${ab.block_threshold ?? 75}" /></label>
          </div>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("Max Age (days)"))}</span><input id="sd-ab-age" type="number" min="1" max="365" value="${ab.max_age_days ?? 90}" /></label>
            <label><span>${esc(t("Cache TTL (s)"))}</span><input id="sd-ab-ttl" type="number" min="60" value="${ab.cache_ttl_secs ?? 21600}" /></label>
            <label><span>${esc(t("Daily Quota Cap / Node"))}</span><input id="sd-ab-cap" type="number" min="10" value="${ab.max_daily_lookups ?? 900}" /></label>
          </div>
          <div class="tri-stack" style="margin-top:10px;">
            ${renderBinSlider({ attrName: "data-sd-abrep-bin", attrVal: "report_enabled", label: t("Report Confirmed Attackers to AbuseIPDB"), sub: t("Off by default. Only honeypot-verified exploits that produced a new ban are submitted — at most one per IP per 24h, per AbuseIPDB's 15-minute per-IP rule"), val: ab.report_enabled })}
          </div>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("Daily Report Quota / Node"))}</span><input id="sd-abrep-q" type="number" min="1" max="1000" value="${ab.report_daily_quota ?? 100}" /></label>
            <label><span>${esc(t("Min Ban Level (1-8)"))}</span><input id="sd-abrep-lvl" type="number" min="1" max="8" value="${ab.report_min_offense_level ?? 1}" /></label>
            <label><span>${esc(t("Category IDs (blank = auto)"))}</span><input id="sd-abrep-cats" value="${esc((ab.report_categories || []).join(","))}" placeholder="21,15" /></label>
          </div>
        </div>

        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header"><h3>${esc(t("Evilpot Honeypot Engine Defaults"))}</h3></div>
          <div class="inspector-row">
            <label><span>${esc(t("Persona Rotation (s)"))}</span><input id="sd-ep-rot" type="number" min="60" value="${ep.rotation_interval_secs ?? 300}" /></label>
            <label><span>${esc(t("Persona Slots"))}</span><input id="sd-ep-slots" type="number" min="1" max="32" value="${ep.persona_slots ?? 16}" /></label>
            <label><span>${esc(t("Max Tarpit Conns"))}</span><input id="sd-ep-tconns" type="number" min="1" max="256" value="${ep.max_tarpit_connections ?? 256}" /></label>
          </div>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("Tarpit Drip (B/s)"))}</span><input id="sd-ep-drip" type="number" min="16" max="16384" value="${ep.tarpit_drip_bytes_per_sec ?? 256}" /></label>
            <label><span>${esc(t("SQLi Blind Delay (ms)"))}</span><input id="sd-ep-sqli" type="number" min="100" max="5000" value="${ep.sqli_time_delay_ms ?? 2500}" /></label>
            <label><span>${esc(t("Max Tracked Sessions"))}</span><input id="sd-ep-maxs" type="number" min="16" max="4096" value="${ep.max_tracked_sessions ?? 2048}" /></label>
          </div>
          <label style="margin-top:8px;"><span>${esc(t("Canary Webhook Base URL"))}</span>
            <input id="sd-ep-curl" value="${esc(ep.canary_webhook_url || "")}" placeholder="https://canary.internal.example.com/t" />
          </label>
          <div class="inspector-row" style="margin-top:6px;">
            <label><span>${esc(t("Identical-Payload Decoy Hits"))}</span><input id="sd-ep-decoys" type="number" min="0" max="100" value="${ep.identical_payload_decoy_hits ?? 1}" /></label>
          </div>
          <p class="muted-sm" style="margin:6px 0 0;">
            ${esc(t("How many times the exact same blocked payload (same IP + same signature) still gets the fake decoy. After that, every repeated submission returns a real 403 with the Ray ID, so a user who tripped a false positive can quote it to an administrator. Different payloads are unaffected and still reach the honeypot and auto-ban."))}
          </p>
        </div>
      </div>
    `;

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
    wireBinSliders(container, "data-sd-abrep-bin", (f, v) => store.mutate((s) => { ensureAb(s)[f] = v; }, false));
    el("sd-abrep-q")?.addEventListener("input", (ev) => store.mutate((s) => { ensureAb(s).report_daily_quota = parseNum(ev.target.value, 100, 1, 1000); }, false));
    el("sd-abrep-lvl")?.addEventListener("input", (ev) => store.mutate((s) => { ensureAb(s).report_min_offense_level = parseNum(ev.target.value, 1, 1, 8); }, false));
    el("sd-abrep-cats")?.addEventListener("input", (ev) => {
      const ids = ev.target.value
        .split(/[^0-9]+/)
        .map((v) => Number(v))
        .filter((v) => Number.isInteger(v) && v >= 1 && v <= 23);
      store.mutate((s) => { ensureAb(s).report_categories = [...new Set(ids)]; }, false);
    });
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
        if (subTab === "intel") render();
      }
    });

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
    el("sd-ep-decoys")?.addEventListener("input", (ev) => store.mutate((s) => { ensureEp(s).identical_payload_decoy_hits = parseNum(ev.target.value, 1, 0, 100); }, false));
  }

  /* ---------- IP Exemption (cluster-wide ingress scope, not honeypot-only) ---------- */

  function renderExemptSubTab(container) {
    const defs = store.spec.defaults || defaultTopologyDefaults();
    const ig = defs.ingress || (defs.ingress = defaultTopologyDefaults().ingress);

    container.innerHTML = `
      <div class="defaults-grid">
        <div class="panel" style="margin-bottom:0;grid-column:1 / -1;">
          <div class="panel-header"><h3>${esc(t("IP Exemption List"))}</h3></div>
          <p class="muted-sm" style="margin:0 0 8px;">
            ${esc(t("Exact IPs or CIDRs, one per line. This is not a honeypot-only setting: it applies to the whole ingress pipeline, so exempt clients skip WAF / OWASP CRS inspection, Evilpot honeypot diversion, antibot & GeoIP challenges, bucket rate limiting, auto-ban and AbuseIPDB lookup/reporting — only ordinary traffic logs are kept."))}
          </p>
          <textarea id="sd-exempt-ips" rows="8" spellcheck="false" placeholder="203.0.113.7&#10;10.0.0.0/8&#10;2001:db8::/32">${esc((ig.exempt_ips || []).join("\n"))}</textarea>
          <p class="muted-sm" style="margin:8px 0 0;">
            ${esc(t("Built-in /cdn-cgi/ endpoints (PoW page, fp.js beacon, fp-report) are still served to exempt clients — they are edge-only assets and are never proxied to an origin."))}
          </p>
          <p class="muted-sm" style="margin:8px 0 0;">
            ${esc(t("Warning: an address here is never intercepted, even if it is actively attacking. Only add ranges you control."))}
          </p>
        </div>
      </div>
    `;

    el("sd-exempt-ips")?.addEventListener("input", (ev) => {
      const list = ev.target.value
        .split(/[\s,]+/)
        .map((v) => v.trim())
        .filter(Boolean)
        .slice(0, 4096);
      store.mutate((s) => {
        if (!s.defaults.ingress) s.defaults.ingress = defaultTopologyDefaults().ingress;
        s.defaults.ingress.exempt_ips = list;
      }, false);
    });
  }

  function render() {
    const root = el("tab-security");
    if (!root) return;

    const bucketCnt = Object.keys(store.spec.bucket_templates || {}).length;
    const antibotCnt = Object.keys(store.spec.antibot_templates || {}).length;
    const wafCnt = Object.keys(store.spec.waf_templates || {}).length;

    root.innerHTML = `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${subTab === "buckets" ? "active" : ""}" data-sec-sub="buckets">
            ${esc(t("Buckets"))} <span class="subtab-count">${bucketCnt}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "antibot" ? "active" : ""}" data-sec-sub="antibot">
            ${esc(t("Antibot & Geo"))} <span class="subtab-count">${antibotCnt}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "waf" ? "active" : ""}" data-sec-sub="waf">
            ${esc(t("WAF (OWASP CRS)"))} <span class="subtab-count">${wafCnt}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "intel" ? "active" : ""}" data-sec-sub="intel">
            ${esc(t("Threat Intel & Honeypot"))}
          </button>
          <button type="button" class="subtab-btn ${subTab === "exempt" ? "active" : ""}" data-sec-sub="exempt">
            ${esc(t("IP Exemption List"))}
          </button>
          <button type="button" class="subtab-btn ${subTab === "geoip" ? "active" : ""}" data-sec-sub="geoip">
            ${esc(t("GeoIP DB"))}
          </button>
          <button type="button" class="subtab-btn ${subTab === "pages" ? "active" : ""}" data-sec-sub="pages">
            ${esc(t("Custom Error & PoW Pages"))}
          </button>
        </div>
        <div class="btn-row">
          ${subTab === "buckets" ? `<button type="button" id="btn-sec-add-bucket" class="btn sm primary">${esc(t("+ New Bucket Set"))}</button>` : ""}
          ${subTab === "antibot" ? `<button type="button" id="btn-sec-add-antibot" class="btn sm primary">${esc(t("+ New Antibot Set"))}</button>` : ""}
          ${
            subTab === "waf"
              ? `<button type="button" id="btn-sec-add-waf" class="btn sm primary">${esc(t("+ New WAF Set"))}</button>
                 <button type="button" id="btn-sec-crs-sync" class="btn sm" ${wafSyncing ? "disabled" : ""}>${esc(wafSyncing ? t("Syncing from coreruleset.org…") : t("Sync OWASP CRS Now"))}</button>`
              : ""
          }
          ${subTab === "geoip" ? `<button type="button" id="btn-sec-geoip-sync" class="btn sm primary" ${geoipSyncing ? "disabled" : ""}>${esc(geoipSyncing ? t("Syncing GeoIP…") : t("Sync GeoIP DB Now"))}</button>` : ""}
          ${subTab === "pages" ? `<button type="button" id="btn-sec-reset-pages" class="btn sm">${esc(t("Reset to Built-in Defaults"))}</button>` : ""}
        </div>
      </div>
      <div id="sec-sub-body"></div>
    `;

    root.querySelectorAll("[data-sec-sub]").forEach((btn) => {
      btn.addEventListener("click", () => {
        subTab = btn.dataset.secSub;
        if (subTab === "waf" && !wafRulesData) loadWafRules();
        else if (subTab === "geoip" && !geoipData) loadGeoIpStatus();
        render();
      });
    });

    const body = el("sec-sub-body");
    if (subTab === "buckets") renderBucketsSubTab(body);
    else if (subTab === "antibot") renderAntibotSubTab(body);
    else if (subTab === "waf") renderWafSubTab(body);
    else if (subTab === "intel") renderThreatIntelSubTab(body);
    else if (subTab === "exempt") renderExemptSubTab(body);
    else if (subTab === "geoip") renderGeoIpSubTab(body);
    else renderPagesSubTab(body);
  }

  async function refresh(opts = {}) {
    if (opts.subTab) {
      if (opts.subTab === "waf-rules") subTab = "waf";
      else if (opts.subTab === "guards") subTab = "antibot";
      else if (["buckets", "antibot", "waf", "intel", "exempt", "geoip", "pages"].includes(opts.subTab)) subTab = opts.subTab;
    }
    if (!store.loaded) await store.loadTopology(false);
    if (subTab === "waf") {
      await loadWafRules();
      return;
    }
    if (subTab === "geoip") {
      await loadGeoIpStatus();
      return;
    }
    render();
  }

  return { refresh, render };
}
