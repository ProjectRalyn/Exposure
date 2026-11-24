// Security View — Buckets, Antibot & GeoIP Region-Targeting, Pure OWASP CRS WAF, GeoIP DB, Evilpot & Unban, Pages
import { formatDateTime } from "../charts.js";
import { t } from "../i18n.js";
import {
  defaultAntibotProfile,
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
  let subTab = "buckets"; // buckets | antibot | waf | geoip | evilpot | pages
  let setScope = "cluster"; // "cluster" | <ingress-node-tag>
  let previewMode = "error"; // error | challenge

  let evilpotData = null;
  let evilpotLoading = false;
  let unbanBusy = false;

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
    showToast(t("sec.migrate.done"));
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
          <strong style="color:var(--warn);">${esc(t("sec.migrate.title"))}</strong>
          <div class="muted-sm">${esc(t("sec.migrate.desc", { count: gCount }))}</div>
        </div>
        <button type="button" id="btn-sec-migrate-guards" class="btn sm primary">${esc(t("sec.migrate.btn"))}</button>
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
              <span class="muted-sm">${esc(t("sec.assign.scope"))}</span>
              <select id="sec-set-scope" class="select-sm" style="width:auto;min-width:170px;">
                <option value="cluster" ${setScope === "cluster" ? "selected" : ""}>${esc(t("sec.assign.cluster_tpl"))}</option>
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
            <span>${esc(t("sec.assign.cluster_default"))}</span>
            <select id="sec-def-cluster-${esc(kind)}">
              <option value="">${esc(t("common.none"))}</option>
              ${clusterOpts.map((k) => `<option value="${esc(k)}" ${clusterDef === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
            </select>
          </label>
          <div style="display:flex;align-items:end;">
            <div class="muted-sm">${esc(t("sec.assign.hint"))}</div>
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
                      <option value="">(${esc(t("sec.assign.inherit"))}: ${esc(clusterDef || t("common.none"))})</option>
                      ${opts.map((k) => `<option value="${esc(k)}" ${val === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
                    </select>
                  </label>
                `;
              })
              .join("")}
          </div>`
            : `<div class="muted-sm">${esc(t("sec.assign.no_ingress"))}</div>`
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
              <button type="button" class="btn sm danger" data-bk-del="${esc(bName)}">${esc(t("common.remove"))}</button>
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
      ${renderScopeAndAssignmentCard("bucket", "sec.assign.buckets")}
      ${
        cardsHtml
          ? `<div class="tpl-card-grid">${cardsHtml}</div>`
          : `<div class="empty-state-box"><p>${esc(t("sec.empty.buckets"))}</p></div>`
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
      inp.addEventListener("change", () => {
        const oldN = inp.dataset.bkRename;
        const newN = inp.value.trim();
        const cur = cfg.getMap(store.spec);
        if (!newN || newN === oldN || isReservedKey(newN) || cur[newN]) {
          inp.value = oldN;
          return;
        }
        store.mutate((s) => {
          const m = cfg.getMap(s);
          m[newN] = m[oldN];
          delete m[oldN];
          renameSetReferences(s, "bucket", oldN, newN);
        });
        render();
      });
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
            <strong style="font-size:12px;letter-spacing:.03em;">${esc(t("geo.policy.title"))}</strong>
            ${g.enabled ? `<span class="pill ok">${esc(t("common.enabled"))}</span>` : `<span class="pill">${esc(t("common.disabled"))}</span>`}
            ${rules.length ? `<span class="pill info">${rules.length} rules</span>` : ""}
          </div>
          <button type="button" class="btn sm ghost" data-ab-geo-toggle="${esc(abName)}">${isOpen ? "▾" : "▸"} ${esc(t("geo.policy.configure"))}</button>
        </div>
        ${
          !isOpen
            ? ""
            : `
          <div style="display:flex;flex-direction:column;gap:8px;padding:10px;background:var(--bg);border:1px solid var(--border);border-radius:8px;">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
              <div style="flex:1;min-width:190px;">
                ${renderBinSlider({ attrName: `data-ab-geo-bin-${abName}`, attrVal: "enabled", label: t("geo.policy.enable"), val: Boolean(g.enabled) })}
              </div>
              <div class="btn-row">
                <span class="muted-sm">${esc(t("geo.policy.quick_target"))}:</span>
                <button type="button" class="btn sm ${quickMode === "deny" ? "primary" : "ghost"}" data-ab-geo-qtarget="${esc(abName)}" data-qval="deny">${esc(t("geo.policy.deny_list"))}</button>
                <button type="button" class="btn sm ${quickMode === "allow" ? "primary" : "ghost"}" data-ab-geo-qtarget="${esc(abName)}" data-qval="allow">${esc(t("geo.policy.allow_list"))}</button>
              </div>
            </div>
            <div>
              <div class="muted-sm" style="margin-bottom:4px;">${esc(t("geo.policy.quick_chips"))}</div>
              <div style="display:flex;flex-wrap:wrap;gap:4px;">
                ${QUICK_GEO_TOKENS.map((tok) => {
                  const inTarget = quickMode === "deny" ? activeDeny.has(tok) : activeAllow.has(tok);
                  return `<button type="button" class="btn sm ${inTarget ? (quickMode === "deny" ? "danger" : "primary") : "ghost"}" data-ab-geo-chip="${esc(abName)}" data-tok="${esc(tok)}">${esc(tok)}</button>`;
                }).join("")}
              </div>
            </div>
            <div class="inspector-row">
              <label><span>${esc(t("geo.policy.allow_regions"))}</span><input data-ab-geo-csv="${esc(abName)}" data-gk="allow_regions" value="${esc((g.allow_regions || []).join(", "))}" placeholder="CN, HK, CONTINENT:AS" /></label>
              <label><span>${esc(t("geo.policy.deny_regions"))}</span><input data-ab-geo-csv="${esc(abName)}" data-gk="deny_regions" value="${esc((g.deny_regions || []).join(", "))}" placeholder="RU, CONTINENT:AF" /></label>
            </div>
            <div class="inspector-row">
              <label><span>${esc(t("geo.policy.deny_action"))}</span>
                <select data-ab-geo-act="${esc(abName)}" data-gk="deny_action">
                  ${GEO_RULE_ACTIONS.map((a) => `<option value="${a}" ${g.deny_action === a ? "selected" : ""}>${a}</option>`).join("")}
                </select>
              </label>
              <label><span>${esc(t("geo.policy.default_action"))}</span>
                <select data-ab-geo-act="${esc(abName)}" data-gk="default_action">
                  ${GEO_RULE_ACTIONS.map((a) => `<option value="${a}" ${g.default_action === a ? "selected" : ""}>${a}</option>`).join("")}
                </select>
              </label>
              <label><span>${esc(t("geo.policy.unknown_action"))}</span>
                <select data-ab-geo-act="${esc(abName)}" data-gk="unknown_action">
                  ${GEO_RULE_ACTIONS.map((a) => `<option value="${a}" ${g.unknown_action === a ? "selected" : ""}>${a}</option>`).join("")}
                </select>
              </label>
            </div>
            <div style="margin-top:4px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <span class="muted-sm"><strong>${esc(t("geo.policy.rules_title"))}</strong> (${rules.length})</span>
                <button type="button" class="btn sm" data-ab-geo-add-rule="${esc(abName)}">+ ${esc(t("geo.policy.add_rule"))}</button>
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
                  : `<div class="muted-sm">${esc(t("geo.policy.no_rules"))}</div>`
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
                <button type="button" class="btn sm danger" data-ab-del="${esc(abName)}">${esc(t("common.remove"))}</button>
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
      ${renderScopeAndAssignmentCard("antibot", "sec.assign.antibot")}
      ${
        cardsHtml
          ? `<div class="tpl-card-grid">${cardsHtml}</div>`
          : `<div class="empty-state-box"><p>${esc(t("sec.empty.antibot"))}</p></div>`
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
      inp.addEventListener("change", () => {
        const oldN = inp.dataset.abRename;
        const newN = inp.value.trim();
        const cur = cfg.getMap(store.spec);
        if (!newN || newN === oldN || isReservedKey(newN) || cur[newN]) {
          inp.value = oldN;
          return;
        }
        store.mutate((s) => {
          const m = cfg.getMap(s);
          m[newN] = m[oldN];
          delete m[oldN];
          renameSetReferences(s, "antibot", oldN, newN);
        });
        render();
      });
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
      showToast(t("waf.crs.synced_ok", { version: res.version || "latest", count: res.rules_count ?? 0 }));
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
              <button type="button" class="btn sm danger" data-ws-del="${esc(wName)}">${esc(t("common.remove"))}</button>
            </div>
            <div class="inspector-row">
              <label><span>${esc(t("waf.mode"))}</span>
                <select data-ws-mode="${esc(wName)}">
                  <option value="off" ${w.mode === "off" ? "selected" : ""}>${esc(t("waf.mode.off"))}</option>
                  <option value="monitor" ${w.mode === "monitor" ? "selected" : ""}>${esc(t("waf.mode.monitor"))}</option>
                  <option value="block" ${w.mode === "block" ? "selected" : ""}>${esc(t("waf.mode.block"))}</option>
                  <option value="evilpot" ${w.mode === "evilpot" ? "selected" : ""}>${esc(t("waf.mode.evilpot"))}</option>
                </select>
              </label>
              <label><span>${esc(t("waf.crs.paranoia"))}</span>
                <select data-ws-pl="${esc(wName)}">
                  ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${(w.crs_paranoia_level || 1) === pl ? "selected" : ""}>PL${pl}</option>`).join("")}
                </select>
              </label>
              <label><span>${esc(t("waf.max_body_kb"))}</span>
                <input type="number" min="0" max="256" data-ws-bodykb="${esc(wName)}" value="${Math.round((w.max_body_bytes ?? 32768) / 1024)}" />
              </label>
            </div>
            <div class="tri-stack" style="margin-top:6px;">
              ${renderBinSlider({ attrName: `data-ws-bin-${wName}`, attrVal: "inspect_headers", label: t("waf.inspect_headers"), val: w.inspect_headers !== false })}
              ${renderBinSlider({ attrName: `data-ws-bin-${wName}`, attrVal: "inspect_body", label: t("waf.inspect_body"), val: w.inspect_body !== false })}
            </div>
            <div class="inspector-row" style="margin-top:6px;">
              <label><span>${esc(t("waf.exempt_paths"))}</span>
                <input data-ws-exempt="${esc(wName)}" value="${esc((w.exempt_paths || []).join(", "))}" placeholder="/api/webhooks/, /cms/" />
              </label>
              <label><span>${esc(t("waf.disabled_rule_ids"))}</span>
                <input data-ws-disids="${esc(wName)}" value="${esc((w.disabled_rule_ids || []).join(", "))}" placeholder="942100, 932100" />
              </label>
            </div>
            <div style="margin-top:6px;">
              <div class="muted" style="font-size:11px;margin-bottom:5px;">${esc(activeCats.length ? t("waf.categories") : t("waf.categories.all"))}</div>
              <div style="display:flex;flex-wrap:wrap;gap:4px;">
                <button type="button" class="btn sm ${activeCats.length === 0 ? "primary" : "ghost"}" data-ws-cat-all="${esc(wName)}">${esc(t("common.all"))}</button>
                ${WAF_CATEGORIES.map((c) => {
                  const on = activeCats.includes(c);
                  return `<button type="button" class="btn sm ${on ? "primary" : "ghost"}" data-ws-cat="${esc(wName)}" data-waf-c="${esc(c)}">${esc(t(`waf.cat.${c}`))}</button>`;
                }).join("")}
              </div>
            </div>
          </div>`;
      })
      .join("");

    container.innerHTML = `
      ${renderLegacyMigrationBanner()}
      ${renderScopeAndAssignmentCard("waf", "sec.assign.waf")}
      ${
        wafCardsHtml
          ? `<div class="tpl-card-grid" style="margin-bottom:16px;">${wafCardsHtml}</div>`
          : `<div class="empty-state-box" style="margin-bottom:16px;"><p>${esc(t("sec.empty.waf"))}</p></div>`
      }

      <div class="kpi-grid" style="margin-bottom:14px;">
        <div class="kpi">
          <div class="kpi-label">${esc(t("waf.crs.version"))}</div>
          <div class="kpi-val" style="font-size:18px;">${esc(meta.version || (wafRulesLoading ? "…" : "builtin"))}</div>
          <div class="kpi-sub"><a href="https://coreruleset.org/" target="_blank" rel="noopener noreferrer" style="color:var(--accent);">coreruleset.org</a></div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("waf.crs.active_count"))}</div>
          <div class="kpi-val">${Math.max(0, allRules.length - disabledSet.size)} / ${allRules.length}</div>
          <div class="kpi-sub">${esc(t("waf.crs.pure_engine"))}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("waf.crs.skipped_pcre"))}</div>
          <div class="kpi-val">${meta.skipped_pcre ?? 0}</div>
          <div class="kpi-sub">Linear-time ReDoS-safe Rust regex</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("waf.crs.updated"))}</div>
          <div class="kpi-val" style="font-size:15px;">${esc(meta.updated_at ? formatDateTime(meta.updated_at) : "—")}</div>
          <div class="kpi-sub">${disabledSet.size} globally disabled</div>
        </div>
      </div>

      <div class="panel" style="margin-bottom:14px;">
        <div class="inspector-row" style="align-items:end;">
          <div style="flex:1.4;">
            ${renderBinSlider({ attrName: "data-crs-bin", attrVal: "auto_update", label: t("waf.crs.auto_update"), val: crsCfg.auto_update !== false })}
          </div>
          <label><span>${esc(t("waf.crs.interval_h"))}</span>
            <input id="crs-interval-h" type="number" min="1" max="720" value="${crsCfg.update_interval_hours ?? 24}" />
          </label>
          <label><span>${esc(t("waf.crs.paranoia"))}</span>
            <select id="crs-default-pl">
              ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${(crsCfg.paranoia_level || 1) === pl ? "selected" : ""}>PL${pl}</option>`).join("")}
            </select>
          </label>
        </div>
        <div class="muted-sm" style="margin-top:8px;">${esc(t("waf.crs.deploy_hint"))}</div>
      </div>

      <div class="panel">
        <div class="fp-search-bar" style="margin-bottom:10px;">
          <label style="flex:2;"><span>${esc(t("common.search"))}</span>
            <input id="waf-rule-search" type="search" value="${esc(wafSearch)}" placeholder="${esc(t("waf.crs.search_ph"))}" />
          </label>
          <label><span>${esc(t("waf.crs.col_pl"))}</span>
            <select id="waf-rule-pl">
              <option value="all" ${wafPlFilter === "all" ? "selected" : ""}>${esc(t("common.all"))}</option>
              ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${String(wafPlFilter) === String(pl) ? "selected" : ""}>PL${pl}</option>`).join("")}
            </select>
          </label>
          <label><span>${esc(t("waf.crs.col_state"))}</span>
            <select id="waf-rule-status">
              <option value="all" ${wafStatusFilter === "all" ? "selected" : ""}>${esc(t("waf.crs.status_all"))}</option>
              <option value="on" ${wafStatusFilter === "on" ? "selected" : ""}>${esc(t("waf.crs.status_on"))}</option>
              <option value="off" ${wafStatusFilter === "off" ? "selected" : ""}>${esc(t("waf.crs.status_off"))}</option>
            </select>
          </label>
        </div>

        <div class="table-scroll" style="max-height:520px;">
          <table class="table">
            <thead>
              <tr>
                <th>${esc(t("waf.crs.col_id"))}</th>
                <th>${esc(t("waf.crs.col_pl"))}</th>
                <th>${esc(t("waf.crs.col_cat"))}</th>
                <th>${esc(t("waf.crs.col_sev"))}</th>
                <th>${esc(t("waf.crs.col_desc"))}</th>
                <th>${esc(t("waf.crs.col_state"))}</th>
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
                        ${esc(isEnabled ? t("waf.crs.status_on") : t("waf.crs.status_off"))}
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
      inp.addEventListener("change", () => {
        const oldN = inp.dataset.wsRename;
        const newN = inp.value.trim();
        const cur = cfg.getMap(store.spec);
        if (!newN || newN === oldN || isReservedKey(newN) || cur[newN]) {
          inp.value = oldN;
          return;
        }
        store.mutate((s) => {
          const m = cfg.getMap(s);
          m[newN] = m[oldN];
          delete m[oldN];
          renameSetReferences(s, "waf", oldN, newN);
        });
        render();
      });
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
          actions: [{ label: t("common.close"), cls: "primary" }],
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
      showToast(t("geo.db.synced_ok", { ok: okCnt, total: (res.nodes || []).length }));
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
        <div class="kpi"><div class="kpi-label">${esc(t("geo.db.nodes_loaded"))}</div><div class="kpi-val">${esc(sum.loaded_nodes)} / ${esc(sum.total_ingress_nodes)}</div><div class="kpi-sub">CC0 IP-to-Country DB</div></div>
        <div class="kpi"><div class="kpi-label">IPv4 Ranges</div><div class="kpi-val">${esc((sum.max_ipv4_ranges || 0).toLocaleString())}</div><div class="kpi-sub">O(log N) binary search</div></div>
        <div class="kpi"><div class="kpi-label">IPv6 Ranges</div><div class="kpi-val">${esc((sum.max_ipv6_ranges || 0).toLocaleString())}</div><div class="kpi-sub">Dual-stack lookup</div></div>
        <div class="kpi"><div class="kpi-label">${esc(t("geo.db.last_pull"))}</div><div class="kpi-val" style="font-size:15px;">${geoipData?.last_pulled_at ? esc(formatDateTime(geoipData.last_pulled_at)) : (geoipLoading ? "…" : "—")}</div><div class="kpi-sub">${esc(t("geo.db.local_cache"))}</div></div>
      </div>

      <div class="panel" style="margin-bottom:14px;">
        <div class="panel-header"><h3>${esc(t("geo.db.settings_title"))}</h3><span class="muted-sm">${esc(t("waf.crs.deploy_hint"))}</span></div>
        <div class="tri-stack" style="margin-bottom:10px;">
          ${renderBinSlider({ attrName: "data-geoip-bin", attrVal: "enabled", label: t("geo.db.enabled"), val: gcfg.enabled !== false })}
          ${renderBinSlider({ attrName: "data-geoip-bin", attrVal: "auto_update", label: t("geo.db.auto_update"), val: gcfg.auto_update !== false })}
        </div>
        <div class="inspector-row">
          <label><span>${esc(t("geo.db.interval_h"))}</span><input id="geoip-interval" type="number" min="6" max="720" value="${gcfg.update_interval_hours ?? 168}" /></label>
          <label><span>${esc(t("geo.db.cache_dir"))}</span><input id="geoip-cache-dir" value="${esc(gcfg.cache_dir || "")}" placeholder="(default: <segment_dir>/geoip)" /></label>
        </div>
        <div class="inspector-row">
          <label><span>Custom IPv4 CSV HTTPS URL</span><input id="geoip-v4-url" value="${esc(gcfg.ipv4_url || "")}" placeholder="(default built-in CC0 mirrors)" /></label>
          <label><span>Custom IPv6 CSV HTTPS URL</span><input id="geoip-v6-url" value="${esc(gcfg.ipv6_url || "")}" placeholder="(default built-in CC0 mirrors)" /></label>
        </div>
      </div>

      <div class="panel" style="margin-bottom:14px;">
        <div class="panel-header"><h3>${esc(t("geo.db.lookup_title"))}</h3></div>
        <div class="fp-search-bar" style="margin-bottom:0;">
          <label style="flex:1.4;"><span>IP Address</span><input id="geoip-test-ip" placeholder="1.1.1.1 / 114.114.114.114 / 2001:4860:4860::8888" /></label>
          <label><span>Ingress Node</span>
            <select id="geoip-test-node">
              <option value="all">${esc(t("geo.db.any_loaded"))}</option>
              ${ingNodes.map(([tag]) => `<option value="${esc(tag)}">${esc(tag)}</option>`).join("")}
            </select>
          </label>
          <div class="btn-row"><button type="button" id="btn-geoip-lookup" class="btn primary">${esc(t("geo.db.lookup_btn"))}</button></div>
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
        <div class="panel-header"><h3>${esc(t("geo.db.node_table"))}</h3></div>
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

  function buildPreviewHtml() {
    const pages = store.spec.defaults?.pages || {};
    if (previewMode === "error") {
      const tpl =
        pages.error_html ||
        `<!DOCTYPE html><html><head><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#020617;color:#e2e8f0;font-family:system-ui,sans-serif}.card{width:min(440px,90vw);background:#0f172a;border:1px solid #1e293b;border-top:3px solid {{accent}};padding:24px}.tag{font-size:11px;letter-spacing:.14em;color:{{accent}};font-weight:700;margin-bottom:8px}h1{margin:0 0 8px;font-size:20px}p{color:#94a3b8;font-size:13px}</style></head><body><main class="card"><div class="tag">HTTP {{status}}</div><h1>{{title}}</h1><p>{{detail}}</p><small style="color:#64748b">Ray ID: {{ray_id}}</small></main></body></html>`;
      return tpl
        .replaceAll("{{status}}", "429")
        .replaceAll("{{title}}", "Too Many Requests")
        .replaceAll("{{detail}}", "Rate limit exceeded on edge guard. Please wait a moment and retry.")
        .replaceAll("{{ray_id}}", "exp-preview-8f91c2a0")
        .replaceAll("{{retry_after}}", "12")
        .replaceAll("{{accent}}", "#FAC800")
        .replaceAll("{{retry_note}}", "<p style='font-size:12px;color:#94a3b8'>Retry-After: 12s</p>");
    }
    const css =
      pages.challenge_css ||
      "body{margin:0;min-height:100vh;display:grid;place-items:center;background:#020617;color:#e2e8f0;font-family:system-ui,sans-serif}.box{padding:24px;border:1px solid #1e293b;border-radius:10px;background:#0f172a;width:360px}";
    const html =
      pages.challenge_html ||
      `<!DOCTYPE html><html><head><style>${css}</style></head><body><div class="box"><h3>Checking your browser…</h3><p id="status-text" style="color:#94a3b8;font-size:13px">Solving SHA-256 PoW (16 bits)</p></div></body></html>`;
    return html.includes("</head>")
      ? html.replace("</head>", `<style>${css}</style></head>`)
      : `<style>${css}</style>${html}`;
  }

  function renderPagesSubTab(container) {
    const pages = store.spec.defaults?.pages || { error_html: null, challenge_html: null, challenge_css: null };
    container.innerHTML = `
      <div class="page-editor-grid">
        <div class="panel" style="display:flex;flex-direction:column;gap:12px;margin-bottom:0;">
          <label><span>${esc(t("sec.pages.error_html"))}</span>
            <textarea id="pg-err-html" class="code-editor" style="min-height:120px;" spellcheck="false" placeholder="Leave empty for built-in 429 / 5xx error page">${esc(pages.error_html || "")}</textarea>
          </label>
          <label><span>${esc(t("sec.pages.chal_html"))}</span>
            <textarea id="pg-chal-html" class="code-editor" style="min-height:110px;" spellcheck="false" placeholder="Leave empty for built-in PoW HTML">${esc(pages.challenge_html || "")}</textarea>
          </label>
          <label><span>${esc(t("sec.pages.chal_css"))}</span>
            <textarea id="pg-chal-css" class="code-editor" style="min-height:100px;" spellcheck="false" placeholder="Leave empty for built-in PoW CSS">${esc(pages.challenge_css || "")}</textarea>
          </label>
        </div>
        <div class="panel" style="display:flex;flex-direction:column;gap:10px;margin-bottom:0;">
          <div class="panel-header" style="margin-bottom:0;">
            <h3>${esc(t("sec.pages.preview"))}</h3>
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

    el("pg-err-html")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.defaults.pages.error_html = ev.target.value.trim() ? ev.target.value : null; }, false);
      refreshFrame();
    });
    el("pg-chal-html")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.defaults.pages.challenge_html = ev.target.value.trim() ? ev.target.value : null; }, false);
      refreshFrame();
    });
    el("pg-chal-css")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.defaults.pages.challenge_css = ev.target.value.trim() ? ev.target.value : null; }, false);
      refreshFrame();
    });

    el("btn-sec-reset-pages")?.addEventListener("click", () => {
      store.mutate((s) => {
        s.defaults.pages = { error_html: null, challenge_html: null, challenge_css: null };
      });
      render();
      showToast("Reset custom pages to built-in defaults");
    });
  }

  function formatBytesShort(b) {
    const n = Number(b) || 0;
    if (n >= 1048576) return `${(n / 1048576).toFixed(2)} MiB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${n} B`;
  }

  function renderEpStatusPill(status) {
    if (status === "verified_exploit") return `<span class="pill err">${esc(t("ep.status.verified"))}</span>`;
    if (status === "multi_step_exploitation") return `<span class="pill warn">${esc(t("ep.status.multistep"))}</span>`;
    return `<span class="pill info">${esc(t("ep.status.probing"))}</span>`;
  }

  async function loadEvilpot(triggerPull = false) {
    if (!api) return;
    evilpotLoading = true;
    if (subTab === "evilpot") render();
    try {
      if (triggerPull) await api("/api/telemetry/pull", { method: "POST" });
      evilpotData = await api("/api/evilpot");
    } catch (e) {
      showToast(e.message, true);
    } finally {
      evilpotLoading = false;
      if (subTab === "evilpot") render();
    }
  }

  async function submitUnban(kind, target, nodeTag = null) {
    if (!api || unbanBusy) return;
    unbanBusy = true;
    render();
    try {
      const res = await api("/api/security/unban", {
        method: "POST",
        body: JSON.stringify({ kind, target, node_tag: nodeTag || null }),
      });
      showToast(t("ep.unban.done", { kind: res.kind || kind, target: res.target || target }));
      await loadEvilpot(false);
    } catch (e) {
      showToast(e.message, true);
    } finally {
      unbanBusy = false;
      if (subTab === "evilpot") render();
    }
  }

  function renderEvilpotSubTab(container) {
    el("btn-sec-ep-pull")?.addEventListener("click", () => loadEvilpot(true));
    if (!evilpotData && !evilpotLoading) loadEvilpot(false);

    const sum = evilpotData?.summary || {
      active_nodes: 0,
      requests_handled: 0,
      traps_triggered: 0,
      canary_verifications: 0,
      verified_attack_sessions: 0,
      tracked_sessions: 0,
      tarpit_bytes_dripped: 0,
      active_tarpit_connections: 0,
      active_ip_bans: 0,
      active_fp_bans: 0,
      total_auto_bans: 0,
      total_ban_drops: 0,
    };
    const sessions = evilpotData?.sessions || [];
    const events = evilpotData?.recent_events || [];
    const activeBans = evilpotData?.active_bans || [];
    const ingNodes = ingressNodes();

    container.innerHTML = `
      <div class="kpi-grid" style="margin-bottom:14px;">
        <div class="kpi-card"><div class="kpi-label">${esc(t("ep.kpi.trapped"))}</div><div class="kpi-value">${esc(sum.traps_triggered)}</div><div class="kpi-sub">${esc(t("ep.kpi.nodes"))}: ${esc(sum.active_nodes)}</div></div>
        <div class="kpi-card"><div class="kpi-label">${esc(t("ep.kpi.verified"))}</div><div class="kpi-value" style="color:var(--err);">${esc(sum.verified_attack_sessions)}</div><div class="kpi-sub">Tracked: ${esc(sum.tracked_sessions)}</div></div>
        <div class="kpi-card"><div class="kpi-label">${esc(t("ep.kpi.canaries"))}</div><div class="kpi-value" style="color:var(--warn);">${esc(sum.canary_verifications)}</div><div class="kpi-sub">Canary replay hits</div></div>
        <div class="kpi-card"><div class="kpi-label">${esc(t("ep.kpi.autoban"))}</div><div class="kpi-value" style="color:var(--err);">${esc(sum.active_ip_bans || 0)} / ${esc(sum.active_fp_bans || 0)}</div><div class="kpi-sub">Drops: ${esc(sum.total_ban_drops || 0)} · Total: ${esc(sum.total_auto_bans || 0)}</div></div>
        <div class="kpi-card"><div class="kpi-label">${esc(t("ep.kpi.tarpit"))}</div><div class="kpi-value">${esc(sum.active_tarpit_connections)} / ${esc(formatBytesShort(sum.tarpit_bytes_dripped))}</div><div class="kpi-sub">${evilpotData?.last_pulled_at ? esc(formatDateTime(evilpotData.last_pulled_at)) : esc(t("common.loading"))}</div></div>
      </div>

      <div class="panel" style="margin-bottom:14px;">
        <div class="panel-header"><h3>${esc(t("ep.unban.title"))}</h3></div>
        <div class="fp-search-bar" style="margin-bottom:0;">
          <label><span>Kind</span>
            <select id="ep-unban-kind">
              <option value="ip">ip</option>
              <option value="js_fp">js_fp</option>
              <option value="composite_fp">composite_fp</option>
            </select>
          </label>
          <label style="flex:1.6;"><span>Target (IP or FP Hash)</span><input id="ep-unban-target" placeholder="e.g. 203.0.113.9 or sha256 fp..." /></label>
          <label><span>Ingress Node</span>
            <select id="ep-unban-node">
              <option value="">${esc(t("ep.unban.all_nodes"))}</option>
              ${ingNodes.map(([tag]) => `<option value="${esc(tag)}">${esc(tag)}</option>`).join("")}
            </select>
          </label>
          <div class="btn-row">
            <button type="button" id="btn-ep-unban-manual" class="btn primary" ${unbanBusy ? "disabled" : ""}>${esc(t("ep.unban.btn"))}</button>
            <button type="button" id="btn-ep-unban-clear" class="btn danger" ${unbanBusy ? "disabled" : ""}>${esc(t("ep.unban.clear_all"))}</button>
          </div>
        </div>
      </div>

      ${
        activeBans.length
          ? `
      <div class="panel">
        <div class="panel-header"><h3>${esc(t("ep.bans.title"))} (${activeBans.length})</h3></div>
        <div class="table-scroll">
          <table class="table">
            <thead>
              <tr><th>Kind</th><th>Target</th><th>Reason</th><th>Level / Drops</th><th>Expires</th><th>Action</th></tr>
            </thead>
            <tbody>
              ${activeBans
                .slice(0, 100)
                .map(
                  (b) => `
                <tr>
                  <td><span class="pill ${b.kind === "ip" ? "err" : "warn"}">${esc(b.kind)}</span></td>
                  <td><code>${esc(b.target)}</code> <span class="muted">(${esc(b.node_tag || "")})</span></td>
                  <td><code>${esc(b.reason)}</code></td>
                  <td>L${esc(b.offense_level || 1)} · <b>${esc(b.hits_blocked || 0)}</b> drops</td>
                  <td style="white-space:nowrap;">${esc(formatDateTime(b.expires_at_unix || 0))}</td>
                  <td><button type="button" class="btn sm ghost" data-unban-kind="${esc(b.kind)}" data-unban-target="${esc(b.target)}" data-unban-node="${esc(b.node_tag || "")}" ${unbanBusy ? "disabled" : ""}>${esc(t("ep.unban.btn"))}</button></td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
      </div>`
          : ""
      }

      ${
        !sessions.length && !events.length && !activeBans.length
          ? `<div class="empty-state-box"><p>${esc(t("ep.empty"))}</p></div>`
          : `
      <div class="panel">
        <div class="panel-header"><h3>${esc(t("ep.sessions.title"))} (${sessions.length})</h3></div>
        <div class="table-scroll">
          <table class="table">
            <thead>
              <tr>
                <th>${esc(t("ep.col.status"))}</th>
                <th>${esc(t("ep.col.ip"))}</th>
                <th>${esc(t("ep.col.persona"))}</th>
                <th>${esc(t("ep.col.activity"))}</th>
                <th>${esc(t("ep.col.iocs"))}</th>
                <th>${esc(t("ep.col.tarpit"))}</th>
                <th>${esc(t("ep.col.evidence"))}</th>
              </tr>
            </thead>
            <tbody>
              ${
                sessions
                  .map((s) => {
                    const cmds = (s.rce_commands_executed || []).slice(-3);
                    const iocs = (s.captured_iocs || []).slice(0, 5);
                    const evs = (s.evidence || []).slice(0, 4);
                    return `
                    <tr>
                      <td>${renderEpStatusPill(s.status)}</td>
                      <td>
                        <div><code>${esc(s.client_ip)}</code></div>
                        <div class="muted" style="font-size:11px;">${esc(s.node_tag || "")} · ${esc(formatDateTime(s.last_seen_unix || 0))}</div>
                      </td>
                      <td><code>${esc(s.persona_hostname)}</code><div class="muted" style="font-size:11px;">Epoch #${esc(s.epoch_id)}</div></td>
                      <td><div>Reqs: <b>${esc(s.total_trapped_requests)}</b></div><div class="muted" style="font-size:11px;">SQLi: ${esc(s.sqli_probes)} (pos:${esc(s.sqli_distinct_positions)}) · Canary: <b>${esc(s.canary_triggers)}</b></div></td>
                      <td style="max-width:260px;word-break:break-all;">
                        ${cmds.map((c) => `<div><code>$ ${esc(c)}</code></div>`).join("")}
                        ${iocs.map((i) => `<div><span class="pill err">${esc(i)}</span></div>`).join("")}
                        ${!cmds.length && !iocs.length ? `<span class="muted">—</span>` : ""}
                      </td>
                      <td>${s.tarpit_bytes_consumed > 0 ? `${esc(formatBytesShort(s.tarpit_bytes_consumed))} <span class="muted">(${esc(s.tarpit_max_duration_ms)}ms)</span>` : `<span class="muted">—</span>`}</td>
                      <td style="max-width:280px;word-break:break-all;">${evs.length ? evs.map((e) => `<div style="font-size:11px;"><code>${esc(e)}</code></div>`).join("") : `<span class="muted">—</span>`}</td>
                    </tr>`;
                  })
                  .join("") || `<tr><td colspan="7" class="muted">—</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header"><h3>${esc(t("ep.events.title"))} (${events.length})</h3></div>
        <div class="table-scroll">
          <table class="table">
            <thead><tr><th>Time</th><th>${esc(t("ep.col.status"))}</th><th>${esc(t("ep.col.ip"))}</th><th>Trap</th><th>Detail</th></tr></thead>
            <tbody>
              ${
                events
                  .slice(0, 60)
                  .map(
                    (ev) => `
                  <tr>
                    <td style="white-space:nowrap;">${esc(formatDateTime(ev.timestamp_unix || 0))}</td>
                    <td>${renderEpStatusPill(ev.verification_status)}</td>
                    <td><code>${esc(ev.client_ip)}</code> <span class="muted">(${esc(ev.node_tag || "")})</span></td>
                    <td><code>${esc(ev.trap_kind)}</code></td>
                    <td style="max-width:420px;word-break:break-all;"><code>${esc(ev.detail)}</code></td>
                  </tr>`
                  )
                  .join("") || `<tr><td colspan="5" class="muted">—</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>`
      }
    `;

    el("btn-ep-unban-manual")?.addEventListener("click", () => {
      const kind = el("ep-unban-kind")?.value || "ip";
      const target = el("ep-unban-target")?.value.trim() || "";
      const node = el("ep-unban-node")?.value || null;
      if (!target) {
        showToast("Enter an IP or fingerprint target to unban", true);
        return;
      }
      submitUnban(kind, target, node);
    });
    el("btn-ep-unban-clear")?.addEventListener("click", () => {
      const node = el("ep-unban-node")?.value || null;
      if (!window.confirm(t("ep.unban.clear_confirm"))) return;
      submitUnban("all", "*", node);
    });
    container.querySelectorAll("[data-unban-kind]").forEach((btn) => {
      btn.addEventListener("click", () => {
        submitUnban(btn.dataset.unbanKind, btn.dataset.unbanTarget, btn.dataset.unbanNode || null);
      });
    });
  }

  function render() {
    const root = el("tab-security");
    if (!root) return;

    const bucketCnt = Object.keys(store.spec.bucket_templates || {}).length;
    const antibotCnt = Object.keys(store.spec.antibot_templates || {}).length;
    const wafCnt = Object.keys(store.spec.waf_templates || {}).length;
    const verifiedCount = evilpotData?.summary?.verified_attack_sessions || 0;
    const trackedCount = evilpotData?.summary?.tracked_sessions || 0;
    const banCount = evilpotData?.active_bans?.length || 0;

    root.innerHTML = `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${subTab === "buckets" ? "active" : ""}" data-sec-sub="buckets">
            ${esc(t("sec.tab.buckets"))} <span class="subtab-count">${bucketCnt}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "antibot" ? "active" : ""}" data-sec-sub="antibot">
            ${esc(t("sec.tab.antibot"))} <span class="subtab-count">${antibotCnt}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "waf" ? "active" : ""}" data-sec-sub="waf">
            ${esc(t("sec.tab.waf"))} <span class="subtab-count">${wafCnt}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "geoip" ? "active" : ""}" data-sec-sub="geoip">
            ${esc(t("sec.tab.geoip"))}
          </button>
          <button type="button" class="subtab-btn ${subTab === "evilpot" ? "active" : ""}" data-sec-sub="evilpot">
            ${esc(t("sec.tab.evilpot"))} ${trackedCount > 0 || banCount > 0 ? `<span class="subtab-count">${banCount > 0 ? `${banCount} bans` : `${verifiedCount}/${trackedCount}`}</span>` : ""}
          </button>
          <button type="button" class="subtab-btn ${subTab === "pages" ? "active" : ""}" data-sec-sub="pages">
            ${esc(t("sec.tab.pages"))}
          </button>
        </div>
        <div class="btn-row">
          ${subTab === "buckets" ? `<button type="button" id="btn-sec-add-bucket" class="btn sm primary">${esc(t("sec.add_bucket"))}</button>` : ""}
          ${subTab === "antibot" ? `<button type="button" id="btn-sec-add-antibot" class="btn sm primary">${esc(t("sec.add_antibot"))}</button>` : ""}
          ${
            subTab === "waf"
              ? `<button type="button" id="btn-sec-add-waf" class="btn sm primary">${esc(t("sec.add_waf"))}</button>
                 <button type="button" id="btn-sec-crs-sync" class="btn sm" ${wafSyncing ? "disabled" : ""}>${esc(wafSyncing ? t("waf.crs.syncing") : t("waf.crs.sync_now"))}</button>`
              : ""
          }
          ${subTab === "geoip" ? `<button type="button" id="btn-sec-geoip-sync" class="btn sm primary" ${geoipSyncing ? "disabled" : ""}>${esc(geoipSyncing ? t("geo.db.syncing") : t("geo.db.sync_now"))}</button>` : ""}
          ${subTab === "evilpot" ? `<button type="button" id="btn-sec-ep-pull" class="btn sm primary" ${evilpotLoading ? "disabled" : ""}>${esc(t("ep.pull_refresh"))}</button>` : ""}
          ${subTab === "pages" ? `<button type="button" id="btn-sec-reset-pages" class="btn sm">${esc(t("sec.pages.reset"))}</button>` : ""}
        </div>
      </div>
      <div id="sec-sub-body"></div>
    `;

    root.querySelectorAll("[data-sec-sub]").forEach((btn) => {
      btn.addEventListener("click", () => {
        subTab = btn.dataset.secSub;
        if (subTab === "evilpot") loadEvilpot(false);
        else if (subTab === "waf" && !wafRulesData) loadWafRules();
        else if (subTab === "geoip" && !geoipData) loadGeoIpStatus();
        render();
      });
    });

    const body = el("sec-sub-body");
    if (subTab === "buckets") renderBucketsSubTab(body);
    else if (subTab === "antibot") renderAntibotSubTab(body);
    else if (subTab === "waf") renderWafSubTab(body);
    else if (subTab === "geoip") renderGeoIpSubTab(body);
    else if (subTab === "evilpot") renderEvilpotSubTab(body);
    else renderPagesSubTab(body);
  }

  async function refresh(opts = {}) {
    if (opts.subTab) {
      if (opts.subTab === "waf-rules") subTab = "waf";
      else if (opts.subTab === "guards") subTab = "antibot";
      else subTab = opts.subTab;
    }
    if (!store.loaded) await store.loadTopology(false);
    if (subTab === "evilpot") {
      await loadEvilpot(false);
      return;
    }
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
