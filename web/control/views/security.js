// Security View — Global Guard Policies, Rate-Limit Buckets, Evilpot Behavior Analysis & Custom Error/PoW Pages
import { formatDateTime } from "../charts.js";
import { t } from "../i18n.js";
import {
  defaultCrsUpdateConfig,
  defaultGuardProfile,
  defaultTopologyDefaults,
  defaultWafConfig,
  isReservedKey,
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

export function createSecurityView({ api, store }) {
  let subTab = "guards"; // guards | waf-rules | buckets | evilpot | pages
  let previewMode = "error"; // error | challenge
  let evilpotData = null;
  let evilpotLoading = false;
  let wafRulesData = null;
  let wafRulesLoading = false;
  let wafSyncing = false;
  let wafSearch = "";
  let wafSourceFilter = "all"; // all | sigil-filter | owasp-crs
  let wafPlFilter = "all"; // all | 1 | 2 | 3 | 4
  let wafStatusFilter = "all"; // all | on | off

  function countGuardUsage() {
    const counts = {};
    const defG = store.spec.defaults?.ingress?.default_guard;
    for (const svc of Object.values(store.spec.services || {})) {
      if (svc.enabled === false) continue;
      const g = svc.guard || defG;
      if (g) counts[g] = (counts[g] || 0) + 1;
    }
    for (const n of Object.values(store.spec.nodes || {})) {
      for (const r of n.ingress?.rules || []) {
        const g = r.guard || defG;
        if (g) counts[g] = (counts[g] || 0) + 1;
      }
    }
    return counts;
  }

  function render() {
    const root = el("tab-security");
    if (!root) return;

    const guardKeys = Object.keys(store.spec.guard_templates || {});
    const bucketKeys = Object.keys(store.spec.bucket_templates || {});

    const verifiedCount = evilpotData?.summary?.verified_attack_sessions || 0;
    const trackedCount = evilpotData?.summary?.tracked_sessions || 0;
    const totalWafRulesCount = wafRulesData
      ? (wafRulesData.builtin_rules?.length || 0) + (wafRulesData.crs_rules?.length || 0)
      : 0;

    root.innerHTML = `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${subTab === "guards" ? "active" : ""}" data-sec-sub="guards">
            ${esc(t("sec.tab.guards"))} <span class="subtab-count">${guardKeys.length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "waf-rules" ? "active" : ""}" data-sec-sub="waf-rules">
            ${esc(t("sec.tab.waf_rules"))} ${totalWafRulesCount > 0 ? `<span class="subtab-count">${totalWafRulesCount}</span>` : ""}
          </button>
          <button type="button" class="subtab-btn ${subTab === "buckets" ? "active" : ""}" data-sec-sub="buckets">
            ${esc(t("sec.tab.buckets"))} <span class="subtab-count">${bucketKeys.length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "evilpot" ? "active" : ""}" data-sec-sub="evilpot">
            ${esc(t("sec.tab.evilpot"))} ${trackedCount > 0 ? `<span class="subtab-count">${verifiedCount > 0 ? `${verifiedCount}/${trackedCount}` : trackedCount}</span>` : ""}
          </button>
          <button type="button" class="subtab-btn ${subTab === "pages" ? "active" : ""}" data-sec-sub="pages">
            ${esc(t("sec.tab.pages"))}
          </button>
        </div>
        <div class="btn-row">
          ${subTab === "guards" ? `<button type="button" id="btn-sec-add-guard" class="btn sm primary">${esc(t("sec.add_guard"))}</button>` : ""}
          ${subTab === "waf-rules" ? `<button type="button" id="btn-sec-crs-sync" class="btn sm primary" ${wafSyncing ? "disabled" : ""}>${esc(wafSyncing ? t("waf.crs.syncing") : t("waf.crs.sync_now"))}</button>` : ""}
          ${subTab === "buckets" ? `<button type="button" id="btn-sec-add-bucket" class="btn sm primary">${esc(t("sec.add_bucket"))}</button>` : ""}
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
        else if (subTab === "waf-rules") loadWafRules();
        render();
      });
    });

    const body = el("sec-sub-body");
    if (subTab === "guards") renderGuardsSubTab(body, guardKeys, bucketKeys);
    else if (subTab === "waf-rules") renderWafRulesSubTab(body);
    else if (subTab === "buckets") renderBucketsSubTab(body, bucketKeys);
    else if (subTab === "evilpot") renderEvilpotSubTab(body);
    else renderPagesSubTab(body);
  }

  function renderGuardsSubTab(container, guardKeys, bucketKeys) {
    const gDefs = store.spec.defaults?.guard || defaultTopologyDefaults().guard;
    const defGuardName = store.spec.defaults?.ingress?.default_guard || "";
    const usage = countGuardUsage();

    const cardsHtml = guardKeys
      .map((gName) => {
        const g = store.spec.guard_templates[gName];
        const used = usage[gName] || 0;
        const isDefault = defGuardName === gName;
        const isUnderAttack = g.antibot === "always";
        const defWaf = gDefs.waf || defaultWafConfig();
        const waf = g.waf;
        const effWafMode = waf ? waf.mode : defWaf.mode;
        const wafSelectVal = waf ? waf.mode : "inherit";
        const activeCats = waf?.categories || [];
        return `
          <div class="subcard">
            <div class="subcard-head">
              <div style="display:flex;gap:8px;align-items:center;flex:1;flex-wrap:wrap;">
                <input class="inline-name" data-gd-rename="${esc(gName)}" value="${esc(gName)}" />
                <span class="pill ${used > 0 ? "ok" : ""}">Used: ${used}</span>
                ${isDefault ? `<span class="pill info">Default Guard</span>` : ""}
                ${isUnderAttack ? `<span class="pill err">UNDER ATTACK</span>` : ""}
                ${effWafMode === "block" ? `<span class="pill err">WAF: BLOCK</span>` : effWafMode === "evilpot" ? `<span class="pill warn">WAF: EVILPOT</span>` : effWafMode === "monitor" ? `<span class="pill info">WAF: MONITOR</span>` : ""}
              </div>
              <div class="btn-row">
                <button type="button" class="btn sm ${isUnderAttack ? "danger" : ""}" data-gd-ua="${esc(gName)}" title="${esc(t("sec.under_attack"))}">⚡ ${isUnderAttack ? "Exit Attack" : "Under Attack"}</button>
                <button type="button" class="btn sm danger" data-gd-del="${esc(gName)}">${esc(t("common.remove"))}</button>
              </div>
            </div>
            <div class="inspector-row">
              <label><span>Antibot Mode</span>
                <select data-gd-mode="${esc(gName)}">
                  <option value="off" ${g.antibot === "off" ? "selected" : ""}>off</option>
                  <option value="silent" ${g.antibot === "silent" ? "selected" : ""}>silent</option>
                  <option value="challenge" ${g.antibot === "challenge" ? "selected" : ""}>challenge</option>
                  <option value="always" ${g.antibot === "always" ? "selected" : ""}>always (Under Attack)</option>
                </select>
              </label>
              <label><span>Rate-Limit Bucket</span>
                <select data-gd-bucket="${esc(gName)}">
                  <option value="">(Default: ${esc(gDefs.rate_limit_bucket || "none")})</option>
                  ${bucketKeys.map((b) => `<option value="${esc(b)}" ${g.rate_limit_bucket === b ? "selected" : ""}>${esc(b)}</option>`).join("")}
                </select>
              </label>
            </div>
            <div class="inspector-row">
              <label><span>Challenge Score</span><input type="number" min="0" max="100" data-gd-num="${esc(gName)}" data-gd-k="challenge_threshold" value="${g.challenge_threshold ?? 50}" /></label>
              <label><span>Reject Score</span><input type="number" min="0" max="100" data-gd-num="${esc(gName)}" data-gd-k="reject_threshold" value="${g.reject_threshold ?? 85}" /></label>
              <label><span>PoW Bits</span><input type="number" min="4" max="28" data-gd-num="${esc(gName)}" data-gd-k="pow_difficulty" value="${g.pow_difficulty ?? 16}" /></label>
              <label><span>Clearance TTL (s)</span><input type="number" min="10" data-gd-num="${esc(gName)}" data-gd-k="clearance_ttl_secs" value="${g.clearance_ttl_secs ?? 1800}" /></label>
            </div>
            <div class="inspector-row">
              <label><span>Allow CIDRs (CSV)</span><input data-gd-csv="${esc(gName)}" data-gd-k="allow_cidrs" value="${esc((g.allow_cidrs || []).join(", "))}" placeholder="10.0.0.0/8" /></label>
              <label><span>Deny CIDRs (CSV)</span><input data-gd-csv="${esc(gName)}" data-gd-k="deny_cidrs" value="${esc((g.deny_cidrs || []).join(", "))}" placeholder="198.51.100.0/24" /></label>
            </div>
            <label><span>API Bypass Headers (one per line: <code>X-Api-Key: secret</code>)</span>
              <textarea rows="2" data-gd-lines="${esc(gName)}" placeholder="X-Api-Key: secret">${esc((g.api_bypass_headers || []).join("\n"))}</textarea>
            </label>
            <div class="tri-stack">
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "bind_ua", label: "Bind User-Agent", val: g.bind_ua, inherited: gDefs.bind_ua })}
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "bind_ip_prefix", label: "Bind Client IP", val: g.bind_ip_prefix, inherited: gDefs.bind_ip_prefix })}
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "block_bots", label: "Block Known Bots", val: g.block_bots, inherited: gDefs.block_bots })}
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "browser_only", label: "Browser-Only Strict Mode", val: g.browser_only, inherited: gDefs.browser_only })}
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "block_headless", label: "Block Headless Browsers", val: g.block_headless, inherited: gDefs.block_headless })}
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "require_client_fp", label: "Require Verified JS FP", val: g.require_client_fp, inherited: gDefs.require_client_fp })}
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "js_fp_beacon", label: "Passive JS FP Beacon", val: g.js_fp_beacon, inherited: gDefs.js_fp_beacon })}
            </div>
            <div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border);">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px;">
                <strong style="font-size:12px;letter-spacing:.03em;">${esc(t("waf.title"))}</strong>
                <select style="width:auto;min-width:170px;" data-gd-waf-mode="${esc(gName)}">
                  <option value="inherit" ${wafSelectVal === "inherit" ? "selected" : ""}>${esc(t("waf.mode.inherit", { mode: defWaf.mode }))}</option>
                  <option value="off" ${wafSelectVal === "off" ? "selected" : ""}>${esc(t("waf.mode.off"))}</option>
                  <option value="monitor" ${wafSelectVal === "monitor" ? "selected" : ""}>${esc(t("waf.mode.monitor"))}</option>
                  <option value="block" ${wafSelectVal === "block" ? "selected" : ""}>${esc(t("waf.mode.block"))}</option>
                  <option value="evilpot" ${wafSelectVal === "evilpot" ? "selected" : ""}>${esc(t("waf.mode.evilpot"))}</option>
                </select>
              </div>
              ${
                waf && waf.mode !== "off"
                  ? `
                <div class="inspector-row">
                  <label><span>${esc(t("waf.min_conf"))}</span><input type="number" step="0.05" min="0.1" max="1" data-gd-waf-conf="${esc(gName)}" value="${waf.min_confidence ?? 0.65}" /></label>
                  <label><span>${esc(t("waf.max_body_kb"))}</span><input type="number" min="0" max="256" data-gd-waf-bodykb="${esc(gName)}" value="${Math.round((waf.max_body_bytes ?? 32768) / 1024)}" /></label>
                  <label><span>${esc(t("waf.crs.paranoia"))}</span>
                    <select data-gd-waf-pl="${esc(gName)}">
                      ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${(waf.crs_paranoia_level || 1) === pl ? "selected" : ""}>PL${pl}</option>`).join("")}
                    </select>
                  </label>
                </div>
                <div class="tri-stack" style="margin-top:6px;">
                  ${renderBinSlider({ attrName: `data-gd-waf-bin-${gName}`, attrVal: "inspect_headers", label: t("waf.inspect_headers"), val: waf.inspect_headers !== false })}
                  ${renderBinSlider({ attrName: `data-gd-waf-bin-${gName}`, attrVal: "inspect_body", label: t("waf.inspect_body"), val: waf.inspect_body !== false })}
                  ${renderBinSlider({ attrName: `data-gd-waf-bin-${gName}`, attrVal: "crs_enabled", label: t("waf.crs.enabled"), val: waf.crs_enabled !== false })}
                </div>
                <label style="margin-top:6px;"><span>${esc(t("waf.exempt_paths"))}</span>
                  <input data-gd-waf-exempt="${esc(gName)}" value="${esc((waf.exempt_paths || []).join(", "))}" placeholder="/api/webhooks/, /cms/" />
                </label>
                <div style="margin-top:6px;">
                  <div class="muted" style="font-size:11px;margin-bottom:5px;">${esc(activeCats.length ? t("waf.categories") : t("waf.categories.all"))}</div>
                  <div style="display:flex;flex-wrap:wrap;gap:4px;">
                    <button type="button" class="btn sm ${activeCats.length === 0 ? "primary" : "ghost"}" data-gd-waf-cat-all="${esc(gName)}">${esc(t("common.all"))}</button>
                    ${WAF_CATEGORIES.map((c) => {
                      const on = activeCats.includes(c);
                      return `<button type="button" class="btn sm ${on ? "primary" : "ghost"}" data-gd-waf-cat="${esc(gName)}" data-waf-c="${esc(c)}">${esc(t(`waf.cat.${c}`))}</button>`;
                    }).join("")}
                  </div>
                </div>`
                  : ""
              }
            </div>
          </div>`;
      })
      .join("");

    container.innerHTML = cardsHtml
      ? `<div class="tpl-card-grid">${cardsHtml}</div>`
      : `<div class="empty-state-box"><p>No global Guard policies yet. Create reusable policies like "standard" or "under-attack" and assign them to any Service.</p></div>`;

    el("btn-sec-add-guard")?.addEventListener("click", () => {
      store.mutate((s) => {
        let name = "standard", k = 1;
        while (s.guard_templates[name]) name = `guard-${k++}`;
        s.guard_templates[name] = defaultGuardProfile(gDefs);
      });
      render();
    });

    container.querySelectorAll("[data-gd-ua]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const gName = btn.dataset.gdUa;
        store.mutate((s) => {
          const g = s.guard_templates[gName];
          g.antibot = g.antibot === "always" ? "challenge" : "always";
        });
        render();
      });
    });

    container.querySelectorAll("[data-gd-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const gName = btn.dataset.gdDel;
        store.mutate((s) => {
          delete s.guard_templates[gName];
          if (s.defaults.ingress.default_guard === gName) s.defaults.ingress.default_guard = null;
          for (const svc of Object.values(s.services || {})) if (svc.guard === gName) svc.guard = null;
        });
        render();
      });
    });

    container.querySelectorAll("[data-gd-rename]").forEach((inp) => {
      inp.addEventListener("change", () => {
        const oldN = inp.dataset.gdRename, newN = inp.value.trim();
        if (!newN || newN === oldN || isReservedKey(newN) || store.spec.guard_templates[newN]) {
          inp.value = oldN;
          return;
        }
        store.mutate((s) => {
          s.guard_templates[newN] = s.guard_templates[oldN];
          delete s.guard_templates[oldN];
          if (s.defaults.ingress.default_guard === oldN) s.defaults.ingress.default_guard = newN;
          for (const svc of Object.values(s.services || {})) if (svc.guard === oldN) svc.guard = newN;
          for (const n of Object.values(s.nodes || {})) {
            for (const r of n.ingress?.rules || []) if (r.guard === oldN) r.guard = newN;
          }
        });
        render();
      });
    });

    container.querySelectorAll("[data-gd-mode]").forEach((sel) => {
      sel.addEventListener("change", () => {
        store.mutate((s) => { s.guard_templates[sel.dataset.gdMode].antibot = sel.value; });
        render();
      });
    });
    container.querySelectorAll("[data-gd-bucket]").forEach((sel) => {
      sel.addEventListener("change", () => {
        store.mutate((s) => { s.guard_templates[sel.dataset.gdBucket].rate_limit_bucket = sel.value || null; }, false);
      });
    });
    container.querySelectorAll("[data-gd-num]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          s.guard_templates[inp.dataset.gdNum][inp.dataset.gdK] = parseNum(inp.value, 0, 0);
        }, false);
      });
    });
    container.querySelectorAll("[data-gd-csv]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          s.guard_templates[inp.dataset.gdCsv][inp.dataset.gdK] = inp.value.split(",").map((x) => x.trim()).filter(Boolean);
        }, false);
      });
    });
    container.querySelectorAll("[data-gd-lines]").forEach((ta) => {
      ta.addEventListener("input", () => {
        store.mutate((s) => {
          s.guard_templates[ta.dataset.gdLines].api_bypass_headers = ta.value.split("\n").map((x) => x.trim()).filter(Boolean);
        }, false);
      });
    });
    for (const gName of guardKeys) {
      wireTriSliders(container, `data-gd-tri-${gName}`, (field, val) => {
        store.mutate((s) => { s.guard_templates[gName][field] = val; }, false);
      });
      wireBinSliders(container, `data-gd-waf-bin-${gName}`, (field, val) => {
        store.mutate((s) => {
          const g = s.guard_templates[gName];
          if (!g.waf) g.waf = defaultWafConfig();
          g.waf[field] = val;
        }, false);
      });
    }

    container.querySelectorAll("[data-gd-waf-mode]").forEach((sel) => {
      sel.addEventListener("change", () => {
        const gName = sel.dataset.gdWafMode;
        const val = sel.value;
        store.mutate((s) => {
          const g = s.guard_templates[gName];
          if (val === "inherit") {
            g.waf = null;
          } else {
            if (!g.waf) g.waf = { ...(s.defaults?.guard?.waf || defaultWafConfig()) };
            g.waf.mode = val;
          }
        });
        render();
      });
    });

    container.querySelectorAll("[data-gd-waf-conf]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const gName = inp.dataset.gdWafConf;
        store.mutate((s) => {
          const g = s.guard_templates[gName];
          if (!g.waf) g.waf = defaultWafConfig();
          g.waf.min_confidence = parseNum(inp.value, 0.65, 0.1, 1.0);
        }, false);
      });
    });

    container.querySelectorAll("[data-gd-waf-bodykb]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const gName = inp.dataset.gdWafBodykb;
        store.mutate((s) => {
          const g = s.guard_templates[gName];
          if (!g.waf) g.waf = defaultWafConfig();
          g.waf.max_body_bytes = parseNum(inp.value, 32, 0, 256) * 1024;
        }, false);
      });
    });

    container.querySelectorAll("[data-gd-waf-pl]").forEach((sel) => {
      sel.addEventListener("change", () => {
        const gName = sel.dataset.gdWafPl;
        store.mutate((s) => {
          const g = s.guard_templates[gName];
          if (!g.waf) g.waf = defaultWafConfig();
          g.waf.crs_paranoia_level = parseNum(sel.value, 1, 1, 4);
        }, false);
      });
    });

    container.querySelectorAll("[data-gd-waf-exempt]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const gName = inp.dataset.gdWafExempt;
        store.mutate((s) => {
          const g = s.guard_templates[gName];
          if (!g.waf) g.waf = defaultWafConfig();
          g.waf.exempt_paths = inp.value.split(",").map((x) => x.trim()).filter(Boolean);
        }, false);
      });
    });

    container.querySelectorAll("[data-gd-waf-cat-all]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const gName = btn.dataset.gdWafCatAll;
        store.mutate((s) => {
          const g = s.guard_templates[gName];
          if (!g.waf) g.waf = defaultWafConfig();
          g.waf.categories = [];
        });
        render();
      });
    });

    container.querySelectorAll("[data-gd-waf-cat]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const gName = btn.dataset.gdWafCat;
        const cat = btn.dataset.wafC;
        store.mutate((s) => {
          const g = s.guard_templates[gName];
          if (!g.waf) g.waf = defaultWafConfig();
          const list = Array.isArray(g.waf.categories) ? [...g.waf.categories] : [];
          const idx = list.indexOf(cat);
          if (idx >= 0) list.splice(idx, 1);
          else list.push(cat);
          g.waf.categories = list;
        });
        render();
      });
    });
  }

  function renderBucketsSubTab(container, bucketKeys) {
    const cardsHtml = bucketKeys
      .map((bName) => {
        const b = store.spec.bucket_templates[bName];
        return `
          <div class="subcard">
            <div class="subcard-head">
              <input class="inline-name" data-bk-rename="${esc(bName)}" value="${esc(bName)}" />
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

    container.innerHTML = cardsHtml
      ? `<div class="tpl-card-grid">${cardsHtml}</div>`
      : `<div class="empty-state-box"><p>No rate-limit buckets yet. Create a bucket (e.g., 60 burst / 10 rps) to bind to Guard policies.</p></div>`;

    el("btn-sec-add-bucket")?.addEventListener("click", () => {
      store.mutate((s) => {
        let name = "web-default", k = 1;
        while (s.bucket_templates[name]) name = `bucket-${k++}`;
        s.bucket_templates[name] = { capacity: 120, refill_per_sec: 20, per_ip: null };
      });
      render();
    });

    container.querySelectorAll("[data-bk-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const bName = btn.dataset.bkDel;
        store.mutate((s) => {
          delete s.bucket_templates[bName];
          if (s.defaults.guard.rate_limit_bucket === bName) s.defaults.guard.rate_limit_bucket = null;
          for (const g of Object.values(s.guard_templates || {})) {
            if (g.rate_limit_bucket === bName) g.rate_limit_bucket = null;
          }
        });
        render();
      });
    });

    container.querySelectorAll("[data-bk-rename]").forEach((inp) => {
      inp.addEventListener("change", () => {
        const oldN = inp.dataset.bkRename, newN = inp.value.trim();
        if (!newN || newN === oldN || isReservedKey(newN) || store.spec.bucket_templates[newN]) {
          inp.value = oldN;
          return;
        }
        store.mutate((s) => {
          s.bucket_templates[newN] = s.bucket_templates[oldN];
          delete s.bucket_templates[oldN];
          if (s.defaults.guard.rate_limit_bucket === oldN) s.defaults.guard.rate_limit_bucket = newN;
          for (const g of Object.values(s.guard_templates || {})) {
            if (g.rate_limit_bucket === oldN) g.rate_limit_bucket = newN;
          }
        });
        render();
      });
    });
    container.querySelectorAll("[data-bk-cap]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => { s.bucket_templates[inp.dataset.bkCap].capacity = parseNum(inp.value, 60, 1); }, false);
      });
    });
    container.querySelectorAll("[data-bk-refill]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => { s.bucket_templates[inp.dataset.bkRefill].refill_per_sec = parseNum(inp.value, 10, 0.1); }, false);
      });
    });
    for (const bName of bucketKeys) {
      wireTriSliders(container, `data-bk-tri-${bName}`, (field, val) => {
        store.mutate((s) => { s.bucket_templates[bName][field] = val; }, false);
      });
    }
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
    const css = pages.challenge_css || "body{margin:0;min-height:100vh;display:grid;place-items:center;background:#020617;color:#e2e8f0;font-family:system-ui,sans-serif}.box{padding:24px;border:1px solid #1e293b;border-radius:10px;background:#0f172a;width:360px}";
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
    if (status === "verified_exploit") {
      return `<span class="pill err">${esc(t("ep.status.verified"))}</span>`;
    }
    if (status === "multi_step_exploitation") {
      return `<span class="pill warn">${esc(t("ep.status.multistep"))}</span>`;
    }
    return `<span class="pill info">${esc(t("ep.status.probing"))}</span>`;
  }

  async function loadEvilpot(triggerPull = false) {
    if (!api) return;
    evilpotLoading = true;
    if (subTab === "evilpot") render();
    try {
      if (triggerPull) {
        await api("/api/telemetry/pull", { method: "POST" });
      }
      evilpotData = await api("/api/evilpot");
    } catch (e) {
      showToast(e.message, true);
    } finally {
      evilpotLoading = false;
      if (subTab === "evilpot") render();
    }
  }

  function renderEvilpotSubTab(container) {
    el("btn-sec-ep-pull")?.addEventListener("click", () => loadEvilpot(true));

    if (!evilpotData && !evilpotLoading) {
      loadEvilpot(false);
    }

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

    container.innerHTML = `
      <div class="kpi-grid" style="margin-bottom:14px;">
        <div class="kpi-card">
          <div class="kpi-label">${esc(t("ep.kpi.trapped"))}</div>
          <div class="kpi-value">${esc(sum.traps_triggered)}</div>
          <div class="kpi-sub">${esc(t("ep.kpi.nodes"))}: ${esc(sum.active_nodes)}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">${esc(t("ep.kpi.verified"))}</div>
          <div class="kpi-value" style="color:var(--err);">${esc(sum.verified_attack_sessions)}</div>
          <div class="kpi-sub">Tracked: ${esc(sum.tracked_sessions)}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">${esc(t("ep.kpi.canaries"))}</div>
          <div class="kpi-value" style="color:var(--warn);">${esc(sum.canary_verifications)}</div>
          <div class="kpi-sub">Canary replay hits</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">${esc(t("ep.kpi.autoban"))}</div>
          <div class="kpi-value" style="color:var(--err);">${esc(sum.active_ip_bans || 0)} / ${esc(sum.active_fp_bans || 0)}</div>
          <div class="kpi-sub">Drops: ${esc(sum.total_ban_drops || 0)} · Total: ${esc(sum.total_auto_bans || 0)}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">${esc(t("ep.kpi.tarpit"))}</div>
          <div class="kpi-value">${esc(sum.active_tarpit_connections)} / ${esc(formatBytesShort(sum.tarpit_bytes_dripped))}</div>
          <div class="kpi-sub">${evilpotData?.last_pulled_at ? esc(formatDateTime(evilpotData.last_pulled_at)) : esc(t("common.loading"))}</div>
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
              <tr>
                <th>Kind</th>
                <th>Target</th>
                <th>Reason</th>
                <th>Level / Drops</th>
                <th>Expires</th>
              </tr>
            </thead>
            <tbody>
              ${activeBans
                .slice(0, 60)
                .map(
                  (b) => `
                <tr>
                  <td><span class="pill ${b.kind === "ip" ? "err" : "warn"}">${esc(b.kind)}</span></td>
                  <td><code>${esc(b.target)}</code> <span class="muted">(${esc(b.node_tag || "")})</span></td>
                  <td><code>${esc(b.reason)}</code></td>
                  <td>L${esc(b.offense_level || 1)} · <b>${esc(b.hits_blocked || 0)}</b> drops</td>
                  <td style="white-space:nowrap;">${esc(formatDateTime(b.expires_at_unix || 0))}</td>
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
                      <td>
                        <code>${esc(s.persona_hostname)}</code>
                        <div class="muted" style="font-size:11px;">Epoch #${esc(s.epoch_id)}</div>
                      </td>
                      <td>
                        <div>Reqs: <b>${esc(s.total_trapped_requests)}</b></div>
                        <div class="muted" style="font-size:11px;">SQLi: ${esc(s.sqli_probes)} (pos:${esc(s.sqli_distinct_positions)}) · Canary: <b>${esc(s.canary_triggers)}</b></div>
                      </td>
                      <td style="max-width:260px;word-break:break-all;">
                        ${cmds.map((c) => `<div><code>$ ${esc(c)}</code></div>`).join("")}
                        ${iocs.map((i) => `<div><span class="pill err">${esc(i)}</span></div>`).join("")}
                        ${!cmds.length && !iocs.length ? `<span class="muted">—</span>` : ""}
                      </td>
                      <td>
                        ${s.tarpit_bytes_consumed > 0 ? `${esc(formatBytesShort(s.tarpit_bytes_consumed))} <span class="muted">(${esc(s.tarpit_max_duration_ms)}ms)</span>` : `<span class="muted">—</span>`}
                      </td>
                      <td style="max-width:280px;word-break:break-all;">
                        ${evs.length ? evs.map((e) => `<div style="font-size:11px;"><code>${esc(e)}</code></div>`).join("") : `<span class="muted">—</span>`}
                      </td>
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
            <thead>
              <tr>
                <th>Time</th>
                <th>${esc(t("ep.col.status"))}</th>
                <th>${esc(t("ep.col.ip"))}</th>
                <th>Trap</th>
                <th>Detail</th>
              </tr>
            </thead>
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
      if (subTab === "waf-rules") render();
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
      if (subTab === "waf-rules") render();
    }
  }

  function renderWafRulesSubTab(container) {
    el("btn-sec-crs-sync")?.addEventListener("click", triggerCrsSync);

    const ensureCrs = (s) => {
      if (!s.defaults) s.defaults = defaultTopologyDefaults();
      if (!s.defaults.ingress) s.defaults.ingress = defaultTopologyDefaults().ingress;
      if (!s.defaults.ingress.crs) s.defaults.ingress.crs = defaultCrsUpdateConfig();
      return s.defaults.ingress.crs;
    };
    const crsCfg = store.spec.defaults?.ingress?.crs || defaultCrsUpdateConfig();
    const disabledSet = new Set((crsCfg.disabled_rule_ids || []).map(Number));
    const meta = wafRulesData?.crs_meta || {};
    const allRules = [
      ...(wafRulesData?.builtin_rules || []),
      ...(wafRulesData?.crs_rules || []),
    ];

    const q = wafSearch.trim().toLowerCase();
    const filtered = allRules.filter((r) => {
      if (wafSourceFilter !== "all" && r.source !== wafSourceFilter) return false;
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

    container.innerHTML = `
      <div class="kpi-grid" style="margin-bottom:14px;">
        <div class="kpi">
          <div class="kpi-label">${esc(t("waf.crs.version"))}</div>
          <div class="kpi-val" style="font-size:18px;">${esc(meta.version || (wafRulesLoading ? "…" : "builtin"))}</div>
          <div class="kpi-sub"><a href="https://coreruleset.org/" target="_blank" rel="noopener noreferrer" style="color:var(--accent);">coreruleset.org</a></div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("waf.crs.active_count"))}</div>
          <div class="kpi-val">${allRules.length - disabledSet.size} / ${allRules.length}</div>
          <div class="kpi-sub">${(wafRulesData?.builtin_rules || []).length} Sigil · ${(wafRulesData?.crs_rules || []).length} CRS</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("waf.crs.skipped_pcre"))}</div>
          <div class="kpi-val">${meta.skipped_pcre ?? 0}</div>
          <div class="kpi-sub">Linear-time ReDoS-safe Rust regex</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">${esc(t("waf.crs.updated"))}</div>
          <div class="kpi-val" style="font-size:15px;">${esc(meta.updated_at ? formatDateTime(meta.updated_at) : "—")}</div>
          <div class="kpi-sub">${disabledSet.size} disabled</div>
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
          <label><span>${esc(t("waf.crs.col_source"))}</span>
            <select id="waf-rule-src">
              <option value="all" ${wafSourceFilter === "all" ? "selected" : ""}>${esc(t("waf.crs.src_all"))}</option>
              <option value="sigil-filter" ${wafSourceFilter === "sigil-filter" ? "selected" : ""}>${esc(t("waf.crs.src_sigil"))}</option>
              <option value="owasp-crs" ${wafSourceFilter === "owasp-crs" ? "selected" : ""}>${esc(t("waf.crs.src_crs"))}</option>
            </select>
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

        <div class="table-scroll" style="max-height:540px;">
          <table class="table">
            <thead>
              <tr>
                <th>${esc(t("waf.crs.col_id"))}</th>
                <th>${esc(t("waf.crs.col_source"))}</th>
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
                    const srcPill = r.source === "sigil-filter"
                      ? `<span class="pill info">sigil-filter</span>`
                      : `<span class="pill ok">OWASP CRS</span>`;
                    return `
                  <tr class="fp-table-row" data-waf-rule-idx="${idx}" style="${isEnabled ? "" : "opacity:0.55;"}">
                    <td><code>${esc(r.id)}</code></td>
                    <td>${srcPill}</td>
                    <td><span class="pill">PL${Number(r.paranoia_level) || 1}</span></td>
                    <td><code>${esc(r.category || "-")}</code></td>
                    <td>${sevPill(r.severity)}</td>
                    <td style="max-width:420px;">
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
                  .join("") || `<tr><td colspan="7" class="muted">${wafRulesLoading ? "Loading…" : "No WAF rules match filter."}</td></tr>`
              }
            </tbody>
          </table>
        </div>
        ${filtered.length > 300 ? `<div class="muted-sm" style="margin-top:6px;">Showing first 300 of ${filtered.length} matching rules — refine search to inspect others.</div>` : ""}
      </div>
    `;

    wireBinSliders(container, "data-crs-bin", (f, v) => {
      store.mutate((s) => { ensureCrs(s)[f] = v; }, false);
    });
    el("crs-interval-h")?.addEventListener("input", (ev) => {
      store.mutate((s) => { ensureCrs(s).update_interval_hours = parseNum(ev.target.value, 24, 1, 720); }, false);
    });
    el("crs-default-pl")?.addEventListener("change", (ev) => {
      store.mutate((s) => { ensureCrs(s).paranoia_level = parseNum(ev.target.value, 1, 1, 4); }, false);
    });
    el("waf-rule-search")?.addEventListener("input", (ev) => { wafSearch = ev.target.value; render(); });
    el("waf-rule-src")?.addEventListener("change", (ev) => { wafSourceFilter = ev.target.value; render(); });
    el("waf-rule-pl")?.addEventListener("change", (ev) => { wafPlFilter = ev.target.value; render(); });
    el("waf-rule-status")?.addEventListener("change", (ev) => { wafStatusFilter = ev.target.value; render(); });

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
          title: `WAF Rule #${r.id} — ${r.source}`,
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

  async function refresh(opts = {}) {
    if (opts.subTab) subTab = opts.subTab;
    if (!store.loaded) await store.loadTopology(false);
    if (subTab === "evilpot") {
      await loadEvilpot(false);
      return;
    }
    if (subTab === "waf-rules") {
      await loadWafRules();
      return;
    }
    render();
  }

  return { refresh, render };
}
