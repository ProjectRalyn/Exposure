// Security View — Global Guard Policies, Rate-Limit Buckets & Custom Error/PoW Pages with Live Preview
import { t } from "../i18n.js";
import {
  defaultGuardProfile,
  defaultTopologyDefaults,
  isReservedKey,
} from "../store.js";
import {
  el,
  esc,
  parseNum,
  renderTriSlider,
  showToast,
  wireTriSliders,
} from "../ui.js";

export function createSecurityView({ store }) {
  let subTab = "guards"; // guards | buckets | pages
  let previewMode = "error"; // error | challenge

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

    root.innerHTML = `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${subTab === "guards" ? "active" : ""}" data-sec-sub="guards">
            ${esc(t("sec.tab.guards"))} <span class="subtab-count">${guardKeys.length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "buckets" ? "active" : ""}" data-sec-sub="buckets">
            ${esc(t("sec.tab.buckets"))} <span class="subtab-count">${bucketKeys.length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "pages" ? "active" : ""}" data-sec-sub="pages">
            ${esc(t("sec.tab.pages"))}
          </button>
        </div>
        <div class="btn-row">
          ${subTab === "guards" ? `<button type="button" id="btn-sec-add-guard" class="btn sm primary">${esc(t("sec.add_guard"))}</button>` : ""}
          ${subTab === "buckets" ? `<button type="button" id="btn-sec-add-bucket" class="btn sm primary">${esc(t("sec.add_bucket"))}</button>` : ""}
          ${subTab === "pages" ? `<button type="button" id="btn-sec-reset-pages" class="btn sm">${esc(t("sec.pages.reset"))}</button>` : ""}
        </div>
      </div>
      <div id="sec-sub-body"></div>
    `;

    root.querySelectorAll("[data-sec-sub]").forEach((btn) => {
      btn.addEventListener("click", () => {
        subTab = btn.dataset.secSub;
        render();
      });
    });

    const body = el("sec-sub-body");
    if (subTab === "guards") renderGuardsSubTab(body, guardKeys, bucketKeys);
    else if (subTab === "buckets") renderBucketsSubTab(body, bucketKeys);
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
        return `
          <div class="subcard">
            <div class="subcard-head">
              <div style="display:flex;gap:8px;align-items:center;flex:1;flex-wrap:wrap;">
                <input class="inline-name" data-gd-rename="${esc(gName)}" value="${esc(gName)}" />
                <span class="pill ${used > 0 ? "ok" : ""}">Used: ${used}</span>
                ${isDefault ? `<span class="pill info">Default Guard</span>` : ""}
                ${isUnderAttack ? `<span class="pill err">UNDER ATTACK</span>` : ""}
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
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "block_headless", label: "Block Headless Browsers", val: g.block_headless, inherited: gDefs.block_headless })}
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "require_client_fp", label: "Require Verified JS FP", val: g.require_client_fp, inherited: gDefs.require_client_fp })}
              ${renderTriSlider({ attrName: `data-gd-tri-${gName}`, attrVal: "js_fp_beacon", label: "Passive JS FP Beacon", val: g.js_fp_beacon, inherited: gDefs.js_fp_beacon })}
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
    }
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

  async function refresh(opts = {}) {
    if (opts.subTab) subTab = opts.subTab;
    if (!store.loaded) await store.loadTopology(false);
    render();
  }

  return { refresh, render };
}
