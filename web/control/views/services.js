// Services View — Service-Centric Declarative Exposure (Define Once -> Auto-Compile Across All Ingress/Relay/Egress)
import { t } from "../i18n.js";
import {
  certCoversHost,
  defaultServiceSpec,
  defaultTopologyDefaults,
  isReservedKey,
  resolveDomainBindingJS,
  resolveServiceTargetIngresses,
  shortestPathBFS,
} from "../store.js";
import {
  closeDrawer,
  el,
  esc,
  openDrawer,
  parseNum,
  renderBinSlider,
  renderTriSlider,
  showToast,
  wireBinSliders,
  wireTriSliders,
} from "../ui.js";

export function createServicesView({ store, navigate }) {
  let subTab = "catalog"; // catalog | matrix | legacy
  let searchQ = "";

  function countLegacyRules() {
    const egressTags = new Set();
    for (const node of Object.values(store.spec.nodes || {})) {
      if (!node.roles?.egress) continue;
      for (const sTag of Object.keys(node.egress?.services || {})) {
        egressTags.add(sTag);
      }
    }
    const existingServices = store.spec.services || {};
    let n = 0;
    for (const node of Object.values(store.spec.nodes || {})) {
      if (!node.roles?.ingress) continue;
      for (const rule of node.ingress?.rules || []) {
        const sTag = rule.service_tag;
        if (!sTag) continue;
        if (!existingServices[sTag] && egressTags.has(sTag)) {
          n++;
        }
      }
    }
    return n;
  }

  function findCertCoverage(host) {
    for (const tpl of Object.values(store.spec.maintainer_templates || {})) {
      if (!tpl?.is_primary_cert_manager) continue;
      for (const ord of tpl.acme?.orders || []) {
        if (certCoversHost(ord.domain, host)) return ord.domain;
      }
    }
    return null;
  }

  function computeServicePaths(svc) {
    const ingresses = resolveServiceTargetIngresses(store.spec, svc);
    const eg = svc.egress?.node || "";
    return ingresses.map((ig) => {
      if (!eg) return { ingress: ig, hops: null, mode: "invalid" };
      if (ig === eg) return { ingress: ig, hops: [ig], mode: "local" };
      if (svc.routing?.mode === "pinned" && svc.routing?.pinned_paths?.[ig]?.length) {
        return { ingress: ig, hops: svc.routing.pinned_paths[ig], mode: "pinned" };
      }
      const hops = shortestPathBFS(store.spec.links, ig, eg, {
        nodes: store.spec.nodes,
        requireRelay: true,
      });
      return { ingress: ig, hops, mode: "auto" };
    });
  }

  function migrateLegacyRules() {
    let migrated = 0;
    store.mutate((s) => {
      // Index egress services: service_tag -> { node, cfg }
      const egressIndex = new Map();
      for (const [nTag, n] of Object.entries(s.nodes || {})) {
        if (!n.roles?.egress) continue;
        for (const [sTag, eCfg] of Object.entries(n.egress?.services || {})) {
          if (!egressIndex.has(sTag)) egressIndex.set(sTag, { node: nTag, cfg: eCfg });
        }
      }

      // Group legacy ingress rules by service_tag
      const grouped = new Map();
      const allIngressTags = Object.entries(s.nodes || {})
        .filter(([, n]) => n.roles?.ingress)
        .map(([k]) => k)
        .sort();

      for (const [igTag, n] of Object.entries(s.nodes || {})) {
        if (!n.roles?.ingress) continue;
        for (const rule of n.ingress?.rules || []) {
          if (!rule.service_tag) continue;
          if (!grouped.has(rule.service_tag)) {
            grouped.set(rule.service_tag, {
              hosts: new Set(),
              ingresses: new Set(),
              url_prefix: rule.match?.url_prefix || null,
              sni: rule.match?.sni || null,
              source_cidrs: rule.match?.source_cidrs || [],
              guard: rule.guard || null,
              intercept_errors: rule.intercept_errors ?? null,
              js_fp_beacon: rule.js_fp_beacon ?? null,
            });
          }
          const g = grouped.get(rule.service_tag);
          if (rule.match?.host) g.hosts.add(rule.match.host);
          g.ingresses.add(igTag);
        }
      }

      const migratedTags = new Set();
      for (const [sTag, g] of grouped.entries()) {
        if (s.services[sTag]) continue;
        const eg = egressIndex.get(sTag);
        if (!eg) continue;
        const ingList = [...g.ingresses].sort();
        const coversAll =
          allIngressTags.length > 0 &&
          allIngressTags.every((t) => g.ingresses.has(t));
        s.services[sTag] = {
          hosts: [...g.hosts],
          url_prefix: g.url_prefix,
          sni: g.sni,
          source_cidrs: g.source_cidrs,
          ingress: {
            mode: coversAll ? "all" : "selected",
            nodes: coversAll ? [] : ingList,
            overrides: {},
          },
          guard: g.guard,
          intercept_errors: g.intercept_errors,
          js_fp_beacon: g.js_fp_beacon,
          egress: {
            node: eg.node,
            backend: eg.cfg.backend || "",
            protocol: eg.cfg.protocol || "auto",
            tls: eg.cfg.tls ?? null,
            ca_cert_path: eg.cfg.ca_cert_path || null,
            insecure_skip_verify: eg.cfg.insecure_skip_verify ?? null,
            timeout_ms: eg.cfg.timeout_ms ?? 0,
            intercept_errors: eg.cfg.intercept_errors ?? null,
            local_health_check: eg.cfg.local_health_check || null,
          },
          routing: { mode: "auto", pinned_paths: {} },
          auto_tls: false,
          enabled: true,
        };
        migratedTags.add(sTag);
        migrated++;
      }

      // Remove migrated rules from per-node ingress/relay/egress so there are no duplicates
      for (const n of Object.values(s.nodes || {})) {
        if (n.ingress?.rules) {
          n.ingress.rules = n.ingress.rules.filter((r) => !migratedTags.has(r.service_tag));
        }
        if (n.relay?.rules) {
          n.relay.rules = n.relay.rules.filter((r) => !migratedTags.has(r.service_tag));
        }
        if (n.egress?.services) {
          for (const tag of migratedTags) delete n.egress.services[tag];
        }
      }
    });
    showToast(migrated ? `Migrated ${migrated} legacy rule group(s) into Services` : "No migratable legacy rules found");
    render();
  }

  function render() {
    const root = el("tab-services");
    if (!root) return;

    const svcEntries = Object.entries(store.spec.services || {});
    const legacyCount = countLegacyRules();
    const compiledCount = (store.compiledPaths || []).length;

    root.innerHTML = `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${subTab === "catalog" ? "active" : ""}" data-svc-sub="catalog">
            ${esc(t("svc.tab.catalog"))} <span class="subtab-count">${svcEntries.length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "matrix" ? "active" : ""}" data-svc-sub="matrix">
            ${esc(t("svc.tab.matrix"))} <span class="subtab-count">${compiledCount}</span>
          </button>
          ${
            legacyCount > 0 || subTab === "legacy"
              ? `<button type="button" class="subtab-btn ${subTab === "legacy" ? "active" : ""}" data-svc-sub="legacy">
                  ${esc(t("svc.tab.legacy"))} <span class="subtab-count">${legacyCount}</span>
                </button>`
              : ""
          }
        </div>
        <div class="btn-row">
          <button type="button" id="btn-svc-new" class="btn sm primary">${esc(t("svc.add"))}</button>
        </div>
      </div>

      ${
        legacyCount > 0 && subTab === "catalog"
          ? `<div class="callout-banner warn">
              <div>
                <strong>${esc(t("svc.migrate_banner", { count: legacyCount }))}</strong>
              </div>
              <button type="button" id="btn-svc-migrate" class="btn sm primary">${esc(t("svc.migrate_btn"))}</button>
            </div>`
          : ""
      }

      <div id="svc-sub-body"></div>
    `;

    root.querySelectorAll("[data-svc-sub]").forEach((btn) => {
      btn.addEventListener("click", () => {
        subTab = btn.dataset.svcSub;
        render();
      });
    });
    el("btn-svc-new")?.addEventListener("click", () => openServiceDrawer(null));
    el("btn-svc-migrate")?.addEventListener("click", migrateLegacyRules);

    const body = el("svc-sub-body");
    if (subTab === "catalog") renderCatalog(body, svcEntries);
    else if (subTab === "matrix") renderMatrix(body);
    else renderLegacy(body);
  }

  function renderCatalog(container, svcEntries) {
    const filtered = svcEntries.filter(([name, svc]) => {
      if (!searchQ) return true;
      const hay = `${name} ${(svc.hosts || []).join(" ")} ${svc.egress?.node || ""} ${svc.egress?.backend || ""}`.toLowerCase();
      return hay.includes(searchQ.toLowerCase());
    });
    const igDefs = store.spec.defaults?.ingress || defaultTopologyDefaults().ingress;

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h3>${esc(t("svc.tab.catalog"))} (${filtered.length})</h3>
          <input id="svc-search-inp" class="input-sm" type="search" value="${esc(searchQ)}" placeholder="${esc(t("svc.search"))}" style="min-width:260px;" />
        </div>
        ${
          filtered.length
            ? `<div class="table-scroll">
                <table class="table">
                  <thead>
                    <tr>
                      <th>${esc(t("svc.col.service"))}</th>
                      <th>${esc(t("svc.col.ingress"))}</th>
                      <th>${esc(t("svc.col.route"))}</th>
                      <th>${esc(t("svc.col.security"))}</th>
                      <th>${esc(t("common.actions"))}</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${filtered
                      .map(([name, svc]) => {
                        const targetIngs = resolveServiceTargetIngresses(store.spec, svc);
                        const paths = computeServicePaths(svc);
                        const allReachable = paths.length > 0 && paths.every((p) => p.hops);
                        const scopeLbl =
                          svc.ingress?.mode === "selected"
                            ? t("svc.scope.selected", { count: targetIngs.length })
                            : svc.ingress?.mode === "exclude"
                            ? t("svc.scope.exclude", { count: (svc.ingress?.nodes || []).length })
                            : t("svc.scope.all", { count: targetIngs.length });
                        const effBucket = svc.bucket || igDefs.default_bucket || "";
                        const effAntibot = svc.antibot || igDefs.default_antibot || "";
                        const effWaf = svc.waf || igDefs.default_waf || "";
                        const effGuard = svc.guard || igDefs.default_guard || "";
                        const hostPills = (svc.hosts || [])
                          .map((h) => {
                            const cov = findCertCoverage(h);
                            const dns = resolveDomainBindingJS(store.spec.domains, h);
                            return `<span class="host-pill">${esc(h)}${cov ? " 🔒" : ""}${dns ? " 🌐" : ""}</span>`;
                          })
                          .join(" ");
                        const samplePath = paths[0]?.hops
                          ? `<div class="hop-chain">${paths[0].hops.map((h) => `<span class="hop-node">${esc(h)}</span>`).join('<span class="hop-arrow">→</span>')}</div>`
                          : `<span class="pill err">${esc(t("svc.route_unreachable"))}</span>`;

                        return `
                      <tr style="${svc.enabled === false ? "opacity:0.55;" : ""}">
                        <td>
                          <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
                            <span class="live-dot ${svc.enabled === false ? "draft" : allReachable ? "online" : "offline"}"></span>
                            <strong>${esc(name)}</strong>
                            ${svc.url_prefix ? `<code>${esc(svc.url_prefix)}</code>` : ""}
                            ${svc.enabled === false ? `<span class="pill">${esc(t("common.disabled"))}</span>` : ""}
                          </div>
                          <div class="tag-list">${hostPills || '<span class="muted-sm">-</span>'}</div>
                        </td>
                        <td>
                          <div><span class="pill ${targetIngs.length ? "ok" : "warn"}">${esc(scopeLbl)}</span></div>
                          <div class="muted-sm" style="margin-top:4px;">${esc(targetIngs.join(", ") || "-")}</div>
                        </td>
                        <td>
                          <div>${samplePath}${paths.length > 1 ? ` <span class="muted-sm">+${paths.length - 1}</span>` : ""}</div>
                          <div class="muted-sm" style="margin-top:4px;"><code>${esc(svc.egress?.node || "?")}</code> → <code>${esc(svc.egress?.backend || "-")}</code></div>
                        </td>
                        <td>
                          <div class="tag-list">
                            ${effBucket ? `<span class="pill">B: ${esc(effBucket)}</span>` : ""}
                            ${effAntibot ? `<span class="pill info">A: ${esc(effAntibot)}</span>` : ""}
                            ${effWaf ? `<span class="pill warn">W: ${esc(effWaf)}</span>` : ""}
                            ${!effBucket && !effAntibot && !effWaf && !effGuard ? `<span class="pill">${esc(t("common.none"))}</span>` : ""}
                            ${effGuard ? `<span class="pill warn">guard: ${esc(effGuard)}</span>` : ""}
                            ${svc.auto_tls ? `<span class="pill ok">Auto-TLS</span>` : ""}
                            ${(svc.cache?.enabled ?? igDefs.cache?.enabled) ? `<span class="pill info">Cache</span>` : ""}
                          </div>
                        </td>
                        <td>
                          <div class="btn-row">
                            <button type="button" class="btn sm primary" data-edit-svc="${esc(name)}">${esc(t("common.edit"))}</button>
                            <button type="button" class="btn sm" data-trace-svc="${esc(name)}">${esc(t("svc.trace"))}</button>
                            <button type="button" class="btn sm danger" data-del-svc="${esc(name)}">${esc(t("common.delete"))}</button>
                          </div>
                        </td>
                      </tr>`;
                      })
                      .join("")}
                  </tbody>
                </table>
              </div>`
            : `<div class="empty-state-box">
                <p>${esc(t("svc.empty"))}</p>
                <button type="button" id="btn-svc-empty-new" class="btn primary">${esc(t("svc.add"))}</button>
              </div>`
        }
      </div>
    `;

    el("svc-search-inp")?.addEventListener("input", (ev) => {
      searchQ = ev.target.value;
      render();
      el("svc-search-inp")?.focus();
    });
    el("btn-svc-empty-new")?.addEventListener("click", () => openServiceDrawer(null));
    container.querySelectorAll("[data-edit-svc]").forEach((btn) => {
      btn.addEventListener("click", () => openServiceDrawer(btn.dataset.editSvc));
    });
    container.querySelectorAll("[data-trace-svc]").forEach((btn) => {
      btn.addEventListener("click", () => navigate("topology", { traceService: btn.dataset.traceSvc }));
    });
    container.querySelectorAll("[data-del-svc]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const name = btn.dataset.delSvc;
        store.mutate((s) => { delete s.services[name]; });
        render();
        showToast(`Deleted service '${name}' from draft`);
      });
    });
  }

  function renderMatrix(container) {
    const paths = store.compiledPaths || [];
    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h3>${esc(t("svc.tab.matrix"))} (${paths.length})</h3>
          <span class="muted-sm">Verified by Control topology compiler</span>
        </div>
        <div class="table-scroll">
          <table class="table">
            <thead><tr><th>Service</th><th>Ingress</th><th>Compiled Hop Chain</th><th>Backend</th><th>Status</th></tr></thead>
            <tbody>
              ${
                paths
                  .map(
                    (p) => `
                  <tr>
                    <td><strong>${esc(p.service_tag)}</strong> ${p.rule_name ? `<div class="muted-sm">${esc(p.rule_name)}</div>` : ""}</td>
                    <td><code>${esc(p.ingress)}</code></td>
                    <td><div class="hop-chain">${(p.hops || []).map((h) => `<span class="hop-node">${esc(h)}</span>`).join('<span class="hop-arrow">→</span>')}</div></td>
                    <td><code>${esc(p.backend || "-")}</code></td>
                    <td>${p.valid ? `<span class="pill ok">VALID</span>` : `<span class="pill err">${esc(p.error || "INVALID")}</span>`}</td>
                  </tr>`
                  )
                  .join("") || `<tr><td colspan="5" class="muted">Click Validate in the top bar to inspect compiled routes.</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  function renderLegacy(container) {
    const rows = [];
    for (const [igTag, n] of Object.entries(store.spec.nodes || {})) {
      for (const r of n.ingress?.rules || []) {
        rows.push({ igTag, r });
      }
    }
    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h3>${esc(t("svc.tab.legacy"))} (${rows.length})</h3>
          ${rows.length ? `<button type="button" id="btn-leg-migrate" class="btn sm primary">${esc(t("svc.migrate_btn"))}</button>` : ""}
        </div>
        <div class="table-scroll">
          <table class="table">
            <thead><tr><th>Ingress Host</th><th>Host Match</th><th>Service Tag</th><th>Next Peer</th><th>Guard</th></tr></thead>
            <tbody>
              ${
                rows
                  .map(
                    ({ igTag, r }) => `
                  <tr>
                    <td><code>${esc(igTag)}</code></td>
                    <td><code>${esc(r.match?.host || "*")}</code> ${r.match?.url_prefix ? `<code>${esc(r.match.url_prefix)}</code>` : ""}</td>
                    <td><strong>${esc(r.service_tag)}</strong></td>
                    <td><code>${esc(r.next_peer)}</code></td>
                    <td>${esc(r.guard || "(default)")}</td>
                  </tr>`
                  )
                  .join("") || `<tr><td colspan="5" class="muted">No legacy per-node ingress rules. All services are cleanly managed in Service Catalog.</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    `;
    el("btn-leg-migrate")?.addEventListener("click", migrateLegacyRules);
  }

  function openServiceDrawer(existingName) {
    const isNew = !existingName;
    const allIngress = Object.entries(store.spec.nodes || {})
      .filter(([, n]) => n.roles?.ingress)
      .map(([k]) => k)
      .sort();
    const allEgress = Object.entries(store.spec.nodes || {})
      .filter(([, n]) => n.roles?.egress)
      .map(([k]) => k)
      .sort();
    const guardNames = Object.keys(store.spec.guard_templates || {});
    const bucketNames = Object.keys(store.spec.bucket_templates || {}).sort();
    const antibotNames = Object.keys(store.spec.antibot_templates || {}).sort();
    const wafNames = Object.keys(store.spec.waf_templates || {}).sort();
    const defs = store.spec.defaults || defaultTopologyDefaults();

    // Work on a local working copy, apply cleanly on Save
    let workingName = existingName || "";
    const draft = isNew
      ? defaultServiceSpec(allEgress[0] || "")
      : JSON.parse(JSON.stringify(store.spec.services[existingName]));

    const renderDrawerContent = () => {
      const targetIngs = resolveServiceTargetIngresses(store.spec, draft);
      const previewPaths = computeServicePaths(draft);
      const effTls = draft.egress.tls != null ? draft.egress.tls : defs.egress.tls;
      const scopeMode = draft.ingress.mode || "all";

      const ingressChipsHtml = allIngress
        .map((ig) => {
          const sel = (draft.ingress.nodes || []).includes(ig);
          return `<button type="button" class="acl-chip ${sel ? "active" : ""}" data-sd-ing-chip="${esc(ig)}">${esc(ig)}</button>`;
        })
        .join("");

      const routePreviewHtml = previewPaths
        .map((p) => {
          if (!p.hops) {
            return `<div class="diff-row"><code>${esc(p.ingress)}</code><span class="pill err">${esc(t("svc.route_unreachable"))}</span></div>`;
          }
          const chain =
            p.mode === "local"
              ? `<span class="pill ok">${esc(t("svc.route_local"))}</span>`
              : `<div class="hop-chain">${p.hops.map((h) => `<span class="hop-node">${esc(h)}</span>`).join('<span class="hop-arrow">→</span>')}</div>`;
          return `
            <div class="diff-row" style="flex-direction:column;align-items:stretch;gap:6px;">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
                <div><code>${esc(p.ingress)}</code> → <code>${esc(draft.egress.node)}</code></div>
                ${chain}
              </div>
              ${
                draft.routing.mode === "pinned" && p.mode !== "local"
                  ? `<input class="input-sm" data-sd-pin="${esc(p.ingress)}" value="${esc((draft.routing.pinned_paths[p.ingress] || p.hops).join(", "))}" placeholder="${esc(p.hops.join(", "))}" />`
                  : ""
              }
            </div>`;
        })
        .join("");

      const overridesHtml = targetIngs
        .map((ig) => {
          const ov = draft.ingress.overrides?.[ig] || {};
          const igSpec = store.spec.nodes?.[ig]?.ingress || {};
          const igBuckets = [...new Set([...bucketNames, ...Object.keys(igSpec.rate_limit_buckets || {})])].sort();
          const igAntibots = [...new Set([...antibotNames, ...Object.keys(igSpec.antibot_sets || {})])].sort();
          const igWafs = [...new Set([...wafNames, ...Object.keys(igSpec.waf_sets || {})])].sort();
          const hasOv = Boolean(
            ov.bucket ||
              ov.antibot ||
              ov.waf ||
              ov.guard ||
              (ov.source_cidrs && ov.source_cidrs.length) ||
              ov.intercept_errors != null ||
              ov.js_fp_beacon != null
          );
          return `
            <details class="subcard" ${hasOv ? "open" : ""}>
              <summary style="cursor:pointer;font-weight:600;font-size:12.5px;">
                <code>${esc(ig)}</code> ${hasOv ? `<span class="pill warn">Overridden</span>` : `<span class="muted-sm">(inherits service defaults)</span>`}
              </summary>
              <div class="inspector-row" style="margin-top:8px;">
                <label><span>Bucket Override</span>
                  <select data-sd-ov-set="bucket" data-ig="${esc(ig)}">
                    <option value="">(Inherit)</option>
                    ${igBuckets.map((k) => `<option value="${esc(k)}" ${ov.bucket === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
                  </select>
                </label>
                <label><span>Antibot Override</span>
                  <select data-sd-ov-set="antibot" data-ig="${esc(ig)}">
                    <option value="">(Inherit)</option>
                    ${igAntibots.map((k) => `<option value="${esc(k)}" ${ov.antibot === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
                  </select>
                </label>
                <label><span>WAF Override</span>
                  <select data-sd-ov-set="waf" data-ig="${esc(ig)}">
                    <option value="">(Inherit)</option>
                    ${igWafs.map((k) => `<option value="${esc(k)}" ${ov.waf === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
                  </select>
                </label>
              </div>
              <div class="inspector-row" style="margin-top:6px;">
                ${
                  ov.guard || guardNames.length
                    ? `<label><span>Guard Override (Legacy)</span>
                        <select data-sd-ov-guard="${esc(ig)}">
                          <option value="">(Inherit service)</option>
                          ${guardNames.map((g) => `<option value="${esc(g)}" ${ov.guard === g ? "selected" : ""}>${esc(g)}</option>`).join("")}
                        </select>
                      </label>`
                    : ""
                }
                <label><span>Source CIDRs Override</span>
                  <input data-sd-ov-cidrs="${esc(ig)}" value="${esc((ov.source_cidrs || []).join(", "))}" placeholder="203.0.113.0/24" />
                </label>
              </div>
            </details>`;
        })
        .join("");

      const bodyHtml = `
        <div class="step-card">
          <div class="step-card-head">
            <span>${esc(t("svc.step.entry"))}</span>
            ${renderBinSlider({ attrName: "data-sd-bin", attrVal: "enabled", label: t("common.enabled"), val: draft.enabled })}
          </div>
          <div class="inspector-row">
            <label><span>${esc(t("svc.field.name"))} *</span>
              <input id="sd-name" value="${esc(workingName)}" placeholder="web-app" ${isNew ? "" : ""} />
            </label>
            <label><span>${esc(t("svc.field.url_prefix"))}</span>
              <input id="sd-prefix" value="${esc(draft.url_prefix || "")}" placeholder="/api" />
            </label>
          </div>
          <label><span>${esc(t("svc.field.hosts"))} *</span>
            <input id="sd-hosts" value="${esc((draft.hosts || []).join(", "))}" placeholder="app.example.com, www.example.com" />
          </label>
          <div class="inspector-row">
            <label><span>${esc(t("svc.field.sni"))}</span>
              <input id="sd-sni" value="${esc(draft.sni || "")}" placeholder="app.example.com" />
            </label>
            <label><span>${esc(t("svc.field.cidrs"))}</span>
              <input id="sd-cidrs" value="${esc((draft.source_cidrs || []).join(", "))}" placeholder="optional CSV" />
            </label>
          </div>
        </div>

        <div class="step-card">
          <div class="step-card-head">
            <span>${esc(t("svc.step.scope"))}</span>
            <span class="pill ok">${targetIngs.length} Ingress</span>
          </div>
          <label><span>${esc(t("svc.field.scope_mode"))}</span>
            <select id="sd-scope-mode">
              <option value="all" ${scopeMode === "all" ? "selected" : ""}>${esc(t("svc.field.scope_all"))}</option>
              <option value="selected" ${scopeMode === "selected" ? "selected" : ""}>${esc(t("svc.field.scope_selected"))}</option>
              <option value="exclude" ${scopeMode === "exclude" ? "selected" : ""}>${esc(t("svc.field.scope_exclude"))}</option>
            </select>
          </label>
          ${
            scopeMode !== "all"
              ? `<div class="acl-chips-row">${ingressChipsHtml || '<span class="muted-sm">No Ingress hosts found</span>'}</div>`
              : ""
          }
          ${
            targetIngs.length
              ? `<details style="margin-top:4px;">
                  <summary class="muted-sm" style="cursor:pointer;font-weight:600;">${esc(t("svc.field.overrides"))}</summary>
                  <div style="display:flex;flex-direction:column;gap:8px;margin-top:8px;">${overridesHtml}</div>
                </details>`
              : ""
          }
        </div>

        <div class="step-card">
          <div class="step-card-head"><span>${esc(t("svc.step.backend"))}</span></div>
          <div class="inspector-row">
            <label><span>${esc(t("svc.field.egress_node"))} *</span>
              <select id="sd-eg-node">
                <option value="">(select egress host)</option>
                ${allEgress.map((n) => `<option value="${esc(n)}" ${draft.egress.node === n ? "selected" : ""}>${esc(n)}</option>`).join("")}
              </select>
            </label>
            <label><span>${esc(t("svc.field.backend"))} *</span>
              <input id="sd-eg-backend" value="${esc(draft.egress.backend || "")}" placeholder="192.168.1.3:10808" />
            </label>
          </div>
          <div class="inspector-row">
            <label><span>${esc(t("svc.field.protocol"))}</span>
              <select id="sd-eg-proto">
                <option value="auto" ${draft.egress.protocol === "auto" ? "selected" : ""}>auto (h2/h1)</option>
                <option value="http1" ${draft.egress.protocol === "http1" ? "selected" : ""}>http1</option>
                <option value="h2" ${draft.egress.protocol === "h2" ? "selected" : ""}>h2</option>
              </select>
            </label>
            <label><span>${esc(t("svc.field.timeout"))}</span>
              <input id="sd-eg-timeout" type="number" min="0" value="${draft.egress.timeout_ms ?? 0}" />
            </label>
          </div>
          <div class="tri-stack">
            ${renderTriSlider({ attrName: "data-sd-eg-tri", attrVal: "tls", label: "Backend TLS (HTTPS)", val: draft.egress.tls, inherited: defs.egress.tls })}
            ${
              effTls
                ? renderTriSlider({ attrName: "data-sd-eg-tri", attrVal: "insecure_skip_verify", label: "Skip Backend Cert Verify", val: draft.egress.insecure_skip_verify, inherited: defs.egress.insecure_skip_verify })
                : ""
            }
            ${renderTriSlider({ attrName: "data-sd-eg-tri", attrVal: "intercept_errors", label: "Egress Error Page (5xx)", val: draft.egress.intercept_errors, inherited: defs.egress.intercept_errors })}
          </div>
        </div>

        <div class="step-card">
          <div class="step-card-head"><span>${esc(t("svc.step.routing"))}</span></div>
          <div class="inspector-row">
            <label><span>${esc(t("svc.field.bucket_set"))}</span>
              <select id="sd-bucket">
                <option value="">(Default: ${esc(defs.ingress.default_bucket || "none")})</option>
                ${bucketNames.map((b) => `<option value="${esc(b)}" ${draft.bucket === b ? "selected" : ""}>${esc(b)}</option>`).join("")}
              </select>
            </label>
            <label><span>${esc(t("svc.field.antibot_set"))}</span>
              <select id="sd-antibot">
                <option value="">(Default: ${esc(defs.ingress.default_antibot || "none")})</option>
                ${antibotNames.map((a) => `<option value="${esc(a)}" ${draft.antibot === a ? "selected" : ""}>${esc(a)}</option>`).join("")}
              </select>
            </label>
            <label><span>${esc(t("svc.field.waf_set"))}</span>
              <select id="sd-waf">
                <option value="">(Default: ${esc(defs.ingress.default_waf || "none")})</option>
                ${wafNames.map((w) => `<option value="${esc(w)}" ${draft.waf === w ? "selected" : ""}>${esc(w)}</option>`).join("")}
              </select>
            </label>
          </div>
          <div class="inspector-row">
            <label><span>${esc(t("svc.field.routing_mode"))}</span>
              <select id="sd-route-mode">
                <option value="auto" ${draft.routing.mode !== "pinned" ? "selected" : ""}>${esc(t("svc.field.routing_auto"))}</option>
                <option value="pinned" ${draft.routing.mode === "pinned" ? "selected" : ""}>${esc(t("svc.field.routing_pinned"))}</option>
              </select>
            </label>
            ${
              draft.guard || guardNames.length
                ? `<label><span>${esc(t("svc.field.guard"))} (Legacy)</span>
                    <select id="sd-guard">
                      <option value="">(None / Use modular sets)</option>
                      ${guardNames.map((g) => `<option value="${esc(g)}" ${draft.guard === g ? "selected" : ""}>${esc(g)}</option>`).join("")}
                    </select>
                  </label>`
                : ""
            }
          </div>
          <div class="tri-stack">
            ${renderBinSlider({ attrName: "data-sd-bin", attrVal: "auto_tls", label: t("svc.field.auto_tls"), sub: t("svc.field.auto_tls_sub"), val: draft.auto_tls })}
            ${renderTriSlider({ attrName: "data-sd-tri", attrVal: "intercept_errors", label: "Ingress Intercept Errors (403/429/5xx)", val: draft.intercept_errors, inherited: defs.ingress.intercept_errors })}
            ${renderTriSlider({ attrName: "data-sd-tri", attrVal: "js_fp_beacon", label: "Passive JS FP Beacon", val: draft.js_fp_beacon, inherited: defs.ingress.js_fp_beacon })}
            ${renderTriSlider({ attrName: "data-sd-ca-tri", attrVal: "enabled", label: "Edge HTTP Cache", sub: "Cache GET/HEAD responses in RAM on Ingress hosts", val: draft.cache?.enabled ?? null, inherited: Boolean(defs.ingress.cache?.enabled) })}
          </div>
          ${
            (draft.cache?.enabled ?? defs.ingress.cache?.enabled)
              ? `<div class="inspector-row">
                  <label><span>Cache TTL Override (s)</span><input id="sd-ca-ttl" type="number" min="0" value="${draft.cache?.default_ttl_secs ?? ""}" placeholder="Default (${defs.ingress.cache?.default_ttl_secs ?? 60}s)" /></label>
                  <label><span>Stale-if-Error (s)</span><input id="sd-ca-stale" type="number" min="0" value="${draft.cache?.stale_if_error_secs ?? ""}" placeholder="Default (${defs.ingress.cache?.stale_if_error_secs ?? 300}s)" /></label>
                </div>
                <div class="tri-stack">
                  ${renderTriSlider({ attrName: "data-sd-ca-tri", attrVal: "respect_cache_control", label: "Respect Cache-Control", val: draft.cache?.respect_cache_control ?? null, inherited: defs.ingress.cache?.respect_cache_control !== false })}
                  ${renderTriSlider({ attrName: "data-sd-ca-tri", attrVal: "ignore_query_string", label: "Ignore Query String", val: draft.cache?.ignore_query_string ?? null, inherited: Boolean(defs.ingress.cache?.ignore_query_string) })}
                </div>`
              : ""
          }
          <div>
            <div class="muted-sm" style="margin-bottom:6px;font-weight:700;">${esc(t("svc.route_preview"))}</div>
            <div class="diff-list">${routePreviewHtml || '<div class="muted-sm">Select an Egress host and at least one Ingress host.</div>'}</div>
          </div>
        </div>
      `;

      const drawer = openDrawer({
        title: isNew ? t("svc.drawer.new") : t("svc.drawer.edit", { name: existingName }),
        subtitle: `${targetIngs.length} Ingress → ${draft.egress.node || "?"} (${draft.egress.backend || "?"})`,
        bodyHtml,
        wide: true,
        footerHtml: `
          <button type="button" id="sd-cancel" class="btn sm ghost">${esc(t("common.cancel"))}</button>
          <button type="button" id="sd-save" class="btn sm primary">${esc(t("common.apply"))}</button>
        `,
      });
      if (!drawer) return;

      el("sd-name")?.addEventListener("input", (ev) => { workingName = ev.target.value.trim(); });
      el("sd-prefix")?.addEventListener("input", (ev) => { draft.url_prefix = ev.target.value.trim() || null; });
      el("sd-hosts")?.addEventListener("input", (ev) => {
        draft.hosts = ev.target.value.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean);
      });
      el("sd-sni")?.addEventListener("input", (ev) => { draft.sni = ev.target.value.trim() || null; });
      el("sd-cidrs")?.addEventListener("input", (ev) => {
        draft.source_cidrs = ev.target.value.split(",").map((s) => s.trim()).filter(Boolean);
      });
      el("sd-scope-mode")?.addEventListener("change", (ev) => {
        draft.ingress.mode = ev.target.value;
        renderDrawerContent();
      });
      drawer.body.querySelectorAll("[data-sd-ing-chip]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const ig = btn.dataset.sdIngChip;
          const idx = draft.ingress.nodes.indexOf(ig);
          if (idx >= 0) draft.ingress.nodes.splice(idx, 1);
          else draft.ingress.nodes.push(ig);
          renderDrawerContent();
        });
      });
      const ensureOv = (ig) => {
        if (!draft.ingress.overrides[ig]) {
          draft.ingress.overrides[ig] = { guard: null, bucket: null, antibot: null, waf: null, source_cidrs: [], intercept_errors: null, js_fp_beacon: null };
        }
        return draft.ingress.overrides[ig];
      };
      drawer.body.querySelectorAll("[data-sd-ov-set]").forEach((sel) => {
        sel.addEventListener("change", () => {
          ensureOv(sel.dataset.ig)[sel.dataset.sdOvSet] = sel.value || null;
        });
      });
      drawer.body.querySelectorAll("[data-sd-ov-guard]").forEach((sel) => {
        sel.addEventListener("change", () => {
          ensureOv(sel.dataset.sdOvGuard).guard = sel.value || null;
        });
      });
      drawer.body.querySelectorAll("[data-sd-ov-cidrs]").forEach((inp) => {
        inp.addEventListener("input", () => {
          ensureOv(inp.dataset.sdOvCidrs).source_cidrs = inp.value.split(",").map((s) => s.trim()).filter(Boolean);
        });
      });

      el("sd-eg-node")?.addEventListener("change", (ev) => {
        draft.egress.node = ev.target.value;
        renderDrawerContent();
      });
      el("sd-eg-backend")?.addEventListener("input", (ev) => { draft.egress.backend = ev.target.value.trim(); });
      el("sd-eg-proto")?.addEventListener("change", (ev) => { draft.egress.protocol = ev.target.value; });
      el("sd-eg-timeout")?.addEventListener("input", (ev) => { draft.egress.timeout_ms = parseNum(ev.target.value, 0, 0); });
      wireTriSliders(drawer.body, "data-sd-eg-tri", (f, val) => {
        draft.egress[f] = val;
        if (f === "tls") renderDrawerContent();
      });

      el("sd-bucket")?.addEventListener("change", (ev) => { draft.bucket = ev.target.value || null; });
      el("sd-antibot")?.addEventListener("change", (ev) => { draft.antibot = ev.target.value || null; });
      el("sd-waf")?.addEventListener("change", (ev) => { draft.waf = ev.target.value || null; });
      el("sd-guard")?.addEventListener("change", (ev) => { draft.guard = ev.target.value || null; });
      el("sd-route-mode")?.addEventListener("change", (ev) => {
        draft.routing.mode = ev.target.value;
        renderDrawerContent();
      });
      drawer.body.querySelectorAll("[data-sd-pin]").forEach((inp) => {
        inp.addEventListener("input", () => {
          const ig = inp.dataset.sdPin;
          draft.routing.pinned_paths[ig] = inp.value.split(",").map((s) => s.trim()).filter(Boolean);
        });
      });
      wireBinSliders(drawer.body, "data-sd-bin", (f, val) => { draft[f] = val; });
      wireTriSliders(drawer.body, "data-sd-tri", (f, val) => { draft[f] = val; });
      const ensureDraftCache = () => {
        if (!draft.cache) draft.cache = { enabled: null, default_ttl_secs: null, stale_if_error_secs: null, respect_cache_control: null, ignore_query_string: null, bypass_cookie_prefixes: [] };
        return draft.cache;
      };
      wireTriSliders(drawer.body, "data-sd-ca-tri", (f, val) => {
        ensureDraftCache()[f] = val;
        if (f === "enabled") renderDrawerContent();
      });
      el("sd-ca-ttl")?.addEventListener("input", (ev) => {
        ensureDraftCache().default_ttl_secs = ev.target.value.trim() ? parseNum(ev.target.value, 60, 0) : null;
      });
      el("sd-ca-stale")?.addEventListener("input", (ev) => {
        ensureDraftCache().stale_if_error_secs = ev.target.value.trim() ? parseNum(ev.target.value, 300, 0) : null;
      });

      el("sd-cancel")?.addEventListener("click", closeDrawer);
      el("sd-save")?.addEventListener("click", () => {
        if (!workingName || isReservedKey(workingName) || !/^[A-Za-z0-9._@-]+$/.test(workingName)) {
          showToast("Invalid service tag", true);
          return;
        }
        if (!draft.hosts.length) {
          showToast("Enter at least one Host (e.g. app.example.com or *)", true);
          return;
        }
        if (!draft.egress.node || !draft.egress.backend) {
          showToast("Select an Egress host and enter backend address", true);
          return;
        }
        if ((isNew || workingName !== existingName) && store.spec.services[workingName]) {
          showToast(`Service '${workingName}' already exists`, true);
          return;
        }
        // Prune empty per-ingress overrides
        for (const [k, ov] of Object.entries(draft.ingress.overrides)) {
          if (!ov.guard && !ov.bucket && !ov.antibot && !ov.waf && !(ov.source_cidrs || []).length && ov.intercept_errors == null && ov.js_fp_beacon == null) {
            delete draft.ingress.overrides[k];
          }
        }
        store.mutate((s) => {
          if (!isNew && existingName !== workingName) delete s.services[existingName];
          s.services[workingName] = draft;
        });
        closeDrawer();
        render();
        showToast(isNew ? `Created service '${workingName}' in draft` : `Updated service '${workingName}'`);
      });
    };

    renderDrawerContent();
  }

  async function refresh() {
    if (!store.loaded) await store.loadTopology(false);
    render();
  }

  return { refresh, render, openServiceDrawer };
}
