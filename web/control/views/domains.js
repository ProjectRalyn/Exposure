// Domains & Smart DNS View (Split-Horizon Line Routing + Live Remote A/AAAA/CNAME Editor + TLS Certs + Providers)
import { formatDateTime } from "../charts.js";
import { COMMON_ALIYUN_LINES, formatLineLabel, getLang, t } from "../i18n.js";
import {
  defaultMaintainerTemplate,
  isReservedKey,
  resolveDomainBindingJS,
  shortestPathBFS,
} from "../store.js";
import {
  closeDrawer,
  el,
  esc,
  openDrawer,
  openModal,
  parseNum,
  showToast,
} from "../ui.js";

export function createDomainsView({ api, store }) {
  let subTab = "domains"; // domains | certs | providers
  let selectedDomain = null;
  let remoteLoading = false;

  function getProviderType(provName) {
    const p = store.spec.dns_providers?.[provName];
    return p?.type || "";
  }

  function isAliyunProvider(provName) {
    const tp = getProviderType(provName);
    return tp === "aliyun" || tp === "alidns";
  }

  function isCloudflareProvider(provName) {
    return getProviderType(provName) === "cloudflare";
  }

  function resolveDesiredSet(domCfg) {
    // Returns array of { line, record_type, value, ttl }
    const desired = [];
    const routes =
      domCfg.line_routes && domCfg.line_routes.length
        ? domCfg.line_routes
        : domCfg.target_nodes?.length
        ? [{ line: "default", target_nodes: domCfg.target_nodes, values: [], record_type: "auto", ttl: domCfg.ttl, enabled: true }]
        : [];
    for (const lr of routes) {
      if (lr.enabled === false) continue;
      const line = (lr.line || "default").trim() || "default";
      const ttl = lr.ttl || domCfg.ttl || 600;
      if (lr.record_type === "cname") {
        for (const v of lr.values || []) {
          const c = v.trim().replace(/\.+$/, "");
          if (c) desired.push({ line, record_type: "CNAME", value: c, ttl });
        }
      } else {
        const vals = new Set();
        for (const nt of lr.target_nodes || []) {
          for (const ip of store.spec.nodes?.[nt]?.external_ips || []) {
            if (ip.trim()) vals.add(ip.trim());
          }
        }
        for (const v of lr.values || []) {
          if (v.trim()) vals.add(v.trim());
        }
        for (const ip of vals) {
          desired.push({
            line,
            record_type: ip.includes(":") ? "AAAA" : "A",
            value: ip,
            ttl,
          });
        }
      }
    }
    return desired;
  }

  async function inspectRemote(domain, includeLines = true) {
    remoteLoading = true;
    render();
    try {
      const qs = new URLSearchParams({ include_lines: includeLines ? "true" : "false" });
      const res = await api(`/api/dns/domains/${encodeURIComponent(domain)}/inspect?${qs}`);
      store.dnsRemoteCache[domain] = {
        capabilities: res.capabilities || {},
        lines: res.lines || [],
        records: res.records || [],
        maintainer_tag: res.maintainer_tag || "",
        fetchedAt: new Date().toISOString(),
      };
      showToast(`Fetched ${(res.records || []).length} remote record(s) for ${domain}`);
    } catch (e) {
      showToast(e.message, true);
    } finally {
      remoteLoading = false;
      render();
    }
  }

  async function syncDnsDomains(domains = null) {
    try {
      const body = domains ? { domains } : {};
      const resp = await api("/api/dns/sync", { method: "POST", body: JSON.stringify(body) });
      const summary = (resp.results || [])
        .map((r) =>
          r.ok
            ? `${r.domain}: +${r.created}/~${r.updated}/-${r.deleted}`
            : `${r.domain}: ERR (${r.error})`
        )
        .join("; ");
      showToast(`DNS sync via ${resp.maintainer_tag}: ${summary || "done"}`, !resp.ok);
      if (selectedDomain && (!domains || domains.includes(selectedDomain))) {
        await inspectRemote(selectedDomain, false);
      }
    } catch (e) {
      showToast(e.message, true);
    }
  }

  function render() {
    const root = el("tab-domains");
    if (!root) return;

    const domainKeys = Object.keys(store.spec.domains || {});
    const provKeys = Object.keys(store.spec.dns_providers || {});
    if (selectedDomain && !store.spec.domains[selectedDomain]) selectedDomain = null;
    if (!selectedDomain && domainKeys.length) selectedDomain = domainKeys[0];

    const liveCerts = store.telemetry?.certificates || [];

    root.innerHTML = `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${subTab === "domains" ? "active" : ""}" data-dns-sub="domains">
            ${esc(t("Domains & Smart DNS"))} <span class="subtab-count">${domainKeys.length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "certs" ? "active" : ""}" data-dns-sub="certs">
            ${esc(t("TLS Certificates"))} <span class="subtab-count">${liveCerts.length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "providers" ? "active" : ""}" data-dns-sub="providers">
            ${esc(t("DNS Providers"))} <span class="subtab-count">${provKeys.length}</span>
          </button>
        </div>
        <div class="btn-row">
          ${
            subTab === "domains"
              ? `<button type="button" id="btn-dns-sync-all" class="btn sm">${esc(t("Sync All DNS"))}</button>
                 <button type="button" id="btn-dns-add-dom" class="btn sm primary">${esc(t("+ Bind Domain"))}</button>`
              : ""
          }
        </div>
      </div>
      <div id="dns-sub-body"></div>
    `;

    root.querySelectorAll("[data-dns-sub]").forEach((btn) => {
      btn.addEventListener("click", () => {
        subTab = btn.dataset.dnsSub;
        render();
      });
    });
    el("btn-dns-sync-all")?.addEventListener("click", () => syncDnsDomains(null));
    el("btn-dns-add-dom")?.addEventListener("click", openAddDomainModal);

    const body = el("dns-sub-body");
    if (subTab === "domains") renderDomainsSubTab(body, domainKeys, provKeys);
    else if (subTab === "certs") renderCertsSubTab(body, liveCerts);
    else renderProvidersSubTab(body, provKeys);
  }

  function openAddDomainModal() {
    const provKeys = Object.keys(store.spec.dns_providers || {});
    openModal({
      title: t("+ Bind Domain"),
      bodyHtml: `
        <div class="form-grid">
          <label><span>Domain (e.g. app.example.com or example.com)</span>
            <input id="nd-name" type="text" placeholder="app.example.com" />
          </label>
          <label><span>DNS Provider Account</span>
            <select id="nd-prov">
              <option value="">(select provider)</option>
              ${provKeys.map((p) => `<option value="${esc(p)}">${esc(p)} (${esc(getProviderType(p))})</option>`).join("")}
            </select>
          </label>
          <label><span>Root / Apex Domain (optional, auto-detected)</span>
            <input id="nd-root" type="text" placeholder="example.com" />
          </label>
        </div>`,
      actions: [
        { label: t("Cancel"), cls: "ghost" },
        {
          label: t("Create"),
          cls: "primary",
          close: false,
          onClick: () => {
            const name = (el("nd-name")?.value || "").trim().replace(/\.+$/, "");
            if (!name || isReservedKey(name)) {
              showToast("Enter a valid domain name", true);
              return;
            }
            if (store.spec.domains[name]) {
              showToast(`Domain '${name}' already exists`, true);
              return;
            }
            const prov = el("nd-prov")?.value || provKeys[0] || "";
            store.mutate((s) => {
              s.domains[name] = {
                provider: prov,
                zone_id: null,
                root_domain: el("nd-root")?.value.trim() || null,
                target_nodes: [],
                line_routes: [
                  { line: "default", target_nodes: [], values: [], record_type: "auto", ttl: null, proxied: null, enabled: true },
                ],
                ttl: 600,
                proxied: false,
              };
            });
            selectedDomain = name;
            el("modal-backdrop")?.classList.add("hidden");
            render();
          },
        },
      ],
    });
  }

  function renderDomainsSubTab(container, domainKeys, provKeys) {
    if (!domainKeys.length) {
      container.innerHTML = `
        <div class="empty-state-box">
          <p>${esc(t("No domains bound yet. Add a DNS provider account first, then bind domains for smart DNS sync and ACME DNS-01 certificates."))}</p>
          <div class="btn-row" style="justify-content:center;">
            ${!provKeys.length ? `<button type="button" id="btn-go-prov" class="btn">Configure DNS Provider →</button>` : ""}
            <button type="button" id="btn-empty-add-dom" class="btn primary">${esc(t("+ Bind Domain"))}</button>
          </div>
        </div>`;
      el("btn-go-prov")?.addEventListener("click", () => { subTab = "providers"; render(); });
      el("btn-empty-add-dom")?.addEventListener("click", openAddDomainModal);
      return;
    }

    const dom = selectedDomain;
    const cfg = store.spec.domains[dom];
    const provType = getProviderType(cfg.provider);
    const supportsLines = isAliyunProvider(cfg.provider);
    const isCf = isCloudflareProvider(cfg.provider);
    const remote = store.dnsRemoteCache[dom] || null;
    const fetchedLines = remote?.lines || [];
    const caps = remote?.capabilities || {
      supports_lines: supportsLines,
      supports_proxied: isCf,
      supports_status_toggle: supportsLines,
      supports_remote_edit: supportsLines || isCf,
    };

    // Ensure line_routes view reflects legacy target_nodes smoothly
    const lineRoutes = cfg.line_routes || [];
    const ingressNodes = Object.entries(store.spec.nodes || {})
      .filter(([, n]) => n.roles?.ingress || (n.external_ips || []).length > 0)
      .map(([k]) => k)
      .sort();

    const desiredRecords = resolveDesiredSet(cfg);
    const desiredKeySet = new Set(
      desiredRecords.map((d) => `${d.record_type}|${d.line.toLowerCase()}|${d.value.toLowerCase()}`)
    );

    const lineOptionsHtml = (selectedCode) => {
      const merged = [];
      const seen = new Set();
      if (fetchedLines.length) {
        for (const l of fetchedLines) {
          if (seen.has(l.code)) continue;
          seen.add(l.code);
          merged.push({ code: l.code, label: `${l.name} (${l.code})` });
        }
      } else {
        for (const l of COMMON_ALIYUN_LINES) {
          seen.add(l.code);
          merged.push({ code: l.code, label: getLang() === "zh-CN" ? `${l.zh} (${l.code})` : `${l.en} (${l.code})` });
        }
      }
      if (selectedCode && !seen.has(selectedCode)) {
        merged.unshift({ code: selectedCode, label: selectedCode });
      }
      return merged
        .map((m) => `<option value="${esc(m.code)}" ${m.code === selectedCode ? "selected" : ""}>${esc(m.label)}</option>`)
        .join("");
    };

    const listHtml = domainKeys
      .map((dk) => {
        const dc = store.spec.domains[dk];
        const pType = getProviderType(dc.provider) || "?";
        const routeCnt = (dc.line_routes || []).length || (dc.target_nodes?.length ? 1 : 0);
        return `
          <button type="button" class="domain-list-item ${dk === dom ? "active" : ""}" data-sel-dom="${esc(dk)}">
            <div class="domain-list-name">${esc(dk)}</div>
            <div class="domain-list-meta">
              <span>${esc(dc.provider || "-")} (${esc(pType)})</span>
              <span class="pill">${routeCnt} ${supportsLines || pType === "aliyun" ? "line(s)" : "route(s)"}</span>
            </div>
          </button>`;
      })
      .join("");

    const lineRowsHtml = lineRoutes
      .map((lr, idx) => {
        const resolvedIps = [];
        if (lr.record_type === "cname") {
          for (const v of lr.values || []) resolvedIps.push(`CNAME ${v}`);
        } else {
          for (const nt of lr.target_nodes || []) {
            for (const ip of store.spec.nodes?.[nt]?.external_ips || []) {
              resolvedIps.push(`${ip.includes(":") ? "AAAA" : "A"} ${ip}`);
            }
          }
          for (const v of lr.values || []) resolvedIps.push(`${v.includes(":") ? "AAAA" : "A"} ${v}`);
        }
        const hostChips = ingressNodes
          .map((hn) => {
            const on = (lr.target_nodes || []).includes(hn);
            const ips = store.spec.nodes?.[hn]?.external_ips || [];
            return `<button type="button" class="acl-chip ${on ? "active" : ""}" data-lr-node="${idx}" data-lr-host="${esc(hn)}" title="${esc(ips.join(", ") || "No external_ips")}">${esc(hn)}</button>`;
          })
          .join("");
        return `
          <div class="subcard" style="${lr.enabled === false ? "opacity:0.55;" : ""}">
            <div class="subcard-head">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                ${
                  supportsLines
                    ? `<select class="select-sm" data-lr-line="${idx}">${lineOptionsHtml(lr.line || "default")}</select>`
                    : `<span class="pill">default</span>`
                }
                <select class="select-sm" data-lr-rtype="${idx}">
                  <option value="auto" ${lr.record_type !== "cname" ? "selected" : ""}>A / AAAA (Host IPs)</option>
                  <option value="cname" ${lr.record_type === "cname" ? "selected" : ""}>CNAME</option>
                </select>
                <label class="check-inline"><input type="checkbox" data-lr-en="${idx}" ${lr.enabled !== false ? "checked" : ""} /> ${esc(t("Enabled"))}</label>
              </div>
              <div class="btn-row">
                <input class="input-sm" type="number" min="1" style="width:82px;" data-lr-ttl="${idx}" value="${lr.ttl ?? ""}" placeholder="TTL ${cfg.ttl ?? 600}" title="TTL override (s)" />
                <button type="button" class="btn sm danger" data-lr-del="${idx}">${esc(t("Remove"))}</button>
              </div>
            </div>
            ${
              lr.record_type !== "cname"
                ? `<div style="margin-bottom:6px;">
                    <div class="muted-sm" style="margin-bottom:4px;">Target Hosts:</div>
                    <div class="acl-chips-row">${hostChips || '<span class="muted-sm">Add external_ips on Hosts first</span>'}</div>
                  </div>`
                : ""
            }
            <label><span>${lr.record_type === "cname" ? "CNAME Target Hostname" : "Extra Manual IPs (optional CSV)"}</span>
              <input data-lr-vals="${idx}" value="${esc((lr.values || []).join(", "))}" placeholder="${lr.record_type === "cname" ? "cdn.example.net" : "203.0.113.50"}" />
            </label>
            <div class="tag-list" style="margin-top:6px;">
              ${resolvedIps.length ? resolvedIps.map((x) => `<span class="host-pill">${esc(x)}</span>`).join("") : `<span class="muted-sm">No resolved values yet</span>`}
            </div>
          </div>`;
      })
      .join("");

    const remoteRecords = remote?.records || [];
    const remoteRowsHtml = remoteRecords
      .map((rec) => {
        const key = `${rec.record_type}|${(rec.line || "default").toLowerCase()}|${rec.value.replace(/\.+$/, "").toLowerCase()}`;
        const inDesired = desiredKeySet.has(key);
        const sameLineDesired = desiredRecords.some(
          (d) => d.record_type === rec.record_type && d.line.toLowerCase() === (rec.line || "default").toLowerCase()
        );
        let statePill = "";
        if (!rec.enabled) statePill = `<span class="pill warn">${esc(t("Paused"))}</span>`;
        else if (inDesired) statePill = `<span class="pill ok">${esc(t("Synced"))}</span>`;
        else if (sameLineDesired) statePill = `<span class="pill err">${esc(t("Drift"))}</span>`;
        else statePill = `<span class="pill">${esc(t("Remote Only"))}</span>`;

        return `
          <tr>
            <td><code>${esc(rec.record_type)}</code></td>
            <td>${esc(formatLineLabel(rec.line, fetchedLines))}</td>
            <td><code>${esc(rec.value)}</code></td>
            <td>${esc(rec.ttl)}s</td>
            ${caps.supports_proxied ? `<td><span class="pill ${rec.proxied ? "warn" : ""}">${rec.proxied ? "Proxied" : "DNS Only"}</span></td>` : ""}
            <td>${statePill}</td>
            <td>
              <div class="btn-row">
                ${
                  caps.supports_remote_edit
                    ? `<button type="button" class="btn sm" data-rem-edit="${esc(rec.record_id)}">${esc(t("Edit"))}</button>`
                    : ""
                }
                ${
                  caps.supports_status_toggle
                    ? `<button type="button" class="btn sm" data-rem-toggle="${esc(rec.record_id)}" data-rem-en="${rec.enabled ? "1" : "0"}">${esc(rec.enabled ? t("Disable") : t("Enable"))}</button>`
                    : ""
                }
                ${
                  caps.supports_remote_edit
                    ? `<button type="button" class="btn sm danger" data-rem-del="${esc(rec.record_id)}">${esc(t("Delete"))}</button>`
                    : ""
                }
              </div>
            </td>
          </tr>`;
      })
      .join("");

    container.innerHTML = `
      <div class="domain-workbench">
        <div class="panel domain-list-panel">
          <div class="panel-header" style="margin-bottom:4px;">
            <h3>Domains (${domainKeys.length})</h3>
          </div>
          ${listHtml}
        </div>

        <div style="display:flex;flex-direction:column;gap:14px;">
          <!-- Domain Header & Metadata -->
          <div class="panel" style="margin-bottom:0;">
            <div class="panel-header">
              <div>
                <h3 style="margin-bottom:4px;">${esc(dom)}</h3>
                <div class="tag-list">
                  <span class="pill">${esc(cfg.provider || "(no provider)")} · ${esc(provType || "?")}</span>
                  ${caps.supports_lines ? `<span class="pill ok">${esc(t("Split Lines Supported"))}</span>` : ""}
                  ${caps.supports_proxied ? `<span class="pill info">${esc(t("Cloudflare Proxy"))}</span>` : ""}
                  ${caps.supports_status_toggle ? `<span class="pill">${esc(t("Record Enable/Pause"))}</span>` : ""}
                  ${!caps.supports_remote_edit ? `<span class="pill">${esc(t("Declarative Sync Only"))}</span>` : ""}
                </div>
              </div>
              <div class="btn-row">
                <button type="button" id="btn-dom-inspect" class="btn sm" ${remoteLoading ? "disabled" : ""}>${esc(remoteLoading ? t("Loading…") : t("Fetch Remote Records"))}</button>
                <button type="button" id="btn-dom-sync-one" class="btn sm primary">${esc(t("Sync This Domain"))}</button>
                <button type="button" id="btn-dom-delete" class="btn sm danger">${esc(t("Delete"))}</button>
              </div>
            </div>
            <div class="inspector-row">
              <label><span>Provider Account</span>
                <select id="dw-prov">
                  <option value="">(select)</option>
                  ${provKeys.map((p) => `<option value="${esc(p)}" ${cfg.provider === p ? "selected" : ""}>${esc(p)} (${esc(getProviderType(p))})</option>`).join("")}
                </select>
              </label>
              <label><span>Root Domain (optional)</span>
                <input id="dw-root" value="${esc(cfg.root_domain || "")}" placeholder="auto" />
              </label>
              <label><span>Default TTL (s)</span>
                <input id="dw-ttl" type="number" min="1" value="${cfg.ttl ?? 600}" />
              </label>
              ${
                isCf
                  ? `<label><span>Cloudflare Zone ID</span><input id="dw-zone" value="${esc(cfg.zone_id || "")}" placeholder="auto-queried" /></label>`
                  : ""
              }
            </div>
            ${
              isCf
                ? `<label class="check-inline" style="margin-top:8px;"><input type="checkbox" id="dw-proxied" ${cfg.proxied ? "checked" : ""} /> Cloudflare Proxied (Orange Cloud)</label>`
                : ""
            }
          </div>

          <!-- Section A: Declarative Split-Horizon Line Routing -->
          <div class="panel" style="margin-bottom:0;">
            <div class="panel-header">
              <div>
                <h3>${esc(t("Declarative Split-Horizon Routing (Bound to Exposure Hosts)"))}</h3>
                <div class="muted-sm">${esc(t("Map provider resolution lines (e.g., Aliyun Default / Telecom / Unicom / Mobile / Overseas) to Exposure Ingress hosts or manual CNAME/IP values."))}</div>
              </div>
              <button type="button" id="btn-add-line-route" class="btn sm primary">${esc(t("+ Add Line Route"))}</button>
            </div>
            ${
              !lineRoutes.length && cfg.target_nodes?.length
                ? `<div class="callout-banner">
                    <span>Legacy flat targets: <code>${esc(cfg.target_nodes.join(", "))}</code></span>
                    <button type="button" id="btn-convert-legacy-dns" class="btn sm">Convert to Line Routes</button>
                  </div>`
                : ""
            }
            <div style="display:flex;flex-direction:column;gap:10px;">
              ${lineRowsHtml || `<div class="muted-sm">No line routes configured yet (domain currently serves as ACME DNS-01 / parent-zone binding only).</div>`}
            </div>
          </div>

          <!-- Section B: Live Remote Exposure Records (A / AAAA / CNAME only) -->
          <div class="panel" style="margin-bottom:0;">
            <div class="panel-header">
              <div>
                <h3>${esc(t("Live Remote Exposure Records (A / AAAA / CNAME)"))}</h3>
                <div class="muted-sm">${esc(t("Fetched directly from DNS provider via Primary Maintainer. Strictly scoped to A, AAAA, and CNAME records for this domain."))}</div>
              </div>
              <div class="btn-row">
                ${
                  caps.supports_remote_edit
                    ? `<button type="button" id="btn-rem-add" class="btn sm primary">${esc(t("+ Add Remote Record"))}</button>`
                    : ""
                }
              </div>
            </div>
            ${
              store.dirty
                ? `<div class="muted-sm" style="margin-bottom:8px;">${esc(t("Note: Save/Deploy DNS provider & domain bindings to Maintainer before querying remote records."))}</div>`
                : ""
            }
            ${
              remote
                ? `<div class="muted-sm" style="margin-bottom:8px;">Maintainer: <code>${esc(remote.maintainer_tag)}</code> · Fetched: ${esc(formatDateTime(remote.fetchedAt))}${fetchedLines.length ? ` · ${fetchedLines.length} lines loaded from provider` : ""}</div>`
                : ""
            }
            <div class="table-scroll">
              <table class="table">
                <thead>
                  <tr>
                    <th>${esc(t("Type"))}</th>
                    <th>${esc(t("Resolution Line"))}</th>
                    <th>${esc(t("Value"))}</th>
                    <th>${esc(t("TTL"))}</th>
                    ${caps.supports_proxied ? `<th>Proxy</th>` : ""}
                    <th>${esc(t("Sync Status"))}</th>
                    <th>${esc(t("Actions"))}</th>
                  </tr>
                </thead>
                <tbody>
                  ${remoteRowsHtml || `<tr><td colspan="${caps.supports_proxied ? 7 : 6}" class="muted">${esc(t("No A / AAAA / CNAME records found on remote provider for this domain (or click Fetch Remote Records)."))}</td></tr>`}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    `;

    // Wire events
    container.querySelectorAll("[data-sel-dom]").forEach((btn) => {
      btn.addEventListener("click", () => {
        selectedDomain = btn.dataset.selDom;
        render();
      });
    });

    el("btn-dom-inspect")?.addEventListener("click", () => inspectRemote(dom, true));
    el("btn-dom-sync-one")?.addEventListener("click", () => syncDnsDomains([dom]));
    el("btn-dom-delete")?.addEventListener("click", () => {
      store.mutate((s) => { delete s.domains[dom]; });
      selectedDomain = null;
      render();
    });

    el("dw-prov")?.addEventListener("change", (ev) => {
      store.mutate((s) => { s.domains[dom].provider = ev.target.value; });
      render();
    });
    el("dw-root")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.domains[dom].root_domain = ev.target.value.trim() || null; }, false);
    });
    el("dw-zone")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.domains[dom].zone_id = ev.target.value.trim() || null; }, false);
    });
    el("dw-ttl")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.domains[dom].ttl = parseNum(ev.target.value, 600, 1, 86400); }, false);
    });
    el("dw-proxied")?.addEventListener("change", (ev) => {
      store.mutate((s) => { s.domains[dom].proxied = ev.target.checked; }, false);
    });

    el("btn-convert-legacy-dns")?.addEventListener("click", () => {
      store.mutate((s) => {
        const d = s.domains[dom];
        d.line_routes = [
          { line: "default", target_nodes: [...(d.target_nodes || [])], values: [], record_type: "auto", ttl: null, proxied: null, enabled: true },
        ];
        d.target_nodes = [];
      });
      render();
    });

    el("btn-add-line-route")?.addEventListener("click", () => {
      store.mutate((s) => {
        const d = s.domains[dom];
        if (!Array.isArray(d.line_routes)) d.line_routes = [];
        const used = new Set(d.line_routes.map((r) => r.line));
        const nextLine =
          ["default", "telecom", "unicom", "mobile", "oversea"].find((l) => !used.has(l)) || "default";
        d.line_routes.push({
          line: supportsLines ? nextLine : "default",
          target_nodes: [],
          values: [],
          record_type: "auto",
          ttl: null,
          proxied: null,
          enabled: true,
        });
      });
      render();
    });

    container.querySelectorAll("[data-lr-line]").forEach((sel) => {
      sel.addEventListener("change", () => {
        store.mutate((s) => { s.domains[dom].line_routes[Number(sel.dataset.lrLine)].line = sel.value; });
        render();
      });
    });
    container.querySelectorAll("[data-lr-rtype]").forEach((sel) => {
      sel.addEventListener("change", () => {
        store.mutate((s) => { s.domains[dom].line_routes[Number(sel.dataset.lrRtype)].record_type = sel.value; });
        render();
      });
    });
    container.querySelectorAll("[data-lr-en]").forEach((chk) => {
      chk.addEventListener("change", () => {
        store.mutate((s) => { s.domains[dom].line_routes[Number(chk.dataset.lrEn)].enabled = chk.checked; });
        render();
      });
    });
    container.querySelectorAll("[data-lr-ttl]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          s.domains[dom].line_routes[Number(inp.dataset.lrTtl)].ttl = inp.value.trim() ? parseNum(inp.value, 600, 1, 86400) : null;
        }, false);
      });
    });
    container.querySelectorAll("[data-lr-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        store.mutate((s) => { s.domains[dom].line_routes.splice(Number(btn.dataset.lrDel), 1); });
        render();
      });
    });
    container.querySelectorAll("[data-lr-node]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.dataset.lrNode);
        const hn = btn.dataset.lrHost;
        store.mutate((s) => {
          const list = s.domains[dom].line_routes[i].target_nodes;
          const pos = list.indexOf(hn);
          if (pos >= 0) list.splice(pos, 1);
          else list.push(hn);
        });
        render();
      });
    });
    container.querySelectorAll("[data-lr-vals]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          s.domains[dom].line_routes[Number(inp.dataset.lrVals)].values = inp.value
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean);
        }, false);
      });
    });

    // Live Remote Record Actions
    el("btn-rem-add")?.addEventListener("click", () => openRemoteRecordDrawer(dom, null, caps, fetchedLines));
    container.querySelectorAll("[data-rem-edit]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const rec = remoteRecords.find((r) => r.record_id === btn.dataset.remEdit);
        if (rec) openRemoteRecordDrawer(dom, rec, caps, fetchedLines);
      });
    });
    container.querySelectorAll("[data-rem-toggle]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const recId = btn.dataset.remToggle;
        const curEn = btn.dataset.remEn === "1";
        try {
          await api(`/api/dns/domains/${encodeURIComponent(dom)}/records/${encodeURIComponent(recId)}/status`, {
            method: "POST",
            body: JSON.stringify({ enabled: !curEn }),
          });
          showToast(curEn ? "Record paused on remote DNS" : "Record enabled on remote DNS");
          await inspectRemote(dom, false);
        } catch (e) {
          showToast(e.message, true);
        }
      });
    });
    container.querySelectorAll("[data-rem-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const recId = btn.dataset.remDel;
        const rec = remoteRecords.find((r) => r.record_id === recId);
        openModal({
          title: `Delete Remote DNS Record`,
          bodyHtml: `<p>Delete <code>${esc(rec?.record_type || "")} ${esc(rec?.value || recId)}</code> (line: <code>${esc(rec?.line || "default")}</code>) from remote DNS provider?</p>`,
          actions: [
            { label: t("Cancel"), cls: "ghost" },
            {
              label: t("Delete"),
              cls: "danger",
              onClick: async () => {
                try {
                  await api(`/api/dns/domains/${encodeURIComponent(dom)}/records/${encodeURIComponent(recId)}`, {
                    method: "DELETE",
                  });
                  showToast("Deleted remote DNS record");
                  await inspectRemote(dom, false);
                } catch (e) {
                  showToast(e.message, true);
                }
              },
            },
          ],
        });
      });
    });
  }

  function openRemoteRecordDrawer(dom, existingRec, caps, fetchedLines) {
    const isNew = !existingRec;
    const lineOpts = (fetchedLines.length ? fetchedLines : COMMON_ALIYUN_LINES.map((l) => ({ code: l.code, name: getLang() === "zh-CN" ? l.zh : l.en })))
      .map((l) => `<option value="${esc(l.code)}" ${(existingRec?.line || "default") === l.code ? "selected" : ""}>${esc(l.name)} (${esc(l.code)})</option>`)
      .join("");

    const hostQuickPicks = Object.entries(store.spec.nodes || {})
      .filter(([, n]) => (n.external_ips || []).length > 0)
      .flatMap(([tag, n]) => n.external_ips.map((ip) => ({ tag, ip })));

    const bodyHtml = `
      <div class="step-card">
        <div class="step-card-head"><span>${esc(dom)} · Exposure DNS Record</span></div>
        <div class="inspector-row">
          <label><span>${esc(t("Type"))} (A / AAAA / CNAME)</span>
            <select id="rr-type">
              <option value="A" ${(existingRec?.record_type || "A") === "A" ? "selected" : ""}>A (IPv4)</option>
              <option value="AAAA" ${existingRec?.record_type === "AAAA" ? "selected" : ""}>AAAA (IPv6)</option>
              <option value="CNAME" ${existingRec?.record_type === "CNAME" ? "selected" : ""}>CNAME</option>
            </select>
          </label>
          <label><span>${esc(t("TTL"))} (s)</span>
            <input id="rr-ttl" type="number" min="1" value="${existingRec?.ttl ?? 600}" />
          </label>
        </div>
        ${
          caps.supports_lines
            ? `<div class="inspector-row">
                <label><span>${esc(t("Resolution Line"))}</span>
                  <select id="rr-line">${lineOpts}</select>
                </label>
                <label><span>Or Custom Line Code</span>
                  <input id="rr-line-custom" placeholder="optional override" />
                </label>
              </div>`
            : ""
        }
        <label><span>${esc(t("Value"))} *</span>
          <input id="rr-value" value="${esc(existingRec?.value || "")}" placeholder="203.0.113.10 or target.example.net" />
        </label>
        ${
          hostQuickPicks.length
            ? `<div>
                <div class="muted-sm" style="margin-bottom:4px;">Quick-fill from Exposure Host IP:</div>
                <div class="acl-chips-row">
                  ${hostQuickPicks.map((h) => `<button type="button" class="acl-chip" data-rr-pick="${esc(h.ip)}">${esc(h.tag)}: ${esc(h.ip)}</button>`).join("")}
                </div>
              </div>`
            : ""
        }
        ${
          caps.supports_proxied
            ? `<label class="check-inline"><input type="checkbox" id="rr-proxied" ${existingRec?.proxied ? "checked" : ""} /> Cloudflare Proxied</label>`
            : ""
        }
      </div>
    `;

    const drawer = openDrawer({
      title: isNew ? t("+ Add Remote Record") : `Edit Remote Record`,
      subtitle: dom,
      bodyHtml,
      footerHtml: `
        <button type="button" id="rr-cancel" class="btn sm ghost">${esc(t("Cancel"))}</button>
        <button type="button" id="rr-submit" class="btn sm primary">${esc(t("Save"))}</button>
      `,
    });
    if (!drawer) return;

    drawer.body.querySelectorAll("[data-rr-pick]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const ip = btn.dataset.rrPick;
        if (el("rr-value")) el("rr-value").value = ip;
        if (el("rr-type")) el("rr-type").value = ip.includes(":") ? "AAAA" : "A";
      });
    });

    el("rr-cancel")?.addEventListener("click", closeDrawer);
    el("rr-submit")?.addEventListener("click", async () => {
      const payload = {
        record_type: el("rr-type").value,
        value: el("rr-value").value.trim(),
        ttl: parseNum(el("rr-ttl").value, 600, 1, 86400),
        line: caps.supports_lines
          ? el("rr-line-custom")?.value.trim() || el("rr-line")?.value || "default"
          : null,
        proxied: caps.supports_proxied ? Boolean(el("rr-proxied")?.checked) : null,
      };
      if (!payload.value) {
        showToast("Enter a record value", true);
        return;
      }
      try {
        if (isNew) {
          await api(`/api/dns/domains/${encodeURIComponent(dom)}/records`, {
            method: "POST",
            body: JSON.stringify(payload),
          });
          showToast("Created remote DNS record");
        } else {
          await api(`/api/dns/domains/${encodeURIComponent(dom)}/records/${encodeURIComponent(existingRec.record_id)}`, {
            method: "PUT",
            body: JSON.stringify(payload),
          });
          showToast("Updated remote DNS record");
        }
        closeDrawer();
        await inspectRemote(dom, false);
      } catch (e) {
        showToast(e.message, true);
      }
    });
  }

  function renderCertsSubTab(container, liveCerts) {
    const nowMs = Date.now();
    const liveCardsHtml = liveCerts.length
      ? liveCerts
          .map((c) => {
            let daysLeft = null;
            if (c.expires_at) {
              const expMs = new Date(c.expires_at).getTime();
              if (!Number.isNaN(expMs)) daysLeft = Math.max(0, Math.round((expMs - nowMs) / 86_400_000));
            }
            const pct = daysLeft != null ? Math.min(100, Math.round((daysLeft / 90) * 100)) : 0;
            const barColor = daysLeft == null ? "var(--muted)" : daysLeft > 30 ? "var(--ok)" : daysLeft > 10 ? "var(--warn)" : "var(--danger)";
            const targets = (c.targets || []).map((tg) => `<span class="role-chip ingress">${esc(tg)}</span>`).join(" ");
            return `
              <div class="cert-card">
                <div class="cert-card-head">
                  <span class="cert-domain">${esc(c.domain)}</span>
                  <span class="pill ${c.status === "valid" ? "ok" : "warn"}">${esc(c.status)}</span>
                </div>
                <div class="cert-bar-track"><div class="cert-bar-fill" style="width:${pct}%;background:${barColor}"></div></div>
                <div class="muted-sm">${daysLeft != null ? `<b>${daysLeft}d</b> left · ` : ""}Expires: ${esc(formatDateTime(c.expires_at))}</div>
                <div class="tag-list">${targets || '<span class="muted-sm">No targets</span>'}</div>
              </div>`;
          })
          .join("")
      : `<div class="muted-sm">No live certificates reported by Maintainer yet.</div>`;

    // Locate primary maintainer & template
    const primEntry = Object.entries(store.spec.nodes || {}).find(([, n]) => n.roles?.maintainer);
    const maintTag = primEntry?.[0] || null;
    const tplName = primEntry?.[1]?.maintainer_template || "default-maint";
    const tpl = maintTag ? store.spec.maintainer_templates?.[tplName] : null;
    const provKeys = Object.keys(store.spec.dns_providers || {});
    const orders = tpl?.acme?.orders || [];

    const ordersHtml = orders
      .map((o, i) => {
        const matched = resolveDomainBindingJS(store.spec.domains, o.domain);
        const hint = o.provider
          ? `Provider override: ${o.provider}`
          : matched
          ? `Auto provider: ${matched[1].provider} (via ${matched[0]})`
          : "No domain binding matched (self-signed only)";
        return `
          <div class="subcard">
            <div class="subcard-head">
              <span>Order #${i + 1}: <strong>${esc(o.domain || "(unset)")}</strong></span>
              <div class="btn-row">
                <button type="button" class="btn sm" data-cert-hops="${i}">Auto Hops</button>
                <button type="button" class="btn sm danger" data-cert-del="${i}">${esc(t("Remove"))}</button>
              </div>
            </div>
            <div class="inspector-row">
              <label><span>Domain</span><input data-cert-dom="${i}" value="${esc(o.domain || "")}" placeholder="*.example.com" /></label>
              <label><span>Provider Override (optional)</span>
                <select data-cert-prov="${i}">
                  <option value="">(auto from domain binding)</option>
                  <option value="none" ${o.provider === "none" ? "selected" : ""}>none (self-signed)</option>
                  ${provKeys.map((p) => `<option value="${esc(p)}" ${o.provider === p ? "selected" : ""}>${esc(p)}</option>`).join("")}
                </select>
              </label>
            </div>
            <div class="inspector-row">
              <label><span>Target Ingress Hosts (CSV)</span><input data-cert-targets="${i}" value="${esc((o.target_nodes || []).join(", "))}" /></label>
              <label><span>Renew Before (days)</span><input type="number" data-cert-renew="${i}" value="${o.renew_before_days ?? 30}" /></label>
            </div>
            <div class="muted-sm">${esc(hint)}</div>
          </div>`;
      })
      .join("");

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header"><h3>${esc(t("Live Certificate Status (Maintainer Telemetry)"))}</h3></div>
        <div class="certs-grid">${liveCardsHtml}</div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <h3>${esc(t("ACME Certificate Orders"))}</h3>
            ${maintTag ? `<div class="muted-sm">Maintainer: <code>${esc(maintTag)}</code> · Template: <code>${esc(tplName)}</code></div>` : ""}
          </div>
          ${
            maintTag
              ? `<button type="button" id="btn-cert-add" class="btn sm primary">${esc(t("+ Add Cert Order"))}</button>`
              : ""
          }
        </div>
        ${
          !maintTag
            ? `<div class="muted-sm">${esc(t("No Primary Maintainer configured yet. Enable the Maintainer role on a host in Hosts first."))}</div>`
            : !tpl
            ? `<button type="button" id="btn-cert-init-tpl" class="btn sm primary">Initialize ACME Template</button>`
            : `<div class="inspector-row" style="margin-bottom:12px;">
                <label><span>ACME Directory URL</span>
                  <input id="acme-dir-url" value="${esc(tpl.acme?.directory_url || "")}" placeholder="self-signed or https://acme-v02.api.letsencrypt.org/directory" />
                </label>
                <label><span>Contact Email</span>
                  <input id="acme-email" value="${esc(tpl.acme?.contact_email || "")}" placeholder="ops@example.com" />
                </label>
              </div>
              <div style="display:flex;flex-direction:column;gap:10px;">
                ${ordersHtml || '<div class="muted-sm">No ACME orders yet (note: Services with Auto-TLS enabled auto-generate orders at compile time).</div>'}
              </div>`
        }
      </div>
    `;

    el("btn-cert-init-tpl")?.addEventListener("click", () => {
      store.mutate((s) => {
        s.maintainer_templates[tplName] = defaultMaintainerTemplate();
        s.nodes[maintTag].maintainer_template = tplName;
      });
      render();
    });
    el("acme-dir-url")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.maintainer_templates[tplName].acme.directory_url = ev.target.value.trim(); }, false);
    });
    el("acme-email")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.maintainer_templates[tplName].acme.contact_email = ev.target.value.trim(); }, false);
    });
    el("btn-cert-add")?.addEventListener("click", () => {
      store.mutate((s) => {
        if (!s.maintainer_templates[tplName]) s.maintainer_templates[tplName] = defaultMaintainerTemplate();
        const ing = Object.entries(s.nodes || {}).filter(([, n]) => n.roles?.ingress).map(([k]) => k);
        s.maintainer_templates[tplName].acme.orders.push({
          domain: Object.keys(s.domains || {})[0] || "example.com",
          provider: null,
          target_nodes: ing,
          target_hops: {},
          renew_before_days: 30,
        });
      });
      render();
    });
    container.querySelectorAll("[data-cert-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        store.mutate((s) => { s.maintainer_templates[tplName].acme.orders.splice(Number(btn.dataset.certDel), 1); });
        render();
      });
    });
    container.querySelectorAll("[data-cert-dom]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => { s.maintainer_templates[tplName].acme.orders[Number(inp.dataset.certDom)].domain = inp.value.trim(); }, false);
      });
    });
    container.querySelectorAll("[data-cert-prov]").forEach((sel) => {
      sel.addEventListener("change", () => {
        store.mutate((s) => { s.maintainer_templates[tplName].acme.orders[Number(sel.dataset.certProv)].provider = sel.value || null; });
        render();
      });
    });
    container.querySelectorAll("[data-cert-targets]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          s.maintainer_templates[tplName].acme.orders[Number(inp.dataset.certTargets)].target_nodes = inp.value
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean);
        }, false);
      });
    });
    container.querySelectorAll("[data-cert-renew]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          s.maintainer_templates[tplName].acme.orders[Number(inp.dataset.certRenew)].renew_before_days = parseNum(inp.value, 30, 1, 89);
        }, false);
      });
    });
    container.querySelectorAll("[data-cert-hops]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.dataset.certHops);
        store.mutate((s) => {
          const ord = s.maintainer_templates[tplName].acme.orders[i];
          ord.target_hops = {};
          for (const tgt of ord.target_nodes || []) {
            if (tgt === maintTag) continue;
            const path = shortestPathBFS(s.links, maintTag, tgt);
            if (path) ord.target_hops[tgt] = path;
          }
        });
        showToast("Auto-computed Maintainer → Target cert hop tables");
      });
    });
  }

  function renderProvidersSubTab(container, provKeys) {
    const cardsHtml = Object.entries(store.spec.dns_providers || {})
      .map(
        ([pName, p]) => `
        <div class="subcard">
          <div class="subcard-head">
            <div style="display:flex;gap:8px;align-items:center;flex:1;">
              <input class="inline-name" data-dp-rename="${esc(pName)}" value="${esc(pName)}" />
              <span class="pill">${esc(p.type)}</span>
            </div>
            <button type="button" class="btn sm danger" data-dp-del="${esc(pName)}">${esc(t("Remove"))}</button>
          </div>
          ${
            p.type === "cloudflare"
              ? `<label><span>API Token</span><input type="password" autocomplete="off" data-dp-f="${esc(pName)}" data-dp-k="api_token" value="${esc(p.api_token || "")}" /></label>`
              : p.type === "aliyun" || p.type === "alidns"
              ? `<div class="inspector-row">
                  <label><span>AccessKey ID</span><input data-dp-f="${esc(pName)}" data-dp-k="access_key_id" value="${esc(p.access_key_id || "")}" placeholder="LTAI..." /></label>
                  <label><span>AccessKey Secret</span><input type="password" autocomplete="off" data-dp-f="${esc(pName)}" data-dp-k="access_key_secret" value="${esc(p.access_key_secret || "")}" /></label>
                </div>
                <label><span>Region ID (optional)</span><input data-dp-f="${esc(pName)}" data-dp-k="region_id" value="${esc(p.region_id || "")}" placeholder="alidns.aliyuncs.com (default)" /></label>`
              : p.type === "webhook"
              ? `<div class="inspector-row">
                  <label><span>Present URL</span><input data-dp-f="${esc(pName)}" data-dp-k="present_url" value="${esc(p.present_url || "")}" /></label>
                  <label><span>Cleanup URL</span><input data-dp-f="${esc(pName)}" data-dp-k="cleanup_url" value="${esc(p.cleanup_url || "")}" /></label>
                </div>
                <div class="inspector-row">
                  <label><span>Sync URL (optional)</span><input data-dp-f="${esc(pName)}" data-dp-k="sync_url" value="${esc(p.sync_url || "")}" /></label>
                  <label><span>Auth Header (optional)</span><input type="password" autocomplete="off" data-dp-f="${esc(pName)}" data-dp-k="auth_header" value="${esc(p.auth_header || "")}" /></label>
                </div>`
              : `<label><span>Exec Command</span><input data-dp-f="${esc(pName)}" data-dp-k="command" value="${esc(p.command || "")}" /></label>`
          }
        </div>`
      )
      .join("");

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h3>${esc(t("DNS Providers"))} (${provKeys.length})</h3>
          <div class="btn-row">
            <button type="button" id="btn-dp-ali" class="btn sm primary">+ Aliyun DNS</button>
            <button type="button" id="btn-dp-cf" class="btn sm">+ Cloudflare</button>
            <button type="button" id="btn-dp-wh" class="btn sm">+ Webhook</button>
            <button type="button" id="btn-dp-ex" class="btn sm">+ Exec</button>
          </div>
        </div>
        ${cardsHtml ? `<div class="tpl-card-grid">${cardsHtml}</div>` : `<div class="empty-state-box"><p>${esc(t("No DNS provider accounts configured yet."))}</p></div>`}
      </div>
    `;

    const addProv = (prefix, payload) => {
      store.mutate((s) => {
        let n = prefix, k = 1;
        while (s.dns_providers[n]) n = `${prefix}-${k++}`;
        s.dns_providers[n] = payload;
      });
      render();
    };
    el("btn-dp-ali")?.addEventListener("click", () => addProv("aliyun", { type: "aliyun", access_key_id: "", access_key_secret: "", region_id: null }));
    el("btn-dp-cf")?.addEventListener("click", () => addProv("cf", { type: "cloudflare", api_token: "" }));
    el("btn-dp-wh")?.addEventListener("click", () => addProv("webhook", { type: "webhook", present_url: "", cleanup_url: "", sync_url: null, auth_header: null }));
    el("btn-dp-ex")?.addEventListener("click", () => addProv("exec", { type: "exec", command: "", args: [] }));

    container.querySelectorAll("[data-dp-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        store.mutate((s) => { delete s.dns_providers[btn.dataset.dpDel]; });
        render();
      });
    });
    container.querySelectorAll("[data-dp-rename]").forEach((inp) => {
      inp.addEventListener("change", () => {
        const oldN = inp.dataset.dpRename, newN = inp.value.trim();
        if (!newN || newN === oldN || isReservedKey(newN) || store.spec.dns_providers[newN]) {
          inp.value = oldN;
          return;
        }
        store.mutate((s) => {
          s.dns_providers[newN] = s.dns_providers[oldN];
          delete s.dns_providers[oldN];
          for (const d of Object.values(s.domains || {})) if (d.provider === oldN) d.provider = newN;
          for (const tpl of Object.values(s.maintainer_templates || {})) {
            for (const o of tpl?.acme?.orders || []) if (o.provider === oldN) o.provider = newN;
          }
        });
        render();
      });
    });
    container.querySelectorAll("[data-dp-f]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const pn = inp.dataset.dpF, k = inp.dataset.dpK;
        const nullable = k === "region_id" || k === "sync_url" || k === "auth_header";
        store.mutate((s) => {
          s.dns_providers[pn][k] = nullable ? inp.value.trim() || null : inp.value.trim();
        }, false);
      });
    });
  }

  async function refresh(opts = {}) {
    if (opts.subTab) subTab = opts.subTab;
    if (!store.loaded) await store.loadTopology(false);
    try {
      const tel = await api("/api/telemetry");
      store.telemetry = tel;
    } catch {}
    render();
  }

  return { refresh, render };
}
