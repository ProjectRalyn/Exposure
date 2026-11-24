// Hosts Management View (Nodes + Observed Links + Onboarding + Slide-Over Host Config Drawer)
import { formatDateTime, formatUptime } from "../charts.js";
import { t } from "../i18n.js";
import {
  defaultMaintainerTemplate,
  defaultNodeSpec,
  defaultTopologyDefaults,
  isReservedKey,
  resolveServiceTargetIngresses,
  rolesFromAny,
  shortestPathBFS,
} from "../store.js";
import {
  closeDrawer,
  copyToClipboard,
  el,
  esc,
  generateRandomSecretHex,
  openDrawer,
  openModal,
  parseNum,
  renderBinSlider,
  renderTriSlider,
  shellQuote,
  showToast,
  wireBinSliders,
  wireTriSliders,
} from "../ui.js";

export function createHostsView({ api, store, navigate }) {
  let subTab = "nodes"; // nodes | links | onboarding
  let searchQ = "";
  let roleFilter = "all";
  let linkSearchQ = "";
  let linkStateFilter = "all";
  let passphrases = [];

  function render() {
    const root = el("tab-hosts");
    if (!root) return;

    const specNodes = store.spec.nodes || {};
    const liveMap = store.liveNodeMap();
    const allTags = new Set([...Object.keys(specNodes), ...liveMap.keys()]);
    const totalCount = allTags.size;
    let onlineCount = 0;
    let ingCount = 0;
    let relCount = 0;
    let egCount = 0;
    let mCount = 0;
    for (const tag of allTags) {
      const live = liveMap.get(tag);
      if (live?.online) onlineCount++;
      const r = specNodes[tag]?.roles || rolesFromAny(live?.roles);
      if (r.ingress) ingCount++;
      if (r.relay) relCount++;
      if (r.egress) egCount++;
      if (r.maintainer) mCount++;
    }

    root.innerHTML = `
      <div class="subtabs-bar">
        <div class="subtabs-list">
          <button type="button" class="subtab-btn ${subTab === "nodes" ? "active" : ""}" data-hosts-sub="nodes">
            ${esc(t("hosts.tab.nodes"))} <span class="subtab-count">${totalCount}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "links" ? "active" : ""}" data-hosts-sub="links">
            ${esc(t("hosts.tab.links"))} <span class="subtab-count">${(store.liveLinks || []).length}</span>
          </button>
          <button type="button" class="subtab-btn ${subTab === "onboarding" ? "active" : ""}" data-hosts-sub="onboarding">
            ${esc(t("hosts.tab.onboarding"))}
          </button>
        </div>
        ${
          subTab === "nodes"
            ? `<div class="btn-row">
                <button type="button" id="btn-hosts-sync-live" class="btn sm">${esc(t("hosts.sync_live"))}</button>
                <button type="button" id="btn-hosts-add" class="btn sm primary">${esc(t("hosts.add_host"))}</button>
              </div>`
            : ""
        }
      </div>

      <div id="hosts-sub-body"></div>
    `;

    root.querySelectorAll("[data-hosts-sub]").forEach((btn) => {
      btn.addEventListener("click", () => {
        subTab = btn.dataset.hostsSub;
        if (subTab === "onboarding") loadPassphrases();
        render();
      });
    });

    el("btn-hosts-add")?.addEventListener("click", openAddHostModal);
    el("btn-hosts-sync-live")?.addEventListener("click", importLiveHosts);

    const body = el("hosts-sub-body");
    if (subTab === "nodes") {
      renderNodesSubTab(body, { totalCount, onlineCount, ingCount, relCount, egCount, mCount, allTags, liveMap });
    } else if (subTab === "links") {
      renderLinksSubTab(body);
    } else {
      renderOnboardingSubTab(body);
    }
  }

  function renderNodesSubTab(container, stats) {
    const specNodes = store.spec.nodes || {};
    const rows = [...stats.allTags]
      .sort()
      .map((tag) => {
        const spec = specNodes[tag] || null;
        const live = stats.liveMap.get(tag) || null;
        const roles = spec?.roles || rolesFromAny(live?.roles);
        return { tag, spec, live, roles };
      })
      .filter((item) => {
        if (roleFilter !== "all" && !item.roles[roleFilter]) return false;
        if (searchQ) {
          const hay = `${item.tag} ${(item.spec?.external_ips || []).join(" ")}`.toLowerCase();
          if (!hay.includes(searchQ.toLowerCase())) return false;
        }
        return true;
      });

    container.innerHTML = `
      <div class="kpi-grid" style="margin-bottom:14px;">
        <div class="kpi"><div class="kpi-label">${esc(t("hosts.tab.nodes"))}</div><div class="kpi-val">${stats.onlineCount} / ${stats.totalCount}</div><div class="kpi-sub">Online / Total</div></div>
        <div class="kpi"><div class="kpi-label">Ingress</div><div class="kpi-val">${stats.ingCount}</div><div class="kpi-sub">Edge entry hosts</div></div>
        <div class="kpi"><div class="kpi-label">Relay</div><div class="kpi-val">${stats.relCount}</div><div class="kpi-sub">Mesh forwarders</div></div>
        <div class="kpi"><div class="kpi-label">Egress</div><div class="kpi-val">${stats.egCount}</div><div class="kpi-sub">Origin connectors</div></div>
        <div class="kpi"><div class="kpi-label">Maintainer</div><div class="kpi-val">${stats.mCount}</div><div class="kpi-sub">ACME &amp; Telemetry</div></div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <h3>${esc(t("hosts.tab.nodes"))} (${rows.length})</h3>
          <div class="btn-row">
            <input id="hosts-search-inp" class="input-sm" type="search" value="${esc(searchQ)}" placeholder="${esc(t("hosts.search"))}" />
            <select id="hosts-role-sel" class="select-sm">
              <option value="all" ${roleFilter === "all" ? "selected" : ""}>${esc(t("hosts.all_roles"))}</option>
              <option value="ingress" ${roleFilter === "ingress" ? "selected" : ""}>Ingress</option>
              <option value="relay" ${roleFilter === "relay" ? "selected" : ""}>Relay</option>
              <option value="egress" ${roleFilter === "egress" ? "selected" : ""}>Egress</option>
              <option value="maintainer" ${roleFilter === "maintainer" ? "selected" : ""}>Maintainer</option>
            </select>
          </div>
        </div>
        <div class="table-scroll">
          <table class="table">
            <thead>
              <tr>
                <th>${esc(t("hosts.col.tag"))}</th>
                <th>${esc(t("hosts.col.roles"))}</th>
                <th>${esc(t("hosts.col.ips"))}</th>
                <th>${esc(t("hosts.col.uptime"))}</th>
                <th>${esc(t("hosts.col.seq"))}</th>
                <th>${esc(t("hosts.col.status"))}</th>
                <th>${esc(t("common.actions"))}</th>
              </tr>
            </thead>
            <tbody>
              ${
                rows
                  .map(({ tag, spec, live, roles }) => {
                    const roleChips = ["ingress", "relay", "egress", "maintainer"]
                      .filter((r) => roles[r])
                      .map((r) => `<span class="role-chip ${r}">${r}</span>`)
                      .join(" ");
                    const ips = spec?.external_ips || [];
                    const ipHtml = ips.length
                      ? ips.map((ip) => `<span class="host-pill">${esc(ip)}</span>`).join(" ")
                      : `<span class="muted-sm">-</span>`;
                    const statusBadge = live
                      ? `<span class="pill ${live.online ? "ok" : "err"}">${esc(live.online ? t("common.online") : t("common.offline"))}</span>`
                      : `<span class="pill warn">${esc(t("common.draft"))}</span>`;
                    const inDraft = Boolean(spec);
                    return `
                  <tr>
                    <td>
                      <div><strong>${esc(tag)}</strong></div>
                      ${live?.pubkey_fingerprint ? `<div class="muted-sm"><code>${esc(live.pubkey_fingerprint.slice(0, 14))}</code></div>` : ""}
                    </td>
                    <td><div class="tag-list">${roleChips || '<span class="muted-sm">-</span>'}</div></td>
                    <td><div class="tag-list">${ipHtml}</div></td>
                    <td>${live ? esc(formatUptime(live.uptime_secs)) : "-"}</td>
                    <td>${live ? `#${esc(live.config_seq)}` : "-"}</td>
                    <td>${statusBadge}</td>
                    <td>
                      <div class="btn-row">
                        <button type="button" class="btn sm primary" data-cfg-host="${esc(tag)}">${esc(t("hosts.configure"))}</button>
                        ${inDraft ? `<button type="button" class="btn sm" data-topo-host="${esc(tag)}">${esc(t("hosts.locate"))}</button>` : ""}
                        ${live ? `<button type="button" class="btn sm" data-push-host="${esc(tag)}">${esc(t("hosts.push"))}</button>` : ""}
                      </div>
                    </td>
                  </tr>`;
                  })
                  .join("") || `<tr><td colspan="7" class="muted">${esc(t("hosts.empty"))}</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    `;

    el("hosts-search-inp")?.addEventListener("input", (ev) => {
      searchQ = ev.target.value;
      render();
      el("hosts-search-inp")?.focus();
    });
    el("hosts-role-sel")?.addEventListener("change", (ev) => {
      roleFilter = ev.target.value;
      render();
    });
    container.querySelectorAll("[data-cfg-host]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tag = btn.dataset.cfgHost;
        if (!store.spec.nodes[tag]) {
          // Bring live-only node into draft automatically before editing
          const live = stats.liveMap.get(tag);
          store.mutate((s) => {
            const n = defaultNodeSpec();
            n.roles = rolesFromAny(live?.roles);
            s.nodes[tag] = n;
          });
        }
        openHostDrawer(tag);
      });
    });
    container.querySelectorAll("[data-topo-host]").forEach((btn) => {
      btn.addEventListener("click", () => navigate("topology", { focusNode: btn.dataset.topoHost }));
    });
    container.querySelectorAll("[data-push-host]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const tag = btn.dataset.pushHost;
        try {
          await api(`/api/nodes/${encodeURIComponent(tag)}/push`, { method: "POST" });
          showToast(`Pushed signed config to ${tag}`);
          refresh();
        } catch (e) {
          showToast(e.message, true);
        }
      });
    });
  }

  function openAddHostModal() {
    openModal({
      title: t("hosts.add_host"),
      bodyHtml: `
        <div class="form-grid">
          <label><span>${esc(t("hosts.col.tag"))}</span>
            <input id="new-host-tag" type="text" placeholder="e.g. ingress-jp" autofocus />
          </label>
          <label><span>${esc(t("hosts.drawer.ips"))}</span>
            <input id="new-host-ips" type="text" placeholder="203.0.113.20" />
          </label>
          <div class="acl-chips-row">
            <label class="check-inline"><input type="checkbox" id="nh-r-ingress" checked /> Ingress</label>
            <label class="check-inline"><input type="checkbox" id="nh-r-relay" /> Relay</label>
            <label class="check-inline"><input type="checkbox" id="nh-r-egress" /> Egress</label>
            <label class="check-inline"><input type="checkbox" id="nh-r-maintainer" /> Maintainer</label>
          </div>
        </div>`,
      actions: [
        { label: t("common.cancel"), cls: "ghost" },
        {
          label: t("common.create"),
          cls: "primary",
          close: false,
          onClick: () => {
            const tag = (el("new-host-tag")?.value || "").trim();
            if (!tag || isReservedKey(tag) || !/^[A-Za-z0-9._-]+$/.test(tag)) {
              showToast("Invalid host tag (use letters, digits, ., _, -)", true);
              return;
            }
            if (store.spec.nodes[tag]) {
              showToast(`Host '${tag}' already exists`, true);
              return;
            }
            const ips = (el("new-host-ips")?.value || "")
              .split(/[,\s]+/)
              .map((s) => s.trim())
              .filter(Boolean);
            store.mutate((s) => {
              const n = defaultNodeSpec();
              n.roles = {
                ingress: Boolean(el("nh-r-ingress")?.checked),
                relay: Boolean(el("nh-r-relay")?.checked),
                egress: Boolean(el("nh-r-egress")?.checked),
                maintainer: Boolean(el("nh-r-maintainer")?.checked),
              };
              n.external_ips = ips;
              if (n.roles.ingress) {
                n.ingress.listeners = [
                  { listen_addr: "0.0.0.0:80", tls: false, redirect_https: true },
                  { listen_addr: "0.0.0.0:443", tls: true, redirect_https: false },
                ];
              }
              if (n.roles.maintainer) {
                if (!s.maintainer_templates["default-maint"]) {
                  s.maintainer_templates["default-maint"] = defaultMaintainerTemplate();
                }
                n.maintainer_template = "default-maint";
              }
              s.nodes[tag] = n;
            });
            el("modal-backdrop")?.classList.add("hidden");
            render();
            openHostDrawer(tag);
          },
        },
      ],
    });
  }

  function importLiveHosts() {
    let added = 0;
    store.mutate((s) => {
      for (const ln of store.liveNodes || []) {
        if (!ln.node_tag || s.nodes[ln.node_tag]) continue;
        const n = defaultNodeSpec();
        n.roles = rolesFromAny(ln.roles);
        s.nodes[ln.node_tag] = n;
        added++;
      }
    });
    showToast(added ? `Imported ${added} live host(s) into draft` : "All live hosts are already in draft");
    render();
  }

  function openHostDrawer(tag) {
    const node = store.spec.nodes[tag];
    if (!node) return;
    const defs = store.spec.defaults || defaultTopologyDefaults();
    const llDefs = defs.link_listener;
    const igDefs = defs.ingress;
    const maintainerNodes = Object.entries(store.spec.nodes || {})
      .filter(([, n]) => n.roles?.maintainer)
      .map(([k]) => k);

    // Compute read-only summary of Services touching this host
    const hostedServices = [];
    for (const [sName, svc] of Object.entries(store.spec.services || {})) {
      const asIng = node.roles.ingress && resolveServiceTargetIngresses(store.spec, svc).includes(tag);
      const asEg = node.roles.egress && svc.egress?.node === tag;
      if (asIng || asEg) {
        hostedServices.push({
          name: sName,
          role: asIng && asEg ? "Ingress + Egress" : asIng ? "Ingress" : "Egress",
          hosts: svc.hosts || [],
        });
      }
    }

    const listenersHtml = (node.ingress.listeners || [])
      .map(
        (l, i) => `
      <div class="subcard">
        <div class="subcard-head">
          <span>Listener #${i + 1}</span>
          <button type="button" class="btn sm danger" data-hd-del-lis="${i}">${esc(t("common.remove"))}</button>
        </div>
        <div class="inspector-row">
          <label><span>${esc(t("hosts.drawer.listen_addr"))}</span>
            <input data-hd-lis-addr="${i}" value="${esc(l.listen_addr || "")}" placeholder="0.0.0.0:443" />
          </label>
          <div style="align-self:end;">
            ${renderBinSlider({ attrName: "data-hd-lis-tls", attrVal: String(i), label: "TLS (HTTPS + h2)", val: l.tls })}
          </div>
        </div>
        ${
          !l.tls
            ? renderBinSlider({
                attrName: "data-hd-lis-redir",
                attrVal: String(i),
                label: "Redirect HTTP → HTTPS",
                val: l.redirect_https,
              })
            : ""
        }
      </div>`
      )
      .join("");

    const bodyHtml = `
      <div class="step-card">
        <div class="step-card-head"><span>${esc(t("hosts.drawer.roles"))}</span></div>
        <div class="acl-chips-row">
          ${["ingress", "relay", "egress", "maintainer"]
            .map(
              (r) =>
                `<button type="button" class="acl-chip ${node.roles[r] ? "active" : ""}" data-hd-role="${r}">${r.toUpperCase()}</button>`
            )
            .join("")}
        </div>
        <label><span>${esc(t("hosts.drawer.ips"))}</span>
          <input id="hd-ext-ips" value="${esc((node.external_ips || []).join(", "))}" placeholder="203.0.113.10, 2001:db8::10" />
        </label>
      </div>

      <div class="step-card">
        <div class="step-card-head">
          <span>${esc(t("hosts.drawer.mesh_listener"))}</span>
          <label class="check-inline"><input type="checkbox" id="hd-ll-en" ${node.link_listener ? "checked" : ""} /> ${esc(t("common.enabled"))}</label>
        </div>
        ${
          node.link_listener
            ? `<label><span>${esc(t("hosts.drawer.listen_addr"))}</span>
                <input id="hd-ll-addr" value="${esc(node.link_listener.listen_addr || "")}" placeholder="0.0.0.0:10802" />
              </label>
              <div class="tri-stack">
                ${renderTriSlider({ attrName: "data-hd-ll-tri", attrVal: "allow_on_demand", label: "Allow On-Demand", val: node.link_listener.allow_on_demand, inherited: llDefs.allow_on_demand })}
                ${renderTriSlider({ attrName: "data-hd-ll-tri", attrVal: "allow_tunnel", label: "Allow Reverse Tunnel", val: node.link_listener.allow_tunnel, inherited: llDefs.allow_tunnel })}
                ${renderTriSlider({ attrName: "data-hd-ll-tri", attrVal: "allow_bootstrap", label: "Allow Bootstrap", val: node.link_listener.allow_bootstrap, inherited: llDefs.allow_bootstrap })}
              </div>`
            : `<div class="muted-sm">Outbound-only mesh host (dials relays via reverse tunnel).</div>`
        }
      </div>

      ${
        node.roles.ingress
          ? `<div class="step-card">
              <div class="step-card-head">
                <span>${esc(t("hosts.drawer.ingress_listeners"))} (${node.ingress.listeners.length})</span>
                <button type="button" id="hd-add-lis" class="btn sm">+ Listener</button>
              </div>
              ${listenersHtml || '<div class="muted-sm">No HTTP/HTTPS listeners yet.</div>'}
              <div class="inspector-row" style="margin-top:6px;">
                <label><span>Server Header</span>
                  <select id="hd-ig-server">
                    <option value="" ${!node.ingress.server_header ? "selected" : ""}>(Default: ${esc(igDefs.server_header || "nginx")})</option>
                    <option value="nginx" ${node.ingress.server_header === "nginx" ? "selected" : ""}>nginx</option>
                    <option value="exposure" ${node.ingress.server_header === "exposure" ? "selected" : ""}>exposure</option>
                  </select>
                </label>
                <label><span>Cert Store Dir</span>
                  <input id="hd-ig-certdir" value="${esc(node.ingress.cert_store_dir || "")}" placeholder="${esc(igDefs.cert_store_dir || "./data/ingress-certs")}" />
                </label>
              </div>
              <div class="inspector-row">
                <label><span>Clearance Secret (empty = Default)</span>
                  <div style="display:flex;gap:6px;">
                    <input id="hd-ig-secret" type="password" autocomplete="off" value="${esc(node.ingress.clearance_secret || "")}" placeholder="Inherited from Defaults" />
                    <button type="button" id="hd-gen-secret" class="btn sm">${esc(t("common.generate"))}</button>
                  </div>
                </label>
                <label><span>JS FP Cooldown TTL (s)</span>
                  <input id="hd-ig-fpttl" type="number" min="60" value="${node.ingress.js_fp_ttl_secs ?? ""}" placeholder="Default (${igDefs.js_fp_ttl_secs ?? 3600})" />
                </label>
              </div>
              <div class="inspector-row">
                <label><span>Default Bucket Set</span>
                  <select id="hd-ig-def-bucket">
                    <option value="">(Inherit: ${esc(igDefs.default_bucket || "none")})</option>
                    ${[...new Set([...Object.keys(store.spec.bucket_templates || {}), ...Object.keys(node.ingress.rate_limit_buckets || {})])].sort().map((k) => `<option value="${esc(k)}" ${node.ingress.default_bucket === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
                  </select>
                </label>
                <label><span>Default Antibot Set</span>
                  <select id="hd-ig-def-antibot">
                    <option value="">(Inherit: ${esc(igDefs.default_antibot || "none")})</option>
                    ${[...new Set([...Object.keys(store.spec.antibot_templates || {}), ...Object.keys(node.ingress.antibot_sets || {})])].sort().map((k) => `<option value="${esc(k)}" ${node.ingress.default_antibot === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
                  </select>
                </label>
                <label><span>Default WAF Set</span>
                  <select id="hd-ig-def-waf">
                    <option value="">(Inherit: ${esc(igDefs.default_waf || "none")})</option>
                    ${[...new Set([...Object.keys(store.spec.waf_templates || {}), ...Object.keys(node.ingress.waf_sets || {})])].sort().map((k) => `<option value="${esc(k)}" ${node.ingress.default_waf === k ? "selected" : ""}>${esc(k)}</option>`).join("")}
                  </select>
                </label>
              </div>
              ${renderTriSlider({
                attrName: "data-hd-ig-tri",
                attrVal: "js_fp_beacon",
                label: "Passive JS FP Beacon (Node Default)",
                val: node.ingress.js_fp_beacon,
                inherited: igDefs.js_fp_beacon,
              })}
            </div>`
          : ""
      }

      ${
        node.roles.maintainer
          ? `<div class="step-card">
              <div class="step-card-head">
                <span>${esc(t("hosts.drawer.maint_tpl"))}</span>
                <button type="button" id="hd-open-certs" class="btn sm">Manage Certs &amp; DNS →</button>
              </div>
              <div class="inspector-row">
                <label><span>Maintainer Template</span>
                  <input id="hd-maint-tpl" value="${esc(node.maintainer_template || "default-maint")}" />
                </label>
                <label class="check-inline" style="align-self:end;padding-bottom:8px;">
                  <input type="checkbox" id="hd-maint-primary" ${store.spec.maintainer_templates?.[node.maintainer_template || "default-maint"]?.is_primary_cert_manager ? "checked" : ""} /> Primary Cert Manager
                </label>
              </div>
            </div>`
          : ""
      }

      <div class="step-card">
        <div class="step-card-head">
          <span>${esc(t("hosts.drawer.maint_hops"))}</span>
          ${
            maintainerNodes.length
              ? `<button type="button" id="hd-auto-mhops" class="btn sm">${esc(t("hosts.drawer.auto_hops"))}</button>`
              : ""
          }
        </div>
        <input id="hd-mhops" value="${esc((node.maintainer_hops || []).join(", "))}" placeholder="${esc(tag)}, relay-1, maintainer-1" />
      </div>

      <div class="step-card">
        <div class="step-card-head">
          <span>${esc(t("hosts.drawer.services_hosted"))} (${hostedServices.length})</span>
          <button type="button" id="hd-go-svcs" class="btn sm">${esc(t("topo.open_services"))}</button>
        </div>
        ${
          hostedServices.length
            ? hostedServices
                .map(
                  (hs) =>
                    `<div class="diff-row"><div><strong>${esc(hs.name)}</strong> <span class="muted-sm">${esc(hs.hosts.join(", "))}</span></div><span class="pill">${esc(hs.role)}</span></div>`
                )
                .join("")
            : `<div class="muted-sm">No declarative services bound to this host yet.</div>`
        }
      </div>
    `;

    const drawer = openDrawer({
      title: t("hosts.drawer.title", { tag }),
      subtitle: ["ingress", "relay", "egress", "maintainer"].filter((r) => node.roles[r]).join(" · ") || "No roles",
      bodyHtml,
      footerHtml: `
        <button type="button" id="hd-del-host" class="btn sm danger">${esc(t("hosts.drawer.delete_host"))}</button>
        <button type="button" id="hd-done" class="btn sm primary">${esc(t("common.close"))}</button>
      `,
    });
    if (!drawer) return;

    drawer.body.querySelectorAll("[data-hd-role]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const r = btn.dataset.hdRole;
        store.mutate((s) => {
          const cur = s.nodes[tag];
          cur.roles[r] = !cur.roles[r];
          if (r === "ingress" && cur.roles.ingress && cur.ingress.listeners.length === 0) {
            cur.ingress.listeners.push({ listen_addr: "0.0.0.0:443", tls: true, redirect_https: false });
          }
          if (r === "maintainer" && cur.roles.maintainer && !cur.maintainer_template) {
            if (!s.maintainer_templates["default-maint"]) {
              s.maintainer_templates["default-maint"] = defaultMaintainerTemplate();
            }
            cur.maintainer_template = "default-maint";
          }
        });
        render();
        openHostDrawer(tag);
      });
    });

    el("hd-ext-ips")?.addEventListener("input", (ev) => {
      store.mutate((s) => {
        s.nodes[tag].external_ips = ev.target.value
          .split(/[,\s]+/)
          .map((x) => x.trim())
          .filter(Boolean);
      }, false);
    });

    el("hd-ll-en")?.addEventListener("change", (ev) => {
      store.mutate((s) => {
        s.nodes[tag].link_listener = ev.target.checked
          ? { listen_addr: "0.0.0.0:10802", allow_on_demand: null, allow_tunnel: null, allow_bootstrap: null }
          : null;
      });
      openHostDrawer(tag);
    });
    el("hd-ll-addr")?.addEventListener("input", (ev) => {
      store.mutate((s) => {
        if (s.nodes[tag].link_listener) s.nodes[tag].link_listener.listen_addr = ev.target.value.trim();
      }, false);
    });
    wireTriSliders(drawer.body, "data-hd-ll-tri", (field, val) => {
      store.mutate((s) => {
        if (s.nodes[tag].link_listener) s.nodes[tag].link_listener[field] = val;
      }, false);
    });

    el("hd-add-lis")?.addEventListener("click", () => {
      store.mutate((s) => {
        s.nodes[tag].ingress.listeners.push({ listen_addr: "0.0.0.0:443", tls: true, redirect_https: false });
      });
      openHostDrawer(tag);
    });
    drawer.body.querySelectorAll("[data-hd-del-lis]").forEach((btn) => {
      btn.addEventListener("click", () => {
        store.mutate((s) => {
          s.nodes[tag].ingress.listeners.splice(Number(btn.dataset.hdDelLis), 1);
        });
        openHostDrawer(tag);
      });
    });
    drawer.body.querySelectorAll("[data-hd-lis-addr]").forEach((inp) => {
      inp.addEventListener("input", () => {
        store.mutate((s) => {
          s.nodes[tag].ingress.listeners[Number(inp.dataset.hdLisAddr)].listen_addr = inp.value.trim();
        }, false);
      });
    });
    wireBinSliders(drawer.body, "data-hd-lis-tls", (idx, val) => {
      store.mutate((s) => {
        s.nodes[tag].ingress.listeners[Number(idx)].tls = val;
        if (val) s.nodes[tag].ingress.listeners[Number(idx)].redirect_https = false;
      });
      openHostDrawer(tag);
    });
    wireBinSliders(drawer.body, "data-hd-lis-redir", (idx, val) => {
      store.mutate((s) => {
        s.nodes[tag].ingress.listeners[Number(idx)].redirect_https = val;
      }, false);
    });

    el("hd-ig-server")?.addEventListener("change", (ev) => {
      store.mutate((s) => { s.nodes[tag].ingress.server_header = ev.target.value; }, false);
    });
    el("hd-ig-certdir")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.nodes[tag].ingress.cert_store_dir = ev.target.value.trim() || null; }, false);
    });
    el("hd-ig-secret")?.addEventListener("input", (ev) => {
      store.mutate((s) => { s.nodes[tag].ingress.clearance_secret = ev.target.value.trim(); }, false);
    });
    el("hd-gen-secret")?.addEventListener("click", () => {
      store.mutate((s) => { s.nodes[tag].ingress.clearance_secret = generateRandomSecretHex(32); });
      openHostDrawer(tag);
    });
    el("hd-ig-fpttl")?.addEventListener("input", (ev) => {
      store.mutate((s) => {
        s.nodes[tag].ingress.js_fp_ttl_secs = ev.target.value.trim() ? parseNum(ev.target.value, 3600, 60) : null;
      }, false);
    });
    el("hd-ig-def-bucket")?.addEventListener("change", (ev) => {
      store.mutate((s) => { s.nodes[tag].ingress.default_bucket = ev.target.value || null; }, false);
    });
    el("hd-ig-def-antibot")?.addEventListener("change", (ev) => {
      store.mutate((s) => { s.nodes[tag].ingress.default_antibot = ev.target.value || null; }, false);
    });
    el("hd-ig-def-waf")?.addEventListener("change", (ev) => {
      store.mutate((s) => { s.nodes[tag].ingress.default_waf = ev.target.value || null; }, false);
    });
    wireTriSliders(drawer.body, "data-hd-ig-tri", (field, val) => {
      store.mutate((s) => { s.nodes[tag].ingress[field] = val; }, false);
    });

    el("hd-maint-tpl")?.addEventListener("change", (ev) => {
      const next = ev.target.value.trim() || "default-maint";
      store.mutate((s) => {
        if (!s.maintainer_templates[next]) s.maintainer_templates[next] = defaultMaintainerTemplate();
        s.nodes[tag].maintainer_template = next;
      });
      openHostDrawer(tag);
    });
    el("hd-maint-primary")?.addEventListener("change", (ev) => {
      store.mutate((s) => {
        const tn = s.nodes[tag].maintainer_template || "default-maint";
        if (!s.maintainer_templates[tn]) s.maintainer_templates[tn] = defaultMaintainerTemplate();
        s.maintainer_templates[tn].is_primary_cert_manager = ev.target.checked;
      });
    });
    el("hd-open-certs")?.addEventListener("click", () => {
      closeDrawer();
      navigate("domains", { subTab: "certs" });
    });

    el("hd-mhops")?.addEventListener("input", (ev) => {
      store.mutate((s) => {
        s.nodes[tag].maintainer_hops = ev.target.value
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean);
      }, false);
    });
    el("hd-auto-mhops")?.addEventListener("click", () => {
      const target = maintainerNodes[0];
      const path = shortestPathBFS(store.spec.links, tag, target);
      if (!path) {
        showToast(`No mesh path found from ${tag} to ${target}`, true);
        return;
      }
      store.mutate((s) => { s.nodes[tag].maintainer_hops = path; });
      openHostDrawer(tag);
      showToast(`Auto hops: ${path.join(" → ")}`);
    });

    el("hd-go-svcs")?.addEventListener("click", () => {
      closeDrawer();
      navigate("services");
    });

    el("hd-done")?.addEventListener("click", () => {
      closeDrawer();
      render();
    });

    el("hd-del-host")?.addEventListener("click", () => {
      store.mutate((s) => {
        delete s.nodes[tag];
        s.links = (s.links || []).filter((l) => l.from !== tag && l.to !== tag);
        for (const d of Object.values(s.domains || {})) {
          d.target_nodes = (d.target_nodes || []).filter((x) => x !== tag);
          for (const lr of d.line_routes || []) {
            lr.target_nodes = (lr.target_nodes || []).filter((x) => x !== tag);
          }
        }
      });
      closeDrawer();
      render();
      showToast(`Removed host '${tag}' from draft`);
    });
  }

  function renderLinksSubTab(container) {
    const links = (store.liveLinks || []).filter((l) => {
      if (linkStateFilter !== "all" && l.state !== linkStateFilter) return false;
      if (linkSearchQ && !`${l.node_tag} ${l.peer_tag} ${l.endpoint}`.toLowerCase().includes(linkSearchQ.toLowerCase())) {
        return false;
      }
      return true;
    });

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <h3>${esc(t("hosts.tab.links"))} (${links.length})</h3>
          <div class="btn-row">
            <input id="hl-search" class="input-sm" type="search" value="${esc(linkSearchQ)}" placeholder="Filter host / peer…" />
            <select id="hl-state" class="select-sm">
              <option value="all" ${linkStateFilter === "all" ? "selected" : ""}>${esc(t("common.all"))}</option>
              <option value="UP" ${linkStateFilter === "UP" ? "selected" : ""}>UP</option>
              <option value="DEGRADED" ${linkStateFilter === "DEGRADED" ? "selected" : ""}>DEGRADED</option>
              <option value="DOWN" ${linkStateFilter === "DOWN" ? "selected" : ""}>DOWN</option>
            </select>
          </div>
        </div>
        <div class="table-scroll">
          <table class="table">
            <thead><tr><th>Host</th><th>Peer</th><th>Endpoint</th><th>State</th><th>RTT</th><th>Loss</th></tr></thead>
            <tbody>
              ${
                links
                  .map((l) => {
                    const cls = l.state === "UP" ? "ok" : l.state === "DEGRADED" ? "warn" : "err";
                    const rtt = l.rtt_ms != null ? Number(l.rtt_ms) : null;
                    const rttPct = rtt != null ? Math.min(100, Math.round((rtt / 300) * 100)) : 0;
                    const rttColor = rtt == null ? "#64748b" : rtt < 80 ? "#009F6B" : rtt < 200 ? "#FAC800" : "#C40233";
                    const lossPct = Math.min(100, (l.loss_rate || 0) * 100);
                    const lossColor = lossPct < 1 ? "#009F6B" : lossPct < 5 ? "#FAC800" : "#C40233";
                    return `
                  <tr>
                    <td><strong>${esc(l.node_tag)}</strong></td>
                    <td>${esc(l.peer_tag)}</td>
                    <td><code>${esc(l.endpoint)}</code></td>
                    <td><span class="pill ${cls}">${esc(l.state)}</span></td>
                    <td>
                      <div class="meter-cell">
                        <div class="meter-bar"><div class="meter-fill" style="width:${rttPct}%;background:${rttColor}"></div></div>
                        <span>${rtt != null ? `${rtt} ms` : "-"}</span>
                      </div>
                    </td>
                    <td>
                      <div class="meter-cell">
                        <div class="meter-bar"><div class="meter-fill" style="width:${lossPct.toFixed(0)}%;background:${lossColor}"></div></div>
                        <span>${lossPct.toFixed(1)}%</span>
                      </div>
                    </td>
                  </tr>`;
                  })
                  .join("") || `<tr><td colspan="6" class="muted">No observed link telemetry yet</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    `;

    el("hl-search")?.addEventListener("input", (ev) => {
      linkSearchQ = ev.target.value;
      render();
      el("hl-search")?.focus();
    });
    el("hl-state")?.addEventListener("change", (ev) => {
      linkStateFilter = ev.target.value;
      render();
    });
  }

  async function loadPassphrases() {
    try {
      const data = await api("/api/passphrases");
      passphrases = data.items || [];
      if (subTab === "onboarding") render();
    } catch (e) {
      showToast(e.message, true);
    }
  }

  function renderOnboardingSubTab(container) {
    const nowSec = Math.floor(Date.now() / 1000);
    container.innerHTML = `
      <div class="dashboard-grid-2">
        <div class="panel">
          <h3>${esc(t("hosts.onboard.title"))}</h3>
          <form id="enroll-form" class="form-grid">
            <label><span>${esc(t("hosts.onboard.node_tag"))}</span>
              <input id="enroll-tag" type="text" placeholder="e.g. ingress-hk-1" required />
            </label>
            <label><span>${esc(t("hosts.onboard.passphrase"))}</span>
              <input id="enroll-passphrase" type="text" placeholder="amber-beacon-cedar-delta-echo" required />
            </label>
            <label><span>${esc(t("hosts.onboard.mode"))}</span>
              <select id="enroll-mode">
                <option value="active">${esc(t("hosts.onboard.mode_active"))}</option>
                <option value="listening">${esc(t("hosts.onboard.mode_listening"))}</option>
              </select>
            </label>
            <label><span>${esc(t("hosts.onboard.addr"))}</span>
              <input id="enroll-addr" type="text" placeholder="198.51.100.10:10802" />
            </label>
            <label><span>${esc(t("hosts.onboard.hops"))}</span>
              <input id="enroll-hops" type="text" placeholder="bootstrap-1, relay-1" />
            </label>
            <div class="form-actions">
              <button type="submit" class="btn primary">${esc(t("hosts.onboard.submit"))}</button>
            </div>
          </form>
        </div>
        <div class="panel">
          <div class="panel-header">
            <h3>${esc(t("hosts.onboard.cli"))}</h3>
            <button type="button" id="btn-copy-cli" class="btn sm">${esc(t("common.copy"))}</button>
          </div>
          <pre id="enroll-cli-preview" class="output-box"></pre>
        </div>
      </div>
      <div class="panel">
        <h3>${esc(t("hosts.onboard.registry"))}</h3>
        <table class="table">
          <thead><tr><th>Host Tag</th><th>Mode</th><th>Expires</th><th>Status</th><th>Action</th></tr></thead>
          <tbody>
            ${
              passphrases
                .map((p) => {
                  const rem = (p.expires_ts || 0) - nowSec;
                  const expText = p.revoked
                    ? "Revoked"
                    : rem > 0
                    ? `${Math.floor(rem / 60)}m ${rem % 60}s`
                    : "Expired";
                  return `
                <tr>
                  <td><strong>${esc(p.node_tag)}</strong></td>
                  <td>${esc(p.mode)}</td>
                  <td>${esc(formatDateTime(p.expires_at))} <small class="muted">(${expText})</small></td>
                  <td><span class="pill ${p.revoked || rem <= 0 ? "err" : "ok"}">${p.revoked ? "REVOKED" : rem <= 0 ? "EXPIRED" : "ACTIVE"}</span></td>
                  <td>${p.revoked ? "-" : `<button type="button" class="btn sm danger" data-revoke-pp="${esc(p.node_tag)}">Revoke</button>`}</td>
                </tr>`;
                })
                .join("") || `<tr><td colspan="5" class="muted">No passphrases registered</td></tr>`
            }
          </tbody>
        </table>
      </div>
    `;

    const updateCli = () => {
      const pre = el("enroll-cli-preview");
      if (!pre) return;
      const tag = el("enroll-tag")?.value.trim() || "node-new-1";
      const pass = el("enroll-passphrase")?.value.trim() || "<one-time-passphrase>";
      const mode = el("enroll-mode")?.value || "active";
      const addr = el("enroll-addr")?.value.trim() || "0.0.0.0:10802";
      const cfgPath = `./${tag.replace(/[^A-Za-z0-9._-]/g, "_")}.yaml`;
      pre.textContent =
        mode === "listening"
          ? `# 1. Initialize listening host\nexposure init-node --tag ${shellQuote(tag)} --output ${shellQuote(cfgPath)} --listen ${shellQuote(addr)} --ingress\n\n# 2. Start host with one-time passphrase\nEXPOSURE_PASSPHRASE=${shellQuote(pass)} exposure node --config ${shellQuote(cfgPath)}`
          : `# 1. Initialize active host pointing to bootstrap tunnel\nexposure init-node --tag ${shellQuote(tag)} --output ${shellQuote(cfgPath)} --bootstrap '<bootstrap-ip:10802>' --egress\n\n# 2. Start host\nEXPOSURE_PASSPHRASE=${shellQuote(pass)} exposure node --config ${shellQuote(cfgPath)}`;
    };
    updateCli();
    ["enroll-tag", "enroll-passphrase", "enroll-mode", "enroll-addr"].forEach((id) => {
      el(id)?.addEventListener("input", updateCli);
      el(id)?.addEventListener("change", updateCli);
    });
    el("btn-copy-cli")?.addEventListener("click", () => copyToClipboard(el("enroll-cli-preview")?.textContent || ""));
    el("enroll-form")?.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      try {
        const hops = (el("enroll-hops")?.value || "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        await api("/api/passphrases", {
          method: "POST",
          body: JSON.stringify({
            node_tag: el("enroll-tag").value.trim(),
            passphrase: el("enroll-passphrase").value.trim(),
            mode: el("enroll-mode").value,
            address: el("enroll-addr").value.trim() || null,
            via_hops: hops,
          }),
        });
        showToast("Passphrase registered");
        el("enroll-form").reset();
        loadPassphrases();
      } catch (e) {
        showToast(e.message, true);
      }
    });
    container.querySelectorAll("[data-revoke-pp]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await api(`/api/passphrases/${encodeURIComponent(btn.dataset.revokePp)}/revoke`, { method: "POST" });
          showToast(`Revoked passphrase for ${btn.dataset.revokePp}`);
          loadPassphrases();
        } catch (e) {
          showToast(e.message, true);
        }
      });
    });
  }

  async function refresh(opts = {}) {
    if (opts.subTab) subTab = opts.subTab;
    const [nodesData] = await Promise.all([
      api("/api/nodes"),
      store.loaded ? Promise.resolve() : store.loadTopology(false),
    ]);
    store.liveNodes = nodesData.nodes || [];
    store.liveLinks = nodesData.links || [];
    if (subTab === "onboarding") await loadPassphrases();
    render();
    if (opts.editHost && store.spec.nodes[opts.editHost]) {
      openHostDrawer(opts.editHost);
    }
    return nodesData;
  }

  return { refresh, render, openHostDrawer };
}
