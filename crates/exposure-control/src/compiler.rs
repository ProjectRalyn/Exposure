use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use exposure_core::config::{
    resolve_domain_binding, AbuseIpDbConfig, AutoBanConfig, CertOrderConfig, CrsUpdateConfig,
    CustomPagesConfig, DomainLineRecordType, EgressConfig, EgressDefaults, EgressServiceConfig,
    EvilpotNodeConfig, GuardDefaults, GuardProfile, IngressConfig, IngressDefaults, IngressRule,
    LinkListenConfig, LinkListenerDefaults, LinkMode, LoggerConfig, NodeCacheConfig, NodeConfig,
    PeerConfig, ProbeConfig, RateLimitBucket, RelayConfig, RelayRule, RuleMatch,
    ServiceIngressMode, ServiceRoutingMode, TopologySpec, TrustedMaintainer, TrustedOrigin,
    TunnelDirection,
};
use exposure_core::crs::WafRuleDescriptor;
use exposure_core::crypto::{is_weak_secret, validate_dns_domain, validate_identifier};
use exposure_core::routing::canonical_ip;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

const MAX_HOP_PATH_LEN: usize = 16;
const MAX_CUSTOM_PAGE_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRouteTrace {
    pub ingress: String,
    #[serde(default)]
    pub rule_name: Option<String>,
    pub service_tag: String,
    pub hops: Vec<String>,
    #[serde(default)]
    pub backend: Option<String>,
    pub valid: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileReport {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub compiled_nodes: Vec<String>,
    #[serde(default)]
    pub paths: Vec<ServiceRouteTrace>,
}

fn validate_endpoint_address(
    raw: &str,
    label: &str,
    errors: &mut Vec<String>,
) {
    let trimmed = raw.trim();
    match trimmed.rsplit_once(':') {
        Some((host, port_str))
            if !host.is_empty()
                && port_str.parse::<u16>().map(|p| p > 0).unwrap_or(false) =>
        {
            let clean = host
                .trim_matches(|c| c == '[' || c == ']')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let is_local_name = clean == "localhost" || clean.ends_with(".localhost");
            let is_local_ip = clean
                .parse::<IpAddr>()
                .map(|ip| {
                    let c = canonical_ip(ip);
                    c.is_loopback() || c.is_unspecified()
                })
                .unwrap_or(false);
            if is_local_name || is_local_ip {
                errors.push(format!(
                    "{label} uses local/wildcard endpoint '{raw}' — specify a reachable LAN/WAN IP"
                ));
            }
        }
        _ => {
            errors.push(format!(
                "{label} has invalid endpoint '{raw}' (expected host:port)"
            ));
        }
    }
}

fn validate_cidr_list(cidrs: &[String], label: &str, errors: &mut Vec<String>) {
    for raw in cidrs {
        let s = raw.trim();
        if s.parse::<IpNet>().is_err() && s.parse::<IpAddr>().is_err() {
            errors.push(format!("{label} contains invalid CIDR/IP '{raw}'"));
        }
    }
}

fn resolve_link_listener(
    ll: &LinkListenConfig,
    defs: &LinkListenerDefaults,
) -> LinkListenConfig {
    LinkListenConfig {
        listen_addr: ll.listen_addr.clone(),
        allow_on_demand: Some(ll.allow_on_demand.unwrap_or(defs.allow_on_demand)),
        allow_tunnel: Some(ll.allow_tunnel.unwrap_or(defs.allow_tunnel)),
        allow_bootstrap: Some(ll.allow_bootstrap.unwrap_or(defs.allow_bootstrap)),
    }
}

fn resolve_guard_profile(g: &GuardProfile, defs: &GuardDefaults) -> GuardProfile {
    let mut out = g.clone();
    if out.rate_limit_bucket.as_deref().map(str::trim).unwrap_or("").is_empty() {
        out.rate_limit_bucket = defs.rate_limit_bucket.clone();
    }
    out.bind_ua = Some(out.bind_ua.unwrap_or(defs.bind_ua));
    out.bind_ip_prefix = Some(out.bind_ip_prefix.unwrap_or(defs.bind_ip_prefix));
    out.block_bots = Some(out.block_bots.unwrap_or(defs.block_bots));
    out.browser_only = Some(out.browser_only.unwrap_or(defs.browser_only));
    out.block_headless = Some(out.block_headless.unwrap_or(defs.block_headless));
    out.require_client_fp = Some(out.require_client_fp.unwrap_or(defs.require_client_fp));
    out.js_fp_beacon = Some(out.js_fp_beacon.unwrap_or(defs.js_fp_beacon));
    out.js_fp_ttl_secs = Some(out.js_fp_ttl_secs.unwrap_or(defs.js_fp_ttl_secs).max(60));
    let mut waf = out.waf.unwrap_or_else(|| defs.waf.clone());
    waf.min_confidence = waf.min_confidence.clamp(0.1, 1.0);
    waf.max_body_bytes = waf.max_body_bytes.min(256 * 1024);
    waf.crs_paranoia_level = waf.crs_paranoia_level.clamp(1, 4);
    out.waf = Some(waf);
    out
}

fn resolve_bucket(b: &RateLimitBucket) -> RateLimitBucket {
    RateLimitBucket {
        capacity: b.capacity,
        refill_per_sec: b.refill_per_sec,
        per_ip: Some(b.effective_per_ip()),
    }
}

fn inherit_opt_page(node_val: &mut Option<String>, default_val: &Option<String>) {
    let empty = node_val.as_deref().map(str::trim).unwrap_or("").is_empty();
    if empty {
        *node_val = default_val
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
    }
}

fn validate_custom_pages(pages: &CustomPagesConfig, label: &str, errors: &mut Vec<String>) {
    for (field, val) in [
        ("error_html", &pages.error_html),
        ("challenge_html", &pages.challenge_html),
        ("challenge_css", &pages.challenge_css),
    ] {
        if let Some(s) = val {
            if s.len() > MAX_CUSTOM_PAGE_BYTES {
                errors.push(format!(
                    "{label}.pages.{field} exceeds {} byte limit",
                    MAX_CUSTOM_PAGE_BYTES
                ));
            }
        }
    }
}

fn resolve_ingress_config(
    src: &IngressConfig,
    ingress_defs: &IngressDefaults,
    guard_defs: &GuardDefaults,
    page_defs: &CustomPagesConfig,
    global_guards: &BTreeMap<String, GuardProfile>,
    global_buckets: &BTreeMap<String, RateLimitBucket>,
) -> IngressConfig {
    let mut out = src.clone();

    // Merge global bucket templates + node-local overrides
    let mut eff_buckets: BTreeMap<String, RateLimitBucket> = global_buckets
        .iter()
        .map(|(k, v)| (k.clone(), resolve_bucket(v)))
        .collect();
    for (k, v) in &src.rate_limit_buckets {
        eff_buckets.insert(k.clone(), resolve_bucket(v));
    }
    out.rate_limit_buckets = eff_buckets;

    // Merge global guard templates + node-local overrides, resolving tri-state defaults
    let mut eff_guards: BTreeMap<String, GuardProfile> = global_guards
        .iter()
        .map(|(k, v)| (k.clone(), resolve_guard_profile(v, guard_defs)))
        .collect();
    for (k, v) in &src.guards {
        eff_guards.insert(k.clone(), resolve_guard_profile(v, guard_defs));
    }
    out.guards = eff_guards;

    if out.clearance_secret.trim().is_empty() && !ingress_defs.clearance_secret.trim().is_empty() {
        out.clearance_secret = ingress_defs.clearance_secret.clone();
    }
    if out.server_header.trim().is_empty() && !ingress_defs.server_header.trim().is_empty() {
        out.server_header = ingress_defs.server_header.clone();
    }
    if out.cert_store_dir.as_deref().map(str::trim).unwrap_or("").is_empty() {
        out.cert_store_dir = ingress_defs.cert_store_dir.clone();
    }
    out.js_fp_beacon = Some(out.js_fp_beacon.unwrap_or(ingress_defs.js_fp_beacon));
    out.js_fp_ttl_secs = Some(out.js_fp_ttl_secs.unwrap_or(ingress_defs.js_fp_ttl_secs).max(60));

    for rule in &mut out.rules {
        if rule.guard.as_deref().map(str::trim).unwrap_or("").is_empty() {
            rule.guard = ingress_defs.default_guard.clone();
        }
        rule.intercept_errors = Some(
            rule.intercept_errors
                .unwrap_or(ingress_defs.intercept_errors),
        );
        // Rule js_fp_beacon: preserve explicit override, else let guard/node default apply
        if rule.js_fp_beacon.is_none() && rule.guard.is_none() {
            rule.js_fp_beacon = out.js_fp_beacon;
        }
    }
    inherit_opt_page(&mut out.pages.error_html, &page_defs.error_html);
    inherit_opt_page(&mut out.pages.challenge_html, &page_defs.challenge_html);
    inherit_opt_page(&mut out.pages.challenge_css, &page_defs.challenge_css);
    if out.cache == NodeCacheConfig::default() {
        out.cache = ingress_defs.cache.clone();
    }
    if out.evilpot == EvilpotNodeConfig::default() {
        out.evilpot = ingress_defs.evilpot.clone();
    }
    if out.auto_ban == AutoBanConfig::default() {
        out.auto_ban = ingress_defs.auto_ban.clone();
    }
    out.auto_ban.ban_ttl_secs = out.auto_ban.ban_ttl_secs.clamp(60, 86_400);
    out.auto_ban.max_ban_ttl_secs = out
        .auto_ban
        .max_ban_ttl_secs
        .max(out.auto_ban.ban_ttl_secs)
        .clamp(60, 7 * 86_400);
    out.auto_ban.confirm_hits = out.auto_ban.confirm_hits.clamp(1, 50);
    if out.abuseipdb == AbuseIpDbConfig::default() {
        out.abuseipdb = ingress_defs.abuseipdb.clone();
    }
    if out.crs == CrsUpdateConfig::default() {
        out.crs = ingress_defs.crs.clone();
    }
    out.crs.paranoia_level = out.crs.paranoia_level.clamp(1, 4);
    out.crs.update_interval_hours = out.crs.update_interval_hours.clamp(1, 720);
    // Merge cluster-wide disabled rule IDs into every guard's WAF config so both
    // `sigil-filter` (100001..100012) and OWASP CRS rules honor global toggles.
    if !out.crs.disabled_rule_ids.is_empty() {
        for g in out.guards.values_mut() {
            if let Some(ref mut waf) = g.waf {
                for &id in &out.crs.disabled_rule_ids {
                    if !waf.disabled_rule_ids.contains(&id) {
                        waf.disabled_rule_ids.push(id);
                    }
                }
            }
        }
    }
    out
}

/// Inject active OWASP CRS ruleset descriptors into every compiled Ingress node config.
pub fn inject_crs_rules(
    compiled: &mut BTreeMap<String, NodeConfig>,
    rules: &[WafRuleDescriptor],
) {
    for cfg in compiled.values_mut() {
        if cfg.roles.ingress {
            cfg.ingress.crs_rules = rules.to_vec();
        } else {
            cfg.ingress.crs_rules.clear();
        }
    }
}

fn resolve_egress_config(
    src: &EgressConfig,
    defs: &EgressDefaults,
    page_defs: &CustomPagesConfig,
) -> EgressConfig {
    let mut out = src.clone();
    for svc in out.services.values_mut() {
        svc.tls = Some(svc.tls.unwrap_or(defs.tls));
        if svc.ca_cert_path.as_deref().map(str::trim).unwrap_or("").is_empty() {
            svc.ca_cert_path = defs.ca_cert_path.clone();
        }
        svc.insecure_skip_verify = Some(
            svc.insecure_skip_verify
                .unwrap_or(defs.insecure_skip_verify),
        );
        svc.allow_any_origin = Some(svc.allow_any_origin.unwrap_or(defs.allow_any_origin));
        svc.intercept_errors = Some(svc.intercept_errors.unwrap_or(defs.intercept_errors));
        if svc.timeout_ms == 0 {
            svc.timeout_ms = defs.timeout_ms;
        }
    }
    inherit_opt_page(&mut out.pages.error_html, &page_defs.error_html);
    // Egress does not serve PoW challenge pages
    out.pages.challenge_html = None;
    out.pages.challenge_css = None;
    out
}

/// Compile a `TopologySpec` into complete per-node `NodeConfig` maps.
/// Enforces pinned node public keys (`require_pinned_pubkeys = true` for production push).
pub fn compile_topology(
    topo: &TopologySpec,
    control_public_key: &str,
    node_pubkeys: &HashMap<String, String>,
    maintainer_keys: &HashMap<String, (String, String)>,
) -> (CompileReport, BTreeMap<String, NodeConfig>) {
    compile_topology_with_options(
        topo,
        control_public_key,
        control_public_key,
        node_pubkeys,
        maintainer_keys,
        true,
    )
}

/// Compile a `TopologySpec` with explicit control link key and pinned-key enforcement option.
pub fn compile_topology_with_options(
    topo: &TopologySpec,
    control_signing_public_key: &str,
    control_link_public_key: &str,
    node_pubkeys: &HashMap<String, String>,
    maintainer_keys: &HashMap<String, (String, String)>,
    require_pinned_pubkeys: bool,
) -> (CompileReport, BTreeMap<String, NodeConfig>) {
    compile_topology_full(
        topo,
        control_signing_public_key,
        control_link_public_key,
        node_pubkeys,
        maintainer_keys,
        require_pinned_pubkeys,
        None,
    )
}

fn cert_covers_host(cert_domain: &str, host: &str) -> bool {
    let cert = cert_domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if cert.is_empty() || h.is_empty() {
        return false;
    }
    if cert == h {
        return true;
    }
    if let Some(suffix) = cert.strip_prefix("*.") {
        if let Some(prefix) = h.strip_suffix(&format!(".{suffix}")) {
            return !prefix.is_empty() && !prefix.contains('.');
        }
    }
    false
}

fn build_mesh_adj(topo: &TopologySpec) -> HashMap<String, Vec<String>> {
    let mut adj: HashMap<String, HashSet<String>> = HashMap::new();
    for link in &topo.links {
        if !topo.nodes.contains_key(&link.from) || !topo.nodes.contains_key(&link.to) || link.from == link.to {
            continue;
        }
        if link.mode == LinkMode::Tunnel && link.tunnel_direction == Some(TunnelDirection::Inbound) {
            continue;
        }
        adj.entry(link.from.clone()).or_default().insert(link.to.clone());
        if link.mode == LinkMode::Tunnel
            || (link.mode == LinkMode::OnDemand
                && link.bidirectional
                && !link.reverse_endpoints.is_empty())
        {
            adj.entry(link.to.clone()).or_default().insert(link.from.clone());
        }
    }
    adj.into_iter()
        .map(|(k, v)| {
            let mut list: Vec<String> = v.into_iter().collect();
            list.sort();
            (k, list)
        })
        .collect()
}

fn find_mesh_path_bfs(
    start: &str,
    goal: &str,
    topo: &TopologySpec,
    adj: &HashMap<String, Vec<String>>,
    require_relay_intermediate: bool,
) -> Option<Vec<String>> {
    if start == goal {
        return Some(vec![start.to_string()]);
    }
    let mut visited: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<Vec<String>> = VecDeque::new();
    visited.insert(start);
    queue.push_back(vec![start.to_string()]);
    while let Some(path) = queue.pop_front() {
        if path.len() >= MAX_HOP_PATH_LEN {
            continue;
        }
        let last = path.last().unwrap().as_str();
        if let Some(nbs) = adj.get(last) {
            for nb in nbs {
                if !visited.insert(nb.as_str()) {
                    continue;
                }
                if nb != goal && require_relay_intermediate {
                    let is_relay = topo.nodes.get(nb).map(|n| n.roles.relay).unwrap_or(false);
                    if !is_relay {
                        continue;
                    }
                }
                let mut next = path.clone();
                next.push(nb.clone());
                if nb == goal {
                    return Some(next);
                }
                queue.push_back(next);
            }
        }
    }
    None
}

fn resolve_link_peer_tag(topo: &TopologySpec, from: &str, to: &str) -> String {
    for link in &topo.links {
        if link.from == from && link.to == to {
            if let Some(ref pt) = link.peer_tag {
                if !pt.trim().is_empty() {
                    return pt.clone();
                }
            }
            return to.to_string();
        }
    }
    to.to_string()
}

/// Expand top-level declarative `TopologySpec.services` into per-node Ingress rules,
/// intermediate Relay rules, Egress service entries (with automatic `allow_from` ACLs),
/// and optional Primary Maintainer ACME cert orders.
fn expand_declarative_services(
    src: &TopologySpec,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> TopologySpec {
    if src.services.is_empty() {
        return src.clone();
    }

    let mut out = src.clone();
    let adj = build_mesh_adj(src);
    let all_ingress_nodes: Vec<String> = src
        .nodes
        .iter()
        .filter(|(_, n)| n.roles.ingress)
        .map(|(tag, _)| tag.clone())
        .collect();

    // Locate primary maintainer (for auto_tls)
    let primary_maint: Option<(String, String)> = src.nodes.iter().find_map(|(tag, n)| {
        if !n.roles.maintainer {
            return None;
        }
        let tpl_name = n.maintainer_template.as_deref()?;
        let tpl = src.maintainer_templates.get(tpl_name)?;
        if tpl.is_primary_cert_manager {
            Some((tag.clone(), tpl_name.to_string()))
        } else {
            None
        }
    });

    for (svc_name, svc) in &src.services {
        if let Err(e) = validate_identifier(svc_name, "service") {
            errors.push(e.to_string());
            continue;
        }
        if !svc.enabled {
            continue;
        }
        let hosts: Vec<String> = svc
            .hosts
            .iter()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .collect();
        if hosts.is_empty() {
            errors.push(format!(
                "service '{svc_name}' must specify at least one host (use '*' explicitly for wildcard)"
            ));
            continue;
        }
        validate_cidr_list(
            &svc.source_cidrs,
            &format!("service '{svc_name}'.source_cidrs"),
            errors,
        );
        for (ov_node, ov) in &svc.ingress.overrides {
            if !src.nodes.contains_key(ov_node) {
                errors.push(format!(
                    "service '{svc_name}' ingress override references unknown node '{ov_node}'"
                ));
            }
            validate_cidr_list(
                &ov.source_cidrs,
                &format!("service '{svc_name}'.ingress.overrides['{ov_node}'].source_cidrs"),
                errors,
            );
        }

        let egress_node = svc.egress.node.trim();
        if egress_node.is_empty() {
            errors.push(format!("service '{svc_name}' is missing egress.node"));
            continue;
        }
        match src.nodes.get(egress_node) {
            None => {
                errors.push(format!(
                    "service '{svc_name}' references unknown egress node '{egress_node}'"
                ));
                continue;
            }
            Some(n) if !n.roles.egress => {
                errors.push(format!(
                    "service '{svc_name}' targets node '{egress_node}' which does not have egress role enabled"
                ));
                continue;
            }
            _ => {}
        }
        if svc.egress.backend.trim().is_empty() {
            errors.push(format!("service '{svc_name}' is missing egress.backend"));
            continue;
        }

        // Resolve target ingress nodes according to ingress.mode
        let target_ingresses: Vec<String> = match svc.ingress.mode {
            ServiceIngressMode::All => all_ingress_nodes.clone(),
            ServiceIngressMode::Selected => {
                let mut list = Vec::new();
                for tag in &svc.ingress.nodes {
                    match src.nodes.get(tag) {
                        None => errors.push(format!(
                            "service '{svc_name}' ingress.nodes references unknown node '{tag}'"
                        )),
                        Some(n) if !n.roles.ingress => errors.push(format!(
                            "service '{svc_name}' ingress.nodes references '{tag}' which does not have ingress role enabled"
                        )),
                        Some(_) => {
                            if !list.contains(tag) {
                                list.push(tag.clone());
                            }
                        }
                    }
                }
                list
            }
            ServiceIngressMode::Exclude => {
                let excl: HashSet<&str> = svc.ingress.nodes.iter().map(|s| s.as_str()).collect();
                for tag in &svc.ingress.nodes {
                    if !src.nodes.contains_key(tag) {
                        warnings.push(format!(
                            "service '{svc_name}' excludes unknown ingress node '{tag}'"
                        ));
                    }
                }
                all_ingress_nodes
                    .iter()
                    .filter(|t| !excl.contains(t.as_str()))
                    .cloned()
                    .collect()
            }
        };

        if target_ingresses.is_empty() {
            warnings.push(format!(
                "service '{svc_name}' matches zero ingress nodes and will not receive external traffic"
            ));
        }

        // Register egress service on target egress node (reject collision with manual egress.services)
        if let Some(eg_spec) = out.nodes.get_mut(egress_node) {
            if eg_spec.egress.services.contains_key(svc_name) {
                errors.push(format!(
                    "service '{svc_name}' conflicts with existing node-level egress service '{svc_name}' on '{egress_node}'"
                ));
                continue;
            }
            eg_spec.egress.services.insert(
                svc_name.clone(),
                EgressServiceConfig {
                    backend: svc.egress.backend.trim().to_string(),
                    protocol: svc.egress.protocol,
                    tls: svc.egress.tls,
                    ca_cert_path: svc.egress.ca_cert_path.clone(),
                    insecure_skip_verify: svc.egress.insecure_skip_verify,
                    allow_from: target_ingresses.clone(),
                    allow_any_origin: Some(false),
                    timeout_ms: svc.egress.timeout_ms,
                    intercept_errors: svc.egress.intercept_errors,
                    local_health_check: svc.egress.local_health_check.clone(),
                },
            );
        }

        // Expand ingress rules & intermediate relay rules for every targeted ingress node
        for ig_tag in &target_ingresses {
            let hops: Option<Vec<String>> = if ig_tag == egress_node {
                Some(vec![ig_tag.clone()])
            } else if svc.routing.mode == ServiceRoutingMode::Pinned {
                if let Some(pinned) = svc.routing.pinned_paths.get(ig_tag) {
                    if !pinned.is_empty() {
                        Some(pinned.clone())
                    } else {
                        find_mesh_path_bfs(ig_tag, egress_node, src, &adj, true)
                    }
                } else {
                    find_mesh_path_bfs(ig_tag, egress_node, src, &adj, true)
                }
            } else {
                find_mesh_path_bfs(ig_tag, egress_node, src, &adj, true)
            };

            let Some(hops) = hops else {
                errors.push(format!(
                    "service '{svc_name}': no reachable mesh route from ingress '{ig_tag}' to egress '{egress_node}'"
                ));
                continue;
            };

            // Validate pinned path shape if >1 hop
            if hops.len() >= 2 {
                if hops.first().map(String::as_str) != Some(ig_tag.as_str())
                    || hops.last().map(String::as_str) != Some(egress_node)
                {
                    errors.push(format!(
                        "service '{svc_name}' pinned path for '{ig_tag}' must start at '{ig_tag}' and end at '{egress_node}'"
                    ));
                    continue;
                }
                let mut path_ok = true;
                for win in hops.windows(2) {
                    let linked = adj
                        .get(&win[0])
                        .map(|nbs| nbs.iter().any(|x| x == &win[1]))
                        .unwrap_or(false);
                    if !linked {
                        errors.push(format!(
                            "service '{svc_name}' route from '{ig_tag}': no link from '{}' to '{}'",
                            win[0], win[1]
                        ));
                        path_ok = false;
                    }
                }
                for mid in &hops[1..hops.len() - 1] {
                    if !src.nodes.get(mid).map(|n| n.roles.relay).unwrap_or(false) {
                        errors.push(format!(
                            "service '{svc_name}' route from '{ig_tag}': intermediate hop '{mid}' does not enable relay role"
                        ));
                        path_ok = false;
                    }
                }
                if !path_ok {
                    continue;
                }
            }

            let next_peer = if hops.len() <= 1 {
                "local".to_string()
            } else {
                resolve_link_peer_tag(src, ig_tag, &hops[1])
            };

            let ov = svc.ingress.overrides.get(ig_tag);
            let eff_guard = ov
                .and_then(|o| o.guard.clone())
                .or_else(|| svc.guard.clone());
            let eff_cidrs = ov
                .filter(|o| !o.source_cidrs.is_empty())
                .map(|o| o.source_cidrs.clone())
                .unwrap_or_else(|| svc.source_cidrs.clone());
            let eff_intercept = ov
                .and_then(|o| o.intercept_errors)
                .or(svc.intercept_errors);
            let eff_beacon = ov.and_then(|o| o.js_fp_beacon).or(svc.js_fp_beacon);
            let eff_cache = ov
                .and_then(|o| o.cache.clone())
                .or_else(|| svc.cache.clone());

            if let Some(ig_spec) = out.nodes.get_mut(ig_tag) {
                for (hi, host) in hosts.iter().enumerate() {
                    let rule_name = if hosts.len() == 1 {
                        format!("svc:{svc_name}")
                    } else {
                        format!("svc:{svc_name}#{}", hi + 1)
                    };
                    ig_spec.ingress.rules.push(IngressRule {
                        name: Some(rule_name),
                        r#match: RuleMatch {
                            host: Some(host.clone()),
                            url_prefix: svc.url_prefix.clone().filter(|s| !s.trim().is_empty()),
                            source_cidrs: eff_cidrs.clone(),
                            sni: svc.sni.clone().filter(|s| !s.trim().is_empty()),
                        },
                        service_tag: svc_name.clone(),
                        next_peer: next_peer.clone(),
                        guard: eff_guard.clone(),
                        intercept_errors: eff_intercept,
                        js_fp_beacon: eff_beacon,
                        cache: eff_cache.clone(),
                    });
                }
            }

            // Inject intermediate relay rules (deduplicated; detect conflicting next_peer)
            for idx in 1..hops.len().saturating_sub(1) {
                let relay_tag = &hops[idx];
                let hop_next = resolve_link_peer_tag(src, relay_tag, &hops[idx + 1]);
                if let Some(r_spec) = out.nodes.get_mut(relay_tag) {
                    if let Some(existing) = r_spec
                        .relay
                        .rules
                        .iter()
                        .find(|r| r.service_tag == *svc_name)
                    {
                        if existing.next_peer != hop_next {
                            errors.push(format!(
                                "service '{svc_name}' has conflicting relay next_peer on '{relay_tag}' ('{}' vs '{}')",
                                existing.next_peer, hop_next
                            ));
                        }
                    } else {
                        r_spec.relay.rules.push(RelayRule {
                            service_tag: svc_name.clone(),
                            next_peer: hop_next,
                        });
                    }
                }
            }
        }

        // Auto-TLS: ensure Primary Maintainer has cert coverage & target_hops for every non-wildcard host
        if svc.auto_tls && !target_ingresses.is_empty() {
            if let Some((ref maint_tag, ref tpl_name)) = primary_maint {
                if let Some(tpl) = out.maintainer_templates.get_mut(tpl_name) {
                    for host in &hosts {
                        if host == "*" {
                            continue;
                        }
                        let covered_idx = tpl
                            .acme
                            .orders
                            .iter()
                            .position(|ord| cert_covers_host(&ord.domain, host));
                        let order = match covered_idx {
                            Some(i) => &mut tpl.acme.orders[i],
                            None => {
                                tpl.acme.orders.push(CertOrderConfig {
                                    domain: host.clone(),
                                    provider: None,
                                    target_nodes: Vec::new(),
                                    target_hops: BTreeMap::new(),
                                    renew_before_days: 30,
                                });
                                tpl.acme.orders.last_mut().unwrap()
                            }
                        };
                        for ig_tag in &target_ingresses {
                            if !order.target_nodes.contains(ig_tag) {
                                order.target_nodes.push(ig_tag.clone());
                            }
                            if ig_tag != maint_tag && !order.target_hops.contains_key(ig_tag) {
                                if let Some(m_hops) =
                                    find_mesh_path_bfs(maint_tag, ig_tag, src, &adj, false)
                                {
                                    order.target_hops.insert(ig_tag.clone(), m_hops);
                                }
                            }
                        }
                    }
                }
            } else {
                warnings.push(format!(
                    "service '{svc_name}' enables auto_tls, but no primary maintainer node is configured"
                ));
            }
        }
    }

    out
}

/// Full topology compiler supporting cluster-wide logger HMAC key injection for accurate cross-node UV.
pub fn compile_topology_full(
    topo: &TopologySpec,
    control_signing_public_key: &str,
    control_link_public_key: &str,
    node_pubkeys: &HashMap<String, String>,
    maintainer_keys: &HashMap<String, (String, String)>,
    require_pinned_pubkeys: bool,
    cluster_hmac_key: Option<&str>,
) -> (CompileReport, BTreeMap<String, NodeConfig>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let expanded_topo = expand_declarative_services(topo, &mut errors, &mut warnings);
    let topo = &expanded_topo;
    let mut peer_map: HashMap<String, Vec<PeerConfig>> = HashMap::new();
    let mut adj: HashMap<String, HashSet<String>> = HashMap::new();

    // Pre-resolve effective link listeners, ingress configs (with global templates/defaults), and egress configs
    let resolved_listeners: HashMap<String, LinkListenConfig> = topo
        .nodes
        .iter()
        .filter_map(|(tag, spec)| {
            spec.link_listener.as_ref().map(|ll| {
                (
                    tag.clone(),
                    resolve_link_listener(ll, &topo.defaults.link_listener),
                )
            })
        })
        .collect();

    let resolved_ingress: HashMap<String, IngressConfig> = topo
        .nodes
        .iter()
        .filter(|(_, spec)| spec.roles.ingress)
        .map(|(tag, spec)| {
            (
                tag.clone(),
                resolve_ingress_config(
                    &spec.ingress,
                    &topo.defaults.ingress,
                    &topo.defaults.guard,
                    &topo.defaults.pages,
                    &topo.guard_templates,
                    &topo.bucket_templates,
                ),
            )
        })
        .collect();

    let resolved_egress: HashMap<String, EgressConfig> = topo
        .nodes
        .iter()
        .filter(|(_, spec)| spec.roles.egress)
        .map(|(tag, spec)| {
            (
                tag.clone(),
                resolve_egress_config(&spec.egress, &topo.defaults.egress, &topo.defaults.pages),
            )
        })
        .collect();

    // 0. Validate global logger, global templates, custom pages, node tags, guards, buckets, CIDRs, and maintainer templates
    validate_custom_pages(&topo.defaults.pages, "defaults", &mut errors);
    if let Some(ref gl) = topo.global_logger {
        if !gl.hmac_key.is_empty() && is_weak_secret(&gl.hmac_key) {
            errors.push(
                "global_logger.hmac_key uses a weak or default secret; provide >=16 random chars or leave empty to auto-generate".into(),
            );
        }
    }
    if !topo.defaults.ingress.clearance_secret.is_empty()
        && is_weak_secret(&topo.defaults.ingress.clearance_secret)
    {
        warnings.push(
            "defaults.ingress.clearance_secret uses a weak or default secret; set a high-entropy random secret (>=16 chars)".into(),
        );
    }
    for (g_name, g) in &topo.guard_templates {
        let resolved_g = resolve_guard_profile(g, &topo.defaults.guard);
        validate_cidr_list(
            &resolved_g.allow_cidrs,
            &format!("guard_templates '{g_name}'.allow_cidrs"),
            &mut errors,
        );
        validate_cidr_list(
            &resolved_g.deny_cidrs,
            &format!("guard_templates '{g_name}'.deny_cidrs"),
            &mut errors,
        );
        if let Some(ref bname) = resolved_g.rate_limit_bucket {
            if !bname.trim().is_empty() && !topo.bucket_templates.contains_key(bname) {
                warnings.push(format!(
                    "guard_template '{g_name}' references rate_limit_bucket '{bname}' not in bucket_templates (must exist on each ingress node using it)"
                ));
            }
        }
    }

    for (dom_key, binding) in &topo.domains {
        if let Err(e) = validate_dns_domain(dom_key) {
            errors.push(format!("domains '{dom_key}': {e}"));
        } else if dom_key.trim() == "*" {
            errors.push("domains key '*' is not a valid DNS domain".into());
        }
        let prov = binding.provider.trim();
        if prov.is_empty() {
            errors.push(format!("domain '{dom_key}' is missing DNS provider account"));
        } else if !topo.dns_providers.contains_key(prov) {
            errors.push(format!(
                "domain '{dom_key}' references unknown dns_provider '{prov}'"
            ));
        }
        if let Some(ref root) = binding.root_domain {
            let rt = root.trim().trim_end_matches('.');
            if !rt.is_empty() {
                if rt.contains('*') {
                    errors.push(format!(
                        "domain '{dom_key}' root_domain '{root}' must not be a wildcard"
                    ));
                } else if let Err(e) = validate_dns_domain(rt) {
                    errors.push(format!("domain '{dom_key}' root_domain: {e}"));
                } else {
                    let dom_norm = dom_key
                        .trim()
                        .trim_start_matches("*.")
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    let rt_lower = rt.to_ascii_lowercase();
                    if dom_norm != rt_lower && !dom_norm.ends_with(&format!(".{rt_lower}")) {
                        errors.push(format!(
                            "domain '{dom_key}' does not belong to configured root_domain '{root}'"
                        ));
                    }
                }
            }
        }
        for target in &binding.target_nodes {
            match topo.nodes.get(target) {
                None => errors.push(format!(
                    "domain '{dom_key}' target_nodes references unknown node '{target}'"
                )),
                Some(n) if n.external_ips.is_empty() => warnings.push(format!(
                    "domain '{dom_key}' targets node '{target}' which has no external_ips configured"
                )),
                _ => {}
            }
        }
        let mut seen_lines = HashSet::new();
        for (ri, lr) in binding.line_routes.iter().enumerate() {
            let line = lr.line.trim();
            if line.is_empty()
                || line.len() > 64
                || !line
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                errors.push(format!(
                    "domain '{dom_key}' line_routes[{ri}] has invalid line code '{}'",
                    lr.line
                ));
            } else if !seen_lines.insert(line.to_ascii_lowercase()) {
                warnings.push(format!(
                    "domain '{dom_key}' defines multiple line_routes entries for line '{line}'"
                ));
            }
            if !lr.enabled {
                continue;
            }
            if lr.target_nodes.is_empty() && lr.values.is_empty() {
                warnings.push(format!(
                    "domain '{dom_key}' line '{line}' has no target_nodes or explicit values"
                ));
            }
            for target in &lr.target_nodes {
                match topo.nodes.get(target) {
                    None => errors.push(format!(
                        "domain '{dom_key}' line '{line}' references unknown node '{target}'"
                    )),
                    Some(n) if n.external_ips.is_empty() && lr.values.is_empty() => warnings.push(
                        format!(
                            "domain '{dom_key}' line '{line}' targets node '{target}' which has no external_ips configured"
                        ),
                    ),
                    _ => {}
                }
            }
            for raw_val in &lr.values {
                let v = raw_val.trim();
                match lr.record_type {
                    DomainLineRecordType::Auto => match v.parse::<IpAddr>() {
                        Ok(ip) => {
                            let c = canonical_ip(ip);
                            if c.is_unspecified() || c.is_multicast() {
                                errors.push(format!(
                                    "domain '{dom_key}' line '{line}' value '{raw_val}' must be a valid unicast IP"
                                ));
                            }
                        }
                        Err(_) => errors.push(format!(
                            "domain '{dom_key}' line '{line}' value '{raw_val}' is not a valid IP address"
                        )),
                    },
                    DomainLineRecordType::Cname => {
                        let clean = v.trim_end_matches('.');
                        if clean.contains('*') || validate_dns_domain(clean).is_err() {
                            errors.push(format!(
                                "domain '{dom_key}' line '{line}' CNAME target '{raw_val}' is not a valid DNS domain"
                            ));
                        }
                    }
                }
            }
        }
    }

    for (node_tag, spec) in &topo.nodes {
        if let Err(e) = validate_identifier(node_tag, "node_tag") {
            errors.push(e.to_string());
        }
        validate_custom_pages(&spec.ingress.pages, &format!("node '{node_tag}'.ingress"), &mut errors);
        validate_custom_pages(&spec.egress.pages, &format!("node '{node_tag}'.egress"), &mut errors);
        for raw_ip in &spec.external_ips {
            let trimmed = raw_ip.trim();
            match trimmed.parse::<IpAddr>() {
                Ok(ip) => {
                    let canon = canonical_ip(ip);
                    if canon.is_unspecified() || canon.is_multicast() {
                        errors.push(format!(
                            "node '{node_tag}' external_ip '{raw_ip}' must be a valid unicast IP"
                        ));
                    } else if canon.is_loopback() {
                        warnings.push(format!(
                            "node '{node_tag}' external_ip '{raw_ip}' is a loopback address"
                        ));
                    }
                }
                Err(_) => {
                    errors.push(format!(
                        "node '{node_tag}' has invalid external_ip '{raw_ip}'"
                    ));
                }
            }
        }
        if let Some(ing) = resolved_ingress.get(node_tag) {
            let uses_any_guard = ing.rules.iter().any(|r| {
                r.guard
                    .as_deref()
                    .map(|g| !g.trim().is_empty())
                    .unwrap_or(false)
            });
            if (uses_any_guard || !spec.ingress.guards.is_empty())
                && is_weak_secret(&ing.clearance_secret)
            {
                warnings.push(format!(
                    "ingress node '{node_tag}' uses a weak or default clearance_secret; set a high-entropy random secret (>=16 chars) on the node or in defaults.ingress"
                ));
            }
            for (g_name, g) in &ing.guards {
                validate_cidr_list(
                    &g.allow_cidrs,
                    &format!("ingress '{node_tag}' guard '{g_name}'.allow_cidrs"),
                    &mut errors,
                );
                validate_cidr_list(
                    &g.deny_cidrs,
                    &format!("ingress '{node_tag}' guard '{g_name}'.deny_cidrs"),
                    &mut errors,
                );
                if let Some(ref bname) = g.rate_limit_bucket {
                    if !bname.trim().is_empty() && !ing.rate_limit_buckets.contains_key(bname) {
                        errors.push(format!(
                            "ingress '{node_tag}' guard '{g_name}' references undefined rate_limit_bucket '{bname}'"
                        ));
                    }
                }
            }
            for rule in &ing.rules {
                let rule_label = rule.name.as_deref().unwrap_or(&rule.service_tag);
                let host_pat = rule.r#match.host.as_deref().map(str::trim).unwrap_or("");
                if host_pat.is_empty() {
                    errors.push(format!(
                        "ingress '{node_tag}' rule '{rule_label}' must specify match.host (enter '*' explicitly to accept all hosts)"
                    ));
                } else if host_pat == "*" {
                    warnings.push(format!(
                        "ingress '{node_tag}' rule '{rule_label}' uses wildcard host '*' (accepts all Host headers)"
                    ));
                }
                validate_cidr_list(
                    &rule.r#match.source_cidrs,
                    &format!("ingress '{node_tag}' rule '{}' source_cidrs", rule.service_tag),
                    &mut errors,
                );
                if let Some(ref gname) = rule.guard {
                    if !gname.trim().is_empty() && !ing.guards.contains_key(gname) {
                        errors.push(format!(
                            "ingress '{node_tag}' rule '{}' references undefined guard '{gname}'",
                            rule.service_tag
                        ));
                    }
                }
            }
        }
        if spec.roles.maintainer {
            if let Some(ref tpl) = spec.maintainer_template {
                if !tpl.trim().is_empty() && !topo.maintainer_templates.contains_key(tpl) {
                    errors.push(format!(
                        "maintainer '{node_tag}' references undefined maintainer_template '{tpl}'"
                    ));
                }
            }
        }
    }

    // 1. Validate links and build per-node Peer lists
    for link in &topo.links {
        if !topo.nodes.contains_key(&link.from) {
            errors.push(format!("link references unknown source node '{}'", link.from));
            continue;
        }
        if !topo.nodes.contains_key(&link.to) {
            errors.push(format!("link references unknown target node '{}'", link.to));
            continue;
        }
        if link.from == link.to {
            errors.push(format!("self-link on node '{}' is not allowed", link.from));
            continue;
        }

        let target_pk = node_pubkeys
            .get(&link.to)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let source_pk = node_pubkeys
            .get(&link.from)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if target_pk.is_none() {
            let msg = format!(
                "link '{} -> {}' target node '{}' is not enrolled (missing pinned public_key)",
                link.from, link.to, link.to
            );
            if require_pinned_pubkeys {
                errors.push(msg);
            } else {
                warnings.push(msg);
            }
        }
        if source_pk.is_none()
            && (link.mode == LinkMode::Tunnel || (link.mode == LinkMode::OnDemand && link.bidirectional))
        {
            let msg = format!(
                "link '{} -> {}' source node '{}' is not enrolled (missing pinned public_key)",
                link.from, link.to, link.from
            );
            if require_pinned_pubkeys {
                errors.push(msg);
            } else {
                warnings.push(msg);
            }
        }

        for ep in &link.endpoints {
            validate_endpoint_address(
                &ep.address,
                &format!("link '{} -> {}'", link.from, link.to),
                &mut errors,
            );
        }

        let mut link_direction_valid = true;
        match link.mode {
            LinkMode::OnDemand => {
                if link.endpoints.is_empty() {
                    errors.push(format!(
                        "on-demand link '{} -> {}' must specify at least one endpoint",
                        link.from, link.to
                    ));
                }
                let target_listener = resolved_listeners.get(&link.to);
                if !target_listener.map(|l| l.effective_allow_on_demand()).unwrap_or(false) {
                    errors.push(format!(
                        "on-demand link '{} -> {}' target '{}' does not enable link_listener.allow_on_demand",
                        link.from, link.to, link.to
                    ));
                }
            }
            LinkMode::Tunnel => match link.tunnel_direction {
                Some(TunnelDirection::Outbound) | None => {
                    if link.endpoints.is_empty() {
                        errors.push(format!(
                            "tunnel outbound link '{} -> {}' must specify at least one endpoint",
                            link.from, link.to
                        ));
                    }
                    let target_listener = resolved_listeners.get(&link.to);
                    if !target_listener.map(|l| l.effective_allow_tunnel()).unwrap_or(false) {
                        errors.push(format!(
                            "tunnel outbound link '{} -> {}' target '{}' does not enable link_listener.allow_tunnel",
                            link.from, link.to, link.to
                        ));
                    }
                }
                Some(TunnelDirection::Inbound) => {
                    link_direction_valid = false;
                    errors.push(format!(
                        "tunnel link '{} -> {}' cannot use 'inbound' in topology; tunnel links always dial 'from -> to' (outbound) — swap 'from' and 'to' instead",
                        link.from, link.to
                    ));
                }
            },
        }
        let peer_tag = link.peer_tag.clone().unwrap_or_else(|| link.to.clone());

        let list = peer_map.entry(link.from.clone()).or_default();
        if list.iter().any(|p| p.peer_tag == peer_tag) {
            errors.push(format!(
                "duplicate peer_tag '{}' on node '{}'",
                peer_tag, link.from
            ));
            continue;
        }
        list.push(PeerConfig {
            peer_tag,
            node_tag: link.to.clone(),
            public_key: target_pk,
            pubkey_fingerprint: None,
            mode: link.mode,
            tunnel_direction: link.tunnel_direction,
            expected_client_addr: link.expected_client_addr.clone(),
            endpoints: link.endpoints.clone(),
        });
        if link_direction_valid {
            adj.entry(link.from.clone())
                .or_default()
                .insert(link.to.clone());
        }

        if link.mode == LinkMode::OnDemand && link.bidirectional {
            let source_listener = resolved_listeners.get(&link.from);
            if !source_listener.map(|l| l.effective_allow_on_demand()).unwrap_or(false) {
                errors.push(format!(
                    "bidirectional on-demand link '{} -> {}' source '{}' does not enable link_listener.allow_on_demand",
                    link.from, link.to, link.from
                ));
            }
            for ep in &link.reverse_endpoints {
                validate_endpoint_address(
                    &ep.address,
                    &format!("link '{} -> {}' reverse", link.from, link.to),
                    &mut errors,
                );
            }
            let rev_list = peer_map.entry(link.to.clone()).or_default();
            if !rev_list.iter().any(|p| p.peer_tag == link.from) {
                if link.reverse_endpoints.is_empty() {
                    errors.push(format!(
                        "bidirectional on-demand link '{} -> {}' requires reverse_endpoints (address for '{}' to dial '{}'), or uncheck Bidirectional",
                        link.from, link.to, link.to, link.from
                    ));
                } else {
                    adj.entry(link.to.clone())
                        .or_default()
                        .insert(link.from.clone());
                    rev_list.push(PeerConfig {
                        peer_tag: link.from.clone(),
                        node_tag: link.from.clone(),
                        public_key: source_pk.clone(),
                        pubkey_fingerprint: None,
                        mode: LinkMode::OnDemand,
                        tunnel_direction: None,
                        expected_client_addr: None,
                        endpoints: link.reverse_endpoints.clone(),
                    });
                }
            } else {
                adj.entry(link.to.clone())
                    .or_default()
                    .insert(link.from.clone());
            }
        }

        if link.mode == LinkMode::Tunnel && link_direction_valid {
            adj.entry(link.to.clone())
                .or_default()
                .insert(link.from.clone());
            let rev_list = peer_map.entry(link.to.clone()).or_default();
            if !rev_list
                .iter()
                .any(|p| p.node_tag == link.from && p.mode == LinkMode::Tunnel)
            {
                let rev_peer_tag = if rev_list.iter().any(|p| p.peer_tag == link.from) {
                    format!("{}-tunnel", link.from)
                } else {
                    link.from.clone()
                };
                rev_list.push(PeerConfig {
                    peer_tag: rev_peer_tag,
                    node_tag: link.from.clone(),
                    public_key: source_pk,
                    pubkey_fingerprint: None,
                    mode: LinkMode::Tunnel,
                    tunnel_direction: Some(TunnelDirection::Inbound),
                    expected_client_addr: link.expected_client_addr.clone(),
                    endpoints: vec![],
                });
            }
        }
    }

    // 2. Collect trusted Maintainer public keys for ingress nodes
    let mut trusted_maintainers = Vec::new();
    for (tag, spec) in &topo.nodes {
        if spec.roles.maintainer {
            if spec.roles.ingress || spec.roles.egress || spec.roles.relay {
                warnings.push(format!(
                    "node '{}' enables maintainer alongside user-traffic roles; maintainer should not carry user traffic",
                    tag
                ));
            }
            if let Some((_, pubk)) = maintainer_keys.get(tag) {
                trusted_maintainers.push(TrustedMaintainer {
                    node_tag: tag.clone(),
                    public_key: pubk.clone(),
                });
            }
        }
    }

    // 3. Validate egress ACL references and duplicate backend warnings
    let mut backend_owners: HashMap<String, Vec<String>> = HashMap::new();
    for (node_tag, spec) in &topo.nodes {
        for (svc_tag, svc) in &spec.egress.services {
            backend_owners
                .entry(format!("{node_tag}:{}", svc.backend))
                .or_default()
                .push(svc_tag.clone());
            for allowed in &svc.allow_from {
                if !topo.nodes.contains_key(allowed) {
                    errors.push(format!(
                        "egress '{}' service '{}' allow_from references unknown node '{}'",
                        node_tag, svc_tag, allowed
                    ));
                }
            }
        }
    }
    for (backend, tags) in backend_owners {
        if tags.len() > 1 {
            warnings.push(format!(
                "duplicate backend '{}' shared by service tags {:?}",
                backend, tags
            ));
        }
    }

    // Helper: resolve peer_tag prioritizing exact peer_tag match over node_tag fallback
    let resolve_peer = |node: &str, next_peer_tag: &str| -> Option<String> {
        let list = peer_map.get(node)?;
        list.iter()
            .find(|p| p.peer_tag == next_peer_tag)
            .or_else(|| list.iter().find(|p| p.node_tag == next_peer_tag))
            .map(|p| p.node_tag.clone())
    };

    // 4. Cross-node path tracing for every ingress rule (loop & reachability verification)
    let mut paths: Vec<ServiceRouteTrace> = Vec::new();
    for (ingress_tag, spec) in &topo.nodes {
        if !spec.roles.ingress {
            continue;
        }
        for rule in &spec.ingress.rules {
            let mut visited = HashSet::new();
            visited.insert(ingress_tag.clone());
            let mut cur_node = ingress_tag.clone();
            let mut next_peer_tag = rule.next_peer.clone();
            let mut trace_hops = vec![ingress_tag.clone()];
            let mut trace_backend = None;
            let mut trace_err: Option<String> = None;

            loop {
                if next_peer_tag == cur_node || next_peer_tag.eq_ignore_ascii_case("local") {
                    let node_spec = &topo.nodes[&cur_node];
                    if !node_spec.roles.egress
                        || !node_spec.egress.services.contains_key(&rule.service_tag)
                    {
                        let msg = format!(
                            "ingress '{}' rule '{}' targets local egress '{}' which does not define service '{}'",
                            ingress_tag, rule.service_tag, cur_node, rule.service_tag
                        );
                        errors.push(msg.clone());
                        trace_err = Some(msg);
                    } else {
                        let svc = &resolved_egress[&cur_node].services[&rule.service_tag];
                        trace_backend = Some(svc.backend.clone());
                        if !svc.effective_allow_any_origin() && !svc.allow_from.contains(ingress_tag) {
                            let msg = format!(
                                "ACL mismatch: egress '{}' service '{}' does not allow origin '{}'",
                                cur_node, rule.service_tag, ingress_tag
                            );
                            errors.push(msg.clone());
                            trace_err = Some(msg);
                        }
                    }
                    break;
                }

                let Some(next_node) = resolve_peer(&cur_node, &next_peer_tag) else {
                    let msg = format!(
                        "unreachable route for service '{}' from '{}': node '{}' has no peer '{}'",
                        rule.service_tag, ingress_tag, cur_node, next_peer_tag
                    );
                    errors.push(msg.clone());
                    trace_err = Some(msg);
                    break;
                };

                trace_hops.push(next_node.clone());
                if !visited.insert(next_node.clone()) {
                    let msg = format!(
                        "routing loop detected for service '{}' starting at '{}' hitting '{}'",
                        rule.service_tag, ingress_tag, next_node
                    );
                    errors.push(msg.clone());
                    trace_err = Some(msg);
                    break;
                }

                let next_spec = &topo.nodes[&next_node];
                if next_spec.roles.egress
                    && next_spec.egress.services.contains_key(&rule.service_tag)
                {
                    let svc = &resolved_egress[&next_node].services[&rule.service_tag];
                    trace_backend = Some(svc.backend.clone());
                    if !svc.effective_allow_any_origin() && !svc.allow_from.contains(ingress_tag) {
                        let msg = format!(
                            "ACL mismatch: egress '{}' service '{}' does not allow origin '{}'",
                            next_node, rule.service_tag, ingress_tag
                        );
                        errors.push(msg.clone());
                        trace_err = Some(msg);
                    }
                    break;
                }

                if next_spec.roles.relay {
                    if let Some(rr) = next_spec
                        .relay
                        .rules
                        .iter()
                        .find(|r| r.service_tag == rule.service_tag)
                    {
                        cur_node = next_node;
                        next_peer_tag = rr.next_peer.clone();
                        continue;
                    }
                }

                let msg = format!(
                    "dead-end route for service '{}' from '{}': reached '{}' which has neither egress service nor relay rule",
                    rule.service_tag, ingress_tag, next_node
                );
                errors.push(msg.clone());
                trace_err = Some(msg);
                break;
            }

            paths.push(ServiceRouteTrace {
                ingress: ingress_tag.clone(),
                rule_name: rule.name.clone(),
                service_tag: rule.service_tag.clone(),
                hops: trace_hops,
                backend: trace_backend,
                valid: trace_err.is_none(),
                error: trace_err,
            });
        }
    }

    // 4b. Validate standalone/orphan relay rules (duplicates, missing peers, and relay-only loops)
    for (relay_tag, spec) in &topo.nodes {
        if !spec.roles.relay {
            continue;
        }
        let mut seen_tags = HashSet::new();
        for rr in &spec.relay.rules {
            if !seen_tags.insert(rr.service_tag.as_str()) {
                errors.push(format!(
                    "relay '{}' has duplicate rule for service_tag '{}'",
                    relay_tag, rr.service_tag
                ));
            }
            let mut visited = HashSet::new();
            visited.insert(relay_tag.clone());
            let mut cur = relay_tag.clone();
            let mut np = rr.next_peer.clone();
            loop {
                let Some(next) = resolve_peer(&cur, &np) else {
                    errors.push(format!(
                        "relay '{}' rule for '{}' references unknown peer '{}'",
                        cur, rr.service_tag, np
                    ));
                    break;
                };
                if !visited.insert(next.clone()) {
                    errors.push(format!(
                        "relay routing loop detected for service '{}' starting at '{}' hitting '{}'",
                        rr.service_tag, relay_tag, next
                    ));
                    break;
                }
                let next_spec = &topo.nodes[&next];
                if next_spec.roles.egress && next_spec.egress.services.contains_key(&rr.service_tag) {
                    break;
                }
                if next_spec.roles.relay {
                    if let Some(next_rr) = next_spec
                        .relay
                        .rules
                        .iter()
                        .find(|r| r.service_tag == rr.service_tag)
                    {
                        cur = next;
                        np = next_rr.next_peer.clone();
                        continue;
                    }
                }
                break;
            }
        }
    }

    // 5. Validate Hop Tables (maintainer_hops)
    for (node_tag, spec) in &topo.nodes {
        let is_self_maintainer_hop = spec.roles.maintainer
            && spec.maintainer_hops.len() == 1
            && spec.maintainer_hops[0] == *node_tag;
        if !spec.maintainer_hops.is_empty() && !is_self_maintainer_hop {
            validate_hop_path(
                &spec.maintainer_hops,
                node_tag,
                None,
                true,
                &adj,
                topo,
                &mut errors,
                &format!("node '{node_tag}' maintainer_hops"),
            );
        }
    }

    // Build consistent cluster-wide LoggerConfig (so all nodes share the exact same IP HMAC key for UV!)
    let mut effective_logger: LoggerConfig = topo.global_logger.clone().unwrap_or_default();
    if effective_logger.hmac_key.trim().is_empty() {
        if let Some(ck) = cluster_hmac_key.filter(|k| !k.trim().is_empty()) {
            effective_logger.hmac_key = ck.to_string();
        }
    }

    // 6. Emit compiled NodeConfig for each node (with least-privilege role secret scoping!)
    let mut compiled = BTreeMap::new();
    for (node_tag, spec) in &topo.nodes {
        let mut maint_cfg = if spec.roles.maintainer {
            let mut mc = spec
                .maintainer_template
                .as_ref()
                .and_then(|t| topo.maintainer_templates.get(t))
                .cloned()
                .unwrap_or_default();
            // Propagate cluster logger settings (hmac_key & store_raw_ip) into Maintainer unless explicitly set
            if mc.logger.hmac_key.trim().is_empty() {
                mc.logger.hmac_key = effective_logger.hmac_key.clone();
            }
            if effective_logger.store_raw_ip {
                mc.logger.store_raw_ip = true;
            }
            if mc.is_primary_cert_manager {
                if let Some((sec, _)) = maintainer_keys.get(node_tag) {
                    mc.cert_signing_secret_key = Some(sec.clone());
                }
                mc.dns_providers = topo.dns_providers.clone();
                mc.domains = topo.domains.clone();
            } else {
                // Least privilege: non-primary maintainers do NOT receive DNS provider secrets, domain bindings, or cert signing private keys
                mc.cert_signing_secret_key = None;
                mc.dns_providers.clear();
                mc.domains.clear();
                mc.acme.orders.clear();
            }
            Some(mc)
        } else {
            None
        };

        if let Some(ref mut mc) = maint_cfg {
            let is_self_signed = mc.acme.directory_url.trim().is_empty()
                || mc.acme.directory_url.eq_ignore_ascii_case("self-signed");
            for order in &mc.acme.orders {
                if let Err(e) = validate_dns_domain(&order.domain) {
                    errors.push(format!("maintainer '{node_tag}' ACME order: {e}"));
                }
                let explicit_prov = order
                    .provider
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                match explicit_prov {
                    Some(p) if p.eq_ignore_ascii_case("none") => {}
                    Some(p) => {
                        if !topo.dns_providers.contains_key(p) {
                            errors.push(format!(
                                "maintainer '{node_tag}' cert order '{}' references unknown dns_provider '{}'",
                                order.domain, p
                            ));
                        }
                    }
                    None => {
                        if let Some((_, binding)) =
                            resolve_domain_binding(&topo.domains, &order.domain)
                        {
                            if !topo.dns_providers.contains_key(binding.provider.trim()) {
                                errors.push(format!(
                                    "maintainer '{node_tag}' cert order '{}' resolved domain binding with unknown dns_provider '{}'",
                                    order.domain, binding.provider
                                ));
                            }
                        } else if !is_self_signed {
                            errors.push(format!(
                                "maintainer '{node_tag}' cert order '{}' has no matching entry in `domains` and no explicit `provider`",
                                order.domain
                            ));
                        }
                    }
                }
                for target in &order.target_nodes {
                    if !topo.nodes.contains_key(target) {
                        errors.push(format!(
                            "maintainer '{node_tag}' cert order '{}' references unknown target node '{target}'",
                            order.domain
                        ));
                    }
                }
                for (target, hops) in &order.target_hops {
                    validate_hop_path(
                        hops,
                        node_tag,
                        Some(target.as_str()),
                        false,
                        &adj,
                        topo,
                        &mut errors,
                        &format!("maintainer '{node_tag}' cert '{}' hop to '{target}'", order.domain),
                    );
                }
            }
        }

        // Collect trusted origin Ingress public keys for this Egress node's `allow_from` ACLs
        let mut trusted_origins: Vec<TrustedOrigin> = Vec::new();
        if spec.roles.egress {
            let mut seen_origins = HashSet::new();
            for svc in spec.egress.services.values() {
                for origin in &svc.allow_from {
                    if seen_origins.insert(origin.clone()) {
                        if let Some(pk) = node_pubkeys
                            .get(origin)
                            .map(|s| s.trim())
                            .filter(|s| !s.is_empty())
                        {
                            trusted_origins.push(TrustedOrigin {
                                node_tag: origin.clone(),
                                public_key: pk.to_string(),
                            });
                        }
                    }
                }
            }
        }

        // Only emit config sections for enabled roles (prevents distributing ingress secrets to non-ingress nodes!)
        let ingress_cfg = resolved_ingress
            .get(node_tag)
            .cloned()
            .unwrap_or_default();
        let egress_cfg = resolved_egress
            .get(node_tag)
            .cloned()
            .unwrap_or_default();
        let relay_cfg = if spec.roles.relay {
            spec.relay.clone()
        } else {
            RelayConfig::default()
        };

        let node_cfg = NodeConfig {
            node_tag: node_tag.clone(),
            identity_secret_key: String::new(),
            control_public_key: Some(control_signing_public_key.to_string()),
            control_link_public_key: Some(control_link_public_key.to_string()),
            roles: spec.roles.clone(),
            link_listener: resolved_listeners.get(node_tag).cloned(),
            peers: peer_map.get(node_tag).cloned().unwrap_or_default(),
            probe: spec.probe.clone().unwrap_or_else(ProbeConfig::default),
            default_ttl: 16,
            maintainer_hops: spec.maintainer_hops.clone(),
            trusted_maintainers: if spec.roles.ingress {
                trusted_maintainers.clone()
            } else {
                Vec::new()
            },
            trusted_origins,
            logger: effective_logger.clone(),
            ingress: ingress_cfg,
            egress: egress_cfg,
            relay: relay_cfg,
            maintainer: maint_cfg,
            bootstrap_tunnel_addr: None,
            config_sequence: 0,
        };
        compiled.insert(node_tag.clone(), node_cfg);
    }

    let report = CompileReport {
        valid: errors.is_empty(),
        errors,
        warnings,
        compiled_nodes: compiled.keys().cloned().collect(),
        paths,
    };
    (report, compiled)
}

#[allow(clippy::too_many_arguments)]
fn validate_hop_path(
    hops: &[String],
    expected_start: &str,
    expected_end: Option<&str>,
    end_must_be_maintainer: bool,
    adj: &HashMap<String, HashSet<String>>,
    topo: &TopologySpec,
    errors: &mut Vec<String>,
    label: &str,
) {
    if hops.len() < 2 {
        errors.push(format!("{label}: hop path must contain at least 2 nodes"));
        return;
    }
    if hops.len() > MAX_HOP_PATH_LEN {
        errors.push(format!(
            "{label}: hop path length {} exceeds max TTL {MAX_HOP_PATH_LEN}",
            hops.len()
        ));
    }
    if hops.first().map(|s| s.as_str()) != Some(expected_start) {
        errors.push(format!(
            "{label}: hop path must start at '{expected_start}' (got '{:?}')",
            hops.first()
        ));
    }
    if let Some(end) = expected_end {
        if hops.last().map(|s| s.as_str()) != Some(end) {
            errors.push(format!(
                "{label}: hop path must end at '{end}' (got '{:?}')",
                hops.last()
            ));
        }
    }
    if end_must_be_maintainer {
        if let Some(last) = hops.last() {
            if !topo.nodes.get(last).map(|n| n.roles.maintainer).unwrap_or(false) {
                errors.push(format!(
                    "{label}: hop path target '{last}' is not a maintainer node"
                ));
            }
        }
    }
    let mut seen = HashSet::new();
    for h in hops {
        if !topo.nodes.contains_key(h) {
            errors.push(format!("{label}: unknown node '{h}' in hop table"));
        }
        if !seen.insert(h.as_str()) {
            errors.push(format!("{label}: cycle/duplicate node '{h}' in hop table"));
        }
    }
    for win in hops.windows(2) {
        let (a, b) = (&win[0], &win[1]);
        let linked = adj.get(a).map(|s| s.contains(b)).unwrap_or(false);
        if !linked {
            errors.push(format!("{label}: no link from '{a}' to '{b}'"));
        }
    }
}

/// Compute shortest Hop Table `[control_id, bootstrap_node, ..., target_node]` via BFS.
pub fn compute_control_hops(
    control_id: &str,
    bootstrap_node: &str,
    target_node: &str,
    topo: &TopologySpec,
) -> Option<Vec<String>> {
    if bootstrap_node == target_node {
        return Some(vec![control_id.to_string(), bootstrap_node.to_string()]);
    }
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for link in &topo.links {
        if link.mode == LinkMode::Tunnel && link.tunnel_direction != Some(TunnelDirection::Outbound) {
            continue;
        }
        adj.entry(link.from.as_str()).or_default().push(link.to.as_str());
        if link.mode == LinkMode::Tunnel
            || (link.mode == LinkMode::OnDemand
                && link.bidirectional
                && !link.reverse_endpoints.is_empty())
        {
            adj.entry(link.to.as_str()).or_default().push(link.from.as_str());
        }
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    visited.insert(bootstrap_node);
    queue.push_back(vec![control_id.to_string(), bootstrap_node.to_string()]);

    while let Some(path) = queue.pop_front() {
        if path.len() > MAX_HOP_PATH_LEN {
            continue;
        }
        let last = path.last().unwrap().as_str();
        if let Some(neighbors) = adj.get(last) {
            for &nb in neighbors {
                if !visited.insert(nb) {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(nb.to_string());
                if nb == target_node {
                    return Some(next_path);
                }
                queue.push_back(next_path);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use exposure_core::config::{
        EgressConfig, EgressServiceConfig, IngressConfig, IngressRule, LinkListenConfig, NodeRoles,
        PeerEndpoint, RelayConfig, RelayRule, RuleMatch, TopologyLinkSpec, TopologyNodeSpec,
    };
    use exposure_core::crypto::NodeKeyPair;

    #[test]
    fn compiler_detects_loop_unpinned_keys_and_validates_happy_path() {
        let kp_in = NodeKeyPair::generate();
        let kp_re = NodeKeyPair::generate();
        let kp_eg = NodeKeyPair::generate();
        let mut pubkeys = HashMap::new();
        pubkeys.insert("ingress-a".into(), kp_in.public_key_b64());
        pubkeys.insert("relay-1".into(), kp_re.public_key_b64());
        pubkeys.insert("egress-1".into(), kp_eg.public_key_b64());

        let mut topo = TopologySpec::default();
        topo.defaults.ingress.clearance_secret = "super-secret-global-clearance-key-0123456789".into();
        topo.defaults.guard.block_bots = true;
        topo.bucket_templates.insert(
            "global-std".into(),
            RateLimitBucket {
                capacity: 60.0,
                refill_per_sec: 10.0,
                per_ip: None,
            },
        );
        topo.guard_templates.insert(
            "global-web".into(),
            GuardProfile {
                rate_limit_bucket: Some("global-std".into()),
                ..Default::default()
            },
        );
        topo.nodes.insert(
            "ingress-a".into(),
            TopologyNodeSpec {
                roles: NodeRoles { ingress: true, ..Default::default() },
                link_listener: Some(LinkListenConfig {
                    listen_addr: "0.0.0.0:9443".into(),
                    allow_on_demand: None,
                    allow_tunnel: None,
                    allow_bootstrap: None,
                }),
                ingress: IngressConfig {
                    rules: vec![IngressRule {
                        name: None,
                        r#match: RuleMatch { host: Some("example.com".into()), ..Default::default() },
                        service_tag: "web".into(),
                        next_peer: "relay-1".into(),
                        guard: Some("global-web".into()),
                        intercept_errors: None,
                        js_fp_beacon: None,
                        cache: None,
                    }],
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        topo.nodes.insert(
            "relay-1".into(),
            TopologyNodeSpec {
                roles: NodeRoles { relay: true, ..Default::default() },
                link_listener: Some(LinkListenConfig {
                    listen_addr: "0.0.0.0:9443".into(),
                    allow_on_demand: Some(true),
                    allow_tunnel: Some(true),
                    allow_bootstrap: Some(false),
                }),
                relay: RelayConfig {
                    rules: vec![RelayRule {
                        service_tag: "web".into(),
                        next_peer: "egress-1".into(),
                    }],
                },
                ..Default::default()
            },
        );
        let mut services = BTreeMap::new();
        services.insert(
            "web".into(),
            EgressServiceConfig {
                backend: "127.0.0.1:8080".into(),
                protocol: Default::default(),
                tls: None,
                ca_cert_path: None,
                insecure_skip_verify: None,
                allow_from: vec!["ingress-a".into()],
                allow_any_origin: None,
                timeout_ms: 5000,
                intercept_errors: None,
                local_health_check: None,
            },
        );
        topo.nodes.insert(
            "egress-1".into(),
            TopologyNodeSpec {
                roles: NodeRoles { egress: true, ..Default::default() },
                link_listener: Some(LinkListenConfig {
                    listen_addr: "0.0.0.0:9443".into(),
                    allow_on_demand: Some(true),
                    allow_tunnel: Some(true),
                    allow_bootstrap: Some(false),
                }),
                egress: EgressConfig { services, ..Default::default() },
                ..Default::default()
            },
        );
        topo.links.push(TopologyLinkSpec {
            from: "ingress-a".into(),
            to: "relay-1".into(),
            peer_tag: None,
            mode: LinkMode::OnDemand,
            tunnel_direction: None,
            bidirectional: false,
            endpoints: vec![PeerEndpoint { address: "198.51.100.1:9001".into(), priority: 10, weight: 100 }],
            reverse_endpoints: vec![],
            expected_client_addr: None,
        });
        topo.links.push(TopologyLinkSpec {
            from: "relay-1".into(),
            to: "egress-1".into(),
            peer_tag: None,
            mode: LinkMode::OnDemand,
            tunnel_direction: None,
            bidirectional: false,
            endpoints: vec![PeerEndpoint { address: "198.51.100.2:9002".into(), priority: 10, weight: 100 }],
            reverse_endpoints: vec![],
            expected_client_addr: None,
        });

        // Missing pubkeys MUST fail compilation by default
        let (unpinned_report, _) = compile_topology(&topo, "ctrl-pk", &HashMap::new(), &HashMap::new());
        assert!(!unpinned_report.valid);

        // With pinned pubkeys, compiles cleanly, resolves global templates/defaults, and injects trusted_origins into egress-1
        let (report, compiled) = compile_topology_full(
            &topo,
            "ctrl-pk",
            "ctrl-pk",
            &pubkeys,
            &HashMap::new(),
            true,
            Some("cluster-hmac-secret-key-0123456789abcdef"),
        );
        assert!(report.valid, "errors: {:?}", report.errors);
        assert_eq!(compiled.len(), 3);
        assert_eq!(compiled["egress-1"].trusted_origins.len(), 1);
        assert_eq!(compiled["egress-1"].trusted_origins[0].node_tag, "ingress-a");
        // Verify global templates + defaults inheritance + cluster hmac key consistency
        assert_eq!(
            compiled["ingress-a"].ingress.clearance_secret,
            "super-secret-global-clearance-key-0123456789"
        );
        assert!(compiled["ingress-a"].ingress.guards["global-web"].effective_block_bots());
        assert!(compiled["ingress-a"].ingress.rate_limit_buckets.contains_key("global-std"));
        assert_eq!(
            compiled["ingress-a"].logger.hmac_key,
            "cluster-hmac-secret-key-0123456789abcdef"
        );
        assert_eq!(
            compiled["egress-1"].logger.hmac_key,
            "cluster-hmac-secret-key-0123456789abcdef"
        );

        // Missing match.host MUST fail compilation unless explicitly '*'
        let mut topo_no_host = topo.clone();
        topo_no_host.nodes.get_mut("ingress-a").unwrap().ingress.rules[0].r#match.host = None;
        let (no_host_report, _) = compile_topology(&topo_no_host, "ctrl-pk", &pubkeys, &HashMap::new());
        assert!(!no_host_report.valid);
        assert!(no_host_report.errors.iter().any(|e| e.contains("match.host")));

        // Introduce loop: relay-1 -> ingress-a
        topo.nodes.get_mut("relay-1").unwrap().relay.rules[0].next_peer = "ingress-a".into();
        topo.links.push(TopologyLinkSpec {
            from: "relay-1".into(),
            to: "ingress-a".into(),
            peer_tag: None,
            mode: LinkMode::OnDemand,
            tunnel_direction: None,
            bidirectional: false,
            endpoints: vec![PeerEndpoint { address: "198.51.100.3:9003".into(), priority: 10, weight: 100 }],
            reverse_endpoints: vec![],
            expected_client_addr: None,
        });
        let (loop_report, _) = compile_topology(&topo, "ctrl-pk", &pubkeys, &HashMap::new());
        assert!(!loop_report.valid);
        assert!(loop_report.errors.iter().any(|e| e.contains("loop")));
    }

    #[test]
    fn compiler_provisions_separated_dns_providers_and_domains() {
        use exposure_core::config::{
            AcmeConfig, CertOrderConfig, DnsProviderAccountConfig, DomainBindingConfig,
            MaintainerConfig,
        };

        let mut topo = TopologySpec::default();
        topo.dns_providers.insert(
            "ali-acct1".into(),
            DnsProviderAccountConfig::Aliyun {
                access_key_id: "LTAI5t1".into(),
                access_key_secret: "secret1".into(),
                region_id: None,
            },
        );
        topo.dns_providers.insert(
            "cf-acct2".into(),
            DnsProviderAccountConfig::Cloudflare {
                api_token: "cf-tok".into(),
            },
        );
        topo.domains.insert(
            "example.com".into(),
            DomainBindingConfig {
                provider: "ali-acct1".into(),
                target_nodes: vec!["ingress-a".into()],
                ..Default::default()
            },
        );
        topo.maintainer_templates.insert(
            "primary".into(),
            MaintainerConfig {
                is_primary_cert_manager: true,
                acme: AcmeConfig {
                    directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
                    orders: vec![CertOrderConfig {
                        domain: "*.api.example.com".into(),
                        provider: None, // auto-resolved via `domains` longest-suffix match
                        target_nodes: vec!["ingress-a".into()],
                        target_hops: BTreeMap::new(),
                        renew_before_days: 30,
                    }],
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        topo.maintainer_templates.insert(
            "backup".into(),
            MaintainerConfig {
                is_primary_cert_manager: false,
                ..Default::default()
            },
        );

        topo.nodes.insert(
            "ingress-a".into(),
            TopologyNodeSpec {
                roles: NodeRoles {
                    ingress: true,
                    ..Default::default()
                },
                external_ips: vec!["203.0.113.10".into(), "2001:db8::10".into()],
                ..Default::default()
            },
        );
        topo.nodes.insert(
            "maint-primary".into(),
            TopologyNodeSpec {
                roles: NodeRoles {
                    maintainer: true,
                    ..Default::default()
                },
                maintainer_template: Some("primary".into()),
                ..Default::default()
            },
        );
        topo.nodes.insert(
            "maint-backup".into(),
            TopologyNodeSpec {
                roles: NodeRoles {
                    maintainer: true,
                    ..Default::default()
                },
                maintainer_template: Some("backup".into()),
                ..Default::default()
            },
        );

        let mut pubkeys = HashMap::new();
        pubkeys.insert("ingress-a".into(), "pk-ing".into());
        pubkeys.insert("maint-primary".into(), "pk-mp".into());
        pubkeys.insert("maint-backup".into(), "pk-mb".into());

        let (report, compiled) = compile_topology(&topo, "ctrl-pk", &pubkeys, &HashMap::new());
        assert!(report.valid, "errors: {:?}", report.errors);

        let mp = compiled["maint-primary"].maintainer.as_ref().unwrap();
        assert_eq!(mp.dns_providers.len(), 2);
        assert!(mp.domains.contains_key("example.com"));

        // Least privilege: backup maintainer does NOT receive dns_providers or domains
        let mb = compiled["maint-backup"].maintainer.as_ref().unwrap();
        assert!(mb.dns_providers.is_empty());
        assert!(mb.domains.is_empty());

        // Invalid external IP fails validation
        let mut bad_ip = topo.clone();
        bad_ip.nodes.get_mut("ingress-a").unwrap().external_ips.push("not-an-ip".into());
        let (bad_ip_rep, _) = compile_topology(&bad_ip, "ctrl-pk", &pubkeys, &HashMap::new());
        assert!(!bad_ip_rep.valid);
        assert!(bad_ip_rep.errors.iter().any(|e| e.contains("external_ip")));

        // Unknown provider on domain fails validation
        let mut bad_dom = topo.clone();
        bad_dom.domains.get_mut("example.com").unwrap().provider = "missing".into();
        let (bad_dom_rep, _) = compile_topology(&bad_dom, "ctrl-pk", &pubkeys, &HashMap::new());
        assert!(!bad_dom_rep.valid);
        assert!(bad_dom_rep.errors.iter().any(|e| e.contains("dns_provider")));
    }

    #[test]
    fn compiler_expands_declarative_services_across_all_ingresses_and_relays() {
        use exposure_core::config::{
            DomainLineRecordType, DomainLineRoute, ServiceEgressTarget, ServiceIngressMode,
            ServiceIngressOverride, ServiceIngressScope, ServiceSpec,
        };

        let mut topo = TopologySpec::default();
        topo.defaults.ingress.clearance_secret = "super-secret-global-clearance-key-0123456789".into();
        topo.guard_templates.insert("std".into(), GuardProfile::default());
        topo.guard_templates.insert("strict".into(), GuardProfile::default());

        for (tag, roles) in [
            ("ingress-hk", NodeRoles { ingress: true, ..Default::default() }),
            ("ingress-jp", NodeRoles { ingress: true, ..Default::default() }),
            ("relay-sg", NodeRoles { relay: true, ..Default::default() }),
            ("egress-home", NodeRoles { egress: true, ..Default::default() }),
        ] {
            topo.nodes.insert(
                tag.into(),
                TopologyNodeSpec {
                    roles,
                    external_ips: vec!["203.0.113.10".into()],
                    link_listener: Some(LinkListenConfig {
                        listen_addr: "0.0.0.0:9443".into(),
                        allow_on_demand: Some(true),
                        allow_tunnel: Some(true),
                        allow_bootstrap: Some(false),
                    }),
                    ..Default::default()
                },
            );
        }

        topo.links.push(TopologyLinkSpec {
            from: "ingress-hk".into(),
            to: "relay-sg".into(),
            peer_tag: None,
            mode: LinkMode::OnDemand,
            tunnel_direction: None,
            bidirectional: false,
            endpoints: vec![PeerEndpoint { address: "198.51.100.1:9443".into(), priority: 10, weight: 100 }],
            reverse_endpoints: vec![],
            expected_client_addr: None,
        });
        topo.links.push(TopologyLinkSpec {
            from: "ingress-jp".into(),
            to: "relay-sg".into(),
            peer_tag: None,
            mode: LinkMode::OnDemand,
            tunnel_direction: None,
            bidirectional: false,
            endpoints: vec![PeerEndpoint { address: "198.51.100.1:9443".into(), priority: 10, weight: 100 }],
            reverse_endpoints: vec![],
            expected_client_addr: None,
        });
        topo.links.push(TopologyLinkSpec {
            from: "egress-home".into(),
            to: "relay-sg".into(),
            peer_tag: None,
            mode: LinkMode::Tunnel,
            tunnel_direction: Some(TunnelDirection::Outbound),
            bidirectional: false,
            endpoints: vec![PeerEndpoint { address: "198.51.100.1:9443".into(), priority: 10, weight: 100 }],
            reverse_endpoints: vec![],
            expected_client_addr: None,
        });

        let mut overrides = BTreeMap::new();
        overrides.insert(
            "ingress-jp".into(),
            ServiceIngressOverride {
                guard: Some("strict".into()),
                ..Default::default()
            },
        );
        topo.services.insert(
            "web-app".into(),
            ServiceSpec {
                hosts: vec!["app.example.com".into(), "www.example.com".into()],
                ingress: ServiceIngressScope {
                    mode: ServiceIngressMode::All,
                    nodes: vec![],
                    overrides,
                },
                guard: Some("std".into()),
                egress: ServiceEgressTarget {
                    node: "egress-home".into(),
                    backend: "127.0.0.1:8080".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        topo.dns_providers.insert(
            "ali".into(),
            exposure_core::config::DnsProviderAccountConfig::Aliyun {
                access_key_id: "LTAI5t1".into(),
                access_key_secret: "secret".into(),
                region_id: None,
            },
        );
        topo.domains.insert(
            "app.example.com".into(),
            exposure_core::config::DomainBindingConfig {
                provider: "ali".into(),
                line_routes: vec![
                    DomainLineRoute {
                        line: "default".into(),
                        target_nodes: vec!["ingress-hk".into()],
                        ..Default::default()
                    },
                    DomainLineRoute {
                        line: "telecom".into(),
                        record_type: DomainLineRecordType::Cname,
                        values: vec!["cdn.example.net".into()],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );

        let mut pubkeys = HashMap::new();
        for tag in ["ingress-hk", "ingress-jp", "relay-sg", "egress-home"] {
            pubkeys.insert(tag.into(), format!("pk-{tag}"));
        }

        let (report, compiled) = compile_topology(&topo, "ctrl-pk", &pubkeys, &HashMap::new());
        assert!(report.valid, "errors: {:?}", report.errors);
        // Both ingress nodes receive 2 rules (one per host)
        assert_eq!(compiled["ingress-hk"].ingress.rules.len(), 2);
        assert_eq!(compiled["ingress-jp"].ingress.rules.len(), 2);
        assert_eq!(compiled["ingress-hk"].ingress.rules[0].guard.as_deref(), Some("std"));
        assert_eq!(compiled["ingress-jp"].ingress.rules[0].guard.as_deref(), Some("strict"));
        // Relay receives deduplicated relay rule
        assert_eq!(compiled["relay-sg"].relay.rules.len(), 1);
        assert_eq!(compiled["relay-sg"].relay.rules[0].next_peer, "egress-home");
        // Egress receives service with automatic allow_from covering both ingresses
        let esvc = &compiled["egress-home"].egress.services["web-app"];
        assert_eq!(esvc.backend, "127.0.0.1:8080");
        assert!(esvc.allow_from.contains(&"ingress-hk".to_string()));
        assert!(esvc.allow_from.contains(&"ingress-jp".to_string()));
        // 4 valid service route traces (2 ingresses x 2 hosts)
        assert_eq!(report.paths.len(), 4);
        assert!(report.paths.iter().all(|p| p.valid));
    }

    #[test]
    fn resolve_guard_profile_inherits_and_clamps_waf_config() {
        use exposure_core::config::{WafConfig, WafMode};

        let mut defs = GuardDefaults::default();
        defs.waf = WafConfig {
            mode: WafMode::Monitor,
            min_confidence: 0.7,
            max_body_bytes: 512 * 1024, // exceeds 256 KiB hard ceiling
            ..Default::default()
        };
        let inherited = resolve_guard_profile(&GuardProfile::default(), &defs);
        let iw = inherited.waf.expect("inherited waf");
        assert_eq!(iw.mode, WafMode::Monitor);
        assert_eq!(iw.min_confidence, 0.7);
        assert_eq!(iw.max_body_bytes, 256 * 1024);

        let custom = GuardProfile {
            waf: Some(WafConfig {
                mode: WafMode::Block,
                min_confidence: 0.01, // clamped to 0.1
                max_body_bytes: 16 * 1024,
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolved = resolve_guard_profile(&custom, &defs);
        let rw = resolved.waf.expect("custom waf");
        assert_eq!(rw.mode, WafMode::Block);
        assert!((rw.min_confidence - 0.1).abs() < 1e-6);
        assert_eq!(rw.max_body_bytes, 16 * 1024);
    }
}
