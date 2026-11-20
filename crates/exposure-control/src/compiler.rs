use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use exposure_core::config::{
    EgressConfig, EgressDefaults, GuardDefaults, GuardProfile, IngressConfig, IngressDefaults,
    LinkListenConfig, LinkListenerDefaults, LinkMode, LoggerConfig, NodeConfig, PeerConfig,
    ProbeConfig, RateLimitBucket, RelayConfig, TopologySpec, TrustedMaintainer, TrustedOrigin,
    TunnelDirection,
};
use exposure_core::crypto::{is_weak_secret, validate_dns_domain, validate_identifier};
use exposure_core::routing::canonical_ip;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

const MAX_HOP_PATH_LEN: usize = 16;

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
    out.block_headless = Some(out.block_headless.unwrap_or(defs.block_headless));
    out.require_client_fp = Some(out.require_client_fp.unwrap_or(defs.require_client_fp));
    out.js_fp_beacon = Some(out.js_fp_beacon.unwrap_or(defs.js_fp_beacon));
    out.js_fp_ttl_secs = Some(out.js_fp_ttl_secs.unwrap_or(defs.js_fp_ttl_secs).max(60));
    out
}

fn resolve_bucket(b: &RateLimitBucket) -> RateLimitBucket {
    RateLimitBucket {
        capacity: b.capacity,
        refill_per_sec: b.refill_per_sec,
        per_ip: Some(b.effective_per_ip()),
    }
}

fn resolve_ingress_config(
    src: &IngressConfig,
    ingress_defs: &IngressDefaults,
    guard_defs: &GuardDefaults,
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
    out
}

fn resolve_egress_config(src: &EgressConfig, defs: &EgressDefaults) -> EgressConfig {
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
                resolve_egress_config(&spec.egress, &topo.defaults.egress),
            )
        })
        .collect();

    // 0. Validate global logger, global templates, node tags, guards, buckets, CIDRs, and maintainer templates
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

    for (node_tag, spec) in &topo.nodes {
        if let Err(e) = validate_identifier(node_tag, "node_tag") {
            errors.push(e.to_string());
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
            } else {
                // Least privilege: non-primary maintainers do NOT receive ACME provider secrets or cert signing private keys
                mc.cert_signing_secret_key = None;
                mc.acme.providers.clear();
                mc.acme.orders.clear();
            }
            Some(mc)
        } else {
            None
        };

        if let Some(ref mut mc) = maint_cfg {
            for order in &mc.acme.orders {
                if let Err(e) = validate_dns_domain(&order.domain) {
                    errors.push(format!("maintainer '{node_tag}' ACME order: {e}"));
                }
                if !order.provider.trim().is_empty()
                    && !order.provider.eq_ignore_ascii_case("none")
                    && !mc.acme.providers.contains_key(&order.provider)
                {
                    errors.push(format!(
                        "maintainer '{node_tag}' cert order '{}' references unknown provider '{}'",
                        order.domain, order.provider
                    ));
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
                egress: EgressConfig { services },
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
}
