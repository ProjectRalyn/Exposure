use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use exposure_core::config::{
    LinkMode, NodeConfig, PeerConfig, ProbeConfig, TopologySpec, TrustedMaintainer,
    TunnelDirection,
};
use serde::{Deserialize, Serialize};

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

/// Compile a `TopologySpec` into complete per-node `NodeConfig` maps, performing:
/// - Peer & Hop Table validation
/// - Service Tag conflict, ACL reference, and cross-node reachability/loop checks
/// - Maintainer credential & trusted_maintainers injection
pub fn compile_topology(
    topo: &TopologySpec,
    control_public_key: &str,
    node_pubkeys: &HashMap<String, String>,
    maintainer_keys: &HashMap<String, (String, String)>,
) -> (CompileReport, BTreeMap<String, NodeConfig>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut peer_map: HashMap<String, Vec<PeerConfig>> = HashMap::new();
    let mut adj: HashMap<String, HashSet<String>> = HashMap::new();

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

        // Preflight endpoint syntax & loopback/wildcard checks
        for ep in &link.endpoints {
            let trimmed = ep.address.trim();
            match trimmed.rsplit_once(':') {
                Some((host, port_str)) if !host.is_empty() && port_str.parse::<u16>().map(|p| p > 0).unwrap_or(false) => {
                    let h = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
                    if h == "0.0.0.0" || h == "::" || h == "127.0.0.1" || h == "::1" || h == "localhost" {
                        errors.push(format!(
                            "link '{} -> {}' uses local/wildcard endpoint '{}' — specify a reachable LAN/WAN IP",
                            link.from, link.to, ep.address
                        ));
                    }
                }
                _ => {
                    errors.push(format!(
                        "link '{} -> {}' has invalid endpoint '{}' (expected host:port)",
                        link.from, link.to, ep.address
                    ));
                }
            }
        }

        match link.mode {
            LinkMode::OnDemand => {
                if link.endpoints.is_empty() {
                    errors.push(format!(
                        "on-demand link '{} -> {}' must specify at least one endpoint",
                        link.from, link.to
                    ));
                }
                let target_listener = topo.nodes.get(&link.to).and_then(|n| n.link_listener.as_ref());
                if !target_listener.map(|l| l.allow_on_demand).unwrap_or(false) {
                    errors.push(format!(
                        "on-demand link '{} -> {}' target '{}' does not enable link_listener.allow_on_demand",
                        link.from, link.to, link.to
                    ));
                }
            }
            LinkMode::Tunnel => match link.tunnel_direction {
                Some(TunnelDirection::Outbound) => {
                    if link.endpoints.is_empty() {
                        errors.push(format!(
                            "tunnel outbound link '{} -> {}' must specify at least one endpoint",
                            link.from, link.to
                        ));
                    }
                    let target_listener = topo.nodes.get(&link.to).and_then(|n| n.link_listener.as_ref());
                    if !target_listener.map(|l| l.allow_tunnel).unwrap_or(false) {
                        errors.push(format!(
                            "tunnel outbound link '{} -> {}' target '{}' does not enable link_listener.allow_tunnel",
                            link.from, link.to, link.to
                        ));
                    }
                }
                Some(TunnelDirection::Inbound) => {
                    errors.push(format!(
                        "tunnel link '{} -> {}' cannot use 'inbound' in topology; tunnel links always dial 'from -> to' (outbound) — swap 'from' and 'to' instead",
                        link.from, link.to
                    ));
                }
                None => {
                    errors.push(format!(
                        "tunnel link '{} -> {}' must specify tunnel_direction ('outbound' or 'inbound')",
                        link.from, link.to
                    ));
                }
            },
        }
        let peer_tag = link.peer_tag.clone().unwrap_or_else(|| link.to.clone());
        let target_pk = node_pubkeys.get(&link.to).cloned();

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
        adj.entry(link.from.clone())
            .or_default()
            .insert(link.to.clone());

        if link.mode == LinkMode::OnDemand && link.bidirectional {
            adj.entry(link.to.clone())
                .or_default()
                .insert(link.from.clone());
            let source_listener = topo.nodes.get(&link.from).and_then(|n| n.link_listener.as_ref());
            if !source_listener.map(|l| l.allow_on_demand).unwrap_or(false) {
                errors.push(format!(
                    "bidirectional on-demand link '{} -> {}' source '{}' does not enable link_listener.allow_on_demand",
                    link.from, link.to, link.from
                ));
            }
            for ep in &link.reverse_endpoints {
                let trimmed = ep.address.trim();
                match trimmed.rsplit_once(':') {
                    Some((host, port_str)) if !host.is_empty() && port_str.parse::<u16>().map(|p| p > 0).unwrap_or(false) => {
                        let h = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
                        if h == "0.0.0.0" || h == "::" || h == "127.0.0.1" || h == "::1" || h == "localhost" {
                            errors.push(format!(
                                "link '{} -> {}' uses local/wildcard reverse endpoint '{}' — specify a reachable LAN/WAN IP",
                                link.from, link.to, ep.address
                            ));
                        }
                    }
                    _ => {
                        errors.push(format!(
                            "link '{} -> {}' has invalid reverse endpoint '{}' (expected host:port)",
                            link.from, link.to, ep.address
                        ));
                    }
                }
            }
            let rev_list = peer_map.entry(link.to.clone()).or_default();
            if !rev_list.iter().any(|p| p.node_tag == link.from) {
                if link.reverse_endpoints.is_empty() {
                    errors.push(format!(
                        "bidirectional on-demand link '{} -> {}' requires reverse_endpoints (address for '{}' to dial '{}'), or uncheck Bidirectional",
                        link.from, link.to, link.to, link.from
                    ));
                } else {
                    rev_list.push(PeerConfig {
                        peer_tag: link.from.clone(),
                        node_tag: link.from.clone(),
                        public_key: node_pubkeys.get(&link.from).cloned(),
                        pubkey_fingerprint: None,
                        mode: LinkMode::OnDemand,
                        tunnel_direction: None,
                        expected_client_addr: link.expected_client_addr.clone(),
                        endpoints: link.reverse_endpoints.clone(),
                    });
                }
            }
        }

        // For inbound/outbound tunnels, links are bidirectional once established
        if link.mode == LinkMode::Tunnel {
            adj.entry(link.to.clone())
                .or_default()
                .insert(link.from.clone());
            // Auto-ensure reverse peer entry on inbound side if not explicitly declared
            let rev_dir = match link.tunnel_direction {
                Some(TunnelDirection::Outbound) => Some(TunnelDirection::Inbound),
                Some(TunnelDirection::Inbound) => Some(TunnelDirection::Outbound),
                None => None,
            };
            let rev_list = peer_map.entry(link.to.clone()).or_default();
            if !rev_list.iter().any(|p| p.node_tag == link.from) {
                rev_list.push(PeerConfig {
                    peer_tag: link.from.clone(),
                    node_tag: link.from.clone(),
                    public_key: node_pubkeys.get(&link.from).cloned(),
                    pubkey_fingerprint: None,
                    mode: LinkMode::Tunnel,
                    tunnel_direction: rev_dir,
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
                // Co-located egress via self node_tag or "local"
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
                        let svc = &node_spec.egress.services[&rule.service_tag];
                        trace_backend = Some(svc.backend.clone());
                        if !svc.allow_any_origin && !svc.allow_from.contains(ingress_tag) {
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

                // Resolve peer_tag on cur_node -> target node_tag
                let peers = peer_map.get(&cur_node);
                let target_node = peers.and_then(|list| {
                    list.iter()
                        .find(|p| p.peer_tag == next_peer_tag || p.node_tag == next_peer_tag)
                        .map(|p| p.node_tag.clone())
                });
                let Some(next_node) = target_node else {
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
                    let svc = &next_spec.egress.services[&rule.service_tag];
                    trace_backend = Some(svc.backend.clone());
                    if !svc.allow_any_origin && !svc.allow_from.contains(ingress_tag) {
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

    // 5. Validate Hop Tables (maintainer_hops)
    for (node_tag, spec) in &topo.nodes {
        if !spec.maintainer_hops.is_empty() {
            validate_hop_path(&spec.maintainer_hops, &adj, topo, &mut errors, &format!("node '{node_tag}' maintainer_hops"));
        }
    }

    // 6. Emit compiled NodeConfig for each node
    let mut compiled = BTreeMap::new();
    for (node_tag, spec) in &topo.nodes {
        let mut maint_cfg = if spec.roles.maintainer {
            let mut mc = spec
                .maintainer_template
                .as_ref()
                .and_then(|t| topo.maintainer_templates.get(t))
                .cloned()
                .unwrap_or_default();
            if let Some((sec, _)) = maintainer_keys.get(node_tag) {
                mc.cert_signing_secret_key = Some(sec.clone());
            }
            Some(mc)
        } else {
            None
        };

        if let Some(ref mut mc) = maint_cfg {
            for order in &mc.acme.orders {
                for (target, hops) in &order.target_hops {
                    validate_hop_path(
                        hops,
                        &adj,
                        topo,
                        &mut errors,
                        &format!("maintainer '{node_tag}' cert '{}' hop to '{target}'", order.domain),
                    );
                }
            }
        }

        let node_cfg = NodeConfig {
            node_tag: node_tag.clone(),
            identity_secret_key: String::new(), // Preserved locally on target Node during hot reload
            control_public_key: Some(control_public_key.to_string()),
            roles: spec.roles.clone(),
            link_listener: spec.link_listener.clone(),
            peers: peer_map.get(node_tag).cloned().unwrap_or_default(),
            probe: spec.probe.clone().unwrap_or_else(ProbeConfig::default),
            default_ttl: 16,
            maintainer_hops: spec.maintainer_hops.clone(),
            trusted_maintainers: trusted_maintainers.clone(),
            logger: topo.global_logger.clone().unwrap_or_default(),
            ingress: spec.ingress.clone(),
            egress: spec.egress.clone(),
            relay: spec.relay.clone(),
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

fn validate_hop_path(
    hops: &[String],
    adj: &HashMap<String, HashSet<String>>,
    topo: &TopologySpec,
    errors: &mut Vec<String>,
    label: &str,
) {
    for h in hops {
        if !topo.nodes.contains_key(h) {
            errors.push(format!("{label}: unknown node '{h}' in hop table"));
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
        adj.entry(link.from.as_str()).or_default().push(link.to.as_str());
        // Allow traversal in both directions for tunnel or bidirectional on-demand links
        if link.mode == LinkMode::Tunnel || (link.mode == LinkMode::OnDemand && link.bidirectional) {
            adj.entry(link.to.as_str()).or_default().push(link.from.as_str());
        }
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    visited.insert(bootstrap_node);
    queue.push_back(vec![control_id.to_string(), bootstrap_node.to_string()]);

    while let Some(path) = queue.pop_front() {
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
        EgressConfig, EgressServiceConfig, IngressConfig, IngressRule, NodeRoles, PeerEndpoint,
        RelayConfig, RelayRule, RuleMatch, TopologyLinkSpec, TopologyNodeSpec,
    };

    #[test]
    fn compiler_detects_loop_and_validates_happy_path() {
        let mut topo = TopologySpec::default();
        topo.nodes.insert(
            "ingress-a".into(),
            TopologyNodeSpec {
                roles: NodeRoles { ingress: true, ..Default::default() },
                ingress: IngressConfig {
                    rules: vec![IngressRule {
                        name: None,
                        r#match: RuleMatch { host: Some("example.com".into()), ..Default::default() },
                        service_tag: "web".into(),
                        next_peer: "relay-1".into(),
                        guard: None,
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
                tls: false,
                allow_from: vec!["ingress-a".into()],
                allow_any_origin: false,
                timeout_ms: 5000,
                local_health_check: None,
            },
        );
        topo.nodes.insert(
            "egress-1".into(),
            TopologyNodeSpec {
                roles: NodeRoles { egress: true, ..Default::default() },
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
            endpoints: vec![PeerEndpoint { address: "127.0.0.1:9001".into(), priority: 10, weight: 100 }],
            expected_client_addr: None,
        });
        topo.links.push(TopologyLinkSpec {
            from: "relay-1".into(),
            to: "egress-1".into(),
            peer_tag: None,
            mode: LinkMode::OnDemand,
            tunnel_direction: None,
            endpoints: vec![PeerEndpoint { address: "127.0.0.1:9002".into(), priority: 10, weight: 100 }],
            expected_client_addr: None,
        });

        let (report, compiled) = compile_topology(&topo, "ctrl-pk", &HashMap::new(), &HashMap::new());
        assert!(report.valid, "errors: {:?}", report.errors);
        assert_eq!(compiled.len(), 3);

        // Introduce loop: relay-1 -> ingress-a
        topo.nodes.get_mut("relay-1").unwrap().relay.rules[0].next_peer = "ingress-a".into();
        topo.links.push(TopologyLinkSpec {
            from: "relay-1".into(),
            to: "ingress-a".into(),
            peer_tag: None,
            mode: LinkMode::OnDemand,
            tunnel_direction: None,
            endpoints: vec![],
            expected_client_addr: None,
        });
        let (loop_report, _) = compile_topology(&topo, "ctrl-pk", &HashMap::new(), &HashMap::new());
        assert!(!loop_report.valid);
        assert!(loop_report.errors.iter().any(|e| e.contains("loop")));
    }
}
