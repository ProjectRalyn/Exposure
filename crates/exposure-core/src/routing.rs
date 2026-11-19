use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::config::{IngressRule, PeerEndpoint};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum LinkHealthState {
    Up,
    Degraded,
    Down,
}

impl std::fmt::Display for LinkHealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkHealthState::Up => write!(f, "UP"),
            LinkHealthState::Degraded => write!(f, "DEGRADED"),
            LinkHealthState::Down => write!(f, "DOWN"),
        }
    }
}

pub fn ip_matches_cidrs(ip: IpAddr, cidrs: &[String]) -> bool {
    if cidrs.is_empty() {
        return true;
    }
    for raw in cidrs {
        if let Ok(net) = raw.parse::<IpNet>() {
            if net.contains(&ip) {
                return true;
            }
        } else if let Ok(single) = raw.parse::<IpAddr>() {
            if single == ip {
                return true;
            }
        }
    }
    false
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pat = pattern.trim().to_ascii_lowercase();
    let h = host
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if pat == "*" || pat == h {
        return true;
    }
    if let Some(suffix) = pat.strip_prefix("*.") {
        return h.ends_with(suffix) && h.len() > suffix.len() && h.as_bytes()[h.len() - suffix.len() - 1] == b'.';
    }
    false
}

/// Match an incoming L7 request against configured ingress rules in declaration order.
pub fn match_ingress_rule<'a>(
    rules: &'a [IngressRule],
    host: &str,
    path: &str,
    client_ip: IpAddr,
    sni: Option<&str>,
) -> Option<&'a IngressRule> {
    for rule in rules {
        let m = &rule.r#match;
        if let Some(ref pat) = m.host {
            if !host_matches(pat, host) {
                continue;
            }
        }
        if let Some(ref prefix) = m.url_prefix {
            if !path.starts_with(prefix) {
                continue;
            }
        }
        if !m.source_cidrs.is_empty() && !ip_matches_cidrs(client_ip, &m.source_cidrs) {
            continue;
        }
        if let Some(ref expected_sni) = m.sni {
            match sni {
                Some(actual) if host_matches(expected_sni, actual) => {}
                _ => continue,
            }
        }
        return Some(rule);
    }
    None
}

/// Select an endpoint according to DESIGN.md §6.4:
/// 1. Prefer highest priority (smallest numeric `priority` value) among UP endpoints (fallback to DEGRADED).
/// 2. Within same priority, distribute proportionally by `weight`.
/// 3. Endpoints with `weight == 0` act purely as backups when no weighted healthy endpoint is available.
pub fn select_endpoint<'a>(
    endpoints: &'a [PeerEndpoint],
    health: &HashMap<String, LinkHealthState>,
    selector_ticket: u64,
) -> Option<&'a PeerEndpoint> {
    if endpoints.is_empty() {
        return None;
    }

    let state_of = |ep: &PeerEndpoint| -> LinkHealthState {
        health
            .get(&ep.address)
            .copied()
            .unwrap_or(LinkHealthState::Up)
    };

    // Pass 1: primary (weight > 0) UP -> Pass 2: primary DEGRADED -> Pass 3: backup (weight == 0) UP -> Pass 4: backup DEGRADED
    let phases: [(bool, LinkHealthState); 4] = [
        (true, LinkHealthState::Up),
        (true, LinkHealthState::Degraded),
        (false, LinkHealthState::Up),
        (false, LinkHealthState::Degraded),
    ];

    for (primary_only, target_state) in phases {
        let candidates: Vec<&PeerEndpoint> = endpoints
            .iter()
            .filter(|ep| {
                let is_primary = ep.weight > 0;
                is_primary == primary_only && state_of(ep) == target_state
            })
            .collect();

        if candidates.is_empty() {
            continue;
        }

        let best_prio = candidates.iter().map(|e| e.priority).min().unwrap();
        let top: Vec<&PeerEndpoint> = candidates
            .into_iter()
            .filter(|e| e.priority == best_prio)
            .collect();

        if primary_only {
            let total_weight: u64 = top.iter().map(|e| e.weight as u64).sum();
            if total_weight == 0 {
                return Some(top[0]);
            }
            let mut pick = selector_ticket % total_weight;
            for ep in top {
                let w = ep.weight as u64;
                if pick < w {
                    return Some(ep);
                }
                pick -= w;
            }
        } else {
            let idx = (selector_ticket as usize) % top.len();
            return Some(top[idx]);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleMatch;

    #[test]
    fn ingress_rule_matching() {
        let rules = vec![
            IngressRule {
                name: Some("region-a".into()),
                r#match: RuleMatch {
                    host: Some("*.example.com".into()),
                    url_prefix: Some("/api".into()),
                    source_cidrs: vec!["203.0.113.0/24".into()],
                    sni: None,
                },
                service_tag: "web@region-a".into(),
                next_peer: "relay-a".into(),
                guard: None,
            },
            IngressRule {
                name: Some("default".into()),
                r#match: RuleMatch {
                    host: Some("api.example.com".into()),
                    url_prefix: None,
                    source_cidrs: vec![],
                    sni: None,
                },
                service_tag: "web@default".into(),
                next_peer: "relay-b".into(),
                guard: None,
            },
        ];

        let r1 = match_ingress_rule(&rules, "api.example.com:443", "/api/v1", "203.0.113.42".parse().unwrap(), None);
        assert_eq!(r1.unwrap().service_tag, "web@region-a");

        let r2 = match_ingress_rule(&rules, "api.example.com", "/api/v1", "198.51.100.5".parse().unwrap(), None);
        assert_eq!(r2.unwrap().service_tag, "web@default");
    }

    #[test]
    fn endpoint_priority_weight_and_backup_zero() {
        let eps = vec![
            PeerEndpoint { address: "a:1".into(), priority: 10, weight: 70 },
            PeerEndpoint { address: "b:1".into(), priority: 10, weight: 30 },
            PeerEndpoint { address: "backup:1".into(), priority: 1, weight: 0 },
        ];
        let mut health = HashMap::new();
        health.insert("a:1".into(), LinkHealthState::Up);
        health.insert("b:1".into(), LinkHealthState::Up);
        health.insert("backup:1".into(), LinkHealthState::Up);

        // Weight 0 backup should NOT be selected while primary endpoints are UP
        assert_eq!(select_endpoint(&eps, &health, 0).unwrap().address, "a:1");
        assert_eq!(select_endpoint(&eps, &health, 75).unwrap().address, "b:1");

        // When primary endpoints go DOWN, backup (weight 0) takes over
        health.insert("a:1".into(), LinkHealthState::Down);
        health.insert("b:1".into(), LinkHealthState::Down);
        assert_eq!(select_endpoint(&eps, &health, 0).unwrap().address, "backup:1");
    }
}
