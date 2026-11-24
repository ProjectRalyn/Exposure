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

/// Normalize IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to canonical `IpAddr::V4`.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Returns `true` for globally routable unicast IPv4/IPv6 addresses (excluding loopback,
/// RFC1918 private, CGNAT `100.64.0.0/10`, link-local, documentation, ULA, multicast, etc.).
pub fn is_public_routable_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

pub fn ip_matches_cidrs(ip: IpAddr, cidrs: &[String]) -> bool {
    if cidrs.is_empty() {
        return true;
    }
    let ip = canonical_ip(ip);
    for raw in cidrs {
        if let Ok(net) = raw.trim().parse::<IpNet>() {
            if net.contains(&ip) {
                return true;
            }
        } else if let Ok(single) = raw.trim().parse::<IpAddr>() {
            if canonical_ip(single) == ip {
                return true;
            }
        }
    }
    false
}

/// Extract normalized hostname without port (IPv6-bracket safe) and without trailing FQDN dot.
pub fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    let without_port = if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((v6, _)) = rest.split_once(']') {
            v6
        } else {
            trimmed
        }
    } else if trimmed.matches(':').count() == 1 {
        trimmed.split(':').next().unwrap_or("")
    } else {
        // Bare IPv6 address without brackets or hostname without port
        trimmed
    };
    without_port
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pat = normalize_host(pattern);
    let h = normalize_host(host);
    if pat == "*" || pat == h {
        return true;
    }
    if let Some(suffix) = pat.strip_prefix("*.") {
        return h.ends_with(suffix)
            && h.len() > suffix.len()
            && h.as_bytes()[h.len() - suffix.len() - 1] == b'.';
    }
    false
}

/// Normalize a request path by decoding percent-encoded unreserved/slash bytes, collapsing `//`,
/// and resolving `.` and `..` segments to prevent `url_prefix` rule bypasses.
pub fn normalize_path_for_match(raw_path: &str) -> String {
    let decoded = percent_decode_path_chars(raw_path);
    let mut stack: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", stack.join("/"))
    }
}

fn percent_decode_path_chars(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                let decoded = (hi << 4) | lo;
                if decoded.is_ascii_graphic() && decoded != b'?' && decoded != b'#' {
                    // Treat a percent-encoded backslash as a path separator too, so `..%5c`
                    // cannot be viewed differently by rule matching vs. a `\`-aware backend.
                    out.push(if decoded == b'\\' { '/' } else { decoded as char });
                    i += 3;
                    continue;
                }
            }
        }
        if bytes[i] == b'\\' {
            out.push('/');
        } else {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn path_matches_prefix(normalized_path: &str, raw_prefix: &str) -> bool {
    let prefix = normalize_path_for_match(raw_prefix);
    if prefix == "/" {
        return normalized_path.starts_with('/');
    }
    if !normalized_path.starts_with(&prefix) {
        return false;
    }
    normalized_path.len() == prefix.len()
        || normalized_path.as_bytes()[prefix.len()] == b'/'
}

/// Check whether any configured ingress rule explicitly matches the given `host`.
/// Rules with empty/missing `match.host` never match (must explicitly set `"*"` to accept all hosts).
pub fn any_rule_matches_host(rules: &[IngressRule], host: &str) -> bool {
    let norm_h = normalize_host(host);
    if norm_h.is_empty() {
        return false;
    }
    rules.iter().any(|rule| {
        rule.r#match
            .host
            .as_deref()
            .map(str::trim)
            .filter(|pat| !pat.is_empty())
            .map(|pat| host_matches(pat, &norm_h))
            .unwrap_or(false)
    })
}

/// Match an incoming L7 request against configured ingress rules in declaration order.
/// Every rule MUST explicitly specify `match.host` (set `"*"` explicitly to match all hosts).
pub fn match_ingress_rule<'a>(
    rules: &'a [IngressRule],
    host: &str,
    path: &str,
    client_ip: IpAddr,
    sni: Option<&str>,
) -> Option<&'a IngressRule> {
    let norm_h = normalize_host(host);
    if norm_h.is_empty() {
        return None;
    }
    let norm_path = normalize_path_for_match(path);
    for rule in rules {
        let m = &rule.r#match;
        let Some(pat) = m.host.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
            continue;
        };
        if !host_matches(pat, &norm_h) {
            continue;
        }
        if let Some(ref prefix) = m.url_prefix {
            if !path_matches_prefix(&norm_path, prefix) {
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

    // Health-first ordering: a healthy backup must be preferred over a degraded primary,
    // otherwise failover to backups never happens while a primary is merely degraded.
    let phases: [(bool, LinkHealthState); 4] = [
        (true, LinkHealthState::Up),
        (false, LinkHealthState::Up),
        (true, LinkHealthState::Degraded),
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
    fn ingress_rule_matching_and_normalization() {
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
                intercept_errors: Some(false),
                js_fp_beacon: None,
                cache: None,
                ..Default::default()
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
                intercept_errors: Some(false),
                js_fp_beacon: None,
                cache: None,
                ..Default::default()
            },
        ];

        // Normal match + trailing dot + IPv4-mapped IPv6 + traversal path normalization
        let mapped_v6: IpAddr = "::ffff:203.0.113.42".parse().unwrap();
        let r1 = match_ingress_rule(&rules, "api.example.com.:443", "/x/../%61pi/v1", mapped_v6, None);
        assert_eq!(r1.unwrap().service_tag, "web@region-a");

        // Segment boundary: /api-public must NOT match /api
        let r_seg = match_ingress_rule(&rules, "api.example.com", "/api-public", mapped_v6, None);
        assert_eq!(r_seg.unwrap().service_tag, "web@default");

        let r2 = match_ingress_rule(&rules, "api.example.com", "/api/v1", "198.51.100.5".parse().unwrap(), None);
        assert_eq!(r2.unwrap().service_tag, "web@default");

        // IPv6 bracket host normalization
        assert_eq!(normalize_host("[2001:db8::1]:443"), "2001:db8::1");
        assert!(host_matches("2001:db8::1", "[2001:db8::1]:443"));

        // Unknown host must not match; rule with host=None must fail closed unless host="*"
        assert!(!any_rule_matches_host(&rules, "evil.example"));
        assert!(match_ingress_rule(&rules, "evil.example", "/", mapped_v6, None).is_none());
        let hostless = vec![IngressRule {
            name: Some("empty-host".into()),
            r#match: RuleMatch {
                host: None,
                url_prefix: None,
                source_cidrs: vec![],
                sni: None,
            },
            service_tag: "svc".into(),
            next_peer: "p".into(),
            guard: None,
            intercept_errors: None,
            js_fp_beacon: None,
            cache: None,
            ..Default::default()
        }];
        assert!(match_ingress_rule(&hostless, "anything.test", "/", mapped_v6, None).is_none());
        let explicit_wildcard = vec![IngressRule {
            r#match: RuleMatch {
                host: Some("*".into()),
                ..Default::default()
            },
            ..hostless[0].clone()
        }];
        assert!(match_ingress_rule(&explicit_wildcard, "anything.test", "/", mapped_v6, None).is_some());
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

        assert_eq!(select_endpoint(&eps, &health, 0).unwrap().address, "a:1");
        assert_eq!(select_endpoint(&eps, &health, 75).unwrap().address, "b:1");

        health.insert("a:1".into(), LinkHealthState::Down);
        health.insert("b:1".into(), LinkHealthState::Down);
        assert_eq!(select_endpoint(&eps, &health, 0).unwrap().address, "backup:1");
    }
}
