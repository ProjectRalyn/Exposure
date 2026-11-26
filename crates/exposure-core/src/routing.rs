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
/// RFC1918 private, `0.0.0.0/8`, CGNAT `100.64.0.0/10`, link-local, benchmarking `198.18.0.0/15`,
/// documentation, reserved `240.0.0.0/4`, ULA, NAT64, deprecated site-local, multicast, etc.).
pub fn is_public_routable_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let is_nat64 = (s[0] == 0x0064
                && s[1] == 0xff9b
                && s[2] == 0
                && s[3] == 0
                && s[4] == 0
                && s[5] == 0)
                || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 1);
            let is_site_local = (s[0] & 0xffc0) == 0xfec0;
            let is_doc = s[0] == 0x2001 && s[1] == 0x0db8;
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || is_nat64
                || is_site_local
                || is_doc)
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

/// Upper bound on entries parsed into an [`IpMatcher`] so a malformed/hostile config can never
/// turn the per-request exemption lookup into a memory or CPU hazard.
pub const MAX_IP_MATCHER_ENTRIES: usize = 4_096;

/// Pre-parsed CIDR / exact-IP matcher for fully exempted client addresses.
///
/// `ip_matches_cidrs` re-parses strings on every call, which is fine for rare guard decisions but
/// not for the request hot path. This type parses once when the node config is applied and keeps
/// the result as a compact `IpNet` list.
#[derive(Debug, Clone, Default)]
pub struct IpMatcher {
    nets: Vec<IpNet>,
    exact: Vec<IpAddr>,
}

impl IpMatcher {
    pub fn parse(entries: &[String]) -> Self {
        let mut nets = Vec::new();
        let mut exact = Vec::new();
        for raw in entries.iter().take(MAX_IP_MATCHER_ENTRIES) {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            if let Ok(net) = raw.parse::<IpNet>() {
                if !nets.contains(&net) {
                    nets.push(net);
                }
            } else if let Ok(ip) = raw.parse::<IpAddr>() {
                let ip = canonical_ip(ip);
                if !exact.contains(&ip) {
                    exact.push(ip);
                }
            }
        }
        Self { nets, exact }
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty() && self.exact.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nets.len() + self.exact.len()
    }

    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.is_empty() {
            return false;
        }
        let ip = canonical_ip(ip);
        self.exact.contains(&ip) || self.nets.iter().any(|net| net.contains(&ip))
    }
}

fn has_forbidden_host_chars(s: &str) -> bool {
    s.is_empty()
        || s.bytes().any(|b| {
            b <= 0x20 || b >= 0x7f || matches!(b, b'@' | b'/' | b'\\' | b'?' | b'#' | b'[' | b']')
        })
}

/// Strictly validate an HTTP `Host` / `:authority` header value.
/// Returns canonical lowercase `host` (keeping `[ipv6]` brackets and valid non-empty numeric `:port`)
/// or `None` for malformed values (`@` userinfo, path separators, invalid ports, control chars).
pub fn parse_valid_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.bytes().any(|b| {
            b <= 0x20 || b >= 0x7f || matches!(b, b'@' | b'/' | b'\\' | b'?' | b'#' | b'*')
        })
    {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (v6, tail) = rest.split_once(']')?;
        let parsed_v6 = v6.parse::<std::net::Ipv6Addr>().ok()?;
        if tail.is_empty() {
            return Some(format!("[{parsed_v6}]"));
        }
        let port_str = tail.strip_prefix(':')?;
        let port: u16 = port_str.parse().ok().filter(|&p| p > 0)?;
        return Some(format!("[{parsed_v6}]:{port}"));
    }
    if let Ok(parsed_v6) = trimmed.parse::<std::net::Ipv6Addr>() {
        return Some(format!("[{parsed_v6}]"));
    }
    let (host_part, port_opt) = match trimmed.split_once(':') {
        Some((h, p)) => {
            if h.is_empty() || p.contains(':') {
                return None;
            }
            let port: u16 = p.parse().ok().filter(|&n| n > 0)?;
            (h, Some(port))
        }
        None => (trimmed, None),
    };
    let clean_host = host_part.trim_end_matches('.');
    if clean_host.is_empty()
        || has_forbidden_host_chars(clean_host)
        || clean_host.starts_with('.')
        || clean_host.contains("..")
    {
        return None;
    }
    let lower = clean_host.to_ascii_lowercase();
    Some(match port_opt {
        Some(p) => format!("{lower}:{p}"),
        None => lower,
    })
}

/// Extract normalized hostname without port (IPv6-bracket & strict-port safe) and without trailing FQDN dot.
/// Malformed host strings (e.g. `allowed.example:@evil.example`) normalize to `""` so they never match.
pub fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_empty()
        || trimmed
            .bytes()
            .any(|b| b <= 0x20 || b >= 0x7f || matches!(b, b'@' | b'/' | b'\\' | b'?' | b'#'))
    {
        return String::new();
    }
    let without_port = if let Some(rest) = trimmed.strip_prefix('[') {
        let Some((v6, tail)) = rest.split_once(']') else {
            return String::new();
        };
        if !tail.is_empty() {
            let Some(port_str) = tail.strip_prefix(':') else {
                return String::new();
            };
            if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
                return String::new();
            }
        }
        if v6.parse::<std::net::Ipv6Addr>().is_err() {
            return String::new();
        }
        v6
    } else if let Some((h, port_str)) = trimmed.split_once(':') {
        if trimmed.matches(':').count() == 1 {
            if port_str.is_empty()
                || !port_str.bytes().all(|b| b.is_ascii_digit())
                || has_forbidden_host_chars(h)
            {
                return String::new();
            }
            h
        } else if trimmed.parse::<std::net::Ipv6Addr>().is_ok() {
            trimmed
        } else {
            return String::new();
        }
    } else if has_forbidden_host_chars(trimmed) {
        return String::new();
    } else {
        trimmed
    };
    without_port.trim_end_matches('.').to_ascii_lowercase()
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
                    out.push(if decoded == b'\\' {
                        '/'
                    } else {
                        decoded as char
                    });
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
    normalized_path.len() == prefix.len() || normalized_path.as_bytes()[prefix.len()] == b'/'
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
        let r1 = match_ingress_rule(
            &rules,
            "api.example.com.:443",
            "/x/../%61pi/v1",
            mapped_v6,
            None,
        );
        assert_eq!(r1.unwrap().service_tag, "web@region-a");

        // Segment boundary: /api-public must NOT match /api
        let r_seg = match_ingress_rule(&rules, "api.example.com", "/api-public", mapped_v6, None);
        assert_eq!(r_seg.unwrap().service_tag, "web@default");

        let r2 = match_ingress_rule(
            &rules,
            "api.example.com",
            "/api/v1",
            "198.51.100.5".parse().unwrap(),
            None,
        );
        assert_eq!(r2.unwrap().service_tag, "web@default");

        // IPv6 bracket host normalization & strict port validation
        assert_eq!(normalize_host("[2001:db8::1]:443"), "2001:db8::1");
        assert!(host_matches("2001:db8::1", "[2001:db8::1]:443"));
        assert_eq!(normalize_host("allowed.example:@evil.example"), "");
        assert!(!any_rule_matches_host(
            &rules,
            "api.example.com:@evil.example"
        ));
        assert_eq!(
            parse_valid_host("App.Example.COM.:443").as_deref(),
            Some("app.example.com:443")
        );
        assert_eq!(parse_valid_host("allowed.example:@evil.example"), None);
        assert_eq!(parse_valid_host("good.example/path"), None);
        assert!(!is_public_routable_ip("0.0.0.1".parse().unwrap()));
        assert!(!is_public_routable_ip("198.18.0.1".parse().unwrap()));
        assert!(!is_public_routable_ip("240.0.0.1".parse().unwrap()));
        assert!(!is_public_routable_ip("64:ff9b::1".parse().unwrap()));
        assert!(!is_public_routable_ip("fec0::1".parse().unwrap()));
        assert!(!is_public_routable_ip("2001:db8::1".parse().unwrap()));
        assert!(is_public_routable_ip("1.1.1.1".parse().unwrap()));

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
        assert!(
            match_ingress_rule(&explicit_wildcard, "anything.test", "/", mapped_v6, None).is_some()
        );
    }

    #[test]
    fn endpoint_priority_weight_and_backup_zero() {
        let eps = vec![
            PeerEndpoint {
                address: "a:1".into(),
                priority: 10,
                weight: 70,
            },
            PeerEndpoint {
                address: "b:1".into(),
                priority: 10,
                weight: 30,
            },
            PeerEndpoint {
                address: "backup:1".into(),
                priority: 1,
                weight: 0,
            },
        ];
        let mut health = HashMap::new();
        health.insert("a:1".into(), LinkHealthState::Up);
        health.insert("b:1".into(), LinkHealthState::Up);
        health.insert("backup:1".into(), LinkHealthState::Up);

        assert_eq!(select_endpoint(&eps, &health, 0).unwrap().address, "a:1");
        assert_eq!(select_endpoint(&eps, &health, 75).unwrap().address, "b:1");

        health.insert("a:1".into(), LinkHealthState::Down);
        health.insert("b:1".into(), LinkHealthState::Down);
        assert_eq!(
            select_endpoint(&eps, &health, 0).unwrap().address,
            "backup:1"
        );
    }

    #[test]
    fn ip_matcher_handles_exact_cidr_and_v4_mapped_addresses() {
        let m = IpMatcher::parse(&[
            " 203.0.113.7 ".to_string(),
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
            "not-an-ip".to_string(),
            "".to_string(),
            "10.0.0.0/8".to_string(), // duplicate is collapsed
        ]);
        assert_eq!(m.len(), 3);
        assert!(m.contains("203.0.113.7".parse().unwrap()));
        assert!(!m.contains("203.0.113.8".parse().unwrap()));
        assert!(m.contains("10.42.1.9".parse().unwrap()));
        assert!(m.contains("2001:db8::5".parse().unwrap()));
        assert!(!m.contains("2001:db9::5".parse().unwrap()));
        // IPv4-mapped IPv6 peers must match their IPv4 entry.
        assert!(m.contains("::ffff:203.0.113.7".parse().unwrap()));
        assert!(m.contains("::ffff:10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn empty_ip_matcher_never_matches() {
        let m = IpMatcher::parse(&[]);
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
        assert!(!m.contains("8.8.8.8".parse().unwrap()));
    }
}
