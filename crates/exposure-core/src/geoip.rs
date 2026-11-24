use std::net::IpAddr;

use ipnet::IpNet;

use crate::config::{GeoPolicyConfig, GeoRuleAction};
use crate::routing::{canonical_ip, is_public_routable_ip};

const GEOIP_BIN_MAGIC: &[u8; 8] = b"EXPGEO01";
const MAX_GEOIP_BINARY_RANGES: usize = 4_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoLookupResult {
    pub country: [u8; 2],
    pub continent: &'static str,
}

impl GeoLookupResult {
    pub fn country_str(&self) -> &str {
        std::str::from_utf8(&self.country).unwrap_or("XX")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoDecision {
    Allow {
        suspicion_boost: i16,
    },
    Monitor {
        suspicion_boost: i16,
        reason: String,
    },
    Challenge {
        suspicion_boost: i16,
        reason: String,
    },
    Block {
        reason: String,
    },
    Evilpot {
        reason: String,
    },
}

/// Compact sorted-interval in-memory GeoIP IPv4/IPv6 database (~6 MB RAM, O(log N) lookup).
#[derive(Debug, Clone, Default)]
pub struct GeoIpDatabase {
    v4: Vec<(u32, u32, [u8; 2])>,
    v6: Vec<(u128, u128, [u8; 2])>,
    pub source: String,
    pub updated_at: i64,
}

impl GeoIpDatabase {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn ipv4_len(&self) -> usize {
        self.v4.len()
    }

    pub fn ipv6_len(&self) -> usize {
        self.v6.len()
    }

    /// Parse free CSV IPv4/IPv6 GeoIP databases (supports both `start,end,CC` ranges from
    /// `sapics/ip-location-db` and `cidr,CC` format).
    pub fn parse_csv_ranges(
        ipv4_csv: Option<&str>,
        ipv6_csv: Option<&str>,
        source: impl Into<String>,
        updated_at: i64,
    ) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();

        if let Some(csv) = ipv4_csv {
            for line in csv.lines() {
                parse_csv_line_into(line, &mut v4, &mut v6);
            }
        }
        if let Some(csv) = ipv6_csv {
            for line in csv.lines() {
                parse_csv_line_into(line, &mut v4, &mut v6);
            }
        }

        coalesce_v4(&mut v4);
        coalesce_v6(&mut v6);

        Self {
            v4,
            v6,
            source: source.into(),
            updated_at,
        }
    }

    /// Look up country & continent for any IPv4/IPv6 address (~50ns O(log N) binary search).
    /// Non-public / loopback / RFC1918 / RFC5737 IPs always return `None`.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLookupResult> {
        let canon = canonical_ip(ip);
        if !is_public_routable_ip(canon) {
            return None;
        }
        let cc = match canon {
            IpAddr::V4(addr) => {
                let n = u32::from(addr);
                let idx = self.v4.partition_point(|r| r.0 <= n);
                let prev = idx.checked_sub(1)?;
                let r = self.v4[prev];
                if n >= r.0 && n <= r.1 {
                    r.2
                } else {
                    return None;
                }
            }
            IpAddr::V6(addr) => {
                let n = u128::from(addr);
                let idx = self.v6.partition_point(|r| r.0 <= n);
                let prev = idx.checked_sub(1)?;
                let r = self.v6[prev];
                if n >= r.0 && n <= r.1 {
                    r.2
                } else {
                    return None;
                }
            }
        };
        let cc_str = std::str::from_utf8(&cc).unwrap_or("XX");
        Some(GeoLookupResult {
            country: cc,
            continent: country_to_continent(cc_str),
        })
    }

    /// Encode sorted IPv4/IPv6 ranges into compact binary format (`EXPGEO01`) for instant disk cache load.
    pub fn encode_binary(&self) -> Vec<u8> {
        let src_bytes = self.source.as_bytes();
        let src_len = src_bytes.len().min(u16::MAX as usize);
        let cap = 8 + 8 + 2 + src_len + 4 + self.v4.len() * 10 + 4 + self.v6.len() * 34;
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(GEOIP_BIN_MAGIC);
        out.extend_from_slice(&self.updated_at.to_le_bytes());
        out.extend_from_slice(&(src_len as u16).to_le_bytes());
        out.extend_from_slice(&src_bytes[..src_len]);

        let v4_cnt = self.v4.len().min(MAX_GEOIP_BINARY_RANGES);
        out.extend_from_slice(&(v4_cnt as u32).to_le_bytes());
        for &(s, e, cc) in &self.v4[..v4_cnt] {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&cc);
        }

        let v6_cnt = self.v6.len().min(MAX_GEOIP_BINARY_RANGES);
        out.extend_from_slice(&(v6_cnt as u32).to_le_bytes());
        for &(s, e, cc) in &self.v6[..v6_cnt] {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&cc);
        }
        out
    }

    /// Decode `EXPGEO01` binary cache with strict bounds checking against truncation or OOM corruption.
    pub fn decode_binary(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 22 || &bytes[..8] != GEOIP_BIN_MAGIC {
            return Err("invalid geoip binary header".into());
        }
        let mut pos = 8;
        let updated_at = i64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let src_len = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if pos + src_len + 4 > bytes.len() {
            return Err("truncated geoip source string".into());
        }
        let source = String::from_utf8_lossy(&bytes[pos..pos + src_len]).into_owned();
        pos += src_len;

        let v4_cnt = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if v4_cnt > MAX_GEOIP_BINARY_RANGES
            || pos.saturating_add(v4_cnt.saturating_mul(10)).saturating_add(4) > bytes.len()
        {
            return Err("invalid/truncated geoip v4 section".into());
        }
        let mut v4 = Vec::with_capacity(v4_cnt);
        for _ in 0..v4_cnt {
            let s = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
            let e = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap());
            let cc = [bytes[pos + 8], bytes[pos + 9]];
            v4.push((s, e, cc));
            pos += 10;
        }

        let v6_cnt = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if v6_cnt > MAX_GEOIP_BINARY_RANGES
            || pos.saturating_add(v6_cnt.saturating_mul(34)) > bytes.len()
        {
            return Err("invalid/truncated geoip v6 section".into());
        }
        let mut v6 = Vec::with_capacity(v6_cnt);
        for _ in 0..v6_cnt {
            let s = u128::from_le_bytes(bytes[pos..pos + 16].try_into().unwrap());
            let e = u128::from_le_bytes(bytes[pos + 16..pos + 32].try_into().unwrap());
            let cc = [bytes[pos + 32], bytes[pos + 33]];
            v6.push((s, e, cc));
            pos += 34;
        }

        Ok(Self {
            v4,
            v6,
            source,
            updated_at,
        })
    }
}

fn clean_csv_field(raw: &str) -> &str {
    raw.trim().trim_matches('"').trim()
}

fn parse_country_code(raw: &str) -> Option<[u8; 2]> {
    let s = clean_csv_field(raw);
    if s.len() != 2 || !s.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let b = s.as_bytes();
    let cc = [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()];
    if &cc == b"ZZ" || &cc == b"XX" {
        return None;
    }
    Some(cc)
}

fn parse_csv_line_into(
    line: &str,
    v4: &mut Vec<(u32, u32, [u8; 2])>,
    v6: &mut Vec<(u128, u128, [u8; 2])>,
) {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    let parts: Vec<&str> = trimmed.split(',').collect();
    match parts.len() {
        3 => {
            let Some(cc) = parse_country_code(parts[2]) else {
                return;
            };
            let Ok(start_ip) = clean_csv_field(parts[0]).parse::<IpAddr>() else {
                return;
            };
            let Ok(end_ip) = clean_csv_field(parts[1]).parse::<IpAddr>() else {
                return;
            };
            match (canonical_ip(start_ip), canonical_ip(end_ip)) {
                (IpAddr::V4(s), IpAddr::V4(e)) => {
                    let sv = u32::from(s);
                    let ev = u32::from(e);
                    if sv <= ev {
                        v4.push((sv, ev, cc));
                    }
                }
                (IpAddr::V6(s), IpAddr::V6(e)) => {
                    let sv = u128::from(s);
                    let ev = u128::from(e);
                    if sv <= ev {
                        v6.push((sv, ev, cc));
                    }
                }
                _ => {}
            }
        }
        2 => {
            let Some(cc) = parse_country_code(parts[1]) else {
                return;
            };
            let Ok(net) = clean_csv_field(parts[0]).parse::<IpNet>() else {
                return;
            };
            match net {
                IpNet::V4(n) => v4.push((u32::from(n.network()), u32::from(n.broadcast()), cc)),
                IpNet::V6(n) => v6.push((u128::from(n.network()), u128::from(n.broadcast()), cc)),
            }
        }
        _ => {}
    }
}

fn coalesce_v4(ranges: &mut Vec<(u32, u32, [u8; 2])>) {
    if ranges.len() <= 1 {
        return;
    }
    ranges.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut write = 0usize;
    for read in 1..ranges.len() {
        let cur = ranges[read];
        let prev = &mut ranges[write];
        if cur.2 == prev.2 && cur.0 <= prev.1.saturating_add(1) {
            if cur.1 > prev.1 {
                prev.1 = cur.1;
            }
        } else {
            write += 1;
            ranges[write] = cur;
        }
    }
    ranges.truncate(write + 1);
}

fn coalesce_v6(ranges: &mut Vec<(u128, u128, [u8; 2])>) {
    if ranges.len() <= 1 {
        return;
    }
    ranges.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut write = 0usize;
    for read in 1..ranges.len() {
        let cur = ranges[read];
        let prev = &mut ranges[write];
        if cur.2 == prev.2 && cur.0 <= prev.1.saturating_add(1) {
            if cur.1 > prev.1 {
                prev.1 = cur.1;
            }
        } else {
            write += 1;
            ranges[write] = cur;
        }
    }
    ranges.truncate(write + 1);
}

/// Normalize a user-supplied Geo region token (`"cn"` -> `"CN"`, `"continent:as"` -> `"CONTINENT:AS"`, `"*"` -> `"*"`).
pub fn normalize_region_token(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s == "*" {
        return Some("*".into());
    }
    if s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Some(s.to_ascii_uppercase());
    }
    if let Some((prefix, cont)) = s.split_once(':') {
        if prefix.trim().eq_ignore_ascii_case("continent") {
            let cu = cont.trim().to_ascii_uppercase();
            if matches!(cu.as_str(), "AS" | "EU" | "NA" | "SA" | "AF" | "OC" | "AN") {
                return Some(format!("CONTINENT:{cu}"));
            }
        }
    }
    None
}

/// Validate a region selector (`CN`, `US`, `CONTINENT:AS`, `*`).
pub fn is_valid_region_token(raw: &str) -> bool {
    normalize_region_token(raw).is_some()
}

pub fn region_token_matches(token: &str, geo: &GeoLookupResult) -> bool {
    let Some(norm) = normalize_region_token(token) else {
        return false;
    };
    if norm == "*" {
        return true;
    }
    if let Some(cont) = norm.strip_prefix("CONTINENT:") {
        return geo.continent == cont;
    }
    geo.country_str() == norm
}

fn action_to_decision(action: GeoRuleAction, boost: i16, reason: String) -> GeoDecision {
    match action {
        GeoRuleAction::Off | GeoRuleAction::Allow => GeoDecision::Allow {
            suspicion_boost: boost,
        },
        GeoRuleAction::Monitor => GeoDecision::Monitor {
            suspicion_boost: boost,
            reason,
        },
        GeoRuleAction::Challenge => GeoDecision::Challenge {
            suspicion_boost: boost,
            reason,
        },
        GeoRuleAction::Block => GeoDecision::Block { reason },
        GeoRuleAction::Evilpot => GeoDecision::Evilpot { reason },
    }
}

/// Evaluate a GeoIP region-targeting policy against an incoming client's resolved GeoIP info.
pub fn evaluate_geo_policy(
    policy: &GeoPolicyConfig,
    geo: Option<&GeoLookupResult>,
    is_private: bool,
) -> GeoDecision {
    if !policy.enabled || is_private {
        return GeoDecision::Allow { suspicion_boost: 0 };
    }
    let Some(g) = geo else {
        return action_to_decision(policy.unknown_action, 0, "geo:unknown".into());
    };
    let cc = g.country_str();

    // 1. Ordered per-region rules (first match wins)
    for rule in &policy.rules {
        if rule.regions.iter().any(|tok| region_token_matches(tok, g)) {
            let reason = format!(
                "geo:rule:{}:{}",
                cc,
                rule.note
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("matched")
            );
            return action_to_decision(rule.action, rule.suspicion_boost, reason);
        }
    }

    // 2. Explicit denylist
    if !policy.deny_regions.is_empty()
        && policy.deny_regions.iter().any(|tok| region_token_matches(tok, g))
    {
        return action_to_decision(policy.deny_action, 0, format!("geo:deny:{cc}"));
    }

    // 3. Explicit allowlist
    if !policy.allow_regions.is_empty()
        && !policy
            .allow_regions
            .iter()
            .any(|tok| region_token_matches(tok, g))
    {
        return action_to_decision(policy.deny_action, 0, format!("geo:not_allowed:{cc}"));
    }

    // 4. Default action
    action_to_decision(policy.default_action, 0, format!("geo:default:{cc}"))
}

/// Static ISO-3166-1 alpha-2 country code -> Continent code (`AS | EU | NA | SA | AF | OC | AN`).
pub fn country_to_continent(cc: &str) -> &'static str {
    let up = cc.trim().to_ascii_uppercase();
    match up.as_str() {
        // Asia (AS)
        "AE" | "AF" | "AM" | "AZ" | "BD" | "BH" | "BN" | "BT" | "CN" | "CY" | "GE" | "HK"
        | "ID" | "IL" | "IN" | "IQ" | "IR" | "JO" | "JP" | "KG" | "KH" | "KP" | "KR" | "KW"
        | "KZ" | "LA" | "LB" | "LK" | "MM" | "MN" | "MO" | "MV" | "MY" | "NP" | "OM" | "PH"
        | "PK" | "PS" | "QA" | "SA" | "SG" | "SY" | "TH" | "TJ" | "TL" | "TM" | "TR" | "TW"
        | "UZ" | "VN" | "YE" => "AS",
        // Europe (EU)
        "AD" | "AL" | "AT" | "AX" | "BA" | "BE" | "BG" | "BY" | "CH" | "CZ" | "DE" | "DK"
        | "EE" | "ES" | "FI" | "FO" | "FR" | "GB" | "GG" | "GI" | "GR" | "HR" | "HU" | "IE"
        | "IM" | "IS" | "IT" | "JE" | "LI" | "LT" | "LU" | "LV" | "MC" | "MD" | "ME" | "MK"
        | "MT" | "NL" | "NO" | "PL" | "PT" | "RO" | "RS" | "RU" | "SE" | "SI" | "SJ" | "SK"
        | "SM" | "UA" | "VA" | "XK" => "EU",
        // North America (NA)
        "AG" | "AI" | "AW" | "BB" | "BL" | "BM" | "BQ" | "BS" | "BZ" | "CA" | "CR" | "CU"
        | "CW" | "DM" | "DO" | "GD" | "GL" | "GP" | "GT" | "HN" | "HT" | "JM" | "KN" | "KY"
        | "LC" | "MF" | "MQ" | "MS" | "MX" | "NI" | "PA" | "PM" | "PR" | "SV" | "SX" | "TC"
        | "TT" | "US" | "VC" | "VG" | "VI" => "NA",
        // South America (SA)
        "AR" | "BO" | "BR" | "CL" | "CO" | "EC" | "FK" | "GF" | "GY" | "PE" | "PY" | "SR"
        | "UY" | "VE" => "SA",
        // Africa (AF)
        "AO" | "BF" | "BI" | "BJ" | "BW" | "CD" | "CF" | "CG" | "CI" | "CM" | "CV" | "DJ"
        | "DZ" | "EG" | "EH" | "ER" | "ET" | "GA" | "GH" | "GM" | "GN" | "GQ" | "GW" | "KE"
        | "KM" | "LR" | "LS" | "LY" | "MA" | "MG" | "ML" | "MR" | "MU" | "MW" | "MZ" | "NA"
        | "NE" | "NG" | "RE" | "RW" | "SC" | "SD" | "SH" | "SL" | "SN" | "SO" | "SS" | "ST"
        | "SZ" | "TD" | "TG" | "TN" | "TZ" | "UG" | "YT" | "ZA" | "ZM" | "ZW" => "AF",
        // Oceania (OC)
        "AS" | "AU" | "CK" | "FJ" | "FM" | "GU" | "KI" | "MH" | "MP" | "NC" | "NF" | "NR"
        | "NU" | "NZ" | "PF" | "PG" | "PN" | "PW" | "SB" | "TK" | "TO" | "TV" | "UM" | "VU"
        | "WF" | "WS" => "OC",
        // Antarctica (AN)
        "AQ" | "BV" | "GS" | "HM" | "TF" => "AN",
        _ => "XX",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GeoRule;

    #[test]
    fn parses_coalesces_looks_up_and_roundtrips_binary_geoip() {
        let v4_csv = "\
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.1.1.0,1.1.1.255,AU
8.8.8.0/24,US
114.114.114.0,114.114.114.255,CN
114.114.115.0,114.114.115.255,CN
198.51.100.0,198.51.100.255,US
";
        let v6_csv = "2001:4860:4860::,2001:4860:4860:ffff:ffff:ffff:ffff:ffff,US\n";
        let db = GeoIpDatabase::parse_csv_ranges(Some(v4_csv), Some(v6_csv), "test-cc0", 1_700_000_000);
        assert_eq!(db.ipv4_len(), 6);
        assert_eq!(db.ipv6_len(), 1);

        let r1 = db.lookup("1.1.1.1".parse().unwrap()).unwrap();
        assert_eq!(r1.country_str(), "AU");
        assert_eq!(r1.continent, "OC");

        let r2 = db.lookup("8.8.8.8".parse().unwrap()).unwrap();
        assert_eq!(r2.country_str(), "US");
        assert_eq!(r2.continent, "NA");

        let r3 = db.lookup("114.114.114.114".parse().unwrap()).unwrap();
        assert_eq!(r3.country_str(), "CN");
        assert_eq!(r3.continent, "AS");

        // IPv4-mapped IPv6 canonicalizes transparently
        let r4 = db.lookup("::ffff:114.114.114.114".parse().unwrap()).unwrap();
        assert_eq!(r4.country_str(), "CN");

        // IPv6 lookup
        let r6 = db.lookup("2001:4860:4860::8888".parse().unwrap()).unwrap();
        assert_eq!(r6.country_str(), "US");

        // Private / non-public / documentation IPs never return Geo results
        assert!(db.lookup("127.0.0.1".parse().unwrap()).is_none());
        assert!(db.lookup("192.168.1.5".parse().unwrap()).is_none());
        assert!(db.lookup("198.51.100.10".parse().unwrap()).is_none());

        // Binary roundtrip
        let bin = db.encode_binary();
        let dec = GeoIpDatabase::decode_binary(&bin).unwrap();
        assert_eq!(dec.lookup("114.114.114.114".parse().unwrap()).unwrap().country_str(), "CN");
        assert_eq!(dec.lookup("2001:4860:4860::8888".parse().unwrap()).unwrap().country_str(), "US");
    }

    #[test]
    fn evaluates_region_targeting_rules_allowlist_denylist_and_private_exemption() {
        let policy = GeoPolicyConfig {
            enabled: true,
            allow_regions: vec!["CN".into(), "CONTINENT:AS".into()],
            deny_regions: vec!["KP".into()],
            deny_action: GeoRuleAction::Block,
            default_action: GeoRuleAction::Allow,
            unknown_action: GeoRuleAction::Monitor,
            rules: vec![GeoRule {
                regions: vec!["RU".into()],
                action: GeoRuleAction::Challenge,
                suspicion_boost: 30,
                note: Some("verify-ru".into()),
            }],
        };

        let cn = GeoLookupResult { country: *b"CN", continent: "AS" };
        let jp = GeoLookupResult { country: *b"JP", continent: "AS" };
        let us = GeoLookupResult { country: *b"US", continent: "NA" };
        let ru = GeoLookupResult { country: *b"RU", continent: "EU" };

        assert_eq!(evaluate_geo_policy(&policy, Some(&cn), false), GeoDecision::Allow { suspicion_boost: 0 });
        assert_eq!(evaluate_geo_policy(&policy, Some(&jp), false), GeoDecision::Allow { suspicion_boost: 0 });
        assert!(matches!(evaluate_geo_policy(&policy, Some(&ru), false), GeoDecision::Challenge { suspicion_boost: 30, .. }));
        assert!(matches!(evaluate_geo_policy(&policy, Some(&us), false), GeoDecision::Block { .. }));
        assert!(matches!(evaluate_geo_policy(&policy, None, false), GeoDecision::Monitor { .. }));
        assert_eq!(evaluate_geo_policy(&policy, None, true), GeoDecision::Allow { suspicion_boost: 0 });
    }
}
