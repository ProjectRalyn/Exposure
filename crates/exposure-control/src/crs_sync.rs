use std::collections::BTreeMap;
use std::time::Duration;

use chrono::Utc;
use exposure_core::crs::{
    CRS_RULE_FILES, CrsRulesetSnapshot, MAX_CRS_RULES, WafRuleDescriptor, parse_crs_conf,
};
use exposure_core::{ExposureError, Result};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

const CRS_RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/coreruleset/coreruleset/releases/latest";
const CRS_RAW_BASE_URL: &str = "https://raw.githubusercontent.com/coreruleset/coreruleset";
const MAX_RULE_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RELEASE_JSON_BYTES: usize = 256 * 1024;
const MIN_CRS_FILES_OK: usize = 8;
const CRS_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const CRS_USER_AGENT: &str = "exposure-waf/0.1 (+https://coreruleset.org/)";

#[derive(Deserialize)]
struct GithubReleaseLatest {
    tag_name: String,
}

fn is_safe_git_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && !tag.contains("..")
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_allowed_crs_redirect_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    matches!(
        h.as_str(),
        "github.com"
            | "api.github.com"
            | "raw.githubusercontent.com"
            | "objects.githubusercontent.com"
    )
}

async fn read_bounded_bytes(mut resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len as usize > max_bytes {
            return Err(ExposureError::Protocol(format!(
                "CRS response exceeds {max_bytes} byte safety limit"
            )));
        }
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ExposureError::Protocol(format!("read CRS response body: {e}")))?
    {
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ExposureError::Protocol(format!(
                "CRS response exceeds {max_bytes} byte safety limit"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn read_bounded_text(resp: reqwest::Response, max_bytes: usize) -> Result<String> {
    let bytes = read_bounded_bytes(resp, max_bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Fetch the latest OWASP Core Rule Set release from GitHub (`coreruleset/coreruleset`),
/// parse its ModSecurity `REQUEST-9*.conf` rules into ReDoS-safe linear-time `WafRuleDescriptor`s,
/// and return a deduplicated `CrsRulesetSnapshot`.
pub async fn sync_owasp_crs_from_github() -> Result<CrsRulesetSnapshot> {
    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 2 {
            return attempt.error("too many CRS redirects");
        }
        let url = attempt.url();
        let host_ok = url
            .host_str()
            .map(is_allowed_crs_redirect_host)
            .unwrap_or(false);
        if url.scheme() == "https" && host_ok {
            attempt.follow()
        } else {
            attempt.error("disallowed CRS redirect target")
        }
    });
    let client = reqwest::Client::builder()
        .timeout(CRS_HTTP_TIMEOUT)
        .connect_timeout(Duration::from_secs(8))
        .user_agent(CRS_USER_AGENT)
        .redirect(redirect_policy)
        .build()
        .map_err(|e| ExposureError::Config(format!("build CRS http client: {e}")))?;

    let rel_resp = client
        .get(CRS_RELEASES_LATEST_URL)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| ExposureError::Protocol(format!("fetch OWASP CRS latest release: {e}")))?;
    if !rel_resp.status().is_success() {
        return Err(ExposureError::Protocol(format!(
            "GitHub releases API returned HTTP {}",
            rel_resp.status()
        )));
    }
    let rel_bytes = read_bounded_bytes(rel_resp, MAX_RELEASE_JSON_BYTES).await?;
    let release: GithubReleaseLatest = serde_json::from_slice(&rel_bytes)
        .map_err(|e| ExposureError::Protocol(format!("parse GitHub release JSON: {e}")))?;
    let tag = release.tag_name.trim().to_string();
    if !is_safe_git_tag(&tag) {
        return Err(ExposureError::Protocol(format!(
            "unexpected OWASP CRS git tag '{tag}'"
        )));
    }

    let sem = std::sync::Arc::new(Semaphore::new(4));
    let mut join_set = JoinSet::new();
    for &file_name in CRS_RULE_FILES {
        let client = client.clone();
        let tag = tag.clone();
        let sem = std::sync::Arc::clone(&sem);
        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let url = format!("{CRS_RAW_BASE_URL}/{tag}/rules/{file_name}");
            let res = async {
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| ExposureError::Protocol(format!("fetch {file_name}: {e}")))?;
                if !resp.status().is_success() {
                    return Err(ExposureError::Protocol(format!(
                        "fetch {file_name} returned HTTP {}",
                        resp.status()
                    )));
                }
                read_bounded_text(resp, MAX_RULE_FILE_BYTES).await
            }
            .await;
            (file_name, res)
        });
    }

    let mut results: Vec<(&'static str, Result<String>)> = Vec::with_capacity(CRS_RULE_FILES.len());
    while let Some(joined) = join_set.join_next().await {
        if let Ok(item) = joined {
            results.push(item);
        }
    }

    let mut dedup: BTreeMap<u32, WafRuleDescriptor> = BTreeMap::new();
    let mut total_parsed = 0usize;
    let mut total_skipped = 0usize;
    let mut files_ok = 0usize;
    let mut ok_files = std::collections::HashSet::new();

    for (file_name, res) in results {
        match res {
            Ok(text) => {
                files_ok += 1;
                ok_files.insert(file_name);
                let (rules, skipped) = parse_crs_conf(file_name, &text);
                total_parsed += rules.len();
                total_skipped += skipped;
                for r in rules {
                    dedup.entry(r.id).or_insert(r);
                }
            }
            Err(e) => {
                warn!(file = file_name, tag = %tag, error = %e, "failed to download OWASP CRS rule file");
            }
        }
    }

    let has_core_sqli_xss = ok_files.contains("REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
        && ok_files.contains("REQUEST-941-APPLICATION-ATTACK-XSS.conf");
    if files_ok < MIN_CRS_FILES_OK || !has_core_sqli_xss || dedup.is_empty() {
        return Err(ExposureError::Protocol(format!(
            "incomplete OWASP CRS sync for {tag} (files_ok={files_ok}, core_sqli_xss={has_core_sqli_xss}, rules={})",
            dedup.len()
        )));
    }

    let mut rules: Vec<WafRuleDescriptor> = dedup.into_values().collect();
    // Prioritize PL1 baseline rules before higher paranoia levels when bounding to MAX_CRS_RULES.
    rules.sort_by_key(|r| (r.paranoia_level, r.id));
    if rules.len() > MAX_CRS_RULES {
        rules.truncate(MAX_CRS_RULES);
        rules.sort_by_key(|r| r.id);
    }

    info!(
        tag = %tag,
        files_ok,
        rules = rules.len(),
        skipped_pcre = total_skipped,
        "synced OWASP Core Rule Set from coreruleset.org"
    );

    Ok(CrsRulesetSnapshot {
        version: tag.clone(),
        source_url: format!("https://github.com/coreruleset/coreruleset/releases/tag/{tag}"),
        updated_at: Utc::now().to_rfc3339(),
        total_parsed,
        skipped_pcre: total_skipped,
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_safe_git_tags() {
        assert!(is_safe_git_tag("v4.30.0"));
        assert!(is_safe_git_tag("v4.8.0-rc1"));
        assert!(!is_safe_git_tag(""));
        assert!(!is_safe_git_tag("../etc/passwd"));
        assert!(!is_safe_git_tag("v4.0/../../secret"));
        assert!(!is_safe_git_tag("v4.0?foo=bar"));
    }
}
