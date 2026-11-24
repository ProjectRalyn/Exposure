use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use exposure_core::config::{NodeCacheConfig, RuleCacheConfig};
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};

use crate::egress::{full_body, ProxyBody};

const DEFAULT_CACHEABLE_STATUSES: &[u16] = &[200, 203, 204, 206, 301, 308, 404, 410];
const MAX_VARY_HEADERS: usize = 8;
const MAX_VARIANTS_PER_KEY: usize = 8;

#[derive(Debug, Clone)]
pub struct EffectiveCachePolicy {
    pub enabled: bool,
    pub max_memory_bytes: u64,
    pub max_object_bytes: u64,
    pub max_entries: usize,
    pub default_ttl_secs: u64,
    pub stale_if_error_secs: u64,
    pub respect_cache_control: bool,
    pub ignore_query_string: bool,
    pub cacheable_statuses: Vec<u16>,
    pub bypass_cookie_prefixes: Vec<String>,
}

impl EffectiveCachePolicy {
    pub fn resolve(node: &NodeCacheConfig, rule: Option<&RuleCacheConfig>) -> Self {
        let enabled = rule.and_then(|r| r.enabled).unwrap_or(node.enabled);
        let default_ttl_secs = rule
            .and_then(|r| r.default_ttl_secs)
            .unwrap_or(node.default_ttl_secs);
        let stale_if_error_secs = rule
            .and_then(|r| r.stale_if_error_secs)
            .unwrap_or(node.stale_if_error_secs);
        let respect_cache_control = rule
            .and_then(|r| r.respect_cache_control)
            .unwrap_or(node.respect_cache_control);
        let ignore_query_string = rule
            .and_then(|r| r.ignore_query_string)
            .unwrap_or(node.ignore_query_string);
        let mut bypass_cookie_prefixes = node.bypass_cookie_prefixes.clone();
        if let Some(rc) = rule {
            for p in &rc.bypass_cookie_prefixes {
                if !bypass_cookie_prefixes.contains(p) {
                    bypass_cookie_prefixes.push(p.clone());
                }
            }
        }
        let cacheable_statuses = if node.cacheable_statuses.is_empty() {
            DEFAULT_CACHEABLE_STATUSES.to_vec()
        } else {
            node.cacheable_statuses.clone()
        };
        Self {
            enabled,
            max_memory_bytes: node.max_memory_bytes.max(1024),
            max_object_bytes: node.max_object_bytes.max(1024),
            max_entries: node.max_entries.max(1),
            default_ttl_secs,
            stale_if_error_secs,
            respect_cache_control,
            ignore_query_string,
            cacheable_statuses,
            bypass_cookie_prefixes,
        }
    }

    pub fn is_status_cacheable(&self, status: StatusCode) -> bool {
        self.cacheable_statuses.contains(&status.as_u16())
    }
}

#[derive(Debug, Clone)]
pub struct CachedEntry {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub vary_headers: Vec<String>,
    pub vary_signature: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub stored_at: Instant,
    pub expires_at: Instant,
    pub stale_until: Instant,
    pub size_bytes: u64,
}

impl CachedEntry {
    pub fn age_secs(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.stored_at).as_secs()
    }

    pub fn is_fresh(&self, now: Instant) -> bool {
        now < self.expires_at
    }

    pub fn is_usable_stale(&self, now: Instant) -> bool {
        now >= self.expires_at && now < self.stale_until
    }
}

#[derive(Debug)]
pub enum CacheLookup {
    Bypass,
    Miss {
        base_key: String,
    },
    Hit {
        base_key: String,
        entry: Arc<CachedEntry>,
    },
    Stale {
        base_key: String,
        entry: Arc<CachedEntry>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct CacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub stales: u64,
    pub revalidated: u64,
    pub bypasses: u64,
    pub evictions: u64,
    pub current_bytes: u64,
    pub current_entries: usize,
}

struct StoredItem {
    entry: Arc<CachedEntry>,
    lru_seq: u64,
}

struct CacheState {
    max_memory_bytes: u64,
    max_entries: usize,
    total_bytes: u64,
    total_entries: usize,
    next_seq: u64,
    /// base_key -> (vary_signature -> StoredItem)
    buckets: HashMap<String, HashMap<String, StoredItem>>,
    /// Ordered LRU index: lru_seq -> (base_key, vary_signature)
    lru_index: BTreeMap<u64, (String, String)>,
}

impl CacheState {
    fn new(max_memory_bytes: u64, max_entries: usize) -> Self {
        Self {
            max_memory_bytes: max_memory_bytes.max(1024),
            max_entries: max_entries.max(1),
            total_bytes: 0,
            total_entries: 0,
            next_seq: 1,
            buckets: HashMap::new(),
            lru_index: BTreeMap::new(),
        }
    }

    fn alloc_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1).max(1);
        s
    }

    fn remove_entry(&mut self, base_key: &str, vary_sig: &str) -> bool {
        let mut removed = false;
        let mut empty_bucket = false;
        if let Some(variants) = self.buckets.get_mut(base_key) {
            if let Some(item) = variants.remove(vary_sig) {
                self.lru_index.remove(&item.lru_seq);
                self.total_bytes = self.total_bytes.saturating_sub(item.entry.size_bytes);
                self.total_entries = self.total_entries.saturating_sub(1);
                removed = true;
            }
            empty_bucket = variants.is_empty();
        }
        if empty_bucket {
            self.buckets.remove(base_key);
        }
        removed
    }

    fn evict_one_lru(&mut self) -> bool {
        let Some((&seq, _)) = self.lru_index.iter().next() else {
            return false;
        };
        if let Some((base_key, vary_sig)) = self.lru_index.remove(&seq) {
            if let Some(variants) = self.buckets.get_mut(&base_key) {
                if let Some(item) = variants.remove(&vary_sig) {
                    self.total_bytes = self.total_bytes.saturating_sub(item.entry.size_bytes);
                    self.total_entries = self.total_entries.saturating_sub(1);
                }
                if variants.is_empty() {
                    self.buckets.remove(&base_key);
                }
            }
            return true;
        }
        false
    }

    fn enforce_limits(&mut self, incoming_bytes: u64, evictions: &AtomicU64) {
        while (self.total_bytes.saturating_add(incoming_bytes) > self.max_memory_bytes
            || self.total_entries >= self.max_entries)
            && self.total_entries > 0
        {
            if self.evict_one_lru() {
                evictions.fetch_add(1, Ordering::Relaxed);
            } else {
                break;
            }
        }
    }

    fn clear(&mut self) {
        self.buckets.clear();
        self.lru_index.clear();
        self.total_bytes = 0;
        self.total_entries = 0;
    }
}

/// Thread-safe, memory-bounded, Vary-aware HTTP edge response cache for Ingress nodes.
pub struct EdgeCache {
    state: Mutex<CacheState>,
    hits: AtomicU64,
    misses: AtomicU64,
    stales: AtomicU64,
    revalidated: AtomicU64,
    bypasses: AtomicU64,
    evictions: AtomicU64,
}

impl EdgeCache {
    pub fn new(max_memory_bytes: u64, max_entries: usize) -> Self {
        Self {
            state: Mutex::new(CacheState::new(max_memory_bytes, max_entries)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stales: AtomicU64::new(0),
            revalidated: AtomicU64::new(0),
            bypasses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    pub fn reconfigure(&self, max_memory_bytes: u64, max_entries: usize, clear_existing: bool) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.max_memory_bytes = max_memory_bytes.max(1024);
        st.max_entries = max_entries.max(1);
        if clear_existing {
            st.clear();
        } else {
            st.enforce_limits(0, &self.evictions);
        }
    }

    pub fn clear(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.clear();
    }

    pub fn stats(&self) -> CacheStatsSnapshot {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        CacheStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stales: self.stales.load(Ordering::Relaxed),
            revalidated: self.revalidated.load(Ordering::Relaxed),
            bypasses: self.bypasses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            current_bytes: st.total_bytes,
            current_entries: st.total_entries,
        }
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_stale(&self) {
        self.stales.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_revalidated(&self) {
        self.revalidated.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_bypass(&self) {
        self.bypasses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn lookup(
        &self,
        policy: &EffectiveCachePolicy,
        service_tag: &str,
        method: &Method,
        host: &str,
        path_and_query: &str,
        req_headers: &HeaderMap,
    ) -> CacheLookup {
        if !policy.enabled || !is_request_cache_eligible(policy, method, req_headers) {
            return CacheLookup::Bypass;
        }

        let base_key = build_base_cache_key(
            service_tag,
            host,
            path_and_query,
            policy.ignore_query_string,
        );

        let req_cc = parse_cache_control(req_headers);
        if req_cc.no_store {
            return CacheLookup::Bypass;
        }
        let force_revalidate = req_cc.no_cache || req_cc.max_age == Some(0);

        let now = Instant::now();
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());

        let mut matched_sig: Option<String> = None;
        let mut expired_to_prune: Vec<String> = Vec::new();
        if let Some(variants) = st.buckets.get(&base_key) {
            for (sig, item) in variants {
                if now >= item.entry.stale_until {
                    expired_to_prune.push(sig.clone());
                    continue;
                }
                let expected_sig = compute_vary_signature(&item.entry.vary_headers, req_headers);
                if expected_sig == *sig {
                    matched_sig = Some(sig.clone());
                    break;
                }
            }
        }
        for dead in expired_to_prune {
            st.remove_entry(&base_key, &dead);
        }

        let Some(sig) = matched_sig else {
            return CacheLookup::Miss { base_key };
        };

        // Touch LRU sequence
        let new_seq = st.alloc_seq();
        let (entry_arc, old_seq) = {
            let item = st
                .buckets
                .get_mut(&base_key)
                .and_then(|v| v.get_mut(&sig))
                .unwrap();
            let old = item.lru_seq;
            item.lru_seq = new_seq;
            (Arc::clone(&item.entry), old)
        };
        st.lru_index.remove(&old_seq);
        st.lru_index.insert(new_seq, (base_key.clone(), sig));

        if !force_revalidate && entry_arc.is_fresh(now) {
            CacheLookup::Hit {
                base_key,
                entry: entry_arc,
            }
        } else if entry_arc.is_usable_stale(now) || force_revalidate {
            CacheLookup::Stale {
                base_key,
                entry: entry_arc,
            }
        } else {
            CacheLookup::Miss { base_key }
        }
    }

    /// Quick header-only check before buffering an upstream response body in memory.
    pub fn response_headers_cacheable(
        policy: &EffectiveCachePolicy,
        status: StatusCode,
        resp_headers: &HeaderMap,
    ) -> bool {
        if !policy.enabled || !policy.is_status_cacheable(status) {
            return false;
        }
        // Hard safety invariant: NEVER cache responses carrying Set-Cookie
        if resp_headers.contains_key(header::SET_COOKIE) {
            return false;
        }
        // Refuse `Vary: *` (RFC 9111 §4.1)
        if parse_vary_headers(resp_headers).is_none() {
            return false;
        }
        if let Some(cl) = resp_headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            if cl > policy.max_object_bytes || cl > policy.max_memory_bytes {
                return false;
            }
        }
        resolve_ttl_secs(policy, resp_headers).is_some()
    }

    pub fn store(
        &self,
        policy: &EffectiveCachePolicy,
        base_key: &str,
        req_headers: &HeaderMap,
        status: StatusCode,
        resp_headers: &HeaderMap,
        body: Bytes,
    ) -> bool {
        if !Self::response_headers_cacheable(policy, status, resp_headers) {
            return false;
        }
        let Some(vary_headers) = parse_vary_headers(resp_headers) else {
            return false;
        };
        // Cache-poisoning guard: if the client content-negotiated (compression / language) or
        // sent cookies, but the upstream did NOT declare the matching `Vary` dimension, storing
        // this response would serve one client's variant to another. Refuse to store instead.
        if !vary_includes(&vary_headers, "accept-encoding")
            && request_has_nonidentity_accept_encoding(req_headers)
        {
            return false;
        }
        if !vary_includes(&vary_headers, "cookie") && req_headers.contains_key(header::COOKIE) {
            return false;
        }
        let Some(ttl_secs) = resolve_ttl_secs(policy, resp_headers) else {
            return false;
        };
        if body.len() as u64 > policy.max_object_bytes {
            return false;
        }

        let clean_headers = sanitize_cached_headers(resp_headers);
        let headers_overhead: u64 = clean_headers
            .iter()
            .map(|(k, v)| (k.as_str().len() + v.len() + 16) as u64)
            .sum();
        let size_bytes = (body.len() as u64)
            .saturating_add(headers_overhead)
            .saturating_add(base_key.len() as u64 + 64);

        let vary_signature = compute_vary_signature(&vary_headers, req_headers);
        let etag = clean_headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let last_modified = clean_headers
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let cc = parse_cache_control(resp_headers);
        let stale_secs = cc.stale_if_error.unwrap_or(policy.stale_if_error_secs);

        let now = Instant::now();
        let expires_at = now + Duration::from_secs(ttl_secs);
        let stale_until = expires_at + Duration::from_secs(stale_secs);

        let entry = Arc::new(CachedEntry {
            status,
            headers: clean_headers,
            body,
            vary_headers,
            vary_signature: vary_signature.clone(),
            etag,
            last_modified,
            stored_at: now,
            expires_at,
            stale_until,
            size_bytes,
        });

        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if size_bytes > st.max_memory_bytes {
            return false;
        }

        // Remove existing variant if replacing
        st.remove_entry(base_key, &vary_signature);

        // Cap variants per base_key to prevent Vary-explosion memory DoS
        if let Some(variants) = st.buckets.get(base_key) {
            if variants.len() >= MAX_VARIANTS_PER_KEY {
                if let Some(oldest_sig) = variants
                    .iter()
                    .min_by_key(|(_, item)| item.lru_seq)
                    .map(|(k, _)| k.clone())
                {
                    st.remove_entry(base_key, &oldest_sig);
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        st.enforce_limits(size_bytes, &self.evictions);
        let seq = st.alloc_seq();
        st.buckets
            .entry(base_key.to_string())
            .or_default()
            .insert(
                vary_signature.clone(),
                StoredItem {
                    entry,
                    lru_seq: seq,
                },
            );
        st.lru_index.insert(seq, (base_key.to_string(), vary_signature));
        st.total_bytes = st.total_bytes.saturating_add(size_bytes);
        st.total_entries += 1;
        true
    }

    /// Refresh a stale entry after upstream confirms `304 Not Modified`.
    /// Returns `None` (and evicts the cached entry) if the `304` response carries `Set-Cookie`,
    /// `Vary: *`, or non-cacheable directives (`no-store`/`private`/`max-age=0`).
    pub fn revalidate_304(
        &self,
        policy: &EffectiveCachePolicy,
        base_key: &str,
        old_entry: &CachedEntry,
        not_modified_headers: &HeaderMap,
    ) -> Option<Arc<CachedEntry>> {
        if not_modified_headers.contains_key(header::SET_COOKIE)
            || parse_vary_headers(not_modified_headers).is_none()
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.remove_entry(base_key, &old_entry.vary_signature);
            return None;
        }

        let mut merged_headers = old_entry.headers.clone();
        for h in [
            header::CACHE_CONTROL,
            header::ETAG,
            header::LAST_MODIFIED,
            header::EXPIRES,
            header::DATE,
            header::VARY,
        ] {
            if not_modified_headers.contains_key(&h) {
                merged_headers.remove(&h);
                for v in not_modified_headers.get_all(&h) {
                    merged_headers.append(h.clone(), v.clone());
                }
            }
        }
        let Some(ttl_secs) = resolve_ttl_secs(policy, &merged_headers) else {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.remove_entry(base_key, &old_entry.vary_signature);
            return None;
        };
        let cc = parse_cache_control(&merged_headers);
        let stale_secs = cc.stale_if_error.unwrap_or(policy.stale_if_error_secs);
        let now = Instant::now();
        let refreshed = Arc::new(CachedEntry {
            status: old_entry.status,
            headers: merged_headers.clone(),
            body: old_entry.body.clone(),
            vary_headers: old_entry.vary_headers.clone(),
            vary_signature: old_entry.vary_signature.clone(),
            etag: merged_headers
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            last_modified: merged_headers
                .get(header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            stored_at: now,
            expires_at: now + Duration::from_secs(ttl_secs),
            stale_until: now + Duration::from_secs(ttl_secs.saturating_add(stale_secs)),
            size_bytes: old_entry.size_bytes,
        });

        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let new_seq = st.alloc_seq();
        if let Some(item) = st
            .buckets
            .get_mut(base_key)
            .and_then(|v| v.get_mut(&old_entry.vary_signature))
        {
            let old_seq = item.lru_seq;
            item.entry = Arc::clone(&refreshed);
            item.lru_seq = new_seq;
            st.lru_index.remove(&old_seq);
            st.lru_index
                .insert(new_seq, (base_key.to_string(), old_entry.vary_signature.clone()));
        }
        Some(refreshed)
    }
}

/// Build an HTTP response directly from a cached entry (handling `If-None-Match` -> `304` and `HEAD`).
pub fn build_response_from_cache(
    entry: &CachedEntry,
    method: &Method,
    req_headers: &HeaderMap,
    cache_status: &'static str,
) -> Response<ProxyBody> {
    let now = Instant::now();
    let age = entry.age_secs(now);

    if entry.status == StatusCode::OK {
        if let Some(ref etag) = entry.etag {
            if if_none_match_matches(req_headers, etag) {
                let mut rb = Response::builder().status(StatusCode::NOT_MODIFIED);
                for h in [
                    header::ETAG,
                    header::CACHE_CONTROL,
                    header::EXPIRES,
                    header::LAST_MODIFIED,
                    header::VARY,
                ] {
                    if let Some(v) = entry.headers.get(&h) {
                        rb = rb.header(h, v.clone());
                    }
                }
                return rb
                    .header(header::AGE, age.to_string())
                    .header("x-exposure-cache", cache_status)
                    .body(full_body(""))
                    .unwrap();
            }
        }
    }

    let mut resp = Response::new(if method == Method::HEAD {
        full_body("")
    } else {
        full_body(entry.body.clone())
    });
    *resp.status_mut() = entry.status;
    let h = resp.headers_mut();
    for (k, v) in &entry.headers {
        h.append(k, v.clone());
    }
    h.remove(header::TRANSFER_ENCODING);
    if entry.status != StatusCode::NO_CONTENT && entry.status != StatusCode::NOT_MODIFIED {
        if let Ok(hv) = HeaderValue::from_str(&entry.body.len().to_string()) {
            h.insert(header::CONTENT_LENGTH, hv);
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&age.to_string()) {
        h.insert(header::AGE, hv);
    }
    h.insert("x-exposure-cache", HeaderValue::from_static(cache_status));
    resp
}

pub fn build_base_cache_key(
    service_tag: &str,
    host: &str,
    path_and_query: &str,
    ignore_query_string: bool,
) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let uri = if ignore_query_string {
        path_and_query.split('?').next().unwrap_or("/")
    } else {
        path_and_query
    };
    format!("{service_tag}|{h}|{uri}")
}

fn is_request_cache_eligible(
    policy: &EffectiveCachePolicy,
    method: &Method,
    req_headers: &HeaderMap,
) -> bool {
    if method != Method::GET && method != Method::HEAD {
        return false;
    }
    if req_headers.contains_key(header::UPGRADE)
        || req_headers.contains_key(header::AUTHORIZATION)
        || req_headers.contains_key(header::RANGE)
    {
        return false;
    }
    if !policy.bypass_cookie_prefixes.is_empty() {
        for cv in req_headers.get_all(header::COOKIE) {
            if let Ok(raw) = cv.to_str() {
                for pair in raw.split(';') {
                    let trimmed = pair.trim();
                    if policy
                        .bypass_cookie_prefixes
                        .iter()
                        .any(|p| !p.is_empty() && trimmed.starts_with(p))
                    {
                        return false;
                    }
                }
            }
        }
    }
    true
}

#[derive(Debug, Default)]
struct CacheControlDirectives {
    no_store: bool,
    no_cache: bool,
    private: bool,
    s_maxage: Option<u64>,
    max_age: Option<u64>,
    stale_if_error: Option<u64>,
}

fn parse_cache_control(headers: &HeaderMap) -> CacheControlDirectives {
    let mut out = CacheControlDirectives::default();
    for hv in headers.get_all(header::CACHE_CONTROL) {
        let Ok(raw) = hv.to_str() else { continue };
        for part in raw.split(',') {
            let token = part.trim();
            if token.is_empty() {
                continue;
            }
            if let Some((k, v)) = token.split_once('=') {
                let kl = k.trim().to_ascii_lowercase();
                let vl = v.trim().trim_matches('"');
                if let Ok(secs) = vl.parse::<u64>() {
                    match kl.as_str() {
                        "s-maxage" => out.s_maxage = Some(secs),
                        "max-age" => out.max_age = Some(secs),
                        "stale-if-error" => out.stale_if_error = Some(secs),
                        _ => {}
                    }
                }
            } else {
                match token.to_ascii_lowercase().as_str() {
                    "no-store" => out.no_store = true,
                    "no-cache" => out.no_cache = true,
                    "private" => out.private = true,
                    _ => {}
                }
            }
        }
    }
    out
}

fn resolve_ttl_secs(policy: &EffectiveCachePolicy, resp_headers: &HeaderMap) -> Option<u64> {
    if !policy.respect_cache_control {
        return if policy.default_ttl_secs > 0 {
            Some(policy.default_ttl_secs)
        } else {
            None
        };
    }
    let cc = parse_cache_control(resp_headers);
    if cc.no_store || cc.private || cc.no_cache {
        return None;
    }
    if let Some(s) = cc.s_maxage {
        return if s > 0 { Some(s) } else { None };
    }
    if let Some(m) = cc.max_age {
        return if m > 0 { Some(m) } else { None };
    }
    if policy.default_ttl_secs > 0 {
        Some(policy.default_ttl_secs)
    } else {
        None
    }
}

fn vary_includes(vary_headers: &[String], name: &str) -> bool {
    vary_headers.iter().any(|h| h.eq_ignore_ascii_case(name))
}

/// True if the request accepts any content coding other than `identity`
/// (gzip/br/deflate/zstd/...), i.e. a compressed response body must be variant-keyed.
fn request_has_nonidentity_accept_encoding(req_headers: &HeaderMap) -> bool {
    for hv in req_headers.get_all(header::ACCEPT_ENCODING) {
        let Ok(raw) = hv.to_str() else { continue };
        for token in raw.split(',') {
            let codec = token.split(';').next().unwrap_or("").trim();
            if !codec.is_empty() && !codec.eq_ignore_ascii_case("identity") {
                return true;
            }
        }
    }
    false
}

/// Returns `None` if `Vary: *` (uncacheable); otherwise returns sorted lowercase Vary header names.
fn parse_vary_headers(resp_headers: &HeaderMap) -> Option<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    for hv in resp_headers.get_all(header::VARY) {
        let Ok(raw) = hv.to_str() else { continue };
        for part in raw.split(',') {
            let p = part.trim().to_ascii_lowercase();
            if p.is_empty() {
                continue;
            }
            if p == "*" {
                return None;
            }
            if !names.contains(&p) && names.len() < MAX_VARY_HEADERS {
                names.push(p);
            }
        }
    }
    names.sort();
    Some(names)
}

fn compute_vary_signature(vary_headers: &[String], req_headers: &HeaderMap) -> String {
    if vary_headers.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for name in vary_headers {
        let mut combined = String::new();
        if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
            let mut first = true;
            for hv in req_headers.get_all(&hn) {
                if !first {
                    combined.push(',');
                }
                first = false;
                if let Ok(s) = hv.to_str() {
                    combined.push_str(s.trim());
                }
            }
        }
        use std::fmt::Write as _;
        let _ = write!(out, "{}:{name}={}:{combined};", name.len(), combined.len());
    }
    out
}

fn sanitize_cached_headers(src: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in src {
        let name = k.as_str();
        if matches!(
            name,
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "set-cookie"
                | "age"
                | "x-exposure-cache"
        ) {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    out
}

fn strip_weak_etag(tag: &str) -> &str {
    let t = tag.trim();
    t.strip_prefix("W/").or_else(|| t.strip_prefix("w/")).unwrap_or(t)
}

fn if_none_match_matches(req_headers: &HeaderMap, cached_etag: &str) -> bool {
    let target = strip_weak_etag(cached_etag);
    for hv in req_headers.get_all(header::IF_NONE_MATCH) {
        let Ok(raw) = hv.to_str() else { continue };
        for candidate in raw.split(',') {
            let c = candidate.trim();
            if c == "*" || strip_weak_etag(c) == target {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn enabled_policy() -> EffectiveCachePolicy {
        let mut node = NodeCacheConfig::default();
        node.enabled = true;
        node.default_ttl_secs = 60;
        node.stale_if_error_secs = 120;
        node.max_memory_bytes = 64 * 1024;
        node.max_object_bytes = 16 * 1024;
        node.bypass_cookie_prefixes = vec!["session=".into()];
        EffectiveCachePolicy::resolve(&node, None)
    }

    #[tokio::test]
    async fn cache_hit_miss_etag_304_and_vary_isolation() {
        let policy = enabled_policy();
        let cache = EdgeCache::new(policy.max_memory_bytes, policy.max_entries);

        let mut req_gzip = HeaderMap::new();
        req_gzip.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let base_key = match cache.lookup(&policy, "web", &Method::GET, "example.com", "/app.js", &req_gzip) {
            CacheLookup::Miss { base_key } => base_key,
            other => panic!("expected Miss, got {other:?}"),
        };

        let mut resp_h = HeaderMap::new();
        resp_h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, s-maxage=30"));
        resp_h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        resp_h.insert(header::ETAG, HeaderValue::from_static("\"v1\""));
        resp_h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(cache.store(&policy, &base_key, &req_gzip, StatusCode::OK, &resp_h, Bytes::from_static(b"gz-bytes")));

        // Same Accept-Encoding -> HIT
        let hit = match cache.lookup(&policy, "web", &Method::GET, "example.com", "/app.js", &req_gzip) {
            CacheLookup::Hit { entry, .. } => entry,
            other => panic!("expected Hit, got {other:?}"),
        };
        assert_eq!(&hit.body[..], b"gz-bytes");

        // Different Accept-Encoding -> MISS (Vary isolation!)
        let mut req_br = HeaderMap::new();
        req_br.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("br"));
        assert!(matches!(
            cache.lookup(&policy, "web", &Method::GET, "example.com", "/app.js", &req_br),
            CacheLookup::Miss { .. }
        ));

        // Conditional If-None-Match -> 304 Not Modified
        let mut cond_req = req_gzip.clone();
        cond_req.insert(header::IF_NONE_MATCH, HeaderValue::from_static("W/\"v1\""));
        let r304 = build_response_from_cache(&hit, &Method::GET, &cond_req, "HIT");
        assert_eq!(r304.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(r304.headers().get("x-exposure-cache").unwrap(), "HIT");
        let body304 = r304.into_body().collect().await.unwrap().to_bytes();
        assert!(body304.is_empty());

        // HEAD returns empty body with full Content-Length
        let r_head = build_response_from_cache(&hit, &Method::HEAD, &req_gzip, "HIT");
        assert_eq!(r_head.status(), StatusCode::OK);
        assert_eq!(r_head.headers().get(header::CONTENT_LENGTH).unwrap(), "8");
        assert!(r_head.into_body().collect().await.unwrap().to_bytes().is_empty());
    }

    #[test]
    fn cache_refuses_set_cookie_private_no_store_and_auth() {
        let policy = enabled_policy();
        let cache = EdgeCache::new(policy.max_memory_bytes, policy.max_entries);

        // Request with Authorization or bypass cookie -> Bypass
        let mut auth_h = HeaderMap::new();
        auth_h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        assert!(matches!(
            cache.lookup(&policy, "web", &Method::GET, "example.com", "/me", &auth_h),
            CacheLookup::Bypass
        ));
        let mut ck_h = HeaderMap::new();
        ck_h.insert(header::COOKIE, HeaderValue::from_static("theme=dark; session=abc"));
        assert!(matches!(
            cache.lookup(&policy, "web", &Method::GET, "example.com", "/me", &ck_h),
            CacheLookup::Bypass
        ));
        // POST -> Bypass
        assert!(matches!(
            cache.lookup(&policy, "web", &Method::POST, "example.com", "/submit", &HeaderMap::new()),
            CacheLookup::Bypass
        ));

        // Set-Cookie response -> NEVER stored even if respect_cache_control=false
        let mut force_policy = policy.clone();
        force_policy.respect_cache_control = false;
        let mut sc_h = HeaderMap::new();
        sc_h.insert(header::SET_COOKIE, HeaderValue::from_static("sid=123; HttpOnly"));
        assert!(!cache.store(&force_policy, "k1", &HeaderMap::new(), StatusCode::OK, &sc_h, Bytes::from_static(b"ok")));

        // private & no-store refused when respect_cache_control=true
        let mut priv_h = HeaderMap::new();
        priv_h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=60"));
        assert!(!cache.store(&policy, "k2", &HeaderMap::new(), StatusCode::OK, &priv_h, Bytes::from_static(b"ok")));

        let mut ns_h = HeaderMap::new();
        ns_h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        assert!(!cache.store(&policy, "k3", &HeaderMap::new(), StatusCode::OK, &ns_h, Bytes::from_static(b"ok")));
    }

    #[test]
    fn cache_lru_evicts_oldest_under_memory_budget() {
        let mut node = NodeCacheConfig::default();
        node.enabled = true;
        node.max_memory_bytes = 2500;
        node.max_object_bytes = 1200;
        node.max_entries = 100;
        let policy = EffectiveCachePolicy::resolve(&node, None);
        let cache = EdgeCache::new(policy.max_memory_bytes, policy.max_entries);

        let h = HeaderMap::new();
        let big = Bytes::from(vec![b'a'; 1000]);
        assert!(cache.store(&policy, "web|a|/1", &h, StatusCode::OK, &h, big.clone()));
        assert!(cache.store(&policy, "web|a|/2", &h, StatusCode::OK, &h, big.clone()));
        // Touch /1 so /2 becomes LRU
        assert!(matches!(cache.lookup(&policy, "web", &Method::GET, "a", "/1", &h), CacheLookup::Hit { .. }));
        // Inserting /3 forces LRU eviction of /2
        assert!(cache.store(&policy, "web|a|/3", &h, StatusCode::OK, &h, big));

        assert!(matches!(cache.lookup(&policy, "web", &Method::GET, "a", "/1", &h), CacheLookup::Hit { .. }));
        assert!(matches!(cache.lookup(&policy, "web", &Method::GET, "a", "/2", &h), CacheLookup::Miss { .. }));
        assert!(matches!(cache.lookup(&policy, "web", &Method::GET, "a", "/3", &h), CacheLookup::Hit { .. }));
        assert!(cache.stats().evictions >= 1);
    }

    #[tokio::test]
    async fn cache_stale_and_304_revalidation_refreshes_entry() {
        let mut node = NodeCacheConfig::default();
        node.enabled = true;
        node.default_ttl_secs = 1;
        node.stale_if_error_secs = 60;
        let policy = EffectiveCachePolicy::resolve(&node, None);
        let cache = EdgeCache::new(policy.max_memory_bytes, policy.max_entries);

        let h = HeaderMap::new();
        let mut resp_h = HeaderMap::new();
        resp_h.insert(header::ETAG, HeaderValue::from_static("\"etag-1\""));
        resp_h.insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=1"));
        let bk = build_base_cache_key("web", "example.com", "/data", false);
        assert!(cache.store(&policy, &bk, &h, StatusCode::OK, &resp_h, Bytes::from_static(b"payload")));

        // Client with Cache-Control: max-age=0 triggers Stale for revalidation
        let mut reval_req = HeaderMap::new();
        reval_req.insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
        let stale_entry = match cache.lookup(&policy, "web", &Method::GET, "example.com", "/data", &reval_req) {
            CacheLookup::Stale { entry, .. } => entry,
            other => panic!("expected Stale for revalidation, got {other:?}"),
        };

        // Upstream responds 304 Not Modified with extended max-age=120
        let mut h304 = HeaderMap::new();
        h304.insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=120"));
        let refreshed = cache
            .revalidate_304(&policy, &bk, &stale_entry, &h304)
            .expect("valid 304 should refresh entry");
        assert!(refreshed.is_fresh(Instant::now()));

        // Subsequent normal request gets fresh HIT with preserved body
        let hit = match cache.lookup(&policy, "web", &Method::GET, "example.com", "/data", &h) {
            CacheLookup::Hit { entry, .. } => entry,
            other => panic!("expected fresh Hit after 304, got {other:?}"),
        };
        assert_eq!(&hit.body[..], b"payload");

        // 304 carrying Cache-Control: no-store must evict cached entry instead of extending TTL
        let mut h304_ns = HeaderMap::new();
        h304_ns.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        assert!(cache.revalidate_304(&policy, &bk, &hit, &h304_ns).is_none());
        assert!(matches!(
            cache.lookup(&policy, "web", &Method::GET, "example.com", "/data", &h),
            CacheLookup::Miss { .. }
        ));
    }
}
