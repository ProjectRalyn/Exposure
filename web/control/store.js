// Unified Cluster Configuration Store (Draft, Undo/Redo, Diff, Path Solver, Validation & Deploy)

export function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

export function isReservedKey(k) {
  return k === "__proto__" || k === "prototype" || k === "constructor";
}

export function normalizeTri(v) {
  if (v === true) return true;
  if (v === false) return false;
  return null;
}

export function sanitizeRecord(obj) {
  const out = {};
  if (obj && typeof obj === "object" && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj)) {
      if (!isReservedKey(k)) out[k] = v;
    }
  }
  return out;
}

export const WAF_CATEGORIES = [
  "sql-injection",
  "xss",
  "path-traversal",
  "command-injection",
  "nosql-injection",
  "ssrf",
  "ssti",
  "xxe",
  "ldap-injection",
  "crlf-injection",
  "deserialization",
  "buffer-overflow",
];

export const GEO_RULE_ACTIONS = ["allow", "off", "monitor", "challenge", "block", "evilpot"];

export function defaultGeoIpConfig() {
  return {
    enabled: true,
    auto_update: true,
    update_interval_hours: 168,
    ipv4_url: null,
    ipv6_url: null,
    cache_dir: null,
  };
}

export function normalizeGeoIpConfig(raw) {
  const b = defaultGeoIpConfig();
  const s = raw && typeof raw === "object" ? raw : {};
  const hours = Number(s.update_interval_hours ?? b.update_interval_hours);
  const strOrNull = (v) => {
    const t = v != null ? String(v).trim() : "";
    return t ? t : null;
  };
  return {
    enabled: Boolean(s.enabled ?? b.enabled),
    auto_update: Boolean(s.auto_update ?? b.auto_update),
    update_interval_hours: Number.isFinite(hours)
      ? Math.min(720, Math.max(6, Math.round(hours)))
      : b.update_interval_hours,
    ipv4_url: strOrNull(s.ipv4_url),
    ipv6_url: strOrNull(s.ipv6_url),
    cache_dir: strOrNull(s.cache_dir),
  };
}

export function defaultGeoPolicyConfig() {
  return {
    enabled: false,
    allow_regions: [],
    deny_regions: [],
    deny_action: "block",
    default_action: "allow",
    unknown_action: "off",
    rules: [],
  };
}

export function normalizeGeoPolicyConfig(raw) {
  const b = defaultGeoPolicyConfig();
  const s = raw && typeof raw === "object" ? raw : {};
  const normAction = (a, fb) => (GEO_RULE_ACTIONS.includes(a) ? a : fb);
  const normRegions = (arr) =>
    Array.isArray(arr)
      ? [...new Set(arr.map((x) => String(x).trim().toUpperCase()).filter(Boolean))]
      : [];
  const rules = Array.isArray(s.rules)
    ? s.rules.map((r) => {
        const boost = Number(r?.suspicion_boost ?? 0);
        const noteStr = r?.note != null ? String(r.note).trim() : "";
        return {
          regions: normRegions(r?.regions),
          action: normAction(r?.action, "allow"),
          suspicion_boost: Number.isFinite(boost) ? Math.min(100, Math.max(-50, Math.round(boost))) : 0,
          note: noteStr || null,
        };
      })
    : [];
  return {
    enabled: Boolean(s.enabled ?? b.enabled),
    allow_regions: normRegions(s.allow_regions),
    deny_regions: normRegions(s.deny_regions),
    deny_action: normAction(s.deny_action, b.deny_action),
    default_action: normAction(s.default_action, b.default_action),
    unknown_action: normAction(s.unknown_action, b.unknown_action),
    rules,
  };
}

export function defaultWafConfig() {
  return {
    mode: "off",
    categories: [],
    inspect_headers: true,
    inspect_body: true,
    max_body_bytes: 32 * 1024,
    exempt_paths: [],
    crs_paranoia_level: 1,
    disabled_rule_ids: [],
  };
}

export function defaultAbuseIpDbConfig() {
  return {
    enabled: false,
    api_key: "",
    max_age_days: 90,
    challenge_threshold: 25,
    block_threshold: 75,
    high_risk_action: "block",
    cache_ttl_secs: 21600,
    max_daily_lookups: 900,
    report_enabled: false,
    report_daily_quota: 100,
    report_min_offense_level: 1,
    report_categories: [],
  };
}

export function normalizeAbuseIpDbConfig(raw) {
  const b = defaultAbuseIpDbConfig();
  const s = raw && typeof raw === "object" ? raw : {};
  const act = ["off", "monitor", "challenge", "block", "evilpot"].includes(s.high_risk_action)
    ? s.high_risk_action
    : b.high_risk_action;
  return {
    enabled: Boolean(s.enabled ?? b.enabled),
    api_key: String(s.api_key ?? b.api_key).trim(),
    max_age_days: Math.min(365, Math.max(1, Number(s.max_age_days ?? b.max_age_days) || b.max_age_days)),
    challenge_threshold: Math.min(100, Math.max(0, Number(s.challenge_threshold ?? b.challenge_threshold) || 0)),
    block_threshold: Math.min(100, Math.max(0, Number(s.block_threshold ?? b.block_threshold) || 0)),
    high_risk_action: act,
    cache_ttl_secs: Math.max(60, Number(s.cache_ttl_secs ?? b.cache_ttl_secs) || b.cache_ttl_secs),
    max_daily_lookups: Math.max(10, Number(s.max_daily_lookups ?? b.max_daily_lookups) || b.max_daily_lookups),
    report_enabled: Boolean(s.report_enabled ?? b.report_enabled),
    report_daily_quota: Math.max(1, Math.min(1000, Number(s.report_daily_quota ?? b.report_daily_quota) || b.report_daily_quota)),
    report_min_offense_level: Math.max(1, Math.min(8, Number(s.report_min_offense_level ?? b.report_min_offense_level) || b.report_min_offense_level)),
    report_categories: (Array.isArray(s.report_categories) ? s.report_categories : b.report_categories)
      .map((v) => Number(v))
      .filter((v) => Number.isInteger(v) && v >= 1 && v <= 23),
  };
}

export function defaultCrsUpdateConfig() {
  return {
    auto_update: true,
    update_interval_hours: 24,
    paranoia_level: 1,
    disabled_rule_ids: [],
  };
}

export function normalizeCrsUpdateConfig(raw) {
  const b = defaultCrsUpdateConfig();
  const s = raw && typeof raw === "object" ? raw : {};
  return {
    auto_update: Boolean(s.auto_update ?? b.auto_update),
    update_interval_hours: Math.min(720, Math.max(1, Number(s.update_interval_hours ?? b.update_interval_hours) || b.update_interval_hours)),
    paranoia_level: Math.min(4, Math.max(1, Number(s.paranoia_level ?? b.paranoia_level) || b.paranoia_level)),
    disabled_rule_ids: Array.isArray(s.disabled_rule_ids)
      ? [...new Set(s.disabled_rule_ids.map((x) => Number(x)).filter((n) => Number.isInteger(n) && n > 0))]
      : [],
  };
}

export function defaultAutoBanConfig() {
  return {
    enabled: true,
    ban_ttl_secs: 1800,
    max_ban_ttl_secs: 86400,
    confirm_hits: 4,
    ban_fingerprints: true,
    drop_at_tcp: true,
  };
}

export function normalizeAutoBanConfig(raw) {
  const b = defaultAutoBanConfig();
  const s = raw && typeof raw === "object" ? raw : {};
  const ttl = Math.min(86400, Math.max(60, Number(s.ban_ttl_secs ?? b.ban_ttl_secs) || b.ban_ttl_secs));
  const maxTtl = Math.min(7 * 86400, Math.max(ttl, Number(s.max_ban_ttl_secs ?? b.max_ban_ttl_secs) || b.max_ban_ttl_secs));
  return {
    enabled: Boolean(s.enabled ?? b.enabled),
    ban_ttl_secs: ttl,
    max_ban_ttl_secs: maxTtl,
    confirm_hits: Math.min(50, Math.max(1, Number(s.confirm_hits ?? b.confirm_hits) || b.confirm_hits)),
    ban_fingerprints: Boolean(s.ban_fingerprints ?? b.ban_fingerprints),
    drop_at_tcp: Boolean(s.drop_at_tcp ?? b.drop_at_tcp),
  };
}

export function defaultEvilpotConfig() {
  return {
    rotation_interval_secs: 300,
    persona_slots: 16,
    max_tarpit_connections: 256,
    tarpit_drip_bytes_per_sec: 256,
    sqli_time_delay_ms: 2500,
    canary_webhook_url: "https://canary.internal.example.com/t",
    max_tracked_sessions: 2048,
    identical_payload_decoy_hits: 1,
  };
}

export function normalizeEvilpotConfig(raw) {
  const b = defaultEvilpotConfig();
  const s = raw && typeof raw === "object" ? raw : {};
  return {
    rotation_interval_secs: Math.max(60, Number(s.rotation_interval_secs ?? b.rotation_interval_secs) || b.rotation_interval_secs),
    persona_slots: Math.min(32, Math.max(1, Number(s.persona_slots ?? b.persona_slots) || b.persona_slots)),
    max_tarpit_connections: Math.min(256, Math.max(1, Number(s.max_tarpit_connections ?? b.max_tarpit_connections) || b.max_tarpit_connections)),
    tarpit_drip_bytes_per_sec: Math.min(16384, Math.max(16, Number(s.tarpit_drip_bytes_per_sec ?? b.tarpit_drip_bytes_per_sec) || b.tarpit_drip_bytes_per_sec)),
    sqli_time_delay_ms: Math.min(5000, Math.max(100, Number(s.sqli_time_delay_ms ?? b.sqli_time_delay_ms) || b.sqli_time_delay_ms)),
    canary_webhook_url: String(s.canary_webhook_url ?? b.canary_webhook_url).trim().slice(0, 256) || b.canary_webhook_url,
    max_tracked_sessions: Math.min(4096, Math.max(16, Number(s.max_tracked_sessions ?? b.max_tracked_sessions) || b.max_tracked_sessions)),
    identical_payload_decoy_hits:
      s.identical_payload_decoy_hits === null
        ? null
        : Math.min(100, Math.max(0, Math.trunc(Number(s.identical_payload_decoy_hits ?? b.identical_payload_decoy_hits)) || 0)),
  };
}

export function normalizeWafConfig(raw) {
  const b = defaultWafConfig();
  const s = raw && typeof raw === "object" ? raw : {};
  const mode =
    s.mode === "block" || s.mode === "monitor" || s.mode === "evilpot" || s.mode === "off"
      ? s.mode
      : b.mode;
  return {
    mode,
    categories: Array.isArray(s.categories)
      ? s.categories.map(String).filter((c) => WAF_CATEGORIES.includes(c))
      : [],
    inspect_headers: Boolean(s.inspect_headers ?? b.inspect_headers),
    inspect_body: Boolean(s.inspect_body ?? b.inspect_body),
    max_body_bytes: Math.min(
      256 * 1024,
      Math.max(
        0,
        s.max_body_bytes !== null && s.max_body_bytes !== undefined && s.max_body_bytes !== "" && Number.isFinite(Number(s.max_body_bytes))
          ? Number(s.max_body_bytes)
          : b.max_body_bytes,
      ),
    ),
    exempt_paths: Array.isArray(s.exempt_paths) ? s.exempt_paths.map((x) => String(x).trim()).filter(Boolean) : [],
    crs_paranoia_level: Math.min(4, Math.max(1, Number(s.crs_paranoia_level ?? b.crs_paranoia_level) || b.crs_paranoia_level)),
    disabled_rule_ids: Array.isArray(s.disabled_rule_ids)
      ? [...new Set(s.disabled_rule_ids.map((x) => Number(x)).filter((n) => Number.isInteger(n) && n > 0))]
      : [],
  };
}

export function defaultNodeCacheConfig() {
  return {
    enabled: false,
    max_memory_bytes: 64 * 1024 * 1024,
    max_object_bytes: 4 * 1024 * 1024,
    max_entries: 10000,
    default_ttl_secs: 60,
    stale_if_error_secs: 300,
    respect_cache_control: true,
    ignore_query_string: false,
    cacheable_statuses: [],
    bypass_cookie_prefixes: [],
  };
}

export function normalizeNodeCacheConfig(raw) {
  const b = defaultNodeCacheConfig();
  const s = raw && typeof raw === "object" ? raw : {};
  return {
    enabled: Boolean(s.enabled ?? b.enabled),
    max_memory_bytes: Number(s.max_memory_bytes ?? b.max_memory_bytes) || b.max_memory_bytes,
    max_object_bytes: Number(s.max_object_bytes ?? b.max_object_bytes) || b.max_object_bytes,
    max_entries: Number(s.max_entries ?? b.max_entries) || b.max_entries,
    default_ttl_secs: Number(s.default_ttl_secs ?? b.default_ttl_secs) || b.default_ttl_secs,
    stale_if_error_secs: Number(s.stale_if_error_secs ?? b.stale_if_error_secs) || 0,
    respect_cache_control: Boolean(s.respect_cache_control ?? b.respect_cache_control),
    ignore_query_string: Boolean(s.ignore_query_string ?? b.ignore_query_string),
    cacheable_statuses: Array.isArray(s.cacheable_statuses) ? s.cacheable_statuses.map(Number).filter(Boolean) : [],
    bypass_cookie_prefixes: Array.isArray(s.bypass_cookie_prefixes) ? s.bypass_cookie_prefixes.map(String).filter(Boolean) : [],
  };
}

export function normalizeRuleCacheConfig(raw) {
  if (!raw || typeof raw !== "object") return null;
  const out = {
    enabled: normalizeTri(raw.enabled),
    default_ttl_secs: raw.default_ttl_secs != null && raw.default_ttl_secs !== "" ? Number(raw.default_ttl_secs) : null,
    stale_if_error_secs: raw.stale_if_error_secs != null && raw.stale_if_error_secs !== "" ? Number(raw.stale_if_error_secs) : null,
    respect_cache_control: normalizeTri(raw.respect_cache_control),
    ignore_query_string: normalizeTri(raw.ignore_query_string),
    bypass_cookie_prefixes: Array.isArray(raw.bypass_cookie_prefixes) ? raw.bypass_cookie_prefixes.map(String).filter(Boolean) : [],
  };
  if (
    out.enabled == null &&
    out.default_ttl_secs == null &&
    out.stale_if_error_secs == null &&
    out.respect_cache_control == null &&
    out.ignore_query_string == null &&
    !out.bypass_cookie_prefixes.length
  ) {
    return null;
  }
  return out;
}

export function defaultLogProtectionConfig() {
  return {
    enabled: true,
    max_records_per_sec: 500,
    max_per_ip_per_sec: 20,
    max_bytes_per_min: 8 * 1024 * 1024,
    dedup_window_secs: 10,
    log_query_string: true,
    access_log_stdout: false,
    warn_rate_per_sec: 20,
  };
}

export function normalizeLogProtectionConfig(raw) {
  const b = defaultLogProtectionConfig();
  const s = raw && typeof raw === "object" ? raw : {};
  const clamp = (v, fb, min, max) => {
    const n = Number(v);
    if (!Number.isFinite(n)) return fb;
    return Math.min(max, Math.max(min, Math.round(n)));
  };
  return {
    enabled: Boolean(s.enabled ?? b.enabled),
    max_records_per_sec: clamp(s.max_records_per_sec, b.max_records_per_sec, 10, 100000),
    max_per_ip_per_sec: clamp(s.max_per_ip_per_sec, b.max_per_ip_per_sec, 1, 50000),
    max_bytes_per_min: clamp(s.max_bytes_per_min, b.max_bytes_per_min, 64 * 1024, 512 * 1024 * 1024),
    dedup_window_secs: clamp(s.dedup_window_secs, b.dedup_window_secs, 0, 300),
    log_query_string: Boolean(s.log_query_string ?? b.log_query_string),
    access_log_stdout: Boolean(s.access_log_stdout ?? b.access_log_stdout),
    warn_rate_per_sec: clamp(s.warn_rate_per_sec, b.warn_rate_per_sec, 1, 1000),
  };
}

export function defaultTopologyDefaults() {
  return {
    ingress: {
      server_header: "nginx",
      clearance_secret: "",
      cert_store_dir: null,
      default_guard: null,
      default_bucket: null,
      default_antibot: null,
      default_waf: null,
      intercept_errors: false,
      js_fp_beacon: true,
      js_fp_ttl_secs: 3600,
      cache: defaultNodeCacheConfig(),
      evilpot: defaultEvilpotConfig(),
      auto_ban: defaultAutoBanConfig(),
      abuseipdb: defaultAbuseIpDbConfig(),
      exempt_ips: [],
      crs: defaultCrsUpdateConfig(),
      geoip: defaultGeoIpConfig(),
    },
    guard: {
      antibot: "challenge",
      rate_limit_bucket: null,
      challenge_threshold: 50,
      reject_threshold: 85,
      pow_difficulty: 16,
      clearance_ttl_secs: 600,
      bind_ua: true,
      bind_ip_prefix: true,
      block_bots: false,
      browser_only: false,
      block_headless: true,
      require_client_fp: false,
      js_fp_beacon: true,
      js_fp_ttl_secs: 3600,
      waf: defaultWafConfig(),
    },
    egress: {
      protocol: "auto",
      timeout_ms: 30000,
      tls: false,
      ca_cert_path: null,
      insecure_skip_verify: false,
      allow_any_origin: false,
      intercept_errors: false,
    },
    link_listener: {
      allow_on_demand: true,
      allow_tunnel: true,
      allow_bootstrap: false,
    },
    pages: {
      error: null,
      pow: null,
    },
  };
}

export function defaultAntibotProfile(defs = null) {
  const gd = defs || defaultTopologyDefaults().guard;
  return {
    antibot: gd.antibot || "challenge",
    allow_cidrs: [],
    deny_cidrs: [],
    challenge_threshold: gd.challenge_threshold ?? 35,
    reject_threshold: gd.reject_threshold ?? 80,
    pow_difficulty: gd.pow_difficulty ?? 18,
    clearance_ttl_secs: gd.clearance_ttl_secs ?? 3600,
    bind_ua: null,
    bind_ip_prefix: null,
    api_bypass_headers: [],
    block_bots: null,
    browser_only: null,
    block_headless: null,
    require_client_fp: null,
    js_fp_beacon: null,
    js_fp_ttl_secs: null,
    geo: null,
  };
}

export function normalizeAntibotProfile(raw) {
  const src = raw && typeof raw === "object" ? raw : {};
  return {
    antibot: src.antibot || "off",
    allow_cidrs: Array.isArray(src.allow_cidrs) ? src.allow_cidrs : [],
    deny_cidrs: Array.isArray(src.deny_cidrs) ? src.deny_cidrs : [],
    challenge_threshold: src.challenge_threshold ?? 35,
    reject_threshold: src.reject_threshold ?? 80,
    pow_difficulty: src.pow_difficulty ?? 18,
    clearance_ttl_secs: src.clearance_ttl_secs ?? 3600,
    bind_ua: normalizeTri(src.bind_ua),
    bind_ip_prefix: normalizeTri(src.bind_ip_prefix),
    api_bypass_headers: Array.isArray(src.api_bypass_headers) ? src.api_bypass_headers : [],
    block_bots: normalizeTri(src.block_bots),
    browser_only: normalizeTri(src.browser_only),
    block_headless: normalizeTri(src.block_headless),
    require_client_fp: normalizeTri(src.require_client_fp),
    js_fp_beacon: normalizeTri(src.js_fp_beacon),
    js_fp_ttl_secs: src.js_fp_ttl_secs != null && src.js_fp_ttl_secs !== "" ? Number(src.js_fp_ttl_secs) : null,
    geo: src.geo && typeof src.geo === "object" ? normalizeGeoPolicyConfig(src.geo) : null,
  };
}

export function defaultGuardProfile(defs = null) {
  return {
    ...defaultAntibotProfile(defs),
    rate_limit_bucket: null,
    waf: null,
  };
}

export function normalizeGuardProfile(g) {
  const src = g && typeof g === "object" ? g : {};
  return {
    ...normalizeAntibotProfile(src),
    rate_limit_bucket: src.rate_limit_bucket || null,
    waf: src.waf && typeof src.waf === "object" ? normalizeWafConfig(src.waf) : null,
  };
}

export function normalizeBucket(b) {
  const src = b && typeof b === "object" ? b : {};
  return {
    capacity: src.capacity ?? 60,
    refill_per_sec: src.refill_per_sec ?? 10,
    per_ip: normalizeTri(src.per_ip),
  };
}

export function normalizeEgressService(svc) {
  const src = svc && typeof svc === "object" ? svc : {};
  return {
    backend: src.backend || "",
    protocol: src.protocol || "auto",
    tls: normalizeTri(src.tls),
    ca_cert_path: src.ca_cert_path || null,
    insecure_skip_verify: normalizeTri(src.insecure_skip_verify),
    allow_from: Array.isArray(src.allow_from) ? src.allow_from : [],
    allow_any_origin: normalizeTri(src.allow_any_origin),
    timeout_ms: src.timeout_ms ?? 30000,
    intercept_errors: normalizeTri(src.intercept_errors),
    local_health_check: src.local_health_check || null,
  };
}

export function defaultServiceSpec(egressNode = "") {
  return {
    hosts: [],
    url_prefix: null,
    sni: null,
    source_cidrs: [],
    ingress: { mode: "all", nodes: [], overrides: {} },
    guard: null,
    bucket: null,
    antibot: null,
    waf: null,
    intercept_errors: null,
    js_fp_beacon: null,
    cache: null,
    egress: {
      node: egressNode,
      backend: "127.0.0.1:8080",
      protocol: "auto",
      tls: null,
      ca_cert_path: null,
      insecure_skip_verify: null,
      timeout_ms: 0,
      intercept_errors: null,
      local_health_check: null,
    },
    routing: { mode: "auto", pinned_paths: {} },
    auto_tls: false,
    enabled: true,
  };
}

export function normalizeServiceSpec(raw) {
  const src = raw && typeof raw === "object" ? raw : {};
  const rawOverrides = sanitizeRecord(src.ingress?.overrides);
  const overrides = {};
  for (const [k, ov] of Object.entries(rawOverrides)) {
    overrides[k] = {
      guard: ov?.guard || null,
      bucket: ov?.bucket || null,
      antibot: ov?.antibot || null,
      waf: ov?.waf || null,
      source_cidrs: Array.isArray(ov?.source_cidrs) ? ov.source_cidrs.map(String).filter(Boolean) : [],
      intercept_errors: normalizeTri(ov?.intercept_errors),
      js_fp_beacon: normalizeTri(ov?.js_fp_beacon),
    };
  }
  const rawPinned = sanitizeRecord(src.routing?.pinned_paths);
  const pinned_paths = {};
  for (const [k, arr] of Object.entries(rawPinned)) {
    if (Array.isArray(arr)) pinned_paths[k] = arr.map(String).filter(Boolean);
  }
  return {
    hosts: Array.isArray(src.hosts) ? src.hosts.map((s) => String(s).trim()).filter(Boolean) : [],
    url_prefix: src.url_prefix || null,
    sni: src.sni || null,
    source_cidrs: Array.isArray(src.source_cidrs) ? src.source_cidrs.map(String).filter(Boolean) : [],
    ingress: {
      mode: src.ingress?.mode || "all",
      nodes: Array.isArray(src.ingress?.nodes) ? src.ingress.nodes.map(String).filter(Boolean) : [],
      overrides,
    },
    guard: src.guard || null,
    bucket: src.bucket || null,
    antibot: src.antibot || null,
    waf: src.waf || null,
    intercept_errors: normalizeTri(src.intercept_errors),
    js_fp_beacon: normalizeTri(src.js_fp_beacon),
    cache: normalizeRuleCacheConfig(src.cache),
    egress: {
      node: src.egress?.node || "",
      backend: src.egress?.backend || "",
      protocol: src.egress?.protocol || "auto",
      tls: normalizeTri(src.egress?.tls),
      ca_cert_path: src.egress?.ca_cert_path || null,
      insecure_skip_verify: normalizeTri(src.egress?.insecure_skip_verify),
      timeout_ms: Number(src.egress?.timeout_ms ?? 0) || 0,
      intercept_errors: normalizeTri(src.egress?.intercept_errors),
      local_health_check: src.egress?.local_health_check || null,
    },
    routing: {
      mode: src.routing?.mode || "auto",
      pinned_paths,
    },
    auto_tls: Boolean(src.auto_tls),
    enabled: src.enabled !== false,
  };
}

export function defaultNodeSpec() {
  return {
    roles: { ingress: false, egress: false, relay: false, maintainer: false },
    external_ips: [],
    link_listener: {
      listen_addr: "0.0.0.0:10802",
      allow_on_demand: null,
      allow_tunnel: null,
      allow_bootstrap: null,
    },
    maintainer_template: null,
    maintainer_hops: [],
    ingress: {
      listeners: [],
      rules: [],
      guards: {},
      antibot_sets: {},
      waf_sets: {},
      rate_limit_buckets: {},
      tls_certs: [],
      clearance_secret: "",
      cert_store_dir: null,
      default_guard: null,
      default_bucket: null,
      default_antibot: null,
      default_waf: null,
      server_header: "",
      js_fp_beacon: null,
      js_fp_ttl_secs: null,
      geoip: null,
      pages: { error: null, pow: null },
    },
    egress: { services: {}, pages: { error: null, pow: null } },
    relay: { rules: [] },
  };
}

export function rolesFromAny(rawRoles) {
  const base = { ingress: false, egress: false, relay: false, maintainer: false };
  if (Array.isArray(rawRoles)) {
    for (const r of rawRoles) {
      if (Object.hasOwn(base, r)) base[r] = true;
    }
    return base;
  }
  if (rawRoles && typeof rawRoles === "object") {
    return {
      ingress: Boolean(rawRoles.ingress),
      egress: Boolean(rawRoles.egress),
      relay: Boolean(rawRoles.relay),
      maintainer: Boolean(rawRoles.maintainer),
    };
  }
  return base;
}

export function normalizeNode(n) {
  const base = defaultNodeSpec();
  const out = { ...base, ...(n || {}) };
  out.roles = rolesFromAny(n?.roles);
  out.external_ips = Array.isArray(n?.external_ips) ? n.external_ips.map((s) => String(s).trim()).filter(Boolean) : [];
  if (n && n.link_listener === null) {
    out.link_listener = null;
  } else if (n?.link_listener && typeof n.link_listener === "object") {
    out.link_listener = {
      listen_addr: n.link_listener.listen_addr || "",
      allow_on_demand: normalizeTri(n.link_listener.allow_on_demand),
      allow_tunnel: normalizeTri(n.link_listener.allow_tunnel),
      allow_bootstrap: normalizeTri(n.link_listener.allow_bootstrap),
    };
  }
  out.ingress = { ...base.ingress, ...(n?.ingress || {}) };
  out.ingress.clearance_secret = n?.ingress?.clearance_secret || "";
  out.ingress.default_guard = n?.ingress?.default_guard || null;
  out.ingress.default_bucket = n?.ingress?.default_bucket || null;
  out.ingress.default_antibot = n?.ingress?.default_antibot || null;
  out.ingress.default_waf = n?.ingress?.default_waf || null;
  out.ingress.server_header = n?.ingress?.server_header ?? "";
  out.ingress.js_fp_beacon = normalizeTri(n?.ingress?.js_fp_beacon);
  out.ingress.js_fp_ttl_secs =
    n?.ingress?.js_fp_ttl_secs != null && n?.ingress?.js_fp_ttl_secs !== ""
      ? Number(n.ingress.js_fp_ttl_secs)
      : null;
  out.ingress.geoip =
    n?.ingress?.geoip && typeof n.ingress.geoip === "object"
      ? normalizeGeoIpConfig(n.ingress.geoip)
      : null;
  out.ingress.listeners = Array.isArray(out.ingress.listeners)
    ? out.ingress.listeners.map((l) => ({
        listen_addr: l.listen_addr || "",
        tls: Boolean(l.tls),
        redirect_https: Boolean(l.redirect_https),
      }))
    : [];
  out.ingress.rules = Array.isArray(out.ingress.rules)
    ? out.ingress.rules.map((r) => ({
        name: r.name || null,
        match: r.match || {},
        service_tag: r.service_tag || "",
        next_peer: r.next_peer || "",
        guard: r.guard || null,
        bucket: r.bucket || null,
        antibot: r.antibot || null,
        waf: r.waf || null,
        intercept_errors: normalizeTri(r.intercept_errors),
        js_fp_beacon: normalizeTri(r.js_fp_beacon),
      }))
    : [];
  const rawGuards = sanitizeRecord(out.ingress.guards);
  out.ingress.guards = {};
  for (const [k, v] of Object.entries(rawGuards)) out.ingress.guards[k] = normalizeGuardProfile(v);
  const rawAntibots = sanitizeRecord(out.ingress.antibot_sets);
  out.ingress.antibot_sets = {};
  for (const [k, v] of Object.entries(rawAntibots)) out.ingress.antibot_sets[k] = normalizeAntibotProfile(v);
  const rawWafs = sanitizeRecord(out.ingress.waf_sets);
  out.ingress.waf_sets = {};
  for (const [k, v] of Object.entries(rawWafs)) out.ingress.waf_sets[k] = normalizeWafConfig(v);
  const rawBuckets = sanitizeRecord(out.ingress.rate_limit_buckets);
  out.ingress.rate_limit_buckets = {};
  for (const [k, v] of Object.entries(rawBuckets)) out.ingress.rate_limit_buckets[k] = normalizeBucket(v);
  out.ingress.tls_certs = Array.isArray(out.ingress.tls_certs) ? out.ingress.tls_certs : [];
  out.ingress.pages = {
    error: n?.ingress?.pages?.error || null,
    pow: n?.ingress?.pages?.pow || null,
  };
  out.egress = { ...base.egress, ...(n?.egress || {}) };
  out.egress.pages = {
    error: n?.egress?.pages?.error || null,
    pow: null,
  };
  const rawSvcs = sanitizeRecord(out.egress.services);
  out.egress.services = {};
  for (const [k, v] of Object.entries(rawSvcs)) out.egress.services[k] = normalizeEgressService(v);
  out.relay = { ...base.relay, ...(n?.relay || {}) };
  out.relay.rules = Array.isArray(out.relay.rules) ? out.relay.rules : [];
  out.maintainer_hops = Array.isArray(n?.maintainer_hops) ? n.maintainer_hops : [];
  return out;
}

export function defaultMaintainerTemplate() {
  return {
    is_primary_cert_manager: true,
    acme: {
      directory_url: "self-signed",
      contact_email: "",
      storage_dir: "./data/certs",
      orders: [],
    },
  };
}

export function normalizeDefaults(raw) {
  const base = defaultTopologyDefaults();
  const src = raw && typeof raw === "object" ? raw : {};
  return {
    ingress: {
      ...base.ingress,
      ...(src.ingress || {}),
      cert_store_dir: src.ingress?.cert_store_dir || null,
      default_guard: src.ingress?.default_guard || null,
      default_bucket: src.ingress?.default_bucket || null,
      default_antibot: src.ingress?.default_antibot || null,
      default_waf: src.ingress?.default_waf || null,
      intercept_errors: Boolean(src.ingress?.intercept_errors ?? base.ingress.intercept_errors),
      js_fp_beacon: Boolean(src.ingress?.js_fp_beacon ?? base.ingress.js_fp_beacon),
      js_fp_ttl_secs: Number(src.ingress?.js_fp_ttl_secs ?? base.ingress.js_fp_ttl_secs) || 3600,
      cache: normalizeNodeCacheConfig(src.ingress?.cache),
      evilpot: normalizeEvilpotConfig(src.ingress?.evilpot),
      auto_ban: normalizeAutoBanConfig(src.ingress?.auto_ban),
      abuseipdb: normalizeAbuseIpDbConfig(src.ingress?.abuseipdb),
      crs: normalizeCrsUpdateConfig(src.ingress?.crs),
      geoip: normalizeGeoIpConfig(src.ingress?.geoip),
    },
    guard: {
      ...base.guard,
      ...(src.guard || {}),
      rate_limit_bucket: src.guard?.rate_limit_bucket || null,
      bind_ua: Boolean(src.guard?.bind_ua ?? base.guard.bind_ua),
      bind_ip_prefix: Boolean(src.guard?.bind_ip_prefix ?? base.guard.bind_ip_prefix),
      block_bots: Boolean(src.guard?.block_bots ?? base.guard.block_bots),
      browser_only: Boolean(src.guard?.browser_only ?? base.guard.browser_only),
      block_headless: Boolean(src.guard?.block_headless ?? base.guard.block_headless),
      require_client_fp: Boolean(src.guard?.require_client_fp ?? base.guard.require_client_fp),
      js_fp_beacon: Boolean(src.guard?.js_fp_beacon ?? base.guard.js_fp_beacon),
      js_fp_ttl_secs: Number(src.guard?.js_fp_ttl_secs ?? base.guard.js_fp_ttl_secs) || 3600,
      waf: normalizeWafConfig(src.guard?.waf),
    },
    egress: {
      ...base.egress,
      ...(src.egress || {}),
      ca_cert_path: src.egress?.ca_cert_path || null,
      tls: Boolean(src.egress?.tls ?? base.egress.tls),
      insecure_skip_verify: Boolean(src.egress?.insecure_skip_verify ?? base.egress.insecure_skip_verify),
      allow_any_origin: Boolean(src.egress?.allow_any_origin ?? base.egress.allow_any_origin),
      intercept_errors: Boolean(src.egress?.intercept_errors ?? base.egress.intercept_errors),
      timeout_ms: Number(src.egress?.timeout_ms ?? base.egress.timeout_ms) || 30000,
    },
    link_listener: {
      ...base.link_listener,
      ...(src.link_listener || {}),
      allow_on_demand: Boolean(src.link_listener?.allow_on_demand ?? base.link_listener.allow_on_demand),
      allow_tunnel: Boolean(src.link_listener?.allow_tunnel ?? base.link_listener.allow_tunnel),
      allow_bootstrap: Boolean(src.link_listener?.allow_bootstrap ?? base.link_listener.allow_bootstrap),
    },
    pages: {
      error: src.pages?.error || null,
      pow: src.pages?.pow || null,
    },
  };
}

export function normalizeSpec(raw) {
  const defaults = normalizeDefaults(raw?.defaults);
  const rawGuardTpls = sanitizeRecord(raw?.guard_templates);
  const guard_templates = {};
  for (const [k, v] of Object.entries(rawGuardTpls)) {
    guard_templates[k] = normalizeGuardProfile(v);
  }
  const rawBucketTpls = sanitizeRecord(raw?.bucket_templates);
  const bucket_templates = {};
  for (const [k, v] of Object.entries(rawBucketTpls)) {
    bucket_templates[k] = normalizeBucket(v);
  }
  const rawAntibotTpls = sanitizeRecord(raw?.antibot_templates);
  const antibot_templates = {};
  for (const [k, v] of Object.entries(rawAntibotTpls)) {
    antibot_templates[k] = normalizeAntibotProfile(v);
  }
  const rawWafTpls = sanitizeRecord(raw?.waf_templates);
  const waf_templates = {};
  for (const [k, v] of Object.entries(rawWafTpls)) {
    waf_templates[k] = normalizeWafConfig(v);
  }
  const nodes = {};
  if (raw && raw.nodes && typeof raw.nodes === "object") {
    for (const [tag, n] of Object.entries(raw.nodes)) {
      if (isReservedKey(tag)) continue;
      nodes[tag] = normalizeNode(n);
    }
  }
  const services = {};
  const rawSvcs = sanitizeRecord(raw?.services);
  for (const [sName, sVal] of Object.entries(rawSvcs)) {
    services[sName] = normalizeServiceSpec(sVal);
  }
  const links = Array.isArray(raw?.links)
    ? raw.links.map((l) => ({
        from: l.from || "",
        to: l.to || "",
        peer_tag: l.peer_tag || null,
        mode: l.mode || "on-demand",
        tunnel_direction: l.tunnel_direction || (l.mode === "tunnel" ? "outbound" : null),
        bidirectional: l.bidirectional ?? true,
        expected_client_addr: l.expected_client_addr || null,
        endpoints: Array.isArray(l.endpoints) ? l.endpoints : [],
        reverse_endpoints: Array.isArray(l.reverse_endpoints) ? l.reverse_endpoints : [],
      }))
    : [];
  const dns_providers = sanitizeRecord(
    raw?.dns_providers && typeof raw.dns_providers === "object" ? deepClone(raw.dns_providers) : {}
  );
  const domains = {};
  const rawDomains = sanitizeRecord(raw?.domains);
  for (const [dKey, dVal] of Object.entries(rawDomains)) {
    const rawLines = Array.isArray(dVal?.line_routes) ? dVal.line_routes : [];
    domains[dKey] = {
      provider: dVal?.provider || "",
      zone_id: dVal?.zone_id || null,
      root_domain: dVal?.root_domain || null,
      target_nodes: Array.isArray(dVal?.target_nodes) ? dVal.target_nodes.map(String).filter(Boolean) : [],
      line_routes: rawLines.map((lr) => ({
        line: lr?.line || "default",
        target_nodes: Array.isArray(lr?.target_nodes) ? lr.target_nodes.map(String).filter(Boolean) : [],
        values: Array.isArray(lr?.values) ? lr.values.map(String).filter(Boolean) : [],
        record_type: lr?.record_type === "cname" ? "cname" : "auto",
        ttl: lr?.ttl != null && lr.ttl !== "" ? Number(lr.ttl) : null,
        proxied: normalizeTri(lr?.proxied),
        enabled: lr?.enabled !== false,
      })),
      ttl: dVal?.ttl != null ? Number(dVal.ttl) : 600,
      proxied: Boolean(dVal?.proxied),
    };
  }
  const maintainer_templates = sanitizeRecord(
    raw?.maintainer_templates && typeof raw.maintainer_templates === "object"
      ? deepClone(raw.maintainer_templates)
      : {}
  );
  const global_logger = raw?.global_logger ? deepClone(raw.global_logger) : null;
  if (global_logger && typeof global_logger === "object") {
    if (global_logger.protection && typeof global_logger.protection === "object") {
      global_logger.protection = normalizeLogProtectionConfig(global_logger.protection);
    }
    if (global_logger.segment && typeof global_logger.segment === "object" && global_logger.segment.max_recent_logs != null) {
      const m = Number(global_logger.segment.max_recent_logs);
      global_logger.segment.max_recent_logs = Number.isFinite(m) ? Math.min(10000, Math.max(100, Math.round(m))) : 2000;
    }
  }
  return {
    defaults,
    guard_templates,
    bucket_templates,
    antibot_templates,
    waf_templates,
    dns_providers,
    domains,
    services,
    nodes,
    links,
    maintainer_templates,
    global_logger,
  };
}

export function resolveDomainBindingJS(domains, targetDomain) {
  const raw = String(targetDomain || "").trim().replace(/\.+$/, "").toLowerCase();
  if (!raw || !domains) return null;
  const norm = raw.startsWith("*.") ? raw.slice(2) : raw;
  for (const [k, v] of Object.entries(domains)) {
    const kr = k.trim().replace(/\.+$/, "").toLowerCase();
    if (kr === raw) return [k, v];
  }
  for (const [k, v] of Object.entries(domains)) {
    const kr = k.trim().replace(/\.+$/, "").toLowerCase();
    if (!kr.startsWith("*.") && kr === norm) return [k, v];
  }
  let best = null;
  for (const [k, v] of Object.entries(domains)) {
    const kr = k.trim().replace(/\.+$/, "").toLowerCase();
    if (!kr || kr.startsWith("*.")) continue;
    if (norm.endsWith("." + kr)) {
      if (!best || kr.length > best[2]) best = [k, v, kr.length];
    }
  }
  return best ? [best[0], best[1]] : null;
}

export function shortestPathBFS(links, start, goal, { nodes = null, requireRelay = false } = {}) {
  if (!start || !goal) return null;
  if (start === goal) return [start];
  const adj = new Map();
  const add = (a, b) => {
    if (!adj.has(a)) adj.set(a, new Set());
    adj.get(a).add(b);
  };
  for (const l of links || []) {
    if (!l.from || !l.to) continue;
    if (l.mode === "tunnel" && l.tunnel_direction === "inbound") continue;
    add(l.from, l.to);
    if (l.mode === "tunnel") {
      add(l.to, l.from);
    } else if (l.mode === "on-demand" && l.bidirectional !== false && (l.reverse_endpoints || []).length > 0) {
      add(l.to, l.from);
    }
  }
  const visited = new Set([start]);
  const q = [[start]];
  while (q.length) {
    const path = q.shift();
    const last = path[path.length - 1];
    const nbs = [...(adj.get(last) || [])].sort();
    for (const nb of nbs) {
      if (visited.has(nb)) continue;
      if (nb !== goal && requireRelay && nodes && !nodes[nb]?.roles?.relay) continue;
      const next = [...path, nb];
      if (nb === goal) return next;
      visited.add(nb);
      q.push(next);
    }
  }
  return null;
}

export function resolveServiceTargetIngresses(spec, svc) {
  const allIng = Object.entries(spec?.nodes || {})
    .filter(([, n]) => n.roles?.ingress)
    .map(([tag]) => tag)
    .sort();
  const mode = svc?.ingress?.mode || "all";
  if (mode === "all") return allIng;
  if (mode === "selected") {
    return (svc.ingress?.nodes || []).filter((t) => spec?.nodes?.[t]?.roles?.ingress);
  }
  if (mode === "exclude") {
    const excl = new Set(svc.ingress?.nodes || []);
    return allIng.filter((t) => !excl.has(t));
  }
  return allIng;
}

export function certCoversHost(certDomain, host) {
  const cert = String(certDomain || "").trim().replace(/\.+$/, "").toLowerCase();
  const h = String(host || "").trim().replace(/\.+$/, "").toLowerCase();
  if (!cert || !h) return false;
  if (cert === h) return true;
  if (cert.startsWith("*.")) {
    const suf = cert.slice(1);
    if (h.endsWith(suf)) {
      const pref = h.slice(0, h.length - suf.length);
      return pref.length > 0 && !pref.includes(".");
    }
  }
  return false;
}

export function createControlStore({ api }) {
  const listeners = new Set();
  const store = {
    loaded: false,
    spec: normalizeSpec({}),
    savedSpec: normalizeSpec({}),
    yaml: "",
    compiledPaths: [],
    errors: [],
    warnings: [],
    liveNodes: [],
    liveLinks: [],
    overview: null,
    telemetry: null,
    versions: [],
    audit: [],
    dnsRemoteCache: {}, // domain -> { capabilities, lines, records, fetchedAt, maintainer_tag }
    undoStack: [],
    redoStack: [],
    dirty: false,

    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },

    notify(reason = "update") {
      for (const fn of listeners) fn(reason);
    },

    setFromServer(data, force = false) {
      if (store.dirty && !force) {
        // Only update live runtime overlays without clobbering unsaved draft
        if (Array.isArray(data.live_nodes)) store.liveNodes = data.live_nodes;
        if (Array.isArray(data.live_links)) store.liveLinks = data.live_links;
        store.notify("live");
        return;
      }
      store.spec = normalizeSpec(data.spec || {});
      store.savedSpec = deepClone(store.spec);
      store.yaml = data.yaml || "";
      store.compiledPaths = data.paths || [];
      store.errors = data.errors || [];
      store.warnings = data.warnings || [];
      if (Array.isArray(data.live_nodes)) store.liveNodes = data.live_nodes;
      if (Array.isArray(data.live_links)) store.liveLinks = data.live_links;
      store.undoStack = [];
      store.redoStack = [];
      store.dirty = false;
      store.loaded = true;
      store.notify("server");
    },

    async loadTopology(force = false) {
      const data = await api("/api/topology");
      store.setFromServer(data, force);
      return data;
    },

    mutate(mutator, recordHistory = true) {
      if (recordHistory) {
        store.undoStack.push(deepClone(store.spec));
        if (store.undoStack.length > 50) store.undoStack.shift();
        store.redoStack = [];
      }
      mutator(store.spec);
      store.dirty = JSON.stringify(store.spec) !== JSON.stringify(store.savedSpec);
      store.notify("mutate");
    },

    undo() {
      if (!store.undoStack.length) return false;
      store.redoStack.push(deepClone(store.spec));
      store.spec = store.undoStack.pop();
      store.dirty = JSON.stringify(store.spec) !== JSON.stringify(store.savedSpec);
      store.notify("undo");
      return true;
    },

    redo() {
      if (!store.redoStack.length) return false;
      store.undoStack.push(deepClone(store.spec));
      store.spec = store.redoStack.pop();
      store.dirty = JSON.stringify(store.spec) !== JSON.stringify(store.savedSpec);
      store.notify("redo");
      return true;
    },

    discardDraft() {
      store.spec = deepClone(store.savedSpec);
      store.undoStack = [];
      store.redoStack = [];
      store.dirty = false;
      store.notify("discard");
    },

    computeDiff() {
      const changes = [];
      const compareMap = (section, label, prevMap, nextMap) => {
        const prev = prevMap || {};
        const next = nextMap || {};
        const keys = new Set([...Object.keys(prev), ...Object.keys(next)]);
        for (const k of keys) {
          const hasP = Object.hasOwn(prev, k);
          const hasN = Object.hasOwn(next, k);
          if (!hasP && hasN) changes.push({ section, kind: "add", label, name: k });
          else if (hasP && !hasN) changes.push({ section, kind: "remove", label, name: k });
          else if (JSON.stringify(prev[k]) !== JSON.stringify(next[k])) {
            changes.push({ section, kind: "modify", label, name: k });
          }
        }
      };
      compareMap("hosts", "Host", store.savedSpec.nodes, store.spec.nodes);
      compareMap("services", "Service", store.savedSpec.services, store.spec.services);
      compareMap("domains", "Domain", store.savedSpec.domains, store.spec.domains);
      compareMap("dns_providers", "DNS Provider", store.savedSpec.dns_providers, store.spec.dns_providers);
      compareMap("guards", "Guard (Legacy)", store.savedSpec.guard_templates, store.spec.guard_templates);
      compareMap("buckets", "Bucket Set", store.savedSpec.bucket_templates, store.spec.bucket_templates);
      compareMap("antibot", "Antibot Set", store.savedSpec.antibot_templates, store.spec.antibot_templates);
      compareMap("waf", "WAF Set", store.savedSpec.waf_templates, store.spec.waf_templates);
      compareMap("maintainers", "Maintainer Template", store.savedSpec.maintainer_templates, store.spec.maintainer_templates);
      if (JSON.stringify(store.savedSpec.links) !== JSON.stringify(store.spec.links)) {
        changes.push({
          section: "topology",
          kind: "modify",
          label: "Mesh Links",
          name: `${(store.savedSpec.links || []).length} → ${(store.spec.links || []).length}`,
        });
      }
      if (JSON.stringify(store.savedSpec.defaults) !== JSON.stringify(store.spec.defaults)) {
        changes.push({ section: "system", kind: "modify", label: "Cluster Defaults", name: "defaults" });
      }
      if (JSON.stringify(store.savedSpec.global_logger) !== JSON.stringify(store.spec.global_logger)) {
        changes.push({ section: "system", kind: "modify", label: "Global Logger", name: "global_logger" });
      }
      return changes;
    },

    async validate(yamlOverride = null) {
      const payload = yamlOverride != null ? { yaml: yamlOverride, push: false } : { spec: store.spec, push: false };
      const res = await api("/api/topology/validate", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      store.errors = res.errors || [];
      store.warnings = res.warnings || [];
      store.compiledPaths = res.paths || [];
      if (res.yaml) store.yaml = res.yaml;
      if (yamlOverride != null && res.spec) {
        store.mutate(() => {
          store.spec = normalizeSpec(res.spec);
        });
      } else {
        store.notify("validate");
      }
      return res;
    },

    async preflight() {
      return await api("/api/topology/preflight", {
        method: "POST",
        body: JSON.stringify({ spec: store.spec, push: false }),
      });
    },

    async deploy({ push = true, syncDns = false } = {}) {
      const res = await api("/api/topology", {
        method: "PUT",
        body: JSON.stringify({ spec: store.spec, push, sync_dns: syncDns }),
      });
      store.setFromServer(
        {
          yaml: res.yaml,
          spec: res.spec,
          paths: res.paths || [],
          errors: res.push_errors || [],
          warnings: res.warnings || [],
        },
        true
      );
      return res;
    },

    liveNodeMap() {
      const m = new Map();
      for (const n of store.liveNodes || []) m.set(n.node_tag, n);
      return m;
    },
  };

  return store;
}
