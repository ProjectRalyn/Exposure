use regex::RegexBuilder;
use serde::{Deserialize, Serialize};

/// Hard NFA/DFA size cap per compiled regex to guarantee linear-time O(N) evaluation and zero ReDoS.
pub const CRS_REGEX_SIZE_LIMIT: usize = 256 * 1024;
/// Maximum rules accepted from a CRS sync to bound memory & config payload size.
pub const MAX_CRS_RULES: usize = 1024;
/// Maximum pattern length per rule.
pub const MAX_CRS_PATTERN_LEN: usize = 4096;

/// Official OWASP Core Rule Set (CRS) 4.x inbound attack detection files.
pub const CRS_RULE_FILES: &[&str] = &[
    "REQUEST-913-SCANNER-DETECTION.conf",
    "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
    "REQUEST-921-PROTOCOL-ATTACK.conf",
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
    "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
    "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
    "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
    "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WafRuleDescriptor {
    pub id: u32,
    /// Rule source identifier (e.g. `"owasp-crs"`).
    pub source: String,
    pub file: String,
    pub category: String,
    pub paranoia_level: u8,
    pub severity: String,
    pub msg: String,
    #[serde(default)]
    pub targets: Vec<String>,
    /// `"rx"` | `"pm"` | `"contains"` | `"beginsWith"` | `"endsWith"`
    pub operator: String,
    pub pattern: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_true_crs")]
    pub enabled: bool,
}

fn default_true_crs() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrsRulesetSnapshot {
    pub version: String,
    pub updated_at: String,
    pub source_url: String,
    #[serde(default)]
    pub total_parsed: usize,
    #[serde(default)]
    pub skipped_pcre: usize,
    #[serde(default)]
    pub rules: Vec<WafRuleDescriptor>,
}

/// Curated offline OWASP CRS 4.x baseline snapshot so CRS inspection works out-of-the-box
/// across SQLi, XSS, LFI/Path Traversal, CMDi/RCE, PHP, SSTI, SSRF, XXE, NoSQL, CRLF,
/// Deserialization/Log4Shell, and Scanner detection before live CRS sync completes.
pub fn builtin_crs_snapshot() -> CrsRulesetSnapshot {
    let rules = vec![
        WafRuleDescriptor {
            id: 913100,
            source: "owasp-crs".into(),
            file: "REQUEST-913-SCANNER-DETECTION.conf".into(),
            category: "scanner-detection".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "Found User-Agent associated with security scanner".into(),
            targets: vec!["REQUEST_HEADERS:User-Agent".into()],
            operator: "rx".into(),
            pattern: r"(?i)\b(?:sqlmap|nikto|acunetix|nessus|masscan|zgrab|dirbuster|gobuster|nuclei|wpscan|havij|openvas|arachni|w3af|hydra|medusa|metasploit)\b".into(),
            tags: vec!["OWASP_CRS".into(), "attack-reputation-scanner".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 920270,
            source: "owasp-crs".into(),
            file: "REQUEST-920-PROTOCOL-ENFORCEMENT.conf".into(),
            category: "protocol-enforcement".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "Invalid character in request (null byte / control char)".into(),
            targets: vec!["REQUEST_URI".into(), "ARGS".into()],
            operator: "rx".into(),
            pattern: r"(?i)(?:%00|\x00|%0[ad]%0[ad])".into(),
            tags: vec!["OWASP_CRS".into(), "attack-protocol".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 921110,
            source: "owasp-crs".into(),
            file: "REQUEST-921-PROTOCOL-ATTACK.conf".into(),
            category: "crlf-injection".into(),
            paranoia_level: 1,
            severity: "ERROR".into(),
            msg: "HTTP Request Smuggling / CRLF Header Injection".into(),
            targets: vec!["REQUEST_URI".into(), "ARGS".into(), "REQUEST_HEADERS".into()],
            operator: "rx".into(),
            pattern: r"(?i)(?:%0d%0a|%0a|\r\n|\n)\s*(?:set-cookie|location|content-length|transfer-encoding|http/1\.[01]|x-forwarded-host)\s*:".into(),
            tags: vec!["OWASP_CRS".into(), "attack-protocol".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 930100,
            source: "owasp-crs".into(),
            file: "REQUEST-930-APPLICATION-ATTACK-LFI.conf".into(),
            category: "path-traversal".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "Path Traversal Attack (/../) or (/..%2f)".into(),
            targets: vec!["REQUEST_URI".into(), "ARGS".into(), "REQUEST_HEADERS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            pattern: r"(?i)(?:^|[\\/]|%2f|%5c)\.\.(?:[\\/]|%2f|%5c|;|%3b)".into(),
            tags: vec!["OWASP_CRS".into(), "attack-lfi".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 930120,
            source: "owasp-crs".into(),
            file: "REQUEST-930-APPLICATION-ATTACK-LFI.conf".into(),
            category: "path-traversal".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "OS File Access Attempt (/etc/passwd, /etc/ssh/sshd_config, /proc/self, win.ini)".into(),
            targets: vec!["REQUEST_URI".into(), "ARGS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            pattern: r"(?i)(?:/etc/(?:passwd|shadow|group|hosts|hostname|issue|os-release|resolv\.conf|crontab|ssh/sshd_config|nginx/nginx\.conf)|/proc/(?:self/(?:environ|cmdline|maps)|version|cmdline|cpuinfo|meminfo)|(?:^|[\\/])(?:boot\.ini|win\.ini|web\.config|\.env|\.git/(?:config|HEAD)|\.htaccess|\.aws/credentials|\.kube/config|\.ssh/(?:id_rsa|id_ed25519|authorized_keys)))".into(),
            tags: vec!["OWASP_CRS".into(), "attack-lfi".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 932100,
            source: "owasp-crs".into(),
            file: "REQUEST-932-APPLICATION-ATTACK-RCE.conf".into(),
            category: "command-injection".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "Remote Command Execution: Unix Command Injection".into(),
            targets: vec!["ARGS".into(), "REQUEST_BODY".into(), "REQUEST_HEADERS:User-Agent".into()],
            operator: "rx".into(),
            pattern: r"(?i)(?:;|\|\|?|&&|\r|\n|\$\(\s*|\`\s*)(?:\$\{ifs\}|\$ifs\b|\s)*(?:/(?:usr/)?(?:local/)?(?:s?bin)/)?(?:sh|bash|dash|zsh|ash|ksh|csh|fish|busybox|cmd(?:\.exe)?|powershell|pwsh|cat|tac|nl|head|tail|ls|ll|dir|pwd|echo|printf|env|printenv|id|whoami|who|last|lastlog|groups|uname|hostname|hostnamectl|lsb_release|uptime|ps|htop|pgrep|netstat|ss|ip|ifconfig|route|iptables|ping|traceroute|nslookup|dig|curl|wget|fetch|tftp|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|python[23]?|perl|ruby|php|node|awk|sed|grep|egrep|fgrep|find|which|whereis|base64|xxd|tar|gzip|unzip|chmod|chown|rm\s+-rf|sudo|su|crontab|systemctl|service|docker|kubectl|nvidia-smi|sleep)\b".into(),
            tags: vec!["OWASP_CRS".into(), "attack-rce".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 933100,
            source: "owasp-crs".into(),
            file: "REQUEST-933-APPLICATION-ATTACK-PHP.conf".into(),
            category: "php-attack".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "PHP Injection Attack: PHP Open Tag or Wrapper Found".into(),
            targets: vec!["REQUEST_URI".into(), "ARGS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            pattern: r"(?i)(?:<\?(?:php|=)|\bphp://(?:filter|input|memory|temp)\b|\bphar://)".into(),
            tags: vec!["OWASP_CRS".into(), "attack-injection-php".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 934120,
            source: "owasp-crs".into(),
            file: "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf".into(),
            category: "ssrf".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "Server-Side Request Forgery (SSRF): Cloud Metadata or Dangerous Scheme".into(),
            targets: vec!["REQUEST_URI".into(), "ARGS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            // Includes decimal/hex/short-form loopback & link-local encodings used to bypass
            // naive string matching (e.g. `2852039166`, `0xa9fea9fe`, `0x7f000001`, `127.1`).
            pattern: r"(?i)(?:\b169\.254\.169\.254\b|\b2852039166\b|\b0xa9fea9fe\b|\bmetadata\.google\.internal\b|\b100\.100\.100\.200\b|\b(?:2130706433|0x7f[0-9a-f]{6})\b|\b127(?:\.\d{1,3}){1,3}\b|\b(?:gopher|dict|file)://)".into(),
            tags: vec!["OWASP_CRS".into(), "attack-ssrf".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 934130,
            source: "owasp-crs".into(),
            file: "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf".into(),
            category: "xxe".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "XML External Entity (XXE) / DOCTYPE Declaration".into(),
            targets: vec!["ARGS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            pattern: r"(?i)<!(?:entity\s+[^>]{1,120}\b(?:system|public)\b|doctype\s+[^>]{1,120}\[)".into(),
            tags: vec!["OWASP_CRS".into(), "attack-xxe".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 934140,
            source: "owasp-crs".into(),
            file: "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf".into(),
            category: "nosql-injection".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "NoSQL Query Operator Injection ($ne/$gt/$where/$regex)".into(),
            targets: vec!["ARGS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            // Generic operator match also catches unquoted/bracket-quoted forms (`$where`,
            // `["$regex"]`, `user[$ne]=`).
            pattern: r#"(?i)(?:["']\$(?:ne|gt|gte|lt|lte|nin|regex|where|exists|expr)["']\s*:|\[\$(?:ne|gt|gte|lt|lte|nin|regex|where|exists)\]|\$(?:ne|gt|gte|lt|lte|nin|regex|where|exists|expr)\b)"#.into(),
            tags: vec!["OWASP_CRS".into(), "attack-nosql".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 934150,
            source: "owasp-crs".into(),
            file: "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf".into(),
            category: "ssti".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "Server-Side Template Injection (Jinja/Twig/Mustache/EL arithmetic expression)".into(),
            targets: vec!["ARGS".into(), "REQUEST_URI".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            // Detects template-delimiter expressions containing arithmetic (e.g. `{{7*7}}`,
            // `${7*7}`, `#{7*7}`) which are used to fingerprint SSTI engines via computed output,
            // while leaving benign variable interpolation like `{{name}}` untouched.
            // Also flags Jinja globals (`{{config}}`/`{{self}}`), dunder access, and ERB
            // arithmetic (`<%= 7*7 %>`) used to fingerprint SSTI engines.
            pattern: r#"(?i)(?:\{\{[^{}\n]*\d\s*[+\-*/%]\s*\d[^{}\n]*\}\}|\$\{[^{}\n]*\d\s*[+\-*/%]\s*\d[^{}\n]*\}|#\{[^{}\n]*\d\s*[+\-*/%]\s*\d[^{}\n]*\}|\{\{\s*(?:config|self|request|session|lipsum|cycler|joiner|namespace|__class__|__globals__|__builtins__)\b|<%[=\-]?[^%]*[+\-*/%][^%]*%>)"#.into(),
            tags: vec!["OWASP_CRS".into(), "attack-ssti".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 941110,
            source: "owasp-crs".into(),
            file: "REQUEST-941-APPLICATION-ATTACK-XSS.conf".into(),
            category: "xss".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "XSS Filter - Category 1: Script Tag / Event Handler / Pseudo-Protocol".into(),
            targets: vec!["ARGS".into(), "REQUEST_URI".into(), "REQUEST_BODY".into(), "REQUEST_COOKIES".into()],
            operator: "rx".into(),
            // Generic event handler on ANY tag (`<details ontoggle=>`, `<input onfocus=>`,
            // `<marquee onstart=>`) plus whitespace/control-split `java\tscript:`.
            pattern: r"(?i)<\s*/?\s*script\b[^>]*>|java\s*script\s*:|<\s*[a-z][a-z0-9]*\b[^>]*\bon[a-z]+\s*=".into(),
            tags: vec!["OWASP_CRS".into(), "attack-xss".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 942100,
            source: "owasp-crs".into(),
            file: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf".into(),
            category: "sql-injection".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "SQL Injection Attack: Tautology, Boolean Comparison, or Comment Truncation".into(),
            targets: vec!["ARGS".into(), "REQUEST_URI".into(), "REQUEST_BODY".into(), "REQUEST_COOKIES".into()],
            operator: "rx".into(),
            // Covers classic tautologies incl. no-whitespace (`'or'a'='a`), parenthesised operands
            // (`') OR ('1'='1`), hex literals (`0x31 OR 0x31=0x31`), string comparison operators
            // (`' OR 'a'<'b`), `||` string concatenation tricks (`'||'1'='1`), block-comment
            // obfuscation between operators (`or/**/1=1`), value-then-comment truncation (`' or 1#`),
            // multi-column `ORDER BY`/`GROUP BY` (`order by 1,2,3--`) and `HAVING` tautologies.
            pattern: r#"(?i)(?:(?:^|[\s'"\x28\x29 0-9])(?:or|and)(?:\s|/\*[^*]*\*/|\+)*(?:\x28(?:\s|/\*[^*]*\*/|\+)*)?(?:(?:[0-9]+|0x[0-9a-f]+)\s*(?:<=>|<>|!=|<=|>=|={1,3}|<|>)\s*(?:[0-9]+|0x[0-9a-f]+)|'[^']*'\s*(?:<=>|<>|!=|<=|>=|={1,3}|<|>|\blike\b)\s*'[^']*(?:'|$|\s|\x29)|"[^"]*"\s*(?:<=>|<>|!=|<=|>=|={1,3}|<|>|\blike\b)\s*"[^"]*(?:"|$|\s|\x29)|(?:[0-9]+|'[^']*'|"[^"]*")\s*(?:--|#|/\*))|(?:['"\x29]|\d+)(?:\s|/\*[^*]*\*/|\+)+(?:or|and)(?:\s|/\*[^*]*\*/|\+)*(?:true|false)\b|(?:'[^']*'|')\s*\|{1,2}\s*'[^']*'\s*(?:<=>|<>|!=|<=|>=|={1,3}|<|>)\s*'[^']*|'\s*(?:--|#|/\*)|\b(?:order|group)\s+by\s+[0-9]+(?:\s*,\s*[0-9]+)*\s*(?:--|#|/\*|$)|\bhaving\s+[0-9]+\s*(?:<=>|<>|!=|<=|>=|={1,3}|<|>)|(?:^|[\s'"\x28\x29 0-9])(?:or|and)(?:\s|/\*[^*]*\*/|\+)*(?:not\s+)?\(?\s*(?:[0-9]+|0x[0-9a-f]+|'[^']*'|"[^"]*"|null|true|false)\s*\)?\s*(?:<=>|<>|!=|<=|>=|={1,3}|<|>|\b(?:like|regexp|rlike|between|in|is)\b)|(?:[0-9]+|'[^']*'|"[^"]*")\s*(?:\|\||&&)\s*(?:[0-9]+|'[^']*'|"[^"]*")\s*(?:<=>|<>|!=|<=|>=|={1,3}|<|>)|'\s*\|{1,2}\s*')"#.into(),
            tags: vec!["OWASP_CRS".into(), "attack-sqli".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 942140,
            source: "owasp-crs".into(),
            file: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf".into(),
            category: "sql-injection".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "SQL Injection Attack: Common DB Names / UNION SELECT / Blind SQLi".into(),
            targets: vec!["ARGS".into(), "REQUEST_URI".into(), "REQUEST_BODY".into(), "REQUEST_COOKIES".into()],
            operator: "rx".into(),
            // Also detects parenthesised / `EXISTS` subquery injection (`1 AND (SELECT ...)`,
            // `AND EXISTS(SELECT ...)`) and comment-obfuscated keywords (`UNION/**/SELECT`).
            // Tolerates MySQL versioned comments (`/*!50000union*/`), `#`/newline and mixed
            // comment separators between UNION [ALL] SELECT.
            pattern: r"(?i)(?:(?:^|[^a-z])union(?:/\*![0-9]*|\s|/\*[^*]*\*/|[*#/+])+(?:all(?:/\*![0-9]*|\s|/\*[^*]*\*/|[*#/+])+|distinct(?:/\*![0-9]*|\s|/\*[^*]*\*/|[*#/+])+)?select\b|\b(?:and|or)\s*\(\s*select\b|\bexists\s*\(\s*select\b|\b(?:information_schema|sqlite_master|pg_catalog|mysql\.user)\b|\b(?:sleep|pg_sleep|benchmark|extractvalue|updatexml|load_file)\s*\(|\bwaitfor\s+delay\b)".into(),
            tags: vec!["OWASP_CRS".into(), "attack-sqli".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 942150,
            source: "owasp-crs".into(),
            file: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf".into(),
            category: "sql-injection".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "SQL Injection Attack: Stacked DDL/DML Query Statement".into(),
            targets: vec!["ARGS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            pattern: r"(?i);\s*(?:drop|truncate|alter|create|exec|execute)\s+(?:table|database|user|procedure)\b|\bxp_cmdshell\b".into(),
            tags: vec!["OWASP_CRS".into(), "attack-sqli".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 944100,
            source: "owasp-crs".into(),
            file: "REQUEST-944-APPLICATION-ATTACK-JAVA.conf".into(),
            category: "deserialization".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "Remote Command Execution: Java/Log4Shell JNDI & ProcessBuilder".into(),
            targets: vec!["REQUEST_URI".into(), "ARGS".into(), "REQUEST_HEADERS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            pattern: r"(?i)(?:\$\{(?:jndi|lower|upper|::-)[^}]{0,120}(?:ldap|ldaps|rmi|dns|iiop|http):|java\.lang\.(?:runtime|processbuilder)\b)".into(),
            tags: vec!["OWASP_CRS".into(), "attack-rce".into(), "paranoia-level/1".into()],
            enabled: true,
        },
        WafRuleDescriptor {
            id: 934100,
            source: "owasp-crs".into(),
            file: "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf".into(),
            category: "deserialization".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "Node.js / JavaScript Prototype Pollution & SSTI Attempt".into(),
            targets: vec!["ARGS".into(), "REQUEST_BODY".into(), "REQUEST_URI".into()],
            operator: "rx".into(),
            pattern: r"(?i)(?:__proto__|constructor\s*(?:\.|\[['\x22]?)prototype|__class__|__subclasses__|__globals__|__builtins__)".into(),
            tags: vec!["OWASP_CRS".into(), "attack-injection-generic".into(), "paranoia-level/1".into()],
            enabled: true,
        },
    ];
    let total_parsed = rules.len();
    CrsRulesetSnapshot {
        version: "builtin-4.x".into(),
        updated_at: String::new(),
        source_url: "https://coreruleset.org/".into(),
        total_parsed,
        skipped_pcre: 0,
        rules,
    }
}

/// Merge a synced OWASP CRS snapshot with the curated built-in baseline.
///
/// The built-in baseline is placed first so it can never be truncated by the `MAX_CRS_RULES`
/// compile cap, and every synced rule whose ID is not already provided by the baseline is appended.
/// This is critical because the ModSecurity parser intentionally skips constructs the linear-time
/// engine cannot evaluate safely (`@detectSQLi`, chained rules, PCRE lookarounds, anomaly-scoring
/// `pass` rules). Without this union a partial sync could silently drop SQLi/XSS/RCE coverage and
/// leave the node effectively unprotected.
pub fn merge_crs_snapshots(mut synced: CrsRulesetSnapshot, builtin: CrsRulesetSnapshot) -> CrsRulesetSnapshot {
    let mut merged: Vec<WafRuleDescriptor> = builtin.rules;
    let mut seen: std::collections::HashSet<u32> = merged.iter().map(|r| r.id).collect();
    for rule in synced.rules {
        if merged.len() >= MAX_CRS_RULES {
            break;
        }
        if seen.insert(rule.id) {
            merged.push(rule);
        }
    }
    synced.rules = merged;
    synced.total_parsed = synced.total_parsed.max(synced.rules.len());
    synced
}

/// Validate that a regex pattern compiles cleanly in linear-time Rust `regex` within strict size bounds.
pub fn validate_crs_regex(pattern: &str) -> bool {
    if pattern.is_empty() || pattern.len() > MAX_CRS_PATTERN_LEN {
        return false;
    }
    RegexBuilder::new(pattern)
        .size_limit(CRS_REGEX_SIZE_LIMIT)
        .dfa_size_limit(CRS_REGEX_SIZE_LIMIT)
        .build()
        .is_ok()
}

/// Infer Exposure WAF category label from OWASP CRS file name and rule tags.
fn infer_crs_category(file_name: &str, tags: &[String]) -> String {
    for tag in tags {
        let tl = tag.to_ascii_lowercase();
        if tl.contains("attack-sqli") {
            return "sql-injection".into();
        }
        if tl.contains("attack-xss") {
            return "xss".into();
        }
        if tl.contains("attack-lfi") || tl.contains("attack-rfi") {
            return "path-traversal".into();
        }
        if tl.contains("attack-rce") {
            return "command-injection".into();
        }
        if tl.contains("attack-injection-php") {
            return "php-attack".into();
        }
        if tl.contains("attack-reputation-scanner") {
            return "scanner-detection".into();
        }
        if tl.contains("attack-ssrf") {
            return "ssrf".into();
        }
        if tl.contains("attack-xxe") {
            return "xxe".into();
        }
        if tl.contains("attack-nosql") {
            return "nosql-injection".into();
        }
        if tl.contains("attack-ssti") {
            return "ssti".into();
        }
        if tl.contains("attack-protocol") {
            return "protocol-attack".into();
        }
    }
    let fl = file_name.to_ascii_uppercase();
    if fl.contains("SQLI") {
        "sql-injection".into()
    } else if fl.contains("XSS") {
        "xss".into()
    } else if fl.contains("LFI") || fl.contains("RFI") {
        "path-traversal".into()
    } else if fl.contains("RCE") {
        "command-injection".into()
    } else if fl.contains("JAVA") {
        "deserialization".into()
    } else if fl.contains("PHP") {
        "php-attack".into()
    } else if fl.contains("SCANNER") {
        "scanner-detection".into()
    } else if fl.contains("PROTOCOL") {
        "protocol-attack".into()
    } else if fl.contains("SESSION") {
        "session-fixation".into()
    } else {
        "generic-attack".into()
    }
}

/// Parse an OWASP CRS `.conf` file into Exposure `WafRuleDescriptor` items.
/// Only compiles inbound request rules (phase 1/2) with ReDoS-safe linear-time operators
/// (`@rx`, `@pm`, `@contains`, `@beginsWith`, `@endsWith`); skips chained sub-rules, TX-only control
/// rules, and PCRE-only lookaround/backreference regexes cleanly (returning skipped count).
pub fn parse_crs_conf(file_name: &str, conf_text: &str) -> (Vec<WafRuleDescriptor>, usize) {
    // Bound memory for hostile/oversized upstream CRS bundles (auto-synced).
    const MAX_CRS_CONF_BYTES: usize = 8 * 1024 * 1024;
    if conf_text.len() > MAX_CRS_CONF_BYTES {
        return (Vec::new(), 0);
    }
    // 1. Join backslash-continued logical lines
    let mut logical_lines = Vec::new();
    let mut current = String::new();
    for raw_line in conf_text.lines() {
        let trimmed = raw_line.trim();
        if current.is_empty() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        if let Some(stripped) = trimmed.strip_suffix('\\') {
            current.push_str(stripped.trim_end());
            current.push(' ');
        } else {
            current.push_str(trimmed);
            logical_lines.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        logical_lines.push(current);
    }

    let mut out = Vec::new();
    let mut skipped_pcre = 0usize;
    let mut in_chain = false;

    for line in logical_lines {
        if out.len() >= MAX_CRS_RULES {
            // Enforce the documented rule cap to bound memory/CPU from hostile upstream bundles.
            break;
        }
        if !line.starts_with("SecRule ") {
            in_chain = false;
            continue;
        }
        // Skip chained follower rules (multi-condition chains require full ModSecurity TX engine)
        if in_chain {
            in_chain = line.contains(",chain") || line.contains("\"chain,");
            continue;
        }

        let Some((targets_str, op_quoted, actions_quoted)) = split_secrule(&line) else {
            continue;
        };

        let is_chain_head = has_action_flag(actions_quoted, "chain");
        if is_chain_head {
            in_chain = true;
            // Skip chained head rules as well so we don't fire partial conditions and cause false positives!
            continue;
        }

        // Skip internal TX/ctl/skipAfter control rules
        let targets = parse_targets(targets_str);
        if targets.is_empty() {
            continue;
        }

        let Some(id) = extract_action_u32(actions_quoted, "id:") else {
            continue;
        };
        let phase = extract_action_u32(actions_quoted, "phase:").unwrap_or(2);
        if phase > 2 {
            continue;
        }
        // Only load blocking/anomaly-scoring rules (skip `pass,nolog` bookkeeping rules)
        if !has_action_flag(actions_quoted, "block") && !has_action_flag(actions_quoted, "deny") {
            continue;
        }

        // Extract operator & pattern (skip negated operators `!@rx` to avoid false positives)
        let op_trimmed = op_quoted.trim();
        if op_trimmed.starts_with('!') {
            continue;
        }
        let (operator, pattern) = if let Some(rest) = op_trimmed.strip_prefix("@rx ") {
            ("rx", rest.trim())
        } else if let Some(rest) = op_trimmed.strip_prefix("@pm ") {
            ("pm", rest.trim())
        } else if let Some(rest) = op_trimmed.strip_prefix("@contains ") {
            ("contains", rest.trim())
        } else if let Some(rest) = op_trimmed.strip_prefix("@beginsWith ") {
            ("beginsWith", rest.trim())
        } else if let Some(rest) = op_trimmed.strip_prefix("@endsWith ") {
            ("endsWith", rest.trim())
        } else if !op_trimmed.starts_with('@') && !op_trimmed.is_empty() {
            // Bare regex without `@rx` prefix (valid ModSecurity shorthand)
            ("rx", op_trimmed)
        } else {
            // Unsupported ModSecurity built-in operator (@detectSQLi, @pmFromFile, @validateByteRange, etc.)
            continue;
        };

        if pattern.is_empty() || pattern.len() > MAX_CRS_PATTERN_LEN {
            skipped_pcre += 1;
            continue;
        }

        if operator == "rx" && !validate_crs_regex(pattern) {
            skipped_pcre += 1;
            continue;
        }

        let tags = extract_all_quoted_actions(actions_quoted, "tag:");
        let paranoia_level = tags
            .iter()
            .find_map(|t| t.strip_prefix("paranoia-level/").and_then(|n| n.parse::<u8>().ok()))
            .unwrap_or(1)
            .clamp(1, 4);
        let msg = extract_quoted_action(actions_quoted, "msg:")
            .unwrap_or_else(|| format!("OWASP CRS Rule {id}"));
        let severity = extract_quoted_action(actions_quoted, "severity:")
            .unwrap_or_else(|| "CRITICAL".into())
            .to_ascii_uppercase();
        let category = infer_crs_category(file_name, &tags);

        out.push(WafRuleDescriptor {
            id,
            source: "owasp-crs".into(),
            file: file_name.to_string(),
            category,
            paranoia_level,
            severity,
            msg,
            targets,
            operator: operator.to_string(),
            pattern: pattern.to_string(),
            tags,
            enabled: true,
        });
    }

    (out, skipped_pcre)
}

fn split_secrule(line: &str) -> Option<(&str, &str, &str)> {
    let rest = line.strip_prefix("SecRule ")?.trim_start();
    let first_space = rest.find(char::is_whitespace)?;
    let targets = &rest[..first_space];
    let after_targets = rest[first_space..].trim_start();
    let (op, after_op) = read_quoted_token(after_targets)?;
    let after_op = after_op.trim_start();
    let (actions, _) = read_quoted_token(after_op)?;
    Some((targets, op, actions))
}

fn read_quoted_token(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some((&s[1..i], &s[i + 1..]));
        }
        i += 1;
    }
    None
}

fn parse_targets(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in raw.split('|') {
        let p = part.trim();
        if p.is_empty() || p.starts_with('!') || p.starts_with('&') {
            continue;
        }
        let upper = p.to_ascii_uppercase();
        if upper.starts_with("TX:")
            || upper.starts_with("ENV:")
            || upper.starts_with("IP:")
            || upper.starts_with("GLOBAL:")
            || upper == "RESPONSE_BODY"
            || upper.starts_with("RESPONSE_")
        {
            continue;
        }
        if matches!(
            upper.as_str(),
            "ARGS"
                | "ARGS_NAMES"
                | "ARGS_GET"
                | "ARGS_POST"
                | "REQUEST_URI"
                | "REQUEST_URI_RAW"
                | "REQUEST_FILENAME"
                | "REQUEST_BASENAME"
                | "QUERY_STRING"
                | "REQUEST_BODY"
                | "REQUEST_HEADERS"
                | "REQUEST_COOKIES"
                | "REQUEST_COOKIES_NAMES"
                | "REQUEST_LINE"
        ) || upper.starts_with("REQUEST_HEADERS:")
        {
            if !out.iter().any(|x: &String| x.eq_ignore_ascii_case(p)) {
                out.push(p.to_string());
            }
        }
    }
    out
}

fn has_action_flag(actions: &str, flag: &str) -> bool {
    actions
        .split(',')
        .map(str::trim)
        .any(|tok| tok.eq_ignore_ascii_case(flag))
}

fn extract_action_u32(actions: &str, prefix: &str) -> Option<u32> {
    for tok in actions.split(',') {
        let t = tok.trim();
        if let Some(rest) = t.strip_prefix(prefix) {
            let clean = rest.trim().trim_matches('\'').trim_matches('"');
            if let Ok(v) = clean.parse::<u32>() {
                return Some(v);
            }
        }
    }
    None
}

fn extract_quoted_action(actions: &str, prefix: &str) -> Option<String> {
    let idx = actions.find(prefix)?;
    let rest = &actions[idx + prefix.len()..];
    if let Some(inner) = rest.strip_prefix('\'') {
        let end = inner.find('\'')?;
        return Some(inner[..end].to_string());
    }
    let end = rest.find(',').unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

fn extract_all_quoted_actions(actions: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut slice = actions;
    while let Some(idx) = slice.find(prefix) {
        let rest = &slice[idx + prefix.len()..];
        if let Some(inner) = rest.strip_prefix('\'') {
            if let Some(end) = inner.find('\'') {
                out.push(inner[..end].to_string());
                slice = &inner[end + 1..];
                continue;
            }
        }
        break;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_owasp_crs_secrule_syntax_and_skips_pcre_lookarounds() {
        let sample = r#"
# Comment line
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:942011,phase:1,pass,nolog,skipAfter:END"

SecRule ARGS|REQUEST_URI "@rx (?i)(?:union\s+select|drop\s+table)" \
    "id:942999,\
    phase:2,\
    block,\
    msg:'Custom SQLi Test Rule',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    severity:'CRITICAL'"

SecRule ARGS "@rx (?<=foo)bar" \
    "id:942998,\
    phase:2,\
    block,\
    msg:'PCRE lookbehind unsupported by linear regex',\
    tag:'attack-sqli'"
"#;
        let (rules, skipped) = parse_crs_conf("REQUEST-942-APPLICATION-ATTACK-SQLI.conf", sample);
        assert_eq!(rules.len(), 1);
        assert_eq!(skipped, 1);
        assert_eq!(rules[0].id, 942999);
        assert_eq!(rules[0].category, "sql-injection");
        assert_eq!(rules[0].paranoia_level, 2);
        assert_eq!(rules[0].msg, "Custom SQLi Test Rule");
        assert_eq!(rules[0].targets, vec!["ARGS", "REQUEST_URI"]);
    }

    #[test]
    fn builtin_crs_rules_are_valid() {
        let crs = builtin_crs_snapshot();
        assert!(crs.rules.len() >= 14);
        for r in &crs.rules {
            assert_eq!(r.source, "owasp-crs");
            assert!(validate_crs_regex(&r.pattern), "invalid builtin CRS regex id={}", r.id);
        }
    }

    #[test]
    fn merge_snapshots_retains_builtin_coverage_without_duplicates() {
        let builtin = builtin_crs_snapshot();
        let mut synced = CrsRulesetSnapshot {
            version: "v4-test".into(),
            total_parsed: 1,
            ..Default::default()
        };
        synced.rules.push(WafRuleDescriptor {
            id: 949999,
            source: "owasp-crs".into(),
            file: "REQUEST-949-TEST.conf".into(),
            category: "sql-injection".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "synced test rule".into(),
            targets: vec!["ARGS".into()],
            operator: "contains".into(),
            pattern: "synced-needle".into(),
            tags: vec![],
            enabled: true,
        });

        let merged = merge_crs_snapshots(synced, builtin.clone());

        // Synced rule retained and every built-in rule still present (no silent SQLi loss).
        assert!(merged.rules.iter().any(|r| r.id == 949999));
        for b in &builtin.rules {
            assert!(
                merged.rules.iter().any(|r| r.id == b.id),
                "built-in rule {} dropped by merge",
                b.id
            );
        }

        // No duplicate rule IDs.
        let mut ids: Vec<u32> = merged.rules.iter().map(|r| r.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total);
    }
}
