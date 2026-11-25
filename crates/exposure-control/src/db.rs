use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use chrono::{Duration as ChronoDuration, Utc};
use exposure_core::config::{ControlRetentionConfig, NodeRoles, compute_release_revision};
use exposure_core::crypto::{
    NodeKeyPair, generate_random_secret_hex, parse_verifying_key_b64, pubkey_fingerprint_b64,
    restrict_dir_permissions_0700, restrict_file_permissions_0600, verify_passphrase_proof,
};
use exposure_core::{ExposureError, Result};
use rusqlite::{Connection, OptionalExtension, params, types::Value};
use serde::{Deserialize, Serialize};
use tracing::warn;

const MAX_PASSPHRASE_FAILURES: i64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_tag: String,
    pub public_key: String,
    pub pubkey_fingerprint: String,
    pub roles: Vec<String>,
    pub config_seq: u64,
    #[serde(default)]
    pub config_revision: String,
    pub last_reload_status: Option<String>,
    pub online: bool,
    /// NEVER serialize private keys to Web API responses!
    #[serde(skip_serializing)]
    pub maintainer_signing_secret: Option<String>,
    pub maintainer_signing_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseRecord {
    pub node_tag: String,
    /// NEVER serialize raw plaintext passphrases back to Web API responses!
    #[serde(skip_serializing)]
    pub passphrase: String,
    pub mode: String,
    pub address: Option<String>,
    pub via_hops: Vec<String>,
    pub expires_at: String,
    pub expires_ts: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVersionRecord {
    pub id: i64,
    pub sequence: u64,
    pub node_tag: String,
    pub config_json: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigReleaseNodeRecord {
    pub release_seq: u64,
    pub node_tag: String,
    pub status: String,
    pub error: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigReleaseRecord {
    pub release_seq: u64,
    pub revision: String,
    pub revision_full: String,
    pub parent_revision: Option<String>,
    pub trigger_kind: String,
    pub message: String,
    #[serde(skip_serializing)]
    pub topology_yaml: String,
    pub crs_version: String,
    pub pushed_by: String,
    pub created_at: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub nodes: Vec<ConfigReleaseNodeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlStorageStats {
    pub db_bytes: u64,
    pub wal_bytes: u64,
    pub nodes_rows: u64,
    pub config_releases_rows: u64,
    pub config_versions_rows: u64,
    pub audit_logs_rows: u64,
    pub last_cleanup_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlCleanupReport {
    pub deleted_audit_logs: usize,
    pub deleted_releases: usize,
    pub deleted_legacy_versions: usize,
    pub deleted_passphrases: usize,
    pub storage_stats: ControlStorageStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub id: i64,
    pub created_at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub success: bool,
    pub detail: String,
}

/// Local SQLite persistence store for Control (offloads synchronous SQLite I/O via `spawn_blocking`).
pub struct ControlDb {
    db_path: String,
    conn: Arc<StdMutex<Connection>>,
}

impl ControlDb {
    pub fn open(path: &str) -> Result<Arc<Self>> {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                    let _ = restrict_dir_permissions_0700(parent);
                }
            }
        }
        let conn = Connection::open(path)
            .map_err(|e| ExposureError::Storage(format!("open sqlite {path}: {e}")))?;

        if path != ":memory:" {
            let _ = restrict_file_permissions_0600(Path::new(path));
        }

        conn.execute_batch(
            "
            PRAGMA auto_vacuum = INCREMENTAL;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS kv_store (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nodes (
                node_tag TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                pubkey_fingerprint TEXT NOT NULL,
                roles_json TEXT NOT NULL,
                config_seq INTEGER NOT NULL DEFAULT 0,
                config_revision TEXT NOT NULL DEFAULT '',
                last_reload_status TEXT,
                online INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT,
                maintainer_signing_secret TEXT,
                maintainer_signing_pubkey TEXT
            );
            CREATE TABLE IF NOT EXISTS passphrases (
                node_tag TEXT PRIMARY KEY,
                passphrase TEXT NOT NULL,
                mode TEXT NOT NULL,
                address TEXT,
                via_hops_json TEXT NOT NULL,
                expires_ts INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS config_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sequence INTEGER NOT NULL,
                node_tag TEXT NOT NULL,
                config_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_config_versions_seq ON config_versions(sequence);
            CREATE TABLE IF NOT EXISTS config_releases (
                release_seq INTEGER PRIMARY KEY,
                revision TEXT NOT NULL UNIQUE,
                revision_full TEXT NOT NULL,
                parent_revision TEXT,
                trigger_kind TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                topology_yaml TEXT NOT NULL,
                crs_version TEXT NOT NULL DEFAULT '',
                pushed_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_config_releases_ts ON config_releases(created_at_ms DESC, release_seq DESC);
            CREATE TABLE IF NOT EXISTS config_release_nodes (
                release_seq INTEGER NOT NULL,
                node_tag TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (release_seq, node_tag)
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                success INTEGER NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC, id DESC);
            ",
        )
        .map_err(|e| ExposureError::Storage(format!("init sqlite schema: {e}")))?;

        // Idempotent column migrations on pre-existing Control SQLite databases
        let _ = conn.execute(
            "ALTER TABLE passphrases ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE nodes ADD COLUMN config_revision TEXT NOT NULL DEFAULT ''",
            [],
        );

        if path != ":memory:" {
            let _ = restrict_file_permissions_0600(Path::new(path));
            let _ = restrict_file_permissions_0600(Path::new(&format!("{path}-wal")));
            let _ = restrict_file_permissions_0600(Path::new(&format!("{path}-shm")));
        }

        Ok(Arc::new(Self {
            db_path: path.to_string(),
            conn: Arc::new(StdMutex::new(conn)),
        }))
    }

    async fn run<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut guard)
        })
        .await
        .map_err(|e| ExposureError::Storage(format!("sqlite worker join: {e}")))?
    }

    pub async fn get_topology_yaml(&self) -> Result<String> {
        self.run(|conn| {
            let v: Option<String> = conn
                .query_row(
                    "SELECT v FROM kv_store WHERE k = 'topology_yaml'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(v.unwrap_or_default())
        })
        .await
    }

    pub async fn set_topology_yaml(&self, yaml: &str) -> Result<()> {
        let yaml = yaml.to_string();
        self.run(move |conn| {
            conn.execute(
                "INSERT INTO kv_store (k, v) VALUES ('topology_yaml', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![yaml],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn get_kv_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        key: &str,
    ) -> Result<Option<T>> {
        let key = key.to_string();
        let raw: Option<String> = self
            .run(move |conn| {
                let v: Option<String> = conn
                    .query_row("SELECT v FROM kv_store WHERE k = ?1", params![key], |row| {
                        row.get(0)
                    })
                    .optional()
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                Ok(v)
            })
            .await?;
        let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
            return Ok(None);
        };
        let parsed = serde_json::from_str::<T>(&raw)
            .map_err(|e| ExposureError::Storage(format!("decode kv_store json: {e}")))?;
        Ok(Some(parsed))
    }

    pub async fn set_kv_json<T: Serialize>(&self, key: &str, val: &T) -> Result<()> {
        let key = key.to_string();
        let raw = serde_json::to_string(val)
            .map_err(|e| ExposureError::Storage(format!("encode kv_store json: {e}")))?;
        self.run(move |conn| {
            conn.execute(
                "INSERT INTO kv_store (k, v) VALUES (?1, ?2)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![key, raw],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    /// Read cluster-wide logger IP HMAC key if already provisioned (read-only).
    pub async fn get_cluster_hmac_key(&self) -> Result<Option<String>> {
        self.run(|conn| {
            let v: Option<String> = conn
                .query_row(
                    "SELECT v FROM kv_store WHERE k = 'cluster_logger_hmac_key'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(v.filter(|s| !s.trim().is_empty()))
        })
        .await
    }

    /// Atomically read or generate a persistent cluster-wide 32-byte logger IP HMAC key
    /// so every node hashes client IPs consistently for accurate UV union & IP search.
    pub async fn get_or_create_cluster_hmac_key(&self) -> Result<String> {
        self.run(|conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT v FROM kv_store WHERE k = 'cluster_logger_hmac_key'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            if let Some(k) = existing.filter(|s| s.trim().len() >= 32) {
                return Ok(k);
            }
            let key = generate_random_secret_hex(32);
            tx.execute(
                "INSERT INTO kv_store (k, v) VALUES ('cluster_logger_hmac_key', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![&key],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            tx.commit()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(key)
        })
        .await
    }

    pub async fn latest_config_sequence(&self) -> Result<u64> {
        self.run(|conn| {
            let max_ver: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(sequence), 0) FROM config_versions",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let max_rel: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(release_seq), 0) FROM config_releases",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let kv_seq: i64 = conn
                .query_row(
                    "SELECT CAST(v AS INTEGER) FROM kv_store WHERE k = 'last_config_sequence'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?
                .unwrap_or(0);
            let node_max: i64 = conn
                .query_row("SELECT COALESCE(MAX(config_seq), 0) FROM nodes", [], |r| {
                    r.get(0)
                })
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(u64::try_from(max_ver.max(max_rel).max(kv_seq).max(node_max)).unwrap_or(0))
        })
        .await
    }

    /// Atomically allocate the next monotonic config sequence and insert a `"pending"` version record
    /// inside a single `IMMEDIATE` SQLite transaction (eliminating sequence TOCTOU races).
    pub async fn allocate_and_record_config_version(
        &self,
        node_tag: &str,
        config_json: &str,
    ) -> Result<(u64, i64)> {
        let node_tag = node_tag.to_string();
        let config_json = config_json.to_string();
        self.run(move |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let max_ver: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(sequence), 0) FROM config_versions",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let kv_seq: i64 = tx
                .query_row(
                    "SELECT CAST(v AS INTEGER) FROM kv_store WHERE k = 'last_config_sequence'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?
                .unwrap_or(0);
            let node_max: i64 = tx
                .query_row("SELECT COALESCE(MAX(config_seq), 0) FROM nodes", [], |r| {
                    r.get(0)
                })
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let next_seq = max_ver.max(kv_seq).max(node_max).saturating_add(1);
            tx.execute(
                "INSERT INTO kv_store (k, v) VALUES ('last_config_sequence', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![next_seq.to_string()],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            tx.execute(
                "INSERT INTO config_versions (sequence, node_tag, config_json, status, created_at)
                 VALUES (?1, ?2, ?3, 'pending', ?4)",
                params![next_seq, node_tag, config_json, Utc::now().to_rfc3339()],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let row_id = tx.last_insert_rowid();
            tx.commit()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok((u64::try_from(next_seq).unwrap_or(1), row_id))
        })
        .await
    }

    /// Upsert a node WITHOUT ever overwriting an already-pinned non-empty `public_key`!
    /// Returns `Err(ExposureError::Auth)` if an existing pinned key differs from `public_key`.
    /// Also preserves existing `roles_json` when `roles` is empty (so reconnects don't wipe roles).
    pub async fn upsert_node_if_unpinned(
        &self,
        node_tag: &str,
        public_key: &str,
        roles: &NodeRoles,
        online: bool,
    ) -> Result<()> {
        let trimmed_pk = public_key.trim().to_string();
        let fp = if trimmed_pk.is_empty() {
            String::new()
        } else {
            parse_verifying_key_b64(&trimmed_pk)?;
            pubkey_fingerprint_b64(&trimmed_pk)?
        };
        let role_names = roles.names();
        let roles_json = serde_json::to_string(&role_names).unwrap_or_else(|_| "[]".into());
        let has_roles = !role_names.is_empty();
        let node_tag = node_tag.to_string();
        let now = Utc::now().to_rfc3339();

        self.run(move |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let existing_pk: Option<String> = tx
                .query_row(
                    "SELECT public_key FROM nodes WHERE node_tag = ?1",
                    params![&node_tag],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            if let Some(ref cur_pk) = existing_pk {
                if !cur_pk.trim().is_empty()
                    && !trimmed_pk.is_empty()
                    && cur_pk.trim() != trimmed_pk
                {
                    return Err(ExposureError::Auth(format!(
                        "public key conflict for pinned node '{}': refusing automatic overwrite",
                        node_tag
                    )));
                }
            }

            tx.execute(
                "INSERT INTO nodes (node_tag, public_key, pubkey_fingerprint, roles_json, online, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(node_tag) DO UPDATE SET
                   public_key = CASE WHEN nodes.public_key = '' AND excluded.public_key != '' THEN excluded.public_key ELSE nodes.public_key END,
                   pubkey_fingerprint = CASE WHEN nodes.public_key = '' AND excluded.public_key != '' THEN excluded.pubkey_fingerprint ELSE nodes.pubkey_fingerprint END,
                   roles_json = CASE WHEN ?7 THEN excluded.roles_json ELSE nodes.roles_json END,
                   online = excluded.online,
                   last_seen = excluded.last_seen",
                params![
                    node_tag,
                    trimmed_pk,
                    fp,
                    roles_json,
                    if online { 1 } else { 0 },
                    now,
                    has_roles
                ],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            tx.commit()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn set_node_online(&self, node_tag: &str, online: bool) -> Result<()> {
        let node_tag = node_tag.to_string();
        self.run(move |conn| {
            conn.execute(
                "UPDATE nodes SET online = ?2 WHERE node_tag = ?1",
                params![node_tag, if online { 1 } else { 0 }],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn set_node_reload_result(
        &self,
        node_tag: &str,
        seq: u64,
        revision: Option<&str>,
        ok: bool,
        err: Option<&str>,
    ) -> Result<()> {
        let status = if ok {
            "applied".to_string()
        } else {
            format!("failed: {}", err.unwrap_or("unknown"))
        };
        let node_tag = node_tag.to_string();
        let seq_i64 = i64::try_from(seq).unwrap_or(i64::MAX);
        let rev_str = revision.unwrap_or("").trim().to_string();
        let has_rev = ok && !rev_str.is_empty();
        self.run(move |conn| {
            conn.execute(
                "UPDATE nodes SET config_seq = CASE WHEN ?2 THEN ?3 ELSE config_seq END,
                                  config_revision = CASE WHEN ?6 THEN ?7 ELSE config_revision END,
                                  last_reload_status = ?4, online = 1, last_seen = ?5
                 WHERE node_tag = ?1",
                params![
                    node_tag,
                    ok,
                    seq_i64,
                    status,
                    Utc::now().to_rfc3339(),
                    has_rev,
                    rev_str,
                ],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn sync_node_reported_version(
        &self,
        node_tag: &str,
        seq: u64,
        revision: &str,
    ) -> Result<()> {
        let node_tag = node_tag.to_string();
        let seq_i64 = i64::try_from(seq).unwrap_or(i64::MAX);
        let rev = revision.trim().to_string();
        self.run(move |conn| {
            conn.execute(
                "UPDATE nodes SET config_seq = CASE WHEN ?2 > config_seq THEN ?2 ELSE config_seq END,
                                  config_revision = CASE WHEN ?3 != '' THEN ?3 ELSE config_revision END,
                                  last_seen = ?4
                 WHERE node_tag = ?1",
                params![node_tag, seq_i64, rev, Utc::now().to_rfc3339()],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    /// Read existing maintainer keypair without mutating SQLite (used by read-only validation/preview).
    pub async fn get_maintainer_keypair(&self, node_tag: &str) -> Result<Option<(String, String)>> {
        let node_tag = node_tag.to_string();
        self.run(move |conn| {
            let existing: Option<(Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT maintainer_signing_secret, maintainer_signing_pubkey FROM nodes WHERE node_tag = ?1",
                    params![node_tag],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            match existing {
                Some((Some(sec), Some(pubk))) if !sec.is_empty() && !pubk.is_empty() => {
                    Ok(Some((sec, pubk)))
                }
                _ => Ok(None),
            }
        })
        .await
    }

    pub async fn get_or_create_maintainer_keypair(
        &self,
        node_tag: &str,
    ) -> Result<(String, String)> {
        let node_tag = node_tag.to_string();
        self.run(move |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let existing: Option<(Option<String>, Option<String>)> = tx
                .query_row(
                    "SELECT maintainer_signing_secret, maintainer_signing_pubkey FROM nodes WHERE node_tag = ?1",
                    params![&node_tag],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            if let Some((Some(sec), Some(pubk))) = existing {
                if !sec.is_empty() && !pubk.is_empty() {
                    return Ok((sec, pubk));
                }
            }

            let kp = NodeKeyPair::generate();
            let sec = kp.secret_key_b64();
            let pubk = kp.public_key_b64();
            tx.execute(
                "INSERT INTO nodes (node_tag, public_key, pubkey_fingerprint, roles_json, maintainer_signing_secret, maintainer_signing_pubkey)
                 VALUES (?1, '', '', '[\"maintainer\"]', ?2, ?3)
                 ON CONFLICT(node_tag) DO UPDATE SET
                   maintainer_signing_secret = excluded.maintainer_signing_secret,
                   maintainer_signing_pubkey = excluded.maintainer_signing_pubkey",
                params![node_tag, sec, pubk],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            tx.commit()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok((sec, pubk))
        })
        .await
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeRecord>> {
        self.run(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_tag, public_key, pubkey_fingerprint, roles_json, config_seq, config_revision,
                            last_reload_status, online, maintainer_signing_secret, maintainer_signing_pubkey
                     FROM nodes ORDER BY node_tag ASC",
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map([], row_to_node_record)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| ExposureError::Storage(e.to_string()))?);
            }
            Ok(out)
        })
        .await
    }

    pub async fn get_node(&self, node_tag: &str) -> Result<Option<NodeRecord>> {
        let node_tag = node_tag.to_string();
        self.run(move |conn| {
            conn.query_row(
                "SELECT node_tag, public_key, pubkey_fingerprint, roles_json, config_seq, config_revision,
                        last_reload_status, online, maintainer_signing_secret, maintainer_signing_pubkey
                 FROM nodes WHERE node_tag = ?1",
                params![node_tag],
                row_to_node_record,
            )
            .optional()
            .map_err(|e| ExposureError::Storage(e.to_string()))
        })
        .await
    }

    pub async fn register_passphrase(
        &self,
        node_tag: &str,
        passphrase: &str,
        mode: &str,
        address: Option<&str>,
        via_hops: &[String],
        ttl_secs: i64,
    ) -> Result<()> {
        let now = Utc::now();
        let expires_ts = now.timestamp().saturating_add(ttl_secs);
        let hops_json = serde_json::to_string(via_hops).unwrap_or_else(|_| "[]".into());
        let node_tag = node_tag.to_string();
        let passphrase = passphrase.to_string();
        let mode = mode.to_string();
        let address = address.map(|s| s.to_string());
        let created_at = now.to_rfc3339();

        self.run(move |conn| {
            conn.execute(
                "INSERT INTO passphrases (node_tag, passphrase, mode, address, via_hops_json, expires_ts, revoked, failed_attempts, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, ?7)
                 ON CONFLICT(node_tag) DO UPDATE SET
                   passphrase = excluded.passphrase,
                   mode = excluded.mode,
                   address = excluded.address,
                   via_hops_json = excluded.via_hops_json,
                   expires_ts = excluded.expires_ts,
                   revoked = 0,
                   failed_attempts = 0,
                   created_at = excluded.created_at",
                params![node_tag, passphrase, mode, address, hops_json, expires_ts, created_at],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    /// Atomically verify onboarding passphrase proof, enforce failure lockout, pin public key,
    /// revoke & zeroize the one-time passphrase, and return the matched passphrase for computing `reply_proof`.
    pub async fn consume_passphrase_and_enroll(
        &self,
        node_tag: &str,
        public_key: &str,
        nonce: &[u8],
        proof: &str,
    ) -> Result<String> {
        parse_verifying_key_b64(public_key)?;
        let fp = pubkey_fingerprint_b64(public_key)?;
        let node_tag = node_tag.to_string();
        let public_key = public_key.trim().to_string();
        let nonce = nonce.to_vec();
        let proof = proof.to_string();
        let now_ts = Utc::now().timestamp();
        let now_rfc = Utc::now().to_rfc3339();

        self.run(move |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let rec: Option<(String, i64, i64, i64)> = tx
                .query_row(
                    "SELECT passphrase, expires_ts, revoked, failed_attempts FROM passphrases WHERE node_tag = ?1",
                    params![&node_tag],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let Some((passphrase, expires_ts, revoked, failed_attempts)) = rec else {
                return Err(ExposureError::Auth(format!(
                    "no passphrase registered for {node_tag}"
                )));
            };
            if revoked != 0 || passphrase.is_empty() {
                return Err(ExposureError::Auth("passphrase already revoked".into()));
            }
            if now_ts > expires_ts {
                let _ = tx.execute(
                    "UPDATE passphrases SET revoked = 1, passphrase = '' WHERE node_tag = ?1",
                    params![&node_tag],
                );
                let _ = tx.commit();
                return Err(ExposureError::Auth("passphrase expired".into()));
            }
            if failed_attempts >= MAX_PASSPHRASE_FAILURES {
                let _ = tx.execute(
                    "UPDATE passphrases SET revoked = 1, passphrase = '' WHERE node_tag = ?1",
                    params![&node_tag],
                );
                let _ = tx.commit();
                return Err(ExposureError::Auth("passphrase locked out".into()));
            }

            if !verify_passphrase_proof(&passphrase, &node_tag, &public_key, &nonce, &proof) {
                let new_fails = failed_attempts + 1;
                if new_fails >= MAX_PASSPHRASE_FAILURES {
                    let _ = tx.execute(
                        "UPDATE passphrases SET failed_attempts = ?2, revoked = 1, passphrase = '' WHERE node_tag = ?1",
                        params![&node_tag, new_fails],
                    );
                } else {
                    let _ = tx.execute(
                        "UPDATE passphrases SET failed_attempts = ?2 WHERE node_tag = ?1",
                        params![&node_tag, new_fails],
                    );
                }
                let _ = tx.commit();
                return Err(ExposureError::Auth("invalid passphrase proof".into()));
            }

            // Refuse to silently overwrite an already-enrolled node with a different public key
            let existing_pk: Option<String> = tx
                .query_row(
                    "SELECT public_key FROM nodes WHERE node_tag = ?1",
                    params![&node_tag],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            if let Some(ref cur_pk) = existing_pk {
                if !cur_pk.trim().is_empty() && cur_pk.trim() != public_key {
                    return Err(ExposureError::Auth(format!(
                        "node '{node_tag}' is already enrolled with a different public key"
                    )));
                }
            }

            tx.execute(
                "INSERT INTO nodes (node_tag, public_key, pubkey_fingerprint, roles_json, online, last_seen)
                 VALUES (?1, ?2, ?3, '[]', 1, ?4)
                 ON CONFLICT(node_tag) DO UPDATE SET
                   public_key = CASE WHEN nodes.public_key = '' THEN excluded.public_key ELSE nodes.public_key END,
                   pubkey_fingerprint = CASE WHEN nodes.public_key = '' THEN excluded.pubkey_fingerprint ELSE nodes.pubkey_fingerprint END,
                   online = 1,
                   last_seen = excluded.last_seen",
                params![&node_tag, &public_key, &fp, &now_rfc],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;

            // Atomically revoke & zeroize the one-time passphrase
            tx.execute(
                "UPDATE passphrases SET revoked = 1, passphrase = '' WHERE node_tag = ?1",
                params![&node_tag],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;

            tx.commit()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(passphrase)
        })
        .await
    }

    pub async fn list_passphrases(&self) -> Result<Vec<PassphraseRecord>> {
        self.run(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_tag, passphrase, mode, address, via_hops_json, expires_ts, revoked
                     FROM passphrases ORDER BY created_at DESC",
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map([], |r| {
                    let hops_s: String = r.get(4)?;
                    let via_hops: Vec<String> = serde_json::from_str(&hops_s).unwrap_or_default();
                    let exp_ts: i64 = r.get(5)?;
                    let exp_str = chrono::DateTime::from_timestamp(exp_ts, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| exp_ts.to_string());
                    Ok(PassphraseRecord {
                        node_tag: r.get(0)?,
                        passphrase: r.get(1)?,
                        mode: r.get(2)?,
                        address: r.get(3)?,
                        via_hops,
                        expires_at: exp_str,
                        expires_ts: exp_ts,
                        revoked: r.get::<_, i64>(6)? != 0,
                    })
                })
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| ExposureError::Storage(e.to_string()))?);
            }
            Ok(out)
        })
        .await
    }

    pub async fn revoke_passphrase(&self, node_tag: &str) -> Result<()> {
        let node_tag = node_tag.to_string();
        self.run(move |conn| {
            conn.execute(
                "UPDATE passphrases SET revoked = 1, passphrase = '' WHERE node_tag = ?1",
                params![node_tag],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn update_config_version_status(&self, id: i64, status: &str) -> Result<()> {
        let status = status.to_string();
        self.run(move |conn| {
            conn.execute(
                "UPDATE config_versions SET status = ?2 WHERE id = ?1",
                params![id, status],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn list_config_versions(&self, limit: i64) -> Result<Vec<ConfigVersionRecord>> {
        self.run(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, sequence, node_tag, config_json, status, created_at
                     FROM config_versions ORDER BY id DESC LIMIT ?1",
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(params![limit], row_to_config_version)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| ExposureError::Storage(e.to_string()))?);
            }
            Ok(out)
        })
        .await
    }

    pub async fn get_config_version(&self, id: i64) -> Result<Option<ConfigVersionRecord>> {
        self.run(move |conn| {
            conn.query_row(
                "SELECT id, sequence, node_tag, config_json, status, created_at
                 FROM config_versions WHERE id = ?1",
                params![id],
                row_to_config_version,
            )
            .optional()
            .map_err(|e| ExposureError::Storage(e.to_string()))
        })
        .await
    }

    pub async fn append_audit(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        success: bool,
        detail: &str,
    ) {
        let actor: String = actor.chars().filter(|c| !c.is_control()).take(64).collect();
        let action: String = action.chars().take(64).collect();
        let target: String = target
            .chars()
            .filter(|c| !c.is_control())
            .take(128)
            .collect();
        let detail: String = detail
            .chars()
            .filter(|c| !c.is_control() || *c == ' ')
            .take(512)
            .collect();

        if let Err(e) = self
            .run(move |conn| {
                conn.execute(
                    "INSERT INTO audit_logs (created_at, actor, action, target, success, detail)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        Utc::now().to_rfc3339(),
                        actor,
                        action,
                        target,
                        if success { 1 } else { 0 },
                        detail
                    ],
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
                Ok(())
            })
            .await
        {
            warn!(error = %e, "failed to append audit log entry");
        }
    }

    pub async fn list_audit_logs(&self, limit: i64) -> Result<Vec<AuditLogRecord>> {
        self.run(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, created_at, actor, action, target, success, detail
                     FROM audit_logs ORDER BY id DESC LIMIT ?1",
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(params![limit], |r| {
                    Ok(AuditLogRecord {
                        id: r.get(0)?,
                        created_at: r.get(1)?,
                        actor: r.get(2)?,
                        action: r.get(3)?,
                        target: r.get(4)?,
                        success: r.get::<_, i64>(5)? != 0,
                        detail: r.get(6)?,
                    })
                })
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| ExposureError::Storage(e.to_string()))?);
            }
            Ok(out)
        })
        .await
    }

    /// Query audit logs with optional time window, facets, search text, and pagination.
    #[allow(clippy::too_many_arguments)]
    pub async fn query_audit_logs(
        &self,
        from_ms: Option<i64>,
        to_ms: Option<i64>,
        actor: Option<String>,
        action: Option<String>,
        target: Option<String>,
        q: Option<String>,
        offset: usize,
        limit: usize,
    ) -> Result<serde_json::Value> {
        self.run(move |conn| {
            let clean = |v: Option<String>| -> Option<String> {
                v.map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"))
            };
            let like_pat = |raw: &str| -> String {
                let mut out = String::with_capacity(raw.len() + 4);
                for ch in raw.to_ascii_lowercase().chars() {
                    match ch {
                        '\\' | '%' | '_' => {
                            out.push('\\');
                            out.push(ch);
                        }
                        c => out.push(c),
                    }
                }
                format!("%{out}%")
            };

            let avail_actors = Self::distinct_col(conn, "SELECT DISTINCT actor FROM audit_logs ORDER BY 1")?;
            let avail_actions = Self::distinct_col(conn, "SELECT DISTINCT action FROM audit_logs ORDER BY 1")?;

            let mut where_sql = String::from(" WHERE 1=1");
            let mut args: Vec<Value> = Vec::new();
            if let Some(f) = from_ms {
                where_sql.push_str(" AND (unixepoch(created_at) * 1000) >= ?");
                args.push(Value::Integer(f));
            }
            if let Some(t) = to_ms {
                where_sql.push_str(" AND (unixepoch(created_at) * 1000) <= ?");
                args.push(Value::Integer(t));
            }
            if let Some(a) = clean(actor) {
                where_sql.push_str(" AND LOWER(actor) = LOWER(?)");
                args.push(Value::Text(a));
            }
            if let Some(act) = clean(action) {
                where_sql.push_str(" AND LOWER(action) = LOWER(?)");
                args.push(Value::Text(act));
            }
            if let Some(tgt) = clean(target) {
                where_sql.push_str(" AND LOWER(target) LIKE ? ESCAPE '\\'");
                args.push(Value::Text(like_pat(&tgt)));
            }
            if let Some(qs) = clean(q) {
                let pat = like_pat(&qs);
                where_sql.push_str(
                    " AND (LOWER(actor) LIKE ? ESCAPE '\\' OR LOWER(action) LIKE ? ESCAPE '\\' OR LOWER(target) LIKE ? ESCAPE '\\' OR LOWER(detail) LIKE ? ESCAPE '\\')",
                );
                for _ in 0..4 {
                    args.push(Value::Text(pat.clone()));
                }
            }

            let total_matched: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM audit_logs{where_sql}"),
                    rusqlite::params_from_iter(args.clone()),
                    |r| r.get(0),
                )
                .unwrap_or(0);

            let lim = limit.clamp(1, 200);
            let mut page_args = args;
            page_args.push(Value::Integer(lim as i64));
            page_args.push(Value::Integer(offset as i64));
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT id, created_at, actor, action, target, success, detail
                     FROM audit_logs{where_sql}
                     ORDER BY id DESC
                     LIMIT ? OFFSET ?"
                ))
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(page_args), |r| {
                    Ok(AuditLogRecord {
                        id: r.get(0)?,
                        created_at: r.get(1)?,
                        actor: r.get(2)?,
                        action: r.get(3)?,
                        target: r.get(4)?,
                        success: r.get::<_, i64>(5)? != 0,
                        detail: r.get(6)?,
                    })
                })
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let mut items = Vec::new();
            for row in rows {
                items.push(row.map_err(|e| ExposureError::Storage(e.to_string()))?);
            }
            let tot = total_matched.max(0) as usize;
            let has_more = offset.saturating_add(items.len()) < tot;
            Ok(serde_json::json!({
                "total_matched": tot,
                "offset": offset,
                "limit": lim,
                "has_more": has_more,
                "available_actors": avail_actors,
                "available_actions": avail_actions,
                "items": items,
            }))
        })
        .await
    }

    fn distinct_col(conn: &Connection, sql: &str) -> Result<Vec<String>> {
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            let s = r.map_err(|e| ExposureError::Storage(e.to_string()))?;
            if !s.is_empty() {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Atomically allocate one Git-style global `(release_seq, revision)` across all nodes in a deployment.
    pub async fn allocate_release(
        &self,
        trigger_kind: &str,
        message: &str,
        topology_yaml: &str,
        crs_version: &str,
        pushed_by: &str,
        target_nodes: &[String],
    ) -> Result<ConfigReleaseRecord> {
        let trigger_kind = trigger_kind.trim().to_string();
        let message: String = message
            .chars()
            .filter(|c| !c.is_control() || *c == ' ')
            .take(256)
            .collect();
        let topology_yaml = topology_yaml.to_string();
        let crs_version = crs_version.to_string();
        let pushed_by = pushed_by.trim().to_string();
        let target_nodes = target_nodes.to_vec();

        self.run(move |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let last_rel: Option<(i64, String)> = tx
                .query_row(
                    "SELECT release_seq, revision FROM config_releases ORDER BY release_seq DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let max_ver: i64 = tx
                .query_row("SELECT COALESCE(MAX(sequence), 0) FROM config_versions", [], |r| r.get(0))
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let kv_seq: i64 = tx
                .query_row(
                    "SELECT CAST(v AS INTEGER) FROM kv_store WHERE k = 'last_config_sequence'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?
                .unwrap_or(0);
            let node_max: i64 = tx
                .query_row("SELECT COALESCE(MAX(config_seq), 0) FROM nodes", [], |r| r.get(0))
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let rel_max = last_rel.as_ref().map(|x| x.0).unwrap_or(0);
            let parent_revision = last_rel.map(|x| x.1);
            let next_seq_i64 = rel_max.max(max_ver).max(kv_seq).max(node_max).saturating_add(1);
            let next_seq = u64::try_from(next_seq_i64).unwrap_or(1);

            let now = Utc::now();
            let created_at = now.to_rfc3339();
            let created_at_ms = now.timestamp_millis();
            let (revision, revision_full) = compute_release_revision(
                &topology_yaml,
                &crs_version,
                parent_revision.as_deref(),
                next_seq,
                created_at_ms,
            );

            tx.execute(
                "INSERT INTO kv_store (k, v) VALUES ('last_config_sequence', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![next_seq_i64.to_string()],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;

            tx.execute(
                "INSERT INTO config_releases (
                    release_seq, revision, revision_full, parent_revision, trigger_kind,
                    message, topology_yaml, crs_version, pushed_by, created_at, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    next_seq_i64,
                    &revision,
                    &revision_full,
                    &parent_revision,
                    &trigger_kind,
                    &message,
                    &topology_yaml,
                    &crs_version,
                    &pushed_by,
                    &created_at,
                    created_at_ms,
                ],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let mut node_rows = Vec::with_capacity(target_nodes.len());
            for nt in target_nodes {
                tx.execute(
                    "INSERT INTO config_release_nodes (release_seq, node_tag, status, error, updated_at)
                     VALUES (?1, ?2, 'pending', NULL, ?3)
                     ON CONFLICT(release_seq, node_tag) DO UPDATE SET
                        status = 'pending', error = NULL, updated_at = excluded.updated_at",
                    params![next_seq_i64, &nt, &created_at],
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
                node_rows.push(ConfigReleaseNodeRecord {
                    release_seq: next_seq,
                    node_tag: nt,
                    status: "pending".to_string(),
                    error: None,
                    updated_at: created_at.clone(),
                });
            }

            tx.commit()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            Ok(ConfigReleaseRecord {
                release_seq: next_seq,
                revision,
                revision_full,
                parent_revision,
                trigger_kind,
                message,
                topology_yaml,
                crs_version,
                pushed_by,
                created_at,
                created_at_ms,
                nodes: node_rows,
            })
        })
        .await
    }

    pub async fn update_release_node_status(
        &self,
        release_seq: u64,
        node_tag: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let seq_i64 = i64::try_from(release_seq).unwrap_or(i64::MAX);
        let node_tag = node_tag.to_string();
        let status = status.to_string();
        let error = error.map(|s| s.chars().take(512).collect::<String>());
        let now = Utc::now().to_rfc3339();
        self.run(move |conn| {
            conn.execute(
                "INSERT INTO config_release_nodes (release_seq, node_tag, status, error, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(release_seq, node_tag) DO UPDATE SET
                    status = excluded.status,
                    error = excluded.error,
                    updated_at = excluded.updated_at",
                params![seq_i64, node_tag, status, error, now],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    fn load_release_nodes(
        conn: &Connection,
        release_seq: u64,
    ) -> Result<Vec<ConfigReleaseNodeRecord>> {
        let mut stmt = conn
            .prepare(
                "SELECT release_seq, node_tag, status, error, updated_at
                 FROM config_release_nodes WHERE release_seq = ?1 ORDER BY node_tag ASC",
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(params![release_seq as i64], |r| {
                Ok(ConfigReleaseNodeRecord {
                    release_seq: u64::try_from(r.get::<_, i64>(0)?).unwrap_or(0),
                    node_tag: r.get(1)?,
                    status: r.get(2)?,
                    error: r.get(3)?,
                    updated_at: r.get(4)?,
                })
            })
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
        }
        Ok(out)
    }

    pub async fn get_latest_config_release(&self) -> Result<Option<ConfigReleaseRecord>> {
        self.run(|conn| {
            let rec = conn
                .query_row(
                    "SELECT release_seq, revision, revision_full, parent_revision, trigger_kind,
                            message, topology_yaml, crs_version, pushed_by, created_at, created_at_ms
                     FROM config_releases ORDER BY release_seq DESC LIMIT 1",
                    [],
                    row_to_config_release,
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            match rec {
                Some(mut r) => {
                    r.nodes = Self::load_release_nodes(conn, r.release_seq)?;
                    Ok(Some(r))
                }
                None => Ok(None),
            }
        })
        .await
    }

    pub async fn list_config_releases(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<ConfigReleaseRecord>, usize)> {
        self.run(move |conn| {
            let total: i64 = conn
                .query_row("SELECT COUNT(*) FROM config_releases", [], |r| r.get(0))
                .unwrap_or(0);
            let lim = limit.clamp(1, 200) as i64;
            let mut stmt = conn
                .prepare(
                    "SELECT release_seq, revision, revision_full, parent_revision, trigger_kind,
                            message, topology_yaml, crs_version, pushed_by, created_at, created_at_ms
                     FROM config_releases ORDER BY release_seq DESC LIMIT ?1 OFFSET ?2",
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(params![lim, offset as i64], row_to_config_release)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let mut out = Vec::new();
            for row in rows {
                let mut r = row.map_err(|e| ExposureError::Storage(e.to_string()))?;
                r.nodes = Self::load_release_nodes(conn, r.release_seq)?;
                out.push(r);
            }
            Ok((out, total.max(0) as usize))
        })
        .await
    }

    pub async fn get_config_release(
        &self,
        rev_or_seq: &str,
    ) -> Result<Option<ConfigReleaseRecord>> {
        let key = rev_or_seq.trim().to_string();
        self.run(move |conn| {
            let mut rec: Option<ConfigReleaseRecord> = conn
                .query_row(
                    "SELECT release_seq, revision, revision_full, parent_revision, trigger_kind,
                            message, topology_yaml, crs_version, pushed_by, created_at, created_at_ms
                     FROM config_releases
                     WHERE revision = ?1 OR revision_full = ?1 OR (?2 AND release_seq = ?3)
                     LIMIT 1",
                    params![
                        &key,
                        key.parse::<i64>().is_ok(),
                        key.parse::<i64>().unwrap_or(-1),
                    ],
                    row_to_config_release,
                )
                .optional()
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            if let Some(ref mut r) = rec {
                r.nodes = Self::load_release_nodes(conn, r.release_seq)?;
            }
            Ok(rec)
        })
        .await
    }

    pub async fn get_control_retention_config(&self) -> Result<ControlRetentionConfig> {
        let mut cfg = self
            .get_kv_json::<ControlRetentionConfig>("control_retention_json")
            .await?
            .unwrap_or_default();
        clamp_control_retention(&mut cfg);
        Ok(cfg)
    }

    pub async fn set_control_retention_config(&self, cfg: &ControlRetentionConfig) -> Result<()> {
        let mut c = cfg.clone();
        clamp_control_retention(&mut c);
        self.set_kv_json("control_retention_json", &c).await
    }

    fn collect_storage_stats_sync(conn: &Connection, db_path: &str) -> ControlStorageStats {
        let count_tbl = |tbl: &str| -> u64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {tbl}"), [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap_or(0)
            .max(0) as u64
        };
        let (db_bytes, wal_bytes) = if db_path == ":memory:" {
            (0, 0)
        } else {
            let db = std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(0);
            let wal = std::fs::metadata(PathBuf::from(format!("{db_path}-wal")))
                .map(|m| m.len())
                .unwrap_or(0);
            (db, wal)
        };
        let last_cleanup_at: Option<String> = conn
            .query_row(
                "SELECT v FROM kv_store WHERE k = 'last_control_cleanup_at'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);

        ControlStorageStats {
            db_bytes,
            wal_bytes,
            nodes_rows: count_tbl("nodes"),
            config_releases_rows: count_tbl("config_releases"),
            config_versions_rows: count_tbl("config_versions"),
            audit_logs_rows: count_tbl("audit_logs"),
            last_cleanup_at,
        }
    }

    pub async fn storage_stats(&self) -> Result<ControlStorageStats> {
        let path = self.db_path.clone();
        self.run(move |conn| Ok(Self::collect_storage_stats_sync(conn, &path)))
            .await
    }

    /// Retention pruning controlled by `ControlRetentionConfig`, keeping at least `config_releases_keep_min` latest releases.
    pub async fn prune_old_records(
        &self,
        cfg: &ControlRetentionConfig,
    ) -> Result<ControlCleanupReport> {
        let mut ret = cfg.clone();
        clamp_control_retention(&mut ret);
        let db_path = self.db_path.clone();
        self.run(move |conn| {
            let now = Utc::now();
            let now_ts = now.timestamp();
            let stale_pass_cutoff = if ret.expired_passphrases_retention_hours > 0 {
                now_ts.saturating_sub(
                    (ret.expired_passphrases_retention_hours as i64).saturating_mul(3600),
                )
            } else {
                now_ts
            };
            let mut rep = ControlCleanupReport::default();

            if ret.audit_logs_retention_days > 0 {
                let cutoff =
                    (now - ChronoDuration::days(ret.audit_logs_retention_days as i64)).timestamp();
                rep.deleted_audit_logs += conn
                    .execute(
                        "DELETE FROM audit_logs WHERE COALESCE(unixepoch(created_at), 0) < ?1",
                        params![cutoff],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.audit_logs_max_rows > 0 {
                rep.deleted_audit_logs += conn
                    .execute(
                        "DELETE FROM audit_logs WHERE id NOT IN (
                            SELECT id FROM audit_logs ORDER BY id DESC LIMIT ?1
                        )",
                        params![ret.audit_logs_max_rows as i64],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }

            const MIN_KEEP: i64 = 10;
            if ret.config_releases_retention_days > 0 {
                let cutoff_ms = (now
                    - ChronoDuration::days(ret.config_releases_retention_days as i64))
                .timestamp_millis();
                rep.deleted_releases += conn
                    .execute(
                        "DELETE FROM config_releases
                         WHERE created_at_ms < ?1
                           AND release_seq NOT IN (SELECT release_seq FROM config_releases ORDER BY release_seq DESC LIMIT ?2)",
                        params![cutoff_ms, MIN_KEEP],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.config_releases_max_count > 0 {
                let max_keep = (ret.config_releases_max_count as i64).max(MIN_KEEP);
                rep.deleted_releases += conn
                    .execute(
                        "DELETE FROM config_releases WHERE release_seq NOT IN (
                            SELECT release_seq FROM config_releases ORDER BY release_seq DESC LIMIT ?1
                        )",
                        params![max_keep],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            let _ = conn.execute(
                "DELETE FROM config_release_nodes WHERE release_seq NOT IN (SELECT release_seq FROM config_releases)",
                [],
            );

            rep.deleted_legacy_versions = conn
                .execute(
                    "DELETE FROM config_versions WHERE id NOT IN (SELECT id FROM config_versions ORDER BY id DESC LIMIT 200)",
                    [],
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            rep.deleted_passphrases = conn
                .execute(
                    "DELETE FROM passphrases WHERE revoked = 1 OR expires_ts < ?1",
                    params![stale_pass_cutoff],
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let _ = conn.execute(
                "INSERT INTO kv_store (k, v) VALUES ('last_control_cleanup_at', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![now.to_rfc3339()],
            );
            let _ = conn.execute_batch("PRAGMA incremental_vacuum(1024); PRAGMA wal_checkpoint(TRUNCATE);");
            rep.storage_stats = Self::collect_storage_stats_sync(conn, &db_path);
            Ok(rep)
        })
        .await
    }
}

fn clamp_control_retention(c: &mut ControlRetentionConfig) {
    c.audit_logs_retention_days = c.audit_logs_retention_days.min(3_650);
    c.audit_logs_max_rows = c.audit_logs_max_rows.min(10_000_000);
    c.config_releases_retention_days = c.config_releases_retention_days.min(3_650);
    c.config_releases_max_count = c.config_releases_max_count.clamp(1, 100_000);
    c.expired_passphrases_retention_hours = c.expired_passphrases_retention_hours.min(87_600);
    c.control_cleanup_interval_mins = c.control_cleanup_interval_mins.clamp(5, 10_080);
}

fn row_to_node_record(r: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRecord> {
    let roles_s: String = r.get(3)?;
    let roles: Vec<String> = serde_json::from_str(&roles_s).unwrap_or_default();
    Ok(NodeRecord {
        node_tag: r.get(0)?,
        public_key: r.get(1)?,
        pubkey_fingerprint: r.get(2)?,
        roles,
        config_seq: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
        config_revision: r.get(5)?,
        last_reload_status: r.get(6)?,
        online: r.get::<_, i64>(7)? != 0,
        maintainer_signing_secret: r.get(8)?,
        maintainer_signing_pubkey: r.get(9)?,
    })
}

fn row_to_config_version(r: &rusqlite::Row<'_>) -> rusqlite::Result<ConfigVersionRecord> {
    Ok(ConfigVersionRecord {
        id: r.get(0)?,
        sequence: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
        node_tag: r.get(2)?,
        config_json: r.get(3)?,
        status: r.get(4)?,
        created_at: r.get(5)?,
    })
}

fn row_to_config_release(r: &rusqlite::Row<'_>) -> rusqlite::Result<ConfigReleaseRecord> {
    Ok(ConfigReleaseRecord {
        release_seq: u64::try_from(r.get::<_, i64>(0)?).unwrap_or(0),
        revision: r.get(1)?,
        revision_full: r.get(2)?,
        parent_revision: r.get(3)?,
        trigger_kind: r.get(4)?,
        message: r.get(5)?,
        topology_yaml: r.get(6)?,
        crs_version: r.get(7)?,
        pushed_by: r.get(8)?,
        created_at: r.get(9)?,
        created_at_ms: r.get(10)?,
        nodes: Vec::new(),
    })
}
