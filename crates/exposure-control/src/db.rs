use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};

use chrono::Utc;
use exposure_core::config::NodeRoles;
use exposure_core::crypto::{
    parse_verifying_key_b64, pubkey_fingerprint_b64, restrict_dir_permissions_0700,
    restrict_file_permissions_0600, verify_passphrase_proof, NodeKeyPair,
};
use exposure_core::{ExposureError, Result};
use rusqlite::{params, Connection, OptionalExtension};
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
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                success INTEGER NOT NULL,
                detail TEXT NOT NULL
            );
            ",
        )
        .map_err(|e| ExposureError::Storage(format!("init sqlite schema: {e}")))?;

        // Backfill `failed_attempts` column on pre-existing DBs if missing
        let _ = conn.execute(
            "ALTER TABLE passphrases ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0",
            [],
        );

        if path != ":memory:" {
            let _ = restrict_file_permissions_0600(Path::new(path));
            let _ = restrict_file_permissions_0600(Path::new(&format!("{path}-wal")));
            let _ = restrict_file_permissions_0600(Path::new(&format!("{path}-shm")));
        }

        Ok(Arc::new(Self {
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

    pub async fn latest_config_sequence(&self) -> Result<u64> {
        self.run(|conn| {
            let cur: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(sequence), 0) FROM config_versions",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(u64::try_from(cur).unwrap_or(0))
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
            let next_seq = max_ver.max(kv_seq).saturating_add(1);
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
        self.run(move |conn| {
            conn.execute(
                "UPDATE nodes SET config_seq = CASE WHEN ?2 THEN ?3 ELSE config_seq END,
                                  last_reload_status = ?4, online = 1, last_seen = ?5
                 WHERE node_tag = ?1",
                params![node_tag, ok, seq_i64, status, Utc::now().to_rfc3339()],
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

    pub async fn get_or_create_maintainer_keypair(&self, node_tag: &str) -> Result<(String, String)> {
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
                    "SELECT node_tag, public_key, pubkey_fingerprint, roles_json, config_seq,
                            last_reload_status, online, maintainer_signing_secret, maintainer_signing_pubkey
                     FROM nodes ORDER BY node_tag ASC",
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map([], |r| {
                    let roles_s: String = r.get(3)?;
                    let roles: Vec<String> = serde_json::from_str(&roles_s).unwrap_or_default();
                    Ok(NodeRecord {
                        node_tag: r.get(0)?,
                        public_key: r.get(1)?,
                        pubkey_fingerprint: r.get(2)?,
                        roles,
                        config_seq: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                        last_reload_status: r.get(5)?,
                        online: r.get::<_, i64>(6)? != 0,
                        maintainer_signing_secret: r.get(7)?,
                        maintainer_signing_pubkey: r.get(8)?,
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

    pub async fn get_node(&self, node_tag: &str) -> Result<Option<NodeRecord>> {
        let node_tag = node_tag.to_string();
        self.run(move |conn| {
            conn.query_row(
                "SELECT node_tag, public_key, pubkey_fingerprint, roles_json, config_seq,
                        last_reload_status, online, maintainer_signing_secret, maintainer_signing_pubkey
                 FROM nodes WHERE node_tag = ?1",
                params![node_tag],
                |r| {
                    let roles_s: String = r.get(3)?;
                    let roles: Vec<String> = serde_json::from_str(&roles_s).unwrap_or_default();
                    Ok(NodeRecord {
                        node_tag: r.get(0)?,
                        public_key: r.get(1)?,
                        pubkey_fingerprint: r.get(2)?,
                        roles,
                        config_seq: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                        last_reload_status: r.get(5)?,
                        online: r.get::<_, i64>(6)? != 0,
                        maintainer_signing_secret: r.get(7)?,
                        maintainer_signing_pubkey: r.get(8)?,
                    })
                },
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
                .query_map(params![limit], |r| {
                    Ok(ConfigVersionRecord {
                        id: r.get(0)?,
                        sequence: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                        node_tag: r.get(2)?,
                        config_json: r.get(3)?,
                        status: r.get(4)?,
                        created_at: r.get(5)?,
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

    pub async fn get_config_version(&self, id: i64) -> Result<Option<ConfigVersionRecord>> {
        self.run(move |conn| {
            conn.query_row(
                "SELECT id, sequence, node_tag, config_json, status, created_at
                 FROM config_versions WHERE id = ?1",
                params![id],
                |r| {
                    Ok(ConfigVersionRecord {
                        id: r.get(0)?,
                        sequence: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                        node_tag: r.get(2)?,
                        config_json: r.get(3)?,
                        status: r.get(4)?,
                        created_at: r.get(5)?,
                    })
                },
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
        let actor: String = actor
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect();
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

    /// Periodic retention pruning so `audit_logs`, `config_versions`, and expired `passphrases` never grow without bound.
    pub async fn prune_old_records(&self) -> Result<()> {
        let stale_pass_cutoff = Utc::now().timestamp().saturating_sub(86_400);
        self.run(move |conn| {
            let _ = conn.execute(
                "DELETE FROM audit_logs WHERE id NOT IN (SELECT id FROM audit_logs ORDER BY id DESC LIMIT 10000)",
                [],
            );
            let _ = conn.execute(
                "DELETE FROM config_versions WHERE id NOT IN (SELECT id FROM config_versions ORDER BY id DESC LIMIT 500)",
                [],
            );
            let _ = conn.execute(
                "DELETE FROM passphrases WHERE (revoked = 1 OR expires_ts < ?1) AND expires_ts < ?1",
                params![stale_pass_cutoff],
            );
            Ok(())
        })
        .await
    }
}
