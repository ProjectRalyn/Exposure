use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use exposure_core::config::NodeRoles;
use exposure_core::crypto::pubkey_fingerprint_b64;
use exposure_core::{ExposureError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_tag: String,
    pub public_key: String,
    pub pubkey_fingerprint: String,
    pub roles: Vec<String>,
    pub config_seq: u64,
    pub last_reload_status: Option<String>,
    pub online: bool,
    pub maintainer_signing_secret: Option<String>,
    pub maintainer_signing_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseRecord {
    pub node_tag: String,
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

/// Local SQLite persistence store for Control (DESIGN.md §5 & user confirmation).
pub struct ControlDb {
    conn: Mutex<Connection>,
}

impl ControlDb {
    pub fn open(path: &str) -> Result<Arc<Self>> {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
        }
        let conn = Connection::open(path)
            .map_err(|e| ExposureError::Storage(format!("open sqlite {path}: {e}")))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
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

        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
        }))
    }

    pub async fn get_topology_yaml(&self) -> Result<String> {
        let conn = self.conn.lock().await;
        let v: Option<String> = conn
            .query_row(
                "SELECT v FROM kv_store WHERE k = 'topology_yaml'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok(v.unwrap_or_default())
    }

    pub async fn set_topology_yaml(&self, yaml: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO kv_store (k, v) VALUES ('topology_yaml', ?1)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![yaml],
        )
        .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok(())
    }

    pub async fn next_config_sequence(&self) -> Result<u64> {
        let conn = self.conn.lock().await;
        let cur: u64 = conn
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM config_versions",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))? as u64;
        Ok(cur + 1)
    }

    pub async fn latest_config_sequence(&self) -> Result<u64> {
        let conn = self.conn.lock().await;
        let cur: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM config_versions",
                [],
                |r| r.get(0),
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok(cur as u64)
    }

    pub async fn upsert_node(
        &self,
        node_tag: &str,
        public_key: &str,
        roles: &NodeRoles,
        online: bool,
    ) -> Result<()> {
        let fp = pubkey_fingerprint_b64(public_key).unwrap_or_else(|_| "unknown".into());
        let roles_json = serde_json::to_string(&roles.names()).unwrap_or_else(|_| "[]".into());
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO nodes (node_tag, public_key, pubkey_fingerprint, roles_json, online, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(node_tag) DO UPDATE SET
               public_key = CASE WHEN excluded.public_key != '' THEN excluded.public_key ELSE nodes.public_key END,
               pubkey_fingerprint = CASE WHEN excluded.public_key != '' THEN excluded.pubkey_fingerprint ELSE nodes.pubkey_fingerprint END,
               roles_json = excluded.roles_json,
               online = excluded.online,
               last_seen = excluded.last_seen",
            params![node_tag, public_key, fp, roles_json, if online { 1 } else { 0 }, now],
        )
        .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok(())
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
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE nodes SET config_seq = CASE WHEN ?2 THEN ?3 ELSE config_seq END,
                              last_reload_status = ?4, online = 1, last_seen = ?5
             WHERE node_tag = ?1",
            params![node_tag, ok, seq as i64, status, Utc::now().to_rfc3339()],
        )
        .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok(())
    }

    pub async fn get_or_create_maintainer_keypair(&self, node_tag: &str) -> Result<(String, String)> {
        let conn = self.conn.lock().await;
        let existing: Option<(Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT maintainer_signing_secret, maintainer_signing_pubkey FROM nodes WHERE node_tag = ?1",
                params![node_tag],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| ExposureError::Storage(e.to_string()))?;

        if let Some((Some(sec), Some(pubk))) = existing {
            return Ok((sec, pubk));
        }

        let kp = exposure_core::crypto::NodeKeyPair::generate();
        let sec = kp.secret_key_b64();
        let pubk = kp.public_key_b64();
        conn.execute(
            "INSERT INTO nodes (node_tag, public_key, pubkey_fingerprint, roles_json, maintainer_signing_secret, maintainer_signing_pubkey)
             VALUES (?1, '', '', '[\"maintainer\"]', ?2, ?3)
             ON CONFLICT(node_tag) DO UPDATE SET
               maintainer_signing_secret = excluded.maintainer_signing_secret,
               maintainer_signing_pubkey = excluded.maintainer_signing_pubkey",
            params![node_tag, sec, pubk],
        )
        .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok((sec, pubk))
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeRecord>> {
        let conn = self.conn.lock().await;
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
                    config_seq: r.get::<_, i64>(4)? as u64,
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
    }

    pub async fn get_node(&self, node_tag: &str) -> Result<Option<NodeRecord>> {
        let all = self.list_nodes().await?;
        Ok(all.into_iter().find(|n| n.node_tag == node_tag))
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
        let expires_ts = now.timestamp() + ttl_secs;
        let hops_json = serde_json::to_string(via_hops).unwrap_or_else(|_| "[]".into());
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO passphrases (node_tag, passphrase, mode, address, via_hops_json, expires_ts, revoked, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
             ON CONFLICT(node_tag) DO UPDATE SET
               passphrase = excluded.passphrase,
               mode = excluded.mode,
               address = excluded.address,
               via_hops_json = excluded.via_hops_json,
               expires_ts = excluded.expires_ts,
               revoked = 0,
               created_at = excluded.created_at",
            params![node_tag, passphrase, mode, address, hops_json, expires_ts, now.to_rfc3339()],
        )
        .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok(())
    }

    pub async fn list_passphrases(&self) -> Result<Vec<PassphraseRecord>> {
        let conn = self.conn.lock().await;
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
    }

    pub async fn revoke_passphrase(&self, node_tag: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE passphrases SET revoked = 1 WHERE node_tag = ?1",
            params![node_tag],
        )
        .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok(())
    }

    pub async fn record_config_version(
        &self,
        sequence: u64,
        node_tag: &str,
        config_json: &str,
        status: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO config_versions (sequence, node_tag, config_json, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![sequence as i64, node_tag, config_json, status, Utc::now().to_rfc3339()],
        )
        .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok(conn.last_insert_rowid())
    }

    pub async fn update_config_version_status(&self, id: i64, status: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE config_versions SET status = ?2 WHERE id = ?1",
            params![id, status],
        )
        .map_err(|e| ExposureError::Storage(e.to_string()))?;
        Ok(())
    }

    pub async fn list_config_versions(&self, limit: i64) -> Result<Vec<ConfigVersionRecord>> {
        let conn = self.conn.lock().await;
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
                    sequence: r.get::<_, i64>(1)? as u64,
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
    }

    pub async fn get_config_version(&self, id: i64) -> Result<Option<ConfigVersionRecord>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, sequence, node_tag, config_json, status, created_at
             FROM config_versions WHERE id = ?1",
            params![id],
            |r| {
                Ok(ConfigVersionRecord {
                    id: r.get(0)?,
                    sequence: r.get::<_, i64>(1)? as u64,
                    node_tag: r.get(2)?,
                    config_json: r.get(3)?,
                    status: r.get(4)?,
                    created_at: r.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|e| ExposureError::Storage(e.to_string()))
    }

    pub async fn append_audit(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        success: bool,
        detail: &str,
    ) {
        let conn = self.conn.lock().await;
        let _ = conn.execute(
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
        );
    }

    pub async fn list_audit_logs(&self, limit: i64) -> Result<Vec<AuditLogRecord>> {
        let conn = self.conn.lock().await;
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
    }
}
