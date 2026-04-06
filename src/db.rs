use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
    blob_dir: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub auth_key_hash: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub encrypted_master_key: Option<Vec<u8>>,
    pub client_salt: Vec<u8>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ItemRow {
    pub id: String,
    pub owner_id: String,
    pub encrypted_blob: String,
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub item_type: String,
    pub metadata: serde_json::Value,
    pub storage_backend: String,
    pub file_blob_key: Option<String>,
    pub size_bytes: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GrantRow {
    pub id: String,
    pub item_id: Option<String>,
    pub grantor_id: String,
    pub grantee_email: String,
    pub grantee_id: Option<String>,
    pub wrapped_key: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub policy: serde_json::Value,
    pub status: String,
    pub view_count: i32,
    pub created_at: String,
    pub claimed_at: Option<String>,
    pub revoked_at: Option<String>,
    pub file_wrapped_key: Option<Vec<u8>>,
}

impl Database {
    pub fn open(db_path: &Path) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).ok();
            }
        }

        let blob_dir = db_path.parent().unwrap_or(Path::new(".")).join("blobs");
        std::fs::create_dir_all(&blob_dir).ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&blob_dir, std::fs::Permissions::from_mode(0o700)).ok();
        }

        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;

        let db = Self {
            conn: Mutex::new(conn),
            blob_dir,
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                auth_key_hash TEXT NOT NULL,
                public_key BLOB NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                encrypted_master_key BLOB,
                client_salt BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                encrypted_blob TEXT NOT NULL,
                wrapped_key BLOB NOT NULL,
                nonce BLOB NOT NULL,
                item_type TEXT NOT NULL DEFAULT 'encrypted',
                metadata TEXT DEFAULT '{}',
                storage_backend TEXT DEFAULT 'local',
                file_blob_key TEXT,
                size_bytes INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS grants (
                id TEXT PRIMARY KEY,
                item_id TEXT REFERENCES items(id) ON DELETE CASCADE,
                grantor_id TEXT NOT NULL REFERENCES users(id),
                grantee_email TEXT NOT NULL,
                grantee_id TEXT REFERENCES users(id),
                wrapped_key BLOB NOT NULL,
                ephemeral_pubkey BLOB NOT NULL,
                policy TEXT DEFAULT '{}',
                status TEXT DEFAULT 'pending',
                view_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                claimed_at TEXT,
                revoked_at TEXT,
                file_wrapped_key BLOB
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                wrapped_master_key BLOB,
                encrypted_private_key BLOB NOT NULL,
                public_key BLOB,
                scopes TEXT DEFAULT '{}',
                expires_at TEXT,
                last_used_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS api_key_grants (
                id TEXT PRIMARY KEY,
                api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
                item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                wrapped_key BLOB NOT NULL,
                ephemeral_pubkey BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                details TEXT DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            ",
        )
    }

    // --- Config ---

    pub fn get_config(&self, key: &str) -> Option<Vec<u8>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn set_config(&self, key: &str, value: &[u8]) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .ok();
    }

    // --- Users ---

    #[allow(clippy::too_many_arguments)]
    pub fn create_user(
        &self,
        id: &str,
        email: &str,
        auth_key_hash: &str,
        public_key: &[u8],
        encrypted_private_key: &[u8],
        encrypted_master_key: Option<&[u8]>,
        client_salt: &[u8],
    ) -> Result<UserRow, rusqlite::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (id, email, auth_key_hash, public_key, encrypted_private_key, encrypted_master_key, client_salt, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![id, email, auth_key_hash, public_key, encrypted_private_key, encrypted_master_key, client_salt, now, now],
        )?;
        drop(conn);
        self.get_user_by_id(id).map(|u| u.unwrap())
    }

    pub fn get_user_by_email(&self, email: &str) -> Result<Option<UserRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, email, auth_key_hash, public_key, encrypted_private_key, encrypted_master_key, client_salt, created_at, updated_at FROM users WHERE email = ?1",
            params![email],
            |row| Ok(UserRow {
                id: row.get(0)?,
                email: row.get(1)?,
                auth_key_hash: row.get(2)?,
                public_key: row.get(3)?,
                encrypted_private_key: row.get(4)?,
                encrypted_master_key: row.get(5)?,
                client_salt: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            }),
        )
        .optional()
    }

    pub fn get_user_by_id(&self, id: &str) -> Result<Option<UserRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, email, auth_key_hash, public_key, encrypted_private_key, encrypted_master_key, client_salt, created_at, updated_at FROM users WHERE id = ?1",
            params![id],
            |row| Ok(UserRow {
                id: row.get(0)?,
                email: row.get(1)?,
                auth_key_hash: row.get(2)?,
                public_key: row.get(3)?,
                encrypted_private_key: row.get(4)?,
                encrypted_master_key: row.get(5)?,
                client_salt: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            }),
        )
        .optional()
    }

    // --- Items ---

    #[allow(clippy::too_many_arguments)]
    pub fn create_item(
        &self,
        id: &str,
        owner_id: &str,
        encrypted_blob: &str,
        wrapped_key: &[u8],
        nonce: &[u8],
        item_type: &str,
        metadata: &serde_json::Value,
        size_bytes: Option<i64>,
        file_blob_key: Option<&str>,
    ) -> Result<ItemRow, rusqlite::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let meta_str = serde_json::to_string(metadata).unwrap_or_default();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO items (id, owner_id, encrypted_blob, wrapped_key, nonce, item_type, metadata, size_bytes, file_blob_key, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![id, owner_id, encrypted_blob, wrapped_key, nonce, item_type, meta_str, size_bytes, file_blob_key, now, now],
        )?;
        drop(conn);
        self.get_item(id, owner_id).map(|i| i.unwrap())
    }

    pub fn list_items(&self, owner_id: &str) -> Result<Vec<ItemRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, owner_id, encrypted_blob, wrapped_key, nonce, item_type, metadata, storage_backend, file_blob_key, size_bytes, created_at, updated_at FROM items WHERE owner_id = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![owner_id], |row| {
            let meta_str: String = row.get(6)?;
            Ok(ItemRow {
                id: row.get(0)?,
                owner_id: row.get(1)?,
                encrypted_blob: row.get(2)?,
                wrapped_key: row.get(3)?,
                nonce: row.get(4)?,
                item_type: row.get(5)?,
                metadata: serde_json::from_str(&meta_str).unwrap_or_default(),
                storage_backend: row.get(7)?,
                file_blob_key: row.get(8)?,
                size_bytes: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_item(&self, id: &str, owner_id: &str) -> Result<Option<ItemRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, owner_id, encrypted_blob, wrapped_key, nonce, item_type, metadata, storage_backend, file_blob_key, size_bytes, created_at, updated_at FROM items WHERE id = ?1 AND owner_id = ?2",
            params![id, owner_id],
            |row| {
                let meta_str: String = row.get(6)?;
                Ok(ItemRow {
                    id: row.get(0)?,
                    owner_id: row.get(1)?,
                    encrypted_blob: row.get(2)?,
                    wrapped_key: row.get(3)?,
                    nonce: row.get(4)?,
                    item_type: row.get(5)?,
                    metadata: serde_json::from_str(&meta_str).unwrap_or_default(),
                    storage_backend: row.get(7)?,
                    file_blob_key: row.get(8)?,
                    size_bytes: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                })
            },
        )
        .optional()
    }

    pub fn get_item_any_owner(&self, id: &str) -> Result<Option<ItemRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, owner_id, encrypted_blob, wrapped_key, nonce, item_type, metadata, storage_backend, file_blob_key, size_bytes, created_at, updated_at FROM items WHERE id = ?1",
            params![id],
            |row| {
                let meta_str: String = row.get(6)?;
                Ok(ItemRow {
                    id: row.get(0)?,
                    owner_id: row.get(1)?,
                    encrypted_blob: row.get(2)?,
                    wrapped_key: row.get(3)?,
                    nonce: row.get(4)?,
                    item_type: row.get(5)?,
                    metadata: serde_json::from_str(&meta_str).unwrap_or_default(),
                    storage_backend: row.get(7)?,
                    file_blob_key: row.get(8)?,
                    size_bytes: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                })
            },
        )
        .optional()
    }

    pub fn delete_item(&self, id: &str, owner_id: &str) -> Result<bool, rusqlite::Error> {
        // Delete blob file if exists
        if let Ok(Some(item)) = self.get_item(id, owner_id) {
            if let Some(blob_key) = &item.file_blob_key {
                let blob_path = self.blob_dir.join(blob_key);
                std::fs::remove_file(blob_path).ok();
            }
        }
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "DELETE FROM items WHERE id = ?1 AND owner_id = ?2",
            params![id, owner_id],
        )?;
        Ok(affected > 0)
    }

    // --- Grants ---

    #[allow(clippy::too_many_arguments)]
    pub fn create_grant(
        &self,
        id: &str,
        item_id: Option<&str>,
        grantor_id: &str,
        grantee_email: &str,
        grantee_id: Option<&str>,
        wrapped_key: &[u8],
        ephemeral_pubkey: &[u8],
        policy: &serde_json::Value,
        file_wrapped_key: Option<&[u8]>,
    ) -> Result<GrantRow, rusqlite::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let policy_str = serde_json::to_string(policy).unwrap_or_default();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO grants (id, item_id, grantor_id, grantee_email, grantee_id, wrapped_key, ephemeral_pubkey, policy, status, view_count, created_at, file_wrapped_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9, ?10)",
            params![id, item_id, grantor_id, grantee_email, grantee_id, wrapped_key, ephemeral_pubkey, policy_str, now, file_wrapped_key],
        )?;
        drop(conn);
        self.get_grant(id).map(|g| g.unwrap())
    }

    pub fn list_grants_for_user(
        &self,
        user_id: &str,
        email: &str,
    ) -> Result<Vec<GrantRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, item_id, grantor_id, grantee_email, grantee_id, wrapped_key, ephemeral_pubkey, policy, status, view_count, created_at, claimed_at, revoked_at, file_wrapped_key
             FROM grants WHERE grantor_id = ?1 OR grantee_id = ?1 OR grantee_email = ?2
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![user_id, email], Self::map_grant_row)?;
        rows.collect()
    }

    pub fn get_grant(&self, id: &str) -> Result<Option<GrantRow>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, item_id, grantor_id, grantee_email, grantee_id, wrapped_key, ephemeral_pubkey, policy, status, view_count, created_at, claimed_at, revoked_at, file_wrapped_key
             FROM grants WHERE id = ?1",
            params![id],
            Self::map_grant_row,
        )
        .optional()
    }

    pub fn claim_grant(&self, id: &str, grantee_id: &str) -> Result<bool, rusqlite::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE grants SET status = 'active', grantee_id = ?2, claimed_at = ?3 WHERE id = ?1 AND status = 'pending'",
            params![id, grantee_id, now],
        )?;
        Ok(affected > 0)
    }

    pub fn increment_view_count(
        &self,
        id: &str,
        max_views: Option<i32>,
    ) -> Result<Option<i32>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        if let Some(max) = max_views {
            conn.query_row(
                "UPDATE grants SET view_count = view_count + 1 WHERE id = ?1 AND view_count < ?2 RETURNING view_count",
                params![id, max],
                |row| row.get(0),
            )
            .optional()
        } else {
            conn.query_row(
                "UPDATE grants SET view_count = view_count + 1 WHERE id = ?1 RETURNING view_count",
                params![id],
                |row| row.get(0),
            )
            .optional()
        }
    }

    pub fn revoke_grant(&self, id: &str, grantor_id: &str) -> Result<bool, rusqlite::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE grants SET status = 'revoked', revoked_at = ?3 WHERE id = ?1 AND grantor_id = ?2",
            params![id, grantor_id, now],
        )?;
        Ok(affected > 0)
    }

    fn map_grant_row(row: &rusqlite::Row) -> Result<GrantRow, rusqlite::Error> {
        let policy_str: String = row.get(7)?;
        Ok(GrantRow {
            id: row.get(0)?,
            item_id: row.get(1)?,
            grantor_id: row.get(2)?,
            grantee_email: row.get(3)?,
            grantee_id: row.get(4)?,
            wrapped_key: row.get(5)?,
            ephemeral_pubkey: row.get(6)?,
            policy: serde_json::from_str(&policy_str).unwrap_or_default(),
            status: row.get(8)?,
            view_count: row.get(9)?,
            created_at: row.get(10)?,
            claimed_at: row.get(11)?,
            revoked_at: row.get(12)?,
            file_wrapped_key: row.get(13)?,
        })
    }

    // --- Blobs ---

    pub fn conn_ref(&self) -> &Mutex<Connection> {
        &self.conn
    }

    #[allow(dead_code)]
    pub fn blob_dir(&self) -> &Path {
        &self.blob_dir
    }

    pub fn write_blob(&self, key: &str, data: &[u8]) -> std::io::Result<()> {
        let path = self.blob_dir.join(key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            let canonical_parent = parent.canonicalize()?;
            let canonical_blob_dir = self.blob_dir.canonicalize()?;
            if !canonical_parent.starts_with(&canonical_blob_dir) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "path traversal blocked",
                ));
            }
        }
        std::fs::write(path, data)
    }

    pub fn read_blob(&self, key: &str) -> std::io::Result<Vec<u8>> {
        let path = self.blob_dir.join(key);
        let canonical = path.canonicalize()?;
        let canonical_blob_dir = self.blob_dir.canonicalize()?;
        if !canonical.starts_with(&canonical_blob_dir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "path traversal blocked",
            ));
        }
        std::fs::read(canonical)
    }

    // --- Audit ---

    pub fn audit_log(
        &self,
        actor_id: &str,
        action: &str,
        resource_type: &str,
        resource_id: Option<&str>,
        details: &serde_json::Value,
    ) {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let details_str = serde_json::to_string(details).unwrap_or_default();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (id, actor_id, action, resource_type, resource_id, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, actor_id, action, resource_type, resource_id, details_str, now],
        )
        .ok();
    }
}
