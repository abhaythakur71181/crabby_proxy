use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};

/// SHA-256 (hex) of a session bearer token. Tokens are high-entropy, so a fast
/// cryptographic hash is sufficient — we only need the stored value to be
/// non-reversible so a DB read cannot yield a usable token.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Active session info. `token_hash` is the SHA-256 of the bearer token; the raw
/// token is never persisted or returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub token_hash: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Create a new session. `token` is the raw bearer token; only its hash is stored.
pub async fn create_session(
    pool: &SqlitePool,
    user_id: i64,
    token: &str,
    expires_at: i64,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO sessions (user_id, token_hash, created_at, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(hash_token(token))
    .bind(now)
    .bind(expires_at)
    .bind(ip_address)
    .bind(user_agent)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Get session by raw token (looked up by its hash).
pub async fn get_session_by_token(
    pool: &SqlitePool,
    token: &str,
) -> Result<Option<Session>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let row = sqlx::query(
        "SELECT id, user_id, token_hash, created_at, expires_at, ip_address, user_agent FROM sessions WHERE token_hash = ? AND expires_at > ?",
    )
    .bind(hash_token(token))
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| Session {
        id: r.get(0),
        user_id: r.get(1),
        token_hash: r.get(2),
        created_at: r.get(3),
        expires_at: r.get(4),
        ip_address: r.get(5),
        user_agent: r.get(6),
    }))
}

/// List active sessions for a user
pub async fn list_user_sessions(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Vec<Session>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let rows = sqlx::query(
        "SELECT id, user_id, token_hash, created_at, expires_at, ip_address, user_agent FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .bind(now)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| Session {
            id: r.get(0),
            user_id: r.get(1),
            token_hash: r.get(2),
            created_at: r.get(3),
            expires_at: r.get(4),
            ip_address: r.get(5),
            user_agent: r.get(6),
        })
        .collect())
}

/// Delete a specific session (logout)
pub async fn delete_session(pool: &SqlitePool, session_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete all sessions for a user (force logout everywhere)
pub async fn delete_user_sessions(pool: &SqlitePool, user_id: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Expire old sessions (cleanup)
pub async fn cleanup_expired_sessions(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Count active sessions for a user
pub async fn count_user_sessions(pool: &SqlitePool, user_id: i64) -> Result<i64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let row = sqlx::query("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND expires_at > ?")
        .bind(user_id)
        .bind(now)
        .fetch_one(pool)
        .await?;
    Ok(row.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token_is_deterministic_hex_and_non_identity() {
        let a = hash_token("super-secret-bearer");
        let b = hash_token("super-secret-bearer");
        assert_eq!(a, b, "same token must hash equal");
        assert_eq!(a.len(), 64, "SHA-256 hex is 64 chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, "super-secret-bearer", "must not store the raw token");
        assert_ne!(
            a,
            hash_token("different"),
            "distinct tokens hash distinctly"
        );
    }

    async fn migrated_pool() -> SqlitePool {
        let pool = crate::db::create_pool("sqlite::memory:", 1).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        // Satisfy the users FK (foreign_keys is ON per migration 014's parent fix).
        sqlx::query("INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (1, 'u', 'h', 'user', 0, 0)")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    #[tokio::test]
    async fn test_create_and_lookup_stores_only_hash() {
        let pool = migrated_pool().await;
        let raw = "raw-token-value-123";
        let expires = chrono::Utc::now().timestamp() + 3600;
        create_session(&pool, 1, raw, expires, None, None)
            .await
            .unwrap();

        // Raw token must not be present anywhere in the column.
        let stored: String = sqlx::query("SELECT token_hash FROM sessions WHERE user_id = 1")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get(0);
        assert_eq!(stored, hash_token(raw));
        assert_ne!(stored, raw);

        // Lookup by the raw token still works (hashes internally).
        let found = get_session_by_token(&pool, raw).await.unwrap();
        assert!(found.is_some());
        assert!(get_session_by_token(&pool, "wrong")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_foreign_keys_enforced_on_every_connection() {
        // Verifies migration 014's sibling fix (#27): FK enforcement must be on.
        let pool = crate::db::create_pool("sqlite::memory:", 1).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        let expires = chrono::Utc::now().timestamp() + 3600;
        // user_id 999 does not exist -> FK violation must reject the insert.
        let res = create_session(&pool, 999, "t", expires, None, None).await;
        assert!(res.is_err(), "FK enforcement should reject orphan session");
    }
}
