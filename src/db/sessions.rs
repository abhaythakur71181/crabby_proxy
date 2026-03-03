use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

/// Active session info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub token: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Create a new session
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
        "INSERT INTO sessions (user_id, token, created_at, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(token)
    .bind(now)
    .bind(expires_at)
    .bind(ip_address)
    .bind(user_agent)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Get session by token
pub async fn get_session_by_token(
    pool: &SqlitePool,
    token: &str,
) -> Result<Option<Session>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let row = sqlx::query(
        "SELECT id, user_id, token, created_at, expires_at, ip_address, user_agent FROM sessions WHERE token = ? AND expires_at > ?",
    )
    .bind(token)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| Session {
        id: r.get(0),
        user_id: r.get(1),
        token: r.get(2),
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
        "SELECT id, user_id, token, created_at, expires_at, ip_address, user_agent FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC",
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
            token: r.get(2),
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
