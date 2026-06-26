use sqlx::{Row, SqlitePool};

/// Create a new approval
pub async fn create_approval(
    pool: &SqlitePool,
    user_id: i64,
    client_ip: &str,
    approved_by: i64,
    duration_hours: i32,
    reason: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let expires_at = now + (duration_hours as i64 * 3600);

    let result = sqlx::query(
        "INSERT INTO approvals (user_id, client_ip, approved_by, approved_at, expires_at, approval_duration_hours, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(client_ip)
    .bind(approved_by)
    .bind(now)
    .bind(expires_at)
    .bind(duration_hours)
    .bind(reason)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Check if an IP is approved for a user (active, non-expired, non-terminated)
pub async fn is_ip_approved(
    pool: &SqlitePool,
    user_id: i64,
    client_ip: &str,
) -> Result<bool, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let row = sqlx::query(
        "SELECT COUNT(*) as cnt FROM approvals WHERE user_id = ? AND client_ip = ? AND expires_at > ? AND is_expired = 0 AND is_terminated = 0",
    )
    .bind(user_id)
    .bind(client_ip)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(row.get::<i64, _>("cnt") > 0)
}

/// List active approvals for a user
pub async fn list_user_approvals(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Vec<ApprovalRecord>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let rows = sqlx::query_as::<_, ApprovalRecord>(
        "SELECT id, user_id, client_ip, approved_by, approved_at, expires_at, is_expired, is_terminated, terminated_by, terminated_at, termination_reason, reason, approval_duration_hours FROM approvals WHERE user_id = ? AND expires_at > ? AND is_terminated = 0 ORDER BY approved_at DESC",
    )
    .bind(user_id)
    .bind(now)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// List all active approvals (admin)
pub async fn list_all_approvals(pool: &SqlitePool) -> Result<Vec<ApprovalRecord>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let rows = sqlx::query_as::<_, ApprovalRecord>(
        "SELECT id, user_id, client_ip, approved_by, approved_at, expires_at, is_expired, is_terminated, terminated_by, terminated_at, termination_reason, reason, approval_duration_hours FROM approvals WHERE expires_at > ? AND is_terminated = 0 ORDER BY approved_at DESC",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Terminate an approval (admin action)
/// Terminate an active approval. Returns the affected approval's `user_id` when
/// a row was terminated (so the caller can invalidate that user's approval
/// cache), or `None` if the approval was missing / already terminated.
pub async fn terminate_approval(
    pool: &SqlitePool,
    approval_id: i64,
    terminated_by: i64,
    reason: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let user_id = sqlx::query_scalar::<_, i64>(
        "UPDATE approvals SET is_terminated = 1, terminated_by = ?, terminated_at = ?, termination_reason = ? WHERE id = ? AND is_terminated = 0 RETURNING user_id",
    )
    .bind(terminated_by)
    .bind(now)
    .bind(reason)
    .bind(approval_id)
    .fetch_optional(pool)
    .await?;

    Ok(user_id)
}

/// Expire old approvals (background cleanup)
pub async fn expire_old_approvals(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let result =
        sqlx::query("UPDATE approvals SET is_expired = 1 WHERE expires_at <= ? AND is_expired = 0")
            .bind(now)
            .execute(pool)
            .await?;

    Ok(result.rows_affected())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct ApprovalRecord {
    pub id: i64,
    pub user_id: i64,
    pub client_ip: String,
    pub approved_by: i64,
    pub approved_at: i64,
    pub expires_at: i64,
    pub is_expired: bool,
    pub is_terminated: bool,
    pub terminated_by: Option<i64>,
    pub terminated_at: Option<i64>,
    pub termination_reason: Option<String>,
    pub reason: Option<String>,
    pub approval_duration_hours: i32,
}
