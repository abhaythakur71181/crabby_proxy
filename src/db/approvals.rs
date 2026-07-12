use sqlx::SqlitePool;

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

/// Check if an IP is approved for a user (active, non-expired, non-terminated).
///
/// Fetches the user's active approval patterns and matches the concrete IP in
/// Rust, so wildcard / CIDR / IPv6 patterns are honored — not just exact IPs.
/// A stored pattern that fails to parse (corrupt row) is skipped and logged,
/// so one bad row cannot fail-closed the whole check.
pub async fn is_ip_approved(
    pool: &SqlitePool,
    user_id: i64,
    client_ip: &str,
) -> Result<bool, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let patterns = sqlx::query_scalar::<_, String>(
        "SELECT client_ip FROM approvals WHERE user_id = ? AND expires_at > ? AND is_expired = 0 AND is_terminated = 0",
    )
    .bind(user_id)
    .bind(now)
    .fetch_all(pool)
    .await?;

    let ip: std::net::IpAddr = match client_ip.parse() {
        Ok(ip) => ip,
        // Not a concrete IP (shouldn't happen from the proxy path) — nothing to match.
        Err(_) => return Ok(false),
    };

    for pat_str in patterns {
        match crate::ip_pattern::IpPattern::parse(&pat_str) {
            Ok(pat) if pat.matches(ip) => return Ok(true),
            Ok(_) => {}
            Err(e) => tracing::warn!(
                "skipping unparseable approval pattern '{}' for user {}: {}",
                pat_str,
                user_id,
                e
            ),
        }
    }
    Ok(false)
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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                approved_by INTEGER NOT NULL,
                approved_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                is_expired BOOLEAN DEFAULT 0,
                is_terminated BOOLEAN DEFAULT 0,
                terminated_by INTEGER,
                terminated_at INTEGER,
                termination_reason TEXT,
                reason TEXT,
                approval_duration_hours INTEGER NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn wildcard_pattern_matches_concrete_ip() {
        let pool = setup().await;
        create_approval(&pool, 1, "140.11.11.*", 99, 24, None)
            .await
            .unwrap();
        assert!(is_ip_approved(&pool, 1, "140.11.11.5").await.unwrap());
        assert!(!is_ip_approved(&pool, 1, "140.11.12.5").await.unwrap());
    }

    #[tokio::test]
    async fn exact_pattern_still_matches() {
        let pool = setup().await;
        create_approval(&pool, 1, "8.8.8.8", 99, 24, None)
            .await
            .unwrap();
        assert!(is_ip_approved(&pool, 1, "8.8.8.8").await.unwrap());
        assert!(!is_ip_approved(&pool, 1, "8.8.4.4").await.unwrap());
    }

    #[tokio::test]
    async fn expired_and_terminated_never_match() {
        let pool = setup().await;
        let past = chrono::Utc::now().timestamp() - 10;
        // expired '*' grant
        sqlx::query(
            "INSERT INTO approvals (user_id, client_ip, approved_by, approved_at, expires_at, approval_duration_hours) VALUES (1,'*',9,0,?,1)",
        )
        .bind(past)
        .execute(&pool)
        .await
        .unwrap();
        // active-but-terminated '*' grant
        let fut = chrono::Utc::now().timestamp() + 3600;
        sqlx::query(
            "INSERT INTO approvals (user_id, client_ip, approved_by, approved_at, expires_at, is_terminated, approval_duration_hours) VALUES (1,'*',9,0,?,1,1)",
        )
        .bind(fut)
        .execute(&pool)
        .await
        .unwrap();
        assert!(!is_ip_approved(&pool, 1, "8.8.8.8").await.unwrap());
    }

    #[tokio::test]
    async fn corrupt_pattern_is_skipped_not_fatal() {
        let pool = setup().await;
        create_approval(&pool, 1, "not-an-ip", 9, 24, None)
            .await
            .unwrap();
        // Skipped without error; no match.
        assert!(!is_ip_approved(&pool, 1, "8.8.8.8").await.unwrap());
    }
}
