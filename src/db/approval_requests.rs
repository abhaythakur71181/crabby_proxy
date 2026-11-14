use sqlx::SqlitePool;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct ApprovalRequest {
    pub id: i64,
    pub user_id: i64,
    pub client_ip: String,
    pub duration_hours: i32,
    pub reason: Option<String>,
    pub status: String, // "pending", "approved", "rejected"
    pub requested_at: i64,
    pub decided_by: Option<i64>,
    pub decided_at: Option<i64>,
    pub decision_reason: Option<String>,
}

/// Create a new pending approval request
pub async fn create_request(
    pool: &SqlitePool,
    user_id: i64,
    client_ip: &str,
    duration_hours: i32,
    reason: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO approval_requests (user_id, client_ip, duration_hours, reason, status, requested_at) VALUES (?, ?, ?, ?, 'pending', ?)",
    )
    .bind(user_id)
    .bind(client_ip)
    .bind(duration_hours)
    .bind(reason)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Approve a pending request (creates an actual approval and updates request status)
pub async fn approve_request(
    pool: &SqlitePool,
    request_id: i64,
    decided_by: i64,
    decision_reason: Option<&str>,
) -> Result<Option<ApprovalRequest>, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();

    // All three statements run in one transaction so the request can never be
    // marked approved without its matching approval grant being created — a
    // crash or SQLITE_BUSY between them would otherwise leave the user "approved"
    // yet denied by the proxy, with no retry path.
    let mut tx = pool.begin().await?;

    // Update the request status
    let rows = sqlx::query(
        "UPDATE approval_requests SET status = 'approved', decided_by = ?, decided_at = ?, decision_reason = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(decided_by)
    .bind(now)
    .bind(decision_reason)
    .bind(request_id)
    .execute(&mut *tx)
    .await?;

    if rows.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }

    // Fetch the request to get details for creating the actual approval
    let req = sqlx::query_as::<_, ApprovalRequest>(
        "SELECT id, user_id, client_ip, duration_hours, reason, status, requested_at, decided_by, decided_at, decision_reason FROM approval_requests WHERE id = ?",
    )
    .bind(request_id)
    .fetch_one(&mut *tx)
    .await?;

    // Create the actual approval entry so the proxy allows connections
    let expires_at = now + (req.duration_hours as i64 * 3600);
    sqlx::query(
        "INSERT INTO approvals (user_id, client_ip, approved_by, approved_at, expires_at, approval_duration_hours, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(req.user_id)
    .bind(&req.client_ip)
    .bind(decided_by)
    .bind(now)
    .bind(expires_at)
    .bind(req.duration_hours)
    .bind(&req.reason)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Some(req))
}

/// Reject a pending request
pub async fn reject_request(
    pool: &SqlitePool,
    request_id: i64,
    decided_by: i64,
    decision_reason: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "UPDATE approval_requests SET status = 'rejected', decided_by = ?, decided_at = ?, decision_reason = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(decided_by)
    .bind(now)
    .bind(decision_reason)
    .bind(request_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Approval request joined with the requesting user's username, so listings
/// need no per-row user lookup (#25).
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ApprovalRequestWithUser {
    #[sqlx(flatten)]
    #[serde(flatten)]
    pub request: ApprovalRequest,
    pub username: Option<String>,
}

const LIST_COLUMNS: &str = "r.id, r.user_id, r.client_ip, r.duration_hours, r.reason, r.status, r.requested_at, r.decided_by, r.decided_at, r.decision_reason, u.username";

/// List all requests (admin view, optionally filter by status), newest first.
pub async fn list_all_requests(
    pool: &SqlitePool,
    status_filter: Option<&str>,
    page: crate::db::Page,
) -> Result<Vec<ApprovalRequestWithUser>, sqlx::Error> {
    let sql = format!(
        "SELECT {LIST_COLUMNS} FROM approval_requests r LEFT JOIN users u ON u.id = r.user_id \
         WHERE (?1 IS NULL OR r.status = ?1) \
         ORDER BY r.requested_at DESC, r.id DESC LIMIT ?2 OFFSET ?3"
    );
    sqlx::query_as::<_, ApprovalRequestWithUser>(&sql)
        .bind(status_filter)
        .bind(page.limit)
        .bind(page.offset)
        .fetch_all(pool)
        .await
}

/// List requests for a specific user, newest first.
pub async fn list_user_requests(
    pool: &SqlitePool,
    user_id: i64,
    page: crate::db::Page,
) -> Result<Vec<ApprovalRequestWithUser>, sqlx::Error> {
    let sql = format!(
        "SELECT {LIST_COLUMNS} FROM approval_requests r LEFT JOIN users u ON u.id = r.user_id \
         WHERE r.user_id = ? ORDER BY r.requested_at DESC, r.id DESC LIMIT ? OFFSET ?"
    );
    sqlx::query_as::<_, ApprovalRequestWithUser>(&sql)
        .bind(user_id)
        .bind(page.limit)
        .bind(page.offset)
        .fetch_all(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Page;

    async fn setup() -> SqlitePool {
        let pool = crate::db::create_pool("sqlite::memory:", 1).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (1,'alice','h','user',0,0),(2,'bob','h','user',0,0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn listing_joins_username_and_paginates() {
        let pool = setup().await;
        for i in 0..5 {
            let uid = if i % 2 == 0 { 1 } else { 2 };
            create_request(&pool, uid, "10.0.0.1", 1, None)
                .await
                .unwrap();
        }
        reject_request(&pool, 1, 1, None).await.unwrap();

        let all = list_all_requests(&pool, None, Page::default())
            .await
            .unwrap();
        assert_eq!(all.len(), 5);
        for r in &all {
            let expected = if r.request.user_id == 1 {
                "alice"
            } else {
                "bob"
            };
            assert_eq!(r.username.as_deref(), Some(expected));
        }

        let pending = list_all_requests(&pool, Some("pending"), Page::default())
            .await
            .unwrap();
        assert_eq!(pending.len(), 4);

        let first = list_all_requests(&pool, None, Page::new(Some(2), Some(0)))
            .await
            .unwrap();
        let second = list_all_requests(&pool, None, Page::new(Some(2), Some(2)))
            .await
            .unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        assert!(first
            .iter()
            .all(|a| second.iter().all(|b| a.request.id != b.request.id)));

        let mine = list_user_requests(&pool, 2, Page::default()).await.unwrap();
        assert_eq!(mine.len(), 2);
        assert!(mine.iter().all(|r| r.username.as_deref() == Some("bob")));
    }
}
