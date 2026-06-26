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

/// List all requests (admin view, optionally filter by status)
pub async fn list_all_requests(
    pool: &SqlitePool,
    status_filter: Option<&str>,
) -> Result<Vec<ApprovalRequest>, sqlx::Error> {
    if let Some(status) = status_filter {
        sqlx::query_as::<_, ApprovalRequest>(
            "SELECT id, user_id, client_ip, duration_hours, reason, status, requested_at, decided_by, decided_at, decision_reason FROM approval_requests WHERE status = ? ORDER BY requested_at DESC",
        )
        .bind(status)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, ApprovalRequest>(
            "SELECT id, user_id, client_ip, duration_hours, reason, status, requested_at, decided_by, decided_at, decision_reason FROM approval_requests ORDER BY requested_at DESC",
        )
        .fetch_all(pool)
        .await
    }
}

/// List requests for a specific user
pub async fn list_user_requests(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Vec<ApprovalRequest>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRequest>(
        "SELECT id, user_id, client_ip, duration_hours, reason, status, requested_at, decided_by, decided_at, decision_reason FROM approval_requests WHERE user_id = ? ORDER BY requested_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}
