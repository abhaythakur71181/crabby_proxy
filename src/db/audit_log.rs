use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub user_id: i64,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: i64,
}

/// Record an admin action in the audit log
pub async fn log_action(
    pool: &SqlitePool,
    user_id: i64,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<&str>,
    details: Option<&str>,
    ip_address: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO audit_log (user_id, action, target_type, target_id, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(details)
    .bind(ip_address)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Get audit log entries with pagination
pub async fn get_audit_log(
    pool: &SqlitePool,
    limit: i32,
    offset: i32,
    user_id_filter: Option<i64>,
    action_filter: Option<&str>,
) -> Result<Vec<AuditEntry>, sqlx::Error> {
    let mut query = String::from(
        "SELECT id, user_id, action, target_type, target_id, details, ip_address, created_at FROM audit_log WHERE 1=1",
    );
    if user_id_filter.is_some() {
        query.push_str(" AND user_id = ?");
    }
    if action_filter.is_some() {
        query.push_str(" AND action LIKE ?");
    }
    query.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
    let mut q = sqlx::query(&query);
    if let Some(uid) = user_id_filter {
        q = q.bind(uid);
    }
    if let Some(action) = action_filter {
        q = q.bind(format!("%{}%", action));
    }
    q = q.bind(limit).bind(offset);
    let rows = q.fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|r| AuditEntry {
            id: r.get(0),
            user_id: r.get(1),
            action: r.get(2),
            target_type: r.get(3),
            target_id: r.get(4),
            details: r.get(5),
            ip_address: r.get(6),
            created_at: r.get(7),
        })
        .collect())
}

/// Count total audit entries (for pagination)
pub async fn count_audit_entries(
    pool: &SqlitePool,
    user_id_filter: Option<i64>,
    action_filter: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let mut query = String::from("SELECT COUNT(*) FROM audit_log WHERE 1=1");
    if user_id_filter.is_some() {
        query.push_str(" AND user_id = ?");
    }
    if action_filter.is_some() {
        query.push_str(" AND action LIKE ?");
    }
    let mut q = sqlx::query(&query);
    if let Some(uid) = user_id_filter {
        q = q.bind(uid);
    }
    if let Some(action) = action_filter {
        q = q.bind(format!("%{}%", action));
    }
    let row = q.fetch_one(pool).await?;
    Ok(row.get(0))
}
