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

/// Bounds for an action *prefix* filter, expressed as a half-open range
/// `[lower, upper)` so SQLite can serve it from `idx_audit_log_action`.
///
/// The previous `action LIKE '%value%'` could never use the index (leading
/// wildcard, and LIKE is case-insensitive while the index is BINARY), so both
/// the count and the page query scanned the whole table; it also let a
/// user-supplied `%`/`_` silently widen the match. A plain range comparison has
/// no pattern metacharacters at all. Action names are lower-case identifiers,
/// so the filter is lower-cased to keep the old case-insensitive feel.
fn action_prefix_bounds(filter: &str) -> (String, String) {
    let lower = filter.trim().to_lowercase();
    // U+10FFFF sorts after every valid UTF-8 continuation of `lower` under the
    // BINARY collation, so `[lower, lower + U+10FFFF)` is exactly "starts with".
    let upper = format!("{lower}\u{10FFFF}");
    (lower, upper)
}

/// Get audit log entries with pagination. `action_filter` is a prefix match
/// (e.g. `approval_request` matches `approval_request_created`).
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
        query.push_str(" AND action >= ? AND action < ?");
    }
    query.push_str(" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?");
    let mut q = sqlx::query(sqlx::AssertSqlSafe(query));
    if let Some(uid) = user_id_filter {
        q = q.bind(uid);
    }
    if let Some(action) = action_filter {
        let (lower, upper) = action_prefix_bounds(action);
        q = q.bind(lower).bind(upper);
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
        query.push_str(" AND action >= ? AND action < ?");
    }
    let mut q = sqlx::query(sqlx::AssertSqlSafe(query));
    if let Some(uid) = user_id_filter {
        q = q.bind(uid);
    }
    if let Some(action) = action_filter {
        let (lower, upper) = action_prefix_bounds(action);
        q = q.bind(lower).bind(upper);
    }
    let row = q.fetch_one(pool).await?;
    Ok(row.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> SqlitePool {
        let pool = crate::db::create_pool("sqlite::memory:", 1).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (1,'a','h','admin',0,0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for action in [
            "approval_request_created",
            "approval_request_approved",
            "approval_created",
            "user_created",
            "user%weird",
        ] {
            log_action(&pool, 1, action, None, None, None, None)
                .await
                .unwrap();
        }
        pool
    }

    #[tokio::test]
    async fn action_filter_is_prefix_and_ignores_metacharacters() {
        let pool = setup().await;
        let got = |f: &'static str| {
            let pool = pool.clone();
            async move {
                let rows = get_audit_log(&pool, 50, 0, None, Some(f)).await.unwrap();
                let n = count_audit_entries(&pool, None, Some(f)).await.unwrap();
                assert_eq!(rows.len() as i64, n);
                rows.into_iter().map(|e| e.action).collect::<Vec<_>>()
            }
        };
        assert_eq!(got("approval_request").await.len(), 2);
        assert_eq!(got("APPROVAL").await.len(), 3);
        assert_eq!(got("user_created").await, vec!["user_created"]);
        // `%` and `_` are literal, not wildcards.
        assert!(got("%").await.is_empty());
        assert!(got("_").await.is_empty());
        assert_eq!(got("user%").await, vec!["user%weird"]);
        assert_eq!(count_audit_entries(&pool, None, None).await.unwrap(), 5);
    }

    #[tokio::test]
    async fn action_filter_uses_index() {
        let pool = setup().await;
        let (lower, upper) = action_prefix_bounds("user");
        let plan: Vec<String> = sqlx::query(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM audit_log WHERE action >= ? AND action < ?",
        )
        .bind(lower)
        .bind(upper)
        .fetch_all(&pool)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>(3))
        .collect();
        assert!(
            plan.iter().any(|d| d.contains("idx_audit_log_action")),
            "expected index use, got {plan:?}"
        );
    }
}
