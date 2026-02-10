use crate::db::models::Usage;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

/// Record connection usage in the database
pub async fn record_usage(
    pool: &SqlitePool,
    user_id: i64,
    connection_id: &str,
    client_ip: &str,
    target_host: &str,
    protocol: &str,
    started_at: i64,
    ended_at: i64,
    bytes_sent: i64,
    bytes_received: i64,
    status: &str,
) -> Result<i64, sqlx::Error> {
    let duration = (ended_at - started_at) as i32;
    let result = sqlx::query(
        r#"
        INSERT INTO usage (
            user_id, connection_id, client_ip, target_host, protocol,
            started_at, ended_at, duration_seconds,
            bytes_sent, bytes_received, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(user_id)
    .bind(connection_id)
    .bind(client_ip)
    .bind(target_host)
    .bind(protocol)
    .bind(started_at)
    .bind(ended_at)
    .bind(duration)
    .bind(bytes_sent)
    .bind(bytes_received)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// User usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUsageStats {
    pub connection_count: i64,
    pub total_bytes_sent: i64,
    pub total_bytes_received: i64,
    pub total_bandwidth: i64,
}

/// Get user usage statistics for a time period
pub async fn get_user_usage(
    pool: &SqlitePool,
    user_id: i64,
    days: i32,
) -> Result<UserUsageStats, sqlx::Error> {
    let cutoff = chrono::Utc::now().timestamp() - (days as i64 * 86400);
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) as connection_count,
            COALESCE(SUM(bytes_sent), 0) as total_bytes_sent,
            COALESCE(SUM(bytes_received), 0) as total_bytes_received,
            COALESCE(SUM(bytes_sent + bytes_received), 0) as total_bandwidth
        FROM usage
        WHERE user_id = ? AND started_at >= ?
        "#,
    )
    .bind(user_id)
    .bind(cutoff)
    .fetch_one(pool)
    .await?;
    Ok(UserUsageStats {
        connection_count: row.get(0),
        total_bytes_sent: row.get(1),
        total_bytes_received: row.get(2),
        total_bandwidth: row.get(3),
    })
}

/// Get recent usage records for a user
pub async fn get_recent_usage_records(
    pool: &SqlitePool,
    user_id: i64,
    limit: i32,
) -> Result<Vec<Usage>, sqlx::Error> {
    let records = sqlx::query_as::<_, Usage>(
        r#"
        SELECT * FROM usage
        WHERE user_id = ?
        ORDER BY started_at DESC
        LIMIT ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(records)
}

/// Get all-time usage statistics for a user
pub async fn get_all_time_usage(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<UserUsageStats, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) as connection_count,
            COALESCE(SUM(bytes_sent), 0) as total_bytes_sent,
            COALESCE(SUM(bytes_received), 0) as total_bytes_received,
            COALESCE(SUM(bytes_sent + bytes_received), 0) as total_bandwidth
        FROM usage
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(UserUsageStats {
        connection_count: row.get(0),
        total_bytes_sent: row.get(1),
        total_bytes_received: row.get(2),
        total_bandwidth: row.get(3),
    })
}
