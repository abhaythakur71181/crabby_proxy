use crate::db::models::Usage;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

/// Record connection usage in the database
pub async fn record_usage(
    pool: &SqlitePool,
    user_id: i64,
    connection_id: &Uuid,
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
    .bind(connection_id.to_string())
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

/// System-wide usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemUsageStats {
    pub total_connections: i64,
    pub total_bytes_sent: i64,
    pub total_bytes_received: i64,
    pub total_bandwidth: i64,
    pub unique_users: i64,
}

/// Get system-wide usage statistics for a time period
pub async fn get_system_usage_stats(
    pool: &SqlitePool,
    days: i32,
) -> Result<SystemUsageStats, sqlx::Error> {
    let cutoff = chrono::Utc::now().timestamp() - (days as i64 * 86400);
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total_connections,
            COALESCE(SUM(bytes_sent), 0) as total_bytes_sent,
            COALESCE(SUM(bytes_received), 0) as total_bytes_received,
            COALESCE(SUM(bytes_sent + bytes_received), 0) as total_bandwidth,
            COUNT(DISTINCT user_id) as unique_users
        FROM usage
        WHERE started_at >= ?
        "#,
    )
    .bind(cutoff)
    .fetch_one(pool)
    .await?;
    Ok(SystemUsageStats {
        total_connections: row.get(0),
        total_bytes_sent: row.get(1),
        total_bytes_received: row.get(2),
        total_bandwidth: row.get(3),
        unique_users: row.get(4),
    })
}

/// Top users by bandwidth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopUserUsage {
    pub user_id: i64,
    pub total_bandwidth: i64,
    pub connection_count: i64,
}

/// Get top N users by bandwidth usage in a time period
pub async fn get_top_users_by_bandwidth(
    pool: &SqlitePool,
    days: i32,
    limit: i32,
) -> Result<Vec<TopUserUsage>, sqlx::Error> {
    let cutoff = chrono::Utc::now().timestamp() - (days as i64 * 86400);
    let rows = sqlx::query(
        r#"
        SELECT
            user_id,
            SUM(bytes_sent + bytes_received) as total_bandwidth,
            COUNT(*) as connection_count
        FROM usage
        WHERE started_at >= ?
        GROUP BY user_id
        ORDER BY total_bandwidth DESC
        LIMIT ?
        "#,
    )
    .bind(cutoff)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| TopUserUsage {
            user_id: r.get(0),
            total_bandwidth: r.get(1),
            connection_count: r.get(2),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();

        // Create usage table
        sqlx::query(
            r#"
            CREATE TABLE usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                connection_id TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                target_host TEXT NOT NULL,
                protocol TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER NOT NULL,
                duration_seconds INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn test_record_usage() {
        let pool = setup_test_db().await;

        let id = record_usage(
            &pool,
            1,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000123").unwrap(),
            "127.0.0.1",
            "example.com",
            "http",
            1000,
            2000,
            1024,
            2048,
            "success",
        )
        .await
        .unwrap();

        assert!(id > 0);
    }

    #[tokio::test]
    async fn test_get_user_usage_empty() {
        let pool = setup_test_db().await;

        let stats = get_user_usage(&pool, 1, 30).await.unwrap();

        assert_eq!(stats.connection_count, 0);
        assert_eq!(stats.total_bytes_sent, 0);
        assert_eq!(stats.total_bytes_received, 0);
        assert_eq!(stats.total_bandwidth, 0);
    }

    #[tokio::test]
    async fn test_get_user_usage_with_data() {
        let pool = setup_test_db().await;
        let now = chrono::Utc::now().timestamp();

        // Record some usage
        record_usage(
            &pool,
            1,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            "127.0.0.1",
            "example.com",
            "http",
            now - 100,
            now,
            1000,
            2000,
            "success",
        )
        .await
        .unwrap();
        record_usage(
            &pool,
            1,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            "127.0.0.1",
            "test.com",
            "https",
            now - 50,
            now,
            500,
            1500,
            "success",
        )
        .await
        .unwrap();

        let stats = get_user_usage(&pool, 1, 1).await.unwrap();

        assert_eq!(stats.connection_count, 2);
        assert_eq!(stats.total_bytes_sent, 1500);
        assert_eq!(stats.total_bytes_received, 3500);
        assert_eq!(stats.total_bandwidth, 5000);
    }

    #[tokio::test]
    async fn test_get_recent_usage_records() {
        let pool = setup_test_db().await;
        let now = chrono::Utc::now().timestamp();

        // Insert 5 records
        for i in 0..5 {
            record_usage(
                &pool,
                1,
                &Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                "127.0.0.1",
                "example.com",
                "http",
                now - (100 * i),
                now - (90 * i),
                100,
                200,
                "success",
            )
            .await
            .unwrap();
        }

        let records = get_recent_usage_records(&pool, 1, 3).await.unwrap();

        assert_eq!(records.len(), 3);
        // Should be in descending order (most recent first)
        assert_eq!(
            records[0].connection_id,
            "00000000-0000-0000-0000-000000000001"
        );
    }

    #[tokio::test]
    async fn test_get_all_time_usage() {
        let pool = setup_test_db().await;
        let now = chrono::Utc::now().timestamp();

        // Record usage across different time periods
        record_usage(
            &pool,
            1,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            "127.0.0.1",
            "example.com",
            "http",
            now - 86400 * 100,
            now - 86400 * 99,
            1000,
            2000,
            "success",
        )
        .await
        .unwrap();
        record_usage(
            &pool,
            1,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            "127.0.0.1",
            "test.com",
            "https",
            now - 100,
            now,
            500,
            1500,
            "success",
        )
        .await
        .unwrap();

        let stats = get_all_time_usage(&pool, 1).await.unwrap();

        assert_eq!(stats.connection_count, 2);
        assert_eq!(stats.total_bytes_sent, 1500);
        assert_eq!(stats.total_bytes_received, 3500);
        assert_eq!(stats.total_bandwidth, 5000);
    }

    #[tokio::test]
    async fn test_get_user_usage_different_users() {
        let pool = setup_test_db().await;
        let now = chrono::Utc::now().timestamp();

        // Record for two different users
        record_usage(
            &pool,
            1,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            "127.0.0.1",
            "example.com",
            "http",
            now,
            now + 10,
            1000,
            2000,
            "success",
        )
        .await
        .unwrap();
        record_usage(
            &pool,
            2,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            "127.0.0.1",
            "test.com",
            "https",
            now,
            now + 10,
            500,
            1500,
            "success",
        )
        .await
        .unwrap();

        let stats1 = get_user_usage(&pool, 1, 1).await.unwrap();
        let stats2 = get_user_usage(&pool, 2, 1).await.unwrap();

        assert_eq!(stats1.connection_count, 1);
        assert_eq!(stats1.total_bytes_sent, 1000);

        assert_eq!(stats2.connection_count, 1);
        assert_eq!(stats2.total_bytes_sent, 500);
    }

    #[tokio::test]
    async fn test_system_usage_stats() {
        let pool = setup_test_db().await;
        let now = chrono::Utc::now().timestamp();

        // Record usage for two different users
        record_usage(
            &pool,
            1,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            "127.0.0.1",
            "example.com",
            "http",
            now - 100,
            now,
            1000,
            2000,
            "success",
        )
        .await
        .unwrap();
        record_usage(
            &pool,
            2,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            "10.0.0.1",
            "test.com",
            "https",
            now - 50,
            now,
            500,
            1500,
            "success",
        )
        .await
        .unwrap();

        let stats = get_system_usage_stats(&pool, 1).await.unwrap();

        assert_eq!(stats.total_connections, 2);
        assert_eq!(stats.total_bytes_sent, 1500);
        assert_eq!(stats.total_bytes_received, 3500);
        assert_eq!(stats.total_bandwidth, 5000);
        assert_eq!(stats.unique_users, 2);
    }

    #[tokio::test]
    async fn test_top_users_by_bandwidth() {
        let pool = setup_test_db().await;
        let now = chrono::Utc::now().timestamp();

        // User 1: 3000 bytes total bandwidth
        record_usage(
            &pool,
            1,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            "127.0.0.1",
            "example.com",
            "http",
            now - 100,
            now,
            1000,
            2000,
            "success",
        )
        .await
        .unwrap();
        // User 2: 8000 bytes total bandwidth
        record_usage(
            &pool,
            2,
            &Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            "10.0.0.1",
            "test.com",
            "https",
            now - 50,
            now,
            3000,
            5000,
            "success",
        )
        .await
        .unwrap();

        let top = get_top_users_by_bandwidth(&pool, 1, 10).await.unwrap();

        assert_eq!(top.len(), 2);
        // User 2 should be first (higher bandwidth)
        assert_eq!(top[0].user_id, 2);
        assert_eq!(top[0].total_bandwidth, 8000);
        assert_eq!(top[1].user_id, 1);
        assert_eq!(top[1].total_bandwidth, 3000);
    }
}
