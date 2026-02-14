use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Quota usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaStats {
    pub quota_bytes: Option<i64>,
    pub used_bytes: i64,
    pub remaining_bytes: Option<i64>,
    pub percentage_used: Option<f64>,
}

/// Check if user has remaining quota
pub async fn check_quota(pool: &SqlitePool, user_id: i64) -> Result<bool, sqlx::Error> {
    let row: (Option<i64>, i64) = sqlx::query_as(
        r#"
        SELECT 
            quota_bytes,
            COALESCE((SELECT SUM(bytes_sent + bytes_received) FROM usage WHERE user_id = ?), 0) as used_bytes
        FROM users 
        WHERE id = ?
        "#
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    // If quota_bytes is NULL, no limit (infinite quota)
    if let Some(quota) = row.0 {
        Ok(row.1 < quota)
    } else {
        Ok(true)
    }
}

/// Get user's quota usage stats
pub async fn get_quota_stats(pool: &SqlitePool, user_id: i64) -> Result<QuotaStats, sqlx::Error> {
    let row: (Option<i64>, i64) = sqlx::query_as(
        r#"
        SELECT 
            quota_bytes,
            COALESCE((SELECT SUM(bytes_sent + bytes_received) FROM usage WHERE user_id = ?), 0) as used_bytes
        FROM users 
        WHERE id = ?
        "#
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    let remaining_bytes = row.0.map(|q| (q - row.1).max(0));
    let percentage_used = row.0.map(|q| {
        if q > 0 {
            (row.1 as f64 / q as f64) * 100.0
        } else {
            0.0
        }
    });
    Ok(QuotaStats {
        quota_bytes: row.0,
        used_bytes: row.1,
        remaining_bytes,
        percentage_used,
    })
}

/// Update user's quota
pub async fn update_quota(
    pool: &SqlitePool,
    user_id: i64,
    quota_bytes: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET quota_bytes = ? WHERE id = ?")
        .bind(quota_bytes)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();

        // Create users table
        sqlx::query(
            r#"
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                quota_bytes INTEGER
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        // Create usage table
        sqlx::query(
            r#"
            CREATE TABLE usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn test_check_quota_no_limit() {
        let pool = setup_test_db().await;

        // User with no quota limit
        sqlx::query("INSERT INTO users (username, quota_bytes) VALUES ('test', NULL)")
            .execute(&pool)
            .await
            .unwrap();

        let has_quota = check_quota(&pool, 1).await.unwrap();
        assert!(has_quota); // Should always have quota if no limit set
    }

    #[tokio::test]
    async fn test_check_quota_under_limit() {
        let pool = setup_test_db().await;

        // User with 1MB quota
        sqlx::query("INSERT INTO users (username, quota_bytes) VALUES ('test', 1048576)")
            .execute(&pool)
            .await
            .unwrap();

        // Use 500KB
        sqlx::query(
            "INSERT INTO usage (user_id, bytes_sent, bytes_received) VALUES (1, 262144, 262144)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let has_quota = check_quota(&pool, 1).await.unwrap();
        assert!(has_quota); // 500KB < 1MB
    }

    #[tokio::test]
    async fn test_check_quota_exceeded() {
        let pool = setup_test_db().await;

        // User with 1MB quota
        sqlx::query("INSERT INTO users (username, quota_bytes) VALUES ('test', 1048576)")
            .execute(&pool)
            .await
            .unwrap();

        // Use 1.5MB
        sqlx::query(
            "INSERT INTO usage (user_id, bytes_sent, bytes_received) VALUES (1, 786432, 786432)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let has_quota = check_quota(&pool, 1).await.unwrap();
        assert!(!has_quota); // 1.5MB > 1MB
    }

    #[tokio::test]
    async fn test_get_quota_stats() {
        let pool = setup_test_db().await;

        sqlx::query("INSERT INTO users (username, quota_bytes) VALUES ('test', 1048576)")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO usage (user_id, bytes_sent, bytes_received) VALUES (1, 262144, 262144)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let stats = get_quota_stats(&pool, 1).await.unwrap();

        assert_eq!(stats.quota_bytes, Some(1048576));
        assert_eq!(stats.used_bytes, 524288); // 262144 + 262144
        assert_eq!(stats.remaining_bytes, Some(524288)); // 1048576 - 524288
        assert!(stats.percentage_used.unwrap() > 49.0 && stats.percentage_used.unwrap() < 51.0);
    }
}
