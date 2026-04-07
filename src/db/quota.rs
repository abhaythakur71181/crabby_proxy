use chrono::Datelike;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Quota window period for bandwidth tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaPeriod {
    Daily,
    Weekly,
    Monthly,
}

impl Default for QuotaPeriod {
    fn default() -> Self {
        Self::Monthly
    }
}

impl QuotaPeriod {
    /// Get the Unix timestamp for the start of the current period.
    pub fn window_start(&self) -> i64 {
        let now = chrono::Utc::now();
        match self {
            QuotaPeriod::Daily => now
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp(),
            QuotaPeriod::Weekly => {
                let days_since_monday = now.weekday().num_days_from_monday();
                let monday = now.date_naive() - chrono::Duration::days(days_since_monday as i64);
                monday.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp()
            }
            QuotaPeriod::Monthly => {
                let month_start = now.date_naive().with_day(1).unwrap_or(now.date_naive());
                month_start
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_utc()
                    .timestamp()
            }
        }
    }
}

/// Quota usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaStats {
    pub quota_bytes: Option<i64>,
    pub used_bytes: i64,
    pub remaining_bytes: Option<i64>,
    pub percentage_used: Option<f64>,
    pub period: QuotaPeriod,
}

/// Get user's quota usage stats for a given period.
pub async fn get_quota_stats(pool: &SqlitePool, user_id: i64) -> Result<QuotaStats, sqlx::Error> {
    get_quota_stats_with_period(pool, user_id, QuotaPeriod::Monthly).await
}

/// Get user's quota usage stats for a specific period.
pub async fn get_quota_stats_with_period(
    pool: &SqlitePool,
    user_id: i64,
    period: QuotaPeriod,
) -> Result<QuotaStats, sqlx::Error> {
    let window_start = period.window_start();
    // The limit lives in two places historically:
    //   * `monthly_bandwidth_quota` (bytes, optional) — added by migration 006
    //     and exposed via the dedicated PUT /api/users/:id/quota endpoint.
    //   * `bandwidth_limit_mb` (megabytes, NOT NULL, default 1000) — set by
    //     the create/update user form in the admin UI. A value of 0 means
    //     "unlimited" in the UI.
    //
    // The two were never wired together: the UI writes only `bandwidth_limit_mb`
    // while the quota tracker reads only `monthly_bandwidth_quota`, so users
    // who set their limit through the normal admin UI ended up with an
    // unenforceable quota. Resolve them by preferring the explicit byte value
    // when set, and otherwise converting `bandwidth_limit_mb` to bytes
    // (treating 0 as "no limit").
    let row: (Option<i64>, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            monthly_bandwidth_quota as quota_bytes_explicit,
            bandwidth_limit_mb as quota_mb_legacy,
            COALESCE((SELECT SUM(bytes_sent + bytes_received) FROM usage WHERE user_id = ? AND started_at >= ?), 0) as used_bytes
        FROM users
        WHERE id = ?
        "#
    )
    .bind(user_id)
    .bind(window_start)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    let quota_bytes: Option<i64> = match row.0 {
        Some(b) if b > 0 => Some(b),
        _ if row.1 > 0 => Some(row.1.saturating_mul(1024 * 1024)),
        _ => None, // 0 or NULL on both => unlimited
    };
    let used_bytes = row.2;
    let remaining_bytes = quota_bytes.map(|q| (q - used_bytes).max(0));
    let percentage_used = quota_bytes.map(|q| {
        if q > 0 {
            (used_bytes as f64 / q as f64) * 100.0
        } else {
            0.0
        }
    });
    Ok(QuotaStats {
        quota_bytes,
        used_bytes,
        remaining_bytes,
        percentage_used,
        period,
    })
}

/// Update user's quota
pub async fn update_quota(
    pool: &SqlitePool,
    user_id: i64,
    quota_bytes: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET monthly_bandwidth_quota = ? WHERE id = ?")
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
                bandwidth_limit_mb INTEGER NOT NULL DEFAULT 0,
                monthly_bandwidth_quota INTEGER
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
                bytes_received INTEGER NOT NULL,
                started_at INTEGER NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        // Covering index for quota SUM queries
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_usage_quota_lookup ON usage (user_id, started_at, bytes_sent, bytes_received)",
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn test_get_quota_stats() {
        let pool = setup_test_db().await;
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO users (username, monthly_bandwidth_quota) VALUES ('test', 1048576)",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO usage (user_id, bytes_sent, bytes_received, started_at) VALUES (1, 262144, 262144, ?)",
        )
        .bind(now)
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
