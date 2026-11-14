use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use std::str::FromStr;
use std::time::Duration;

pub async fn create_pool(
    database_url: &str,
    max_connections: u32,
) -> Result<SqlitePool, sqlx::Error> {
    // Configure PRAGMAs on the *connect options* so EVERY pooled connection gets
    // them. `foreign_keys` and `busy_timeout` are per-connection state in SQLite
    // (foreign_keys defaults OFF), so setting them via `.execute(&pool)` only
    // configured whichever single connection happened to run the query — leaving
    // FK enforcement effectively off and writers hitting immediate SQLITE_BUSY on
    // every other connection. `create_if_missing` replaces the old `?mode=rwc`.
    let connect_opts = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(connect_opts)
        .await?;

    tracing::info!(
        "SQLite pool ready (per-connection): WAL, busy_timeout=5s, synchronous=NORMAL, foreign_keys=ON"
    );

    Ok(pool)
}

pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations").run(pool).await?;

    Ok(())
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    use sqlx::Row;
    use std::borrow::Cow;

    /// Apply only migrations with version <= `max_version`, so a test can seed
    /// data in the old schema and then run the remaining migrations over it.
    pub(crate) async fn migrate_up_to(pool: &SqlitePool, max_version: i64) {
        let mut m = sqlx::migrate!("./migrations");
        m.migrations = Cow::Owned(
            m.migrations
                .iter()
                .filter(|x| x.version <= max_version)
                .cloned()
                .collect(),
        );
        m.run(pool).await.unwrap();
    }

    /// #35: migration 020 folds `bandwidth_limit_mb` into
    /// `monthly_bandwidth_quota` without changing anyone's effective quota.
    #[tokio::test]
    async fn migration_020_preserves_effective_quota() {
        let pool = create_pool("sqlite::memory:", 1).await.unwrap();
        migrate_up_to(&pool, 15).await;
        // (id, bandwidth_limit_mb, monthly_bandwidth_quota)
        let seed: [(i64, i64, Option<i64>); 5] = [
            (1, 1000, None),       // legacy MB only -> 1000 MiB
            (2, 1000, Some(4096)), // explicit bytes win
            (3, 0, None),          // unlimited
            (4, 0, Some(0)),       // unlimited (0 bytes)
            (5, 7, Some(0)),       // 0 bytes falls back to MB
        ];
        for (id, mb, q) in seed {
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, role, created_at, updated_at, bandwidth_limit_mb, monthly_bandwidth_quota) VALUES (?, ?, 'h', 'user', 0, 0, ?, ?)",
            )
            .bind(id)
            .bind(format!("u{id}"))
            .bind(mb)
            .bind(q)
            .execute(&pool)
            .await
            .unwrap();
        }

        run_migrations(&pool).await.unwrap();

        let rows = sqlx::query("SELECT id, monthly_bandwidth_quota FROM users ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        let got: Vec<(i64, Option<i64>)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
        assert_eq!(
            got,
            vec![
                (1, Some(1000 * 1048576)),
                (2, Some(4096)),
                (3, None),
                (4, None),
                (5, Some(7 * 1048576)),
            ]
        );
        let cols: Vec<String> = sqlx::query("SELECT name FROM pragma_table_info('users')")
            .fetch_all(&pool)
            .await
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert!(!cols.iter().any(|c| c == "bandwidth_limit_mb"));
        assert!(!cols.iter().any(|c| c == "max_concurrent_connections"));

        // The API-facing MB view rounds up, and quota stats agree with storage.
        let u2 = crate::db::users::get_user_by_id(&pool, 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(u2.bandwidth_limit_mb, 1);
        assert!(
            u2.password_hash.is_empty(),
            "plain reads must not load the hash"
        );
        let u3 = crate::db::users::get_user_by_id(&pool, 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(u3.bandwidth_limit_mb, 0);
        let s1 = crate::db::quota::get_quota_stats(&pool, 1).await.unwrap();
        assert_eq!(s1.quota_bytes, Some(1000 * 1048576));
        let s3 = crate::db::quota::get_quota_stats(&pool, 3).await.unwrap();
        assert_eq!(s3.quota_bytes, None);
    }
}
