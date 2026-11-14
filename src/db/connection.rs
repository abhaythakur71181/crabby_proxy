use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use std::str::FromStr;
use std::time::Duration;

/// Pool sizing and lock-wait settings.
#[derive(Debug, Clone, Copy)]
pub struct PoolSettings {
    pub max_connections: u32,
    pub busy_timeout: Duration,
    pub acquire_timeout: Duration,
}

impl From<&crate::config::DatabaseConfig> for PoolSettings {
    fn from(c: &crate::config::DatabaseConfig) -> Self {
        Self {
            max_connections: c.max_connections.max(1),
            busy_timeout: Duration::from_millis(c.busy_timeout_ms),
            acquire_timeout: Duration::from_secs(c.acquire_timeout_secs.max(1)),
        }
    }
}

/// Create a pool with default lock-wait settings (5s busy, 10s acquire).
#[cfg_attr(not(test), allow(dead_code))]
pub async fn create_pool(
    database_url: &str,
    max_connections: u32,
) -> Result<SqlitePool, sqlx::Error> {
    create_pool_with(
        database_url,
        PoolSettings {
            max_connections,
            busy_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(10),
        },
    )
    .await
}

pub async fn create_pool_with(
    database_url: &str,
    settings: PoolSettings,
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
        .busy_timeout(settings.busy_timeout);

    let pool = SqlitePoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(settings.acquire_timeout)
        .connect_with(connect_opts)
        .await?;

    tracing::info!(
        max_connections = settings.max_connections,
        busy_timeout_ms = settings.busy_timeout.as_millis() as u64,
        acquire_timeout_ms = settings.acquire_timeout.as_millis() as u64,
        "SQLite pool ready (per-connection): WAL, synchronous=NORMAL, foreign_keys=ON"
    );

    Ok(pool)
}

/// Apply pending migrations. Migrations are forward-only (see
/// docs/adr/0007-forward-only-migrations.md), so before applying any pending
/// migration to an existing on-disk database a consistent snapshot is taken
/// with `VACUUM INTO`; that snapshot is the rollback path.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let migrator = sqlx::migrate!("./migrations");
    snapshot_before_migrate(pool, &migrator).await?;
    migrator.run(pool).await?;

    Ok(())
}

/// Versions of migrations already applied successfully, or `None` for a fresh
/// database that has never been migrated.
async fn applied_versions(pool: &SqlitePool) -> Result<Option<Vec<i64>>, sqlx::Error> {
    let has_table: Option<(String,)> = sqlx::query_as(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_optional(pool)
    .await?;
    if has_table.is_none() {
        return Ok(None);
    }
    let rows: Vec<(i64,)> =
        sqlx::query_as("SELECT version FROM _sqlx_migrations WHERE success = 1")
            .fetch_all(pool)
            .await?;
    Ok(Some(rows.into_iter().map(|r| r.0).collect()))
}

/// If `migrator` has migrations not yet applied to an existing file-backed
/// database, write a snapshot next to it and return its path. Fresh and
/// in-memory databases have nothing to lose and are skipped. A snapshot
/// failure aborts the migration rather than running it without a way back.
async fn snapshot_before_migrate(
    pool: &SqlitePool,
    migrator: &sqlx::migrate::Migrator,
) -> Result<Option<std::path::PathBuf>, sqlx::Error> {
    let db_path = pool.connect_options().get_filename().to_path_buf();
    if db_path.as_os_str().is_empty() || db_path.as_os_str() == ":memory:" || !db_path.is_file() {
        return Ok(None);
    }
    let Some(applied) = applied_versions(pool).await? else {
        return Ok(None);
    };
    let Some(target) = migrator
        .iter()
        .filter(|m| m.migration_type.is_up_migration() && !applied.contains(&m.version))
        .map(|m| m.version)
        .max()
    else {
        return Ok(None);
    };
    let from = applied.iter().copied().max().unwrap_or(0);
    let mut name = db_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        ".pre-migrate-{from:03}-to-{target:03}-{}.bak",
        chrono::Utc::now().timestamp()
    ));
    let snapshot = db_path.with_file_name(name);
    sqlx::query("VACUUM INTO ?")
        .bind(snapshot.to_string_lossy().into_owned())
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(
                "Pre-migration snapshot to {} failed; refusing to migrate: {}",
                snapshot.display(),
                e
            );
            e
        })?;
    tracing::warn!(
        "Applying migrations {from:03} -> {target:03}; pre-migration snapshot written to {} \
         (restore it to roll back; see docs/adr/0007-forward-only-migrations.md)",
        snapshot.display()
    );
    Ok(Some(snapshot))
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

    /// #37: upgrading an existing file database snapshots it first; a fresh
    /// database or one with nothing pending does not.
    #[tokio::test]
    async fn snapshot_taken_only_when_upgrading_existing_db() {
        let dir = std::env::temp_dir().join(format!("crabby-snap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("proxy.db");
        let url = format!("sqlite:{}", db.display());
        let snapshots = || {
            std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(".pre-migrate-"))
                .collect::<Vec<_>>()
        };

        // Fresh database: nothing to protect.
        {
            let pool = create_pool(&url, 1).await.unwrap();
            migrate_up_to(&pool, 15).await;
            sqlx::query("INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (1,'keep','h','user',0,0)")
                .execute(&pool)
                .await
                .unwrap();
            assert!(snapshots().is_empty());

            // Pending migrations on an existing DB: snapshot first.
            run_migrations(&pool).await.unwrap();
            let snaps = snapshots();
            assert_eq!(snaps.len(), 1, "{snaps:?}");
            assert!(snaps[0].starts_with("proxy.db.pre-migrate-015-to-"));

            // Nothing pending: no new snapshot.
            run_migrations(&pool).await.unwrap();
            assert_eq!(snapshots().len(), 1);
            pool.close().await;
        }

        // The snapshot is a usable pre-migration database.
        let snap_url = format!("sqlite:{}", dir.join(&snapshots()[0]).display());
        let snap = create_pool(&snap_url, 1).await.unwrap();
        let max: i64 = sqlx::query("SELECT MAX(version) FROM _sqlx_migrations")
            .fetch_one(&snap)
            .await
            .unwrap()
            .get(0);
        assert_eq!(max, 15);
        let name: String = sqlx::query("SELECT username FROM users WHERE id = 1")
            .fetch_one(&snap)
            .await
            .unwrap()
            .get(0);
        assert_eq!(name, "keep");
        snap.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #36: migration 021 rebuilds the user-owned tables with ON DELETE
    /// CASCADE, keeps their rows and id high-water marks, and keeps actor /
    /// history references blocking.
    #[tokio::test]
    async fn migration_021_cascades_user_owned_rows() {
        let pool = create_pool("sqlite::memory:", 1).await.unwrap();
        migrate_up_to(&pool, 20).await;
        for stmt in [
            "INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (1,'admin','h','admin',0,0),(2,'u','h','user',0,0)",
            "INSERT INTO user_groups (id, name) VALUES (1,'g')",
            "INSERT INTO user_group_members (user_id, group_id) VALUES (2,1)",
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES (5,2,'t5',0,9)",
            // Deleted row: the AUTOINCREMENT high-water mark must survive.
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES (9,2,'t9',0,9)",
            "DELETE FROM sessions WHERE id = 9",
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, name, created_at) VALUES (2,'k','p','n',0)",
            "INSERT INTO approvals (user_id, client_ip, approved_by, approved_at, expires_at, approval_duration_hours) VALUES (2,'1.2.3.4',1,0,9,1)",
            "INSERT INTO approval_requests (user_id, client_ip, duration_hours, requested_at, decided_by) VALUES (2,'1.2.3.4',1,0,1)",
        ] {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }

        run_migrations(&pool).await.unwrap();

        let count = |t: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query(&format!("SELECT COUNT(*) FROM {t}"))
                    .fetch_one(&pool)
                    .await
                    .unwrap()
                    .get::<i64, _>(0)
            }
        };
        for t in [
            "sessions",
            "api_keys",
            "user_group_members",
            "approvals",
            "approval_requests",
        ] {
            assert_eq!(count(t).await, 1, "{t} rows must survive the rebuild");
        }
        let fk_violations = sqlx::query("PRAGMA foreign_key_check")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert!(fk_violations.is_empty());

        // Ids are not reused after the rebuild.
        let new_id = sqlx::query("INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (2,'t10',0,9)")
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_rowid();
        assert_eq!(new_id, 10);

        // The admin is referenced as an actor: hard delete stays blocked.
        assert!(sqlx::query("DELETE FROM users WHERE id = 1")
            .execute(&pool)
            .await
            .is_err());

        // Hard-deleting the subject user removes everything owned by them.
        sqlx::query("DELETE FROM users WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();
        for t in [
            "sessions",
            "api_keys",
            "user_group_members",
            "approvals",
            "approval_requests",
        ] {
            assert_eq!(count(t).await, 0, "{t} rows must cascade");
        }
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
