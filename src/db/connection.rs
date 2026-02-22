use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::time::Duration;

pub async fn create_pool(
    database_url: &str,
    max_connections: u32,
) -> Result<SqlitePool, sqlx::Error> {
    // Ensure database file can be created by adding mode=rwc (read-write-create)
    let url = if !database_url.contains('?') {
        format!("{}?mode=rwc", database_url)
    } else {
        database_url.to_string()
    };

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await?;

    // Set critical SQLite pragmas
    sqlx::query("PRAGMA journal_mode = WAL")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA busy_timeout = 5000")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA synchronous = NORMAL")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await?;
    tracing::info!(
        "SQLite pragmas set: WAL, busy_timeout=5000, synchronous=NORMAL, foreign_keys=ON"
    );

    Ok(pool)
}

pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations").run(pool).await?;

    Ok(())
}
