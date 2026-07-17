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
