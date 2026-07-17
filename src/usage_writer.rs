//! Bounded background writer for `usage` records.
//!
//! `record_usage` is on the cleanup path of every closed connection. When
//! the proxy is under load (or SQLite is briefly slow) the previous
//! `tokio::spawn` fan-out had no back-pressure: every connection cost a
//! task allocation, and bursts could pile up unbounded write futures.
//!
//! This module routes those writes through a single bounded MPSC channel
//! consumed by one writer task. Senders that find the channel full drop
//! the record and increment `usage_records_dropped_total` so operators
//! can see and alert on it.

use sqlx::SqlitePool;
use tokio::sync::mpsc;
use uuid::Uuid;

const CHANNEL_CAPACITY: usize = 16_384;
/// Max records drained and committed in a single transaction. Batching the
/// COMMIT (one fsync per batch instead of per row) is what lets the single
/// SQLite writer keep up with connection-close bursts.
const BATCH_SIZE: usize = 256;
/// How long `submit` waits for channel capacity before giving up. Brief
/// back-pressure here (instead of an immediate drop) prevents silent
/// usage/quota under-counting under load; we only drop if the writer is truly
/// wedged for this long.
const SUBMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Debug)]
pub struct UsageRecord {
    pub user_id: i64,
    pub connection_id: Uuid,
    pub client_ip: String,
    pub target_host: String,
    pub protocol: String,
    pub started_at: i64,
    pub ended_at: i64,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub status: crate::db::usage::ConnectionStatus,
}

#[derive(Clone)]
pub struct UsageWriter {
    tx: mpsc::Sender<UsageRecord>,
}

impl UsageWriter {
    /// Spawn the background writer task and return a handle.
    pub fn spawn(pool: SqlitePool) -> Self {
        let (tx, mut rx) = mpsc::channel::<UsageRecord>(CHANNEL_CAPACITY);
        tokio::spawn(async move {
            let mut batch: Vec<UsageRecord> = Vec::with_capacity(BATCH_SIZE);
            // recv_many blocks for at least one record, then drains up to
            // BATCH_SIZE that are already queued — so light load stays low
            // latency while bursts amortize the COMMIT.
            while rx.recv_many(&mut batch, BATCH_SIZE).await > 0 {
                write_batch(&pool, &mut batch).await;
            }
            tracing::info!("usage_writer: channel closed, writer task exiting");
        });
        Self { tx }
    }

    /// Enqueue a record. Fast non-blocking path first; if the channel is full,
    /// wait up to `SUBMIT_WAIT` for capacity (back-pressure) rather than
    /// dropping immediately — a dropped record permanently under-counts the
    /// user's usage/quota. Only a sustained stall or a closed channel drops.
    pub async fn submit(&self, rec: UsageRecord) {
        match self.tx.try_send(rec) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(rec)) => {
                match tokio::time::timeout(SUBMIT_WAIT, self.tx.send(rec)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => {
                        crate::metrics::USAGE_RECORDS_DROPPED.inc();
                        tracing::warn!(
                            "usage_writer: writer stalled >{}s, dropping usage record",
                            SUBMIT_WAIT.as_secs()
                        );
                    }
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                crate::metrics::USAGE_RECORDS_DROPPED.inc();
                tracing::error!("usage_writer: channel closed, dropping usage record");
            }
        }
    }
}

/// Insert a drained batch in a single transaction. On any failure the whole
/// batch is retried row-by-row so one bad row can't lose the rest.
async fn write_batch(pool: &SqlitePool, batch: &mut Vec<UsageRecord>) {
    let result = async {
        let mut tx = pool.begin().await?;
        for rec in batch.iter() {
            insert_usage(&mut tx, rec).await?;
        }
        tx.commit().await
    }
    .await;

    if let Err(e) = result {
        tracing::error!(
            "usage_writer: batch of {} failed ({}); retrying row-by-row",
            batch.len(),
            e
        );
        for rec in batch.iter() {
            if let Err(e) = crate::db::usage::record_usage(
                pool,
                rec.user_id,
                &rec.connection_id,
                &rec.client_ip,
                &rec.target_host,
                &rec.protocol,
                rec.started_at,
                rec.ended_at,
                rec.bytes_sent,
                rec.bytes_received,
                rec.status,
            )
            .await
            {
                crate::metrics::USAGE_RECORDS_DROPPED.inc();
                tracing::error!(
                    "usage_writer: failed to record usage for user {}: {}",
                    rec.user_id,
                    e
                );
            }
        }
    }
    batch.clear();
}

/// Insert a single usage row using a transaction-bound connection.
async fn insert_usage(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    rec: &UsageRecord,
) -> Result<(), sqlx::Error> {
    let duration = (rec.ended_at - rec.started_at) as i32;
    sqlx::query(
        r#"
        INSERT INTO usage (
            user_id, connection_id, client_ip, target_host, protocol,
            started_at, ended_at, duration_seconds,
            bytes_sent, bytes_received, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(rec.user_id)
    .bind(rec.connection_id.to_string())
    .bind(&rec.client_ip)
    .bind(&rec.target_host)
    .bind(&rec.protocol)
    .bind(rec.started_at)
    .bind(rec.ended_at)
    .bind(duration)
    .bind(rec.bytes_sent)
    .bind(rec.bytes_received)
    .bind(rec.status.as_str())
    .execute(&mut **tx)
    .await?;
    Ok(())
}
