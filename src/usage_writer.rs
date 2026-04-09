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

const CHANNEL_CAPACITY: usize = 4096;

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
    pub status: String,
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
            while let Some(rec) = rx.recv().await {
                if let Err(e) = crate::db::usage::record_usage(
                    &pool,
                    rec.user_id,
                    &rec.connection_id,
                    &rec.client_ip,
                    &rec.target_host,
                    &rec.protocol,
                    rec.started_at,
                    rec.ended_at,
                    rec.bytes_sent,
                    rec.bytes_received,
                    &rec.status,
                )
                .await
                {
                    tracing::error!(
                        "usage_writer: failed to record usage for user {}: {}",
                        rec.user_id,
                        e
                    );
                }
            }
            tracing::info!("usage_writer: channel closed, writer task exiting");
        });
        Self { tx }
    }

    /// Try to enqueue a record. Drops + counts when the channel is full so
    /// the cleanup path never blocks the relay loop.
    pub fn submit(&self, rec: UsageRecord) {
        if let Err(e) = self.tx.try_send(rec) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    crate::metrics::USAGE_RECORDS_DROPPED.inc();
                    tracing::warn!("usage_writer: channel full, dropping usage record");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    crate::metrics::USAGE_RECORDS_DROPPED.inc();
                    tracing::error!("usage_writer: channel closed, dropping usage record");
                }
            }
        }
    }
}
