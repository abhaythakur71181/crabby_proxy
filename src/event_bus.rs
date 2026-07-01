//! Redis pub/sub event bus for cross-instance coordination.
//!
//! Publishes events (config reload, user invalidation, IP filter changes) to a
//! Redis channel. A background subscriber loop listens and applies changes to
//! the local `AppState`.
//!
//! Gracefully disabled when Redis is unavailable (single-instance fallback).

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Events that can be published across instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyEvent {
    /// Config file was reloaded — other instances should re-read
    ConfigReloaded,
    /// A user's data changed — invalidate caches for this user_id
    UserInvalidated(i64),
    /// A user was deleted — full cleanup
    UserDeleted(i64),
    /// IP filter rules changed — re-read from config
    IpFilterUpdated,
}

/// Publisher half of the event bus.
#[derive(Clone)]
pub struct EventBus {
    conn: ConnectionManager,
    channel: String,
}

impl EventBus {
    /// Create a new event bus publisher.
    pub async fn new(redis_url: &str, prefix: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let client = redis::Client::open(redis_url)?;
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ConnectionManager::new(client),
        )
        .await??;
        let channel = format!("{}events", prefix);
        tracing::info!("Event bus publisher connected (channel: {})", channel);
        Ok(Self { conn, channel })
    }

    /// Publish an event to all subscribers.
    pub async fn publish(&self, event: &ProxyEvent) {
        let mut conn = self.conn.clone();
        if let Ok(json) = serde_json::to_string(event) {
            let result: Result<(), _> = conn.publish(&self.channel, &json).await;
            if let Err(e) = result {
                tracing::warn!("Failed to publish event: {}", e);
            }
        }
    }
}

/// Reconnect backoff bounds for the subscriber loop.
const RECONNECT_MIN: std::time::Duration = std::time::Duration::from_secs(1);
const RECONNECT_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// Start the subscriber loop as a background task.
///
/// Wrapped in an outer reconnect loop: a transient Redis outage (or the
/// pub/sub stream ending) used to terminate the subscriber permanently, which
/// silently stopped cross-instance cache invalidation until restart. Now it
/// reconnects with capped exponential backoff and only exits on shutdown.
pub async fn start_subscriber(
    redis_url: &str,
    prefix: &str,
    state: Arc<crate::app_state::AppState>,
) {
    let channel = format!("{}events", prefix);
    let mut shutdown_rx = state.shutdown_tx.subscribe();
    let mut backoff = RECONNECT_MIN;

    loop {
        match run_subscriber_once(redis_url, &channel, &state, &mut shutdown_rx).await {
            SubscriberExit::Shutdown => {
                tracing::info!("Event bus subscriber: shutdown signal received");
                break;
            }
            SubscriberExit::Disconnected(reason) => {
                tracing::warn!(
                    "Event bus subscriber disconnected ({}); reconnecting in {:?}",
                    reason,
                    backoff
                );
                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(RECONNECT_MAX);
                continue;
            }
        }
    }
    tracing::info!("Event bus subscriber loop ended");
}

enum SubscriberExit {
    Shutdown,
    Disconnected(String),
}

/// One connect→subscribe→consume cycle. Returns when the connection drops
/// (reconnect) or shutdown is signaled. On a clean message run, `backoff` resets
/// implicitly because the caller only grows it between failures.
async fn run_subscriber_once(
    redis_url: &str,
    channel: &str,
    state: &Arc<crate::app_state::AppState>,
    shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
) -> SubscriberExit {
    let client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => return SubscriberExit::Disconnected(format!("client open: {e}")),
    };
    let mut pubsub_conn = match client.get_async_pubsub().await {
        Ok(c) => c,
        Err(e) => return SubscriberExit::Disconnected(format!("pubsub connect: {e}")),
    };
    if let Err(e) = pubsub_conn.subscribe(channel).await {
        return SubscriberExit::Disconnected(format!("subscribe: {e}"));
    }

    tracing::info!("Event bus subscriber listening on channel: {}", channel);

    let mut msg_stream = pubsub_conn.into_on_message();
    use futures_lite::StreamExt;

    loop {
        let msg = tokio::select! {
            biased;
            _ = shutdown_rx.recv() => return SubscriberExit::Shutdown,
            next = msg_stream.next() => match next {
                Some(m) => m,
                None => return SubscriberExit::Disconnected("stream ended".to_string()),
            },
        };
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Event bus: invalid message payload: {}", e);
                continue;
            }
        };
        let event: ProxyEvent = match serde_json::from_str(&payload) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Event bus: failed to deserialize event: {}", e);
                continue;
            }
        };
        tracing::debug!("Event bus received: {:?}", event);
        apply_event(event, state).await;
    }
}

/// Apply a received event to local state.
async fn apply_event(event: ProxyEvent, state: &Arc<crate::app_state::AppState>) {
    match event {
        ProxyEvent::ConfigReloaded => {
            tracing::info!("Event bus: config reload requested by another instance");
            // Route through reload_config so the same security-critical-field
            // preservation (M3) applies cross-instance.
            if let Err(e) = state.reload_config().await {
                tracing::error!("Event bus: failed to reload config: {}", e);
            }
        }
        ProxyEvent::UserInvalidated(user_id) | ProxyEvent::UserDeleted(user_id) => {
            tracing::debug!("Event bus: invalidating caches for user {}", user_id);
            let username = state
                .cached_user_by_id(user_id)
                .await
                .map(|cu| cu.username.clone());
            state
                .invalidate_all_for_user(user_id, username.as_deref())
                .await;
        }
        ProxyEvent::IpFilterUpdated => {
            tracing::info!("Event bus: IP filter update received");
            // IP filter is re-read from config on next access.
        }
    }
}
