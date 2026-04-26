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
        let conn = ConnectionManager::new(client).await?;
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

/// Start the subscriber loop as a background task.
/// Listens for events on the Redis channel and applies state changes.
pub async fn start_subscriber(
    redis_url: &str,
    prefix: &str,
    state: Arc<crate::app_state::AppState>,
) {
    let channel = format!("{}events", prefix);

    // Connect with a dedicated client (pub/sub needs its own connection)
    let client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Event bus subscriber failed to connect: {}", e);
            return;
        }
    };

    let mut pubsub_conn = match client.get_async_pubsub().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Event bus subscriber failed to get pubsub: {}", e);
            return;
        }
    };

    if let Err(e) = pubsub_conn.subscribe(&channel).await {
        tracing::warn!("Event bus subscriber failed to subscribe: {}", e);
        return;
    }

    tracing::info!("Event bus subscriber listening on channel: {}", channel);

    let mut msg_stream = pubsub_conn.into_on_message();
    use futures_lite::StreamExt;

    while let Some(msg) = msg_stream.next().await {
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

        match event {
            ProxyEvent::ConfigReloaded => {
                tracing::info!("Event bus: config reload requested by another instance");
                if let Some(ref path) = state.config_path {
                    match crate::config::Config::from_file(path) {
                        Ok(new_config) => {
                            state.config.store(Arc::new(new_config));
                            tracing::info!("Event bus: config reloaded from {}", path);
                        }
                        Err(e) => {
                            tracing::error!("Event bus: failed to reload config: {}", e);
                        }
                    }
                }
            }
            ProxyEvent::UserInvalidated(user_id) => {
                tracing::debug!("Event bus: invalidating caches for user {}", user_id);
                if let Some(cached) = state.cached_user_by_id(user_id).await {
                    if let Some(ref cache) = state.cache {
                        cache.invalidate_user(user_id, &cached.username).await;
                    }
                }
                // Clear rate limit cache too
                state.user_rate_limiter.invalidate_user(user_id).await;
            }
            ProxyEvent::UserDeleted(user_id) => {
                tracing::info!("Event bus: user {} deleted, full cache cleanup", user_id);
                if let Some(cached) = state.cached_user_by_id(user_id).await {
                    if let Some(ref cache) = state.cache {
                        cache.invalidate_user(user_id, &cached.username).await;
                        cache.invalidate_api_keys_for_user(user_id).await;
                        cache.invalidate_approvals_for_user(user_id).await;
                        cache.invalidate_quota(user_id).await;
                    }
                }
                state.user_rate_limiter.invalidate_user(user_id).await;
                state.quota_cache.remove(&user_id);
            }
            ProxyEvent::IpFilterUpdated => {
                tracing::info!("Event bus: IP filter update received");
                // IP filter is re-read from config on next access
                // Config was already reloaded via ConfigReloaded event
            }
        }
    }

    tracing::info!("Event bus subscriber loop ended");
}
