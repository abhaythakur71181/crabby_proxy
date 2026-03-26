use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;

/// Maximum number of retry attempts for failed webhook deliveries.
const MAX_RETRIES: u32 = 3;

/// Base delay between retries (doubles each attempt: 1s, 2s, 4s).
const BASE_RETRY_DELAY_SECS: u64 = 1;

lazy_static::lazy_static! {
    /// Shared HTTP client for webhook deliveries (reuses connections and DNS cache).
    static ref WEBHOOK_CLIENT: reqwest::Client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .pool_max_idle_per_host(2)
        .build()
        .expect("Failed to create webhook HTTP client");
}

/// Webhook event types
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event: String,
    pub timestamp: i64,
    pub data: serde_json::Value,
}

/// Send a webhook notification with retry on failure (fire-and-forget).
/// Retries up to 3 times with exponential backoff (1s, 2s, 4s).
pub fn send_webhook(config: Arc<RwLock<Config>>, event: &str, data: serde_json::Value) {
    let event = event.to_string();
    tokio::spawn(async move {
        let config = config.read().await;
        let url = match &config.features.webhook_url {
            Some(url) if !url.is_empty() => url.clone(),
            _ => return,
        };
        // Check if this event type is enabled
        if !config.features.webhook_events.is_empty()
            && !config.features.webhook_events.iter().any(|e| e == &event)
        {
            return;
        }
        drop(config);
        let payload = WebhookPayload {
            event: event.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            data,
        };

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay = std::time::Duration::from_secs(
                    BASE_RETRY_DELAY_SECS * 2u64.pow(attempt - 1),
                );
                tracing::debug!(
                    "Webhook retry {}/{} for {} -> {} (delay: {:?})",
                    attempt,
                    MAX_RETRIES,
                    event,
                    url,
                    delay
                );
                tokio::time::sleep(delay).await;
            }

            match WEBHOOK_CLIENT
                .post(&url)
                .json(&payload)
                .header("Content-Type", "application/json")
                .header("User-Agent", "crabby-proxy-webhook/1.0")
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if attempt > 0 {
                        tracing::info!(
                            "Webhook sent (after {} retries): {} -> {}",
                            attempt,
                            event,
                            url
                        );
                    } else {
                        tracing::debug!("Webhook sent: {} -> {}", event, url);
                    }
                    return; // Success, done
                }
                Ok(resp) => {
                    let status = resp.status();
                    // Don't retry client errors (4xx) except 429
                    if status.is_client_error() && status.as_u16() != 429 {
                        tracing::warn!(
                            "Webhook rejected ({}): {} -> {} — not retrying",
                            status,
                            event,
                            url
                        );
                        return;
                    }
                    tracing::warn!(
                        "Webhook failed (attempt {}/{}): {} -> {} (status: {})",
                        attempt + 1,
                        MAX_RETRIES + 1,
                        event,
                        url,
                        status
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Webhook error (attempt {}/{}): {} -> {} ({})",
                        attempt + 1,
                        MAX_RETRIES + 1,
                        event,
                        url,
                        e
                    );
                }
            }
        }

        tracing::error!(
            "Webhook delivery failed after {} attempts: {} -> {}",
            MAX_RETRIES + 1,
            event,
            url
        );
    });
}
