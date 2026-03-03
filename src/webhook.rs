use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;

/// Webhook event types
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event: String,
    pub timestamp: i64,
    pub data: serde_json::Value,
}

/// Send a webhook notification (fire-and-forget)
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
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build();
        let client = match client {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create HTTP client for webhook: {}", e);
                return;
            }
        };
        match client
            .post(&url)
            .json(&payload)
            .header("Content-Type", "application/json")
            .header("User-Agent", "crabby-proxy-webhook/1.0")
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    tracing::debug!("Webhook sent: {} -> {}", event, url);
                } else {
                    tracing::warn!(
                        "Webhook failed: {} -> {} (status: {})",
                        event,
                        url,
                        resp.status()
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Webhook error: {} -> {} ({})", event, url, e);
            }
        }
    });
}
