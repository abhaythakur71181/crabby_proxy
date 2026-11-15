use arc_swap::ArcSwap;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::config::Config;

/// Maximum number of retry attempts for failed webhook deliveries.
const MAX_RETRIES: u32 = 3;

/// Base delay between retries (doubles each attempt: 1s, 2s, 4s).
const BASE_RETRY_DELAY_SECS: u64 = 1;

/// Per-request timeout for webhook deliveries.
const WEBHOOK_TIMEOUT_SECS: u64 = 30;

/// Payload keys that carry per-connection personal data (client addresses and
/// browsing destinations). They are stripped from webhook payloads unless the
/// operator sets `features.webhook_include_pii = true` (#58).
const PII_KEYS: &[&str] = &[
    "client_ip",
    "client_addr",
    "ip",
    "source_ip",
    "target",
    "target_host",
    "target_addr",
    "destination",
    "host",
    "url",
];

/// Webhook event types
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event: String,
    pub timestamp: i64,
    pub data: serde_json::Value,
}

/// Validate a configured webhook URL (#58): it must parse, use `https`, carry
/// no userinfo, and — unless `allow_private` — must not name a literal
/// internal / non-routable address or `localhost`. Hostnames are additionally
/// resolved and checked at delivery time (see [`resolve_vetted`]).
pub fn validate_webhook_url(url: &str, allow_private: bool) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    if parsed.scheme() != "https" {
        return Err(format!(
            "scheme must be https (got '{}'): webhook payloads must not travel in cleartext",
            parsed.scheme()
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("credentials in the URL are not allowed".to_string());
    }
    let host = match parsed.host_str() {
        Some(h) if !h.is_empty() => h,
        _ => return Err("URL has no host".to_string()),
    };
    if !allow_private {
        // host_str() keeps brackets on IPv6 literals.
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            if crate::self_loop::is_blocked_egress(ip) {
                return Err(format!("address {ip} is internal / non-routable"));
            }
        } else {
            let d = bare.trim_end_matches('.').to_ascii_lowercase();
            if d == "localhost" || d.ends_with(".localhost") {
                return Err(format!("host '{d}' is internal"));
            }
        }
    }
    Ok(parsed)
}

/// Resolve the webhook host once and return an address that passed the SSRF
/// egress check. The client is then pinned to that address so a DNS answer
/// that changes between check and connect (rebinding) cannot redirect the
/// request to an internal service.
async fn resolve_vetted(url: &reqwest::Url, allow_private: bool) -> Result<SocketAddr, String> {
    let host = url.host_str().ok_or("URL has no host")?;
    let port = url.port_or_known_default().unwrap_or(443);
    // url keeps brackets on IPv6 literals in host_str(); strip for lookup.
    let lookup_host = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((lookup_host, port))
        .await
        .map_err(|e| format!("DNS resolution failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("DNS resolution returned no addresses".to_string());
    }
    if allow_private {
        return Ok(addrs[0]);
    }
    // Refuse if ANY answer is internal: a mixed answer is a classic rebinding
    // setup, and there is no legitimate reason for a public webhook endpoint
    // to also resolve to a private address.
    if let Some(bad) = addrs
        .iter()
        .find(|a| crate::self_loop::is_blocked_egress(a.ip()))
    {
        return Err(format!(
            "host resolves to internal / non-routable address {}",
            bad.ip()
        ));
    }
    Ok(addrs[0])
}

/// Remove per-connection PII (client addresses, destinations) from a payload,
/// recursively. User IDs are kept so the receiver can still act on the event.
pub fn scrub_pii(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|k, _| !PII_KEYS.contains(&k.to_ascii_lowercase().as_str()));
            for v in map.values_mut() {
                scrub_pii(v);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(scrub_pii),
        _ => {}
    }
}

/// Origin-only form of the URL for logs (paths often embed secret tokens).
fn redacted(url: &reqwest::Url) -> String {
    format!("{}://{}", url.scheme(), url.host_str().unwrap_or("?"))
}

/// Send a webhook notification with retry on failure (fire-and-forget).
/// Retries up to 3 times with exponential backoff (1s, 2s, 4s).
///
/// Delivery is refused (and logged) if the URL fails [`validate_webhook_url`]
/// or resolves to an internal address. Redirects are not followed. PII keys
/// are stripped from `data` unless `features.webhook_include_pii` is set.
pub fn send_webhook(config: Arc<ArcSwap<Config>>, event: &str, mut data: serde_json::Value) {
    let event = event.to_string();
    tokio::spawn(async move {
        let config = config.load();
        let raw_url = match &config.features.webhook_url {
            Some(url) if !url.is_empty() => url.clone(),
            _ => return,
        };
        // Check if this event type is enabled
        if !config.features.webhook_events.is_empty()
            && !config.features.webhook_events.iter().any(|e| e == &event)
        {
            return;
        }
        let allow_private = config.features.webhook_allow_private_targets;
        let include_pii = config.features.webhook_include_pii;
        drop(config);

        let url = match validate_webhook_url(&raw_url, allow_private) {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("Webhook not sent ({}): webhook_url rejected: {}", event, e);
                return;
            }
        };
        let target = redacted(&url);
        let addr = match resolve_vetted(&url, allow_private).await {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("Webhook not sent ({} -> {}): {}", event, target, e);
                return;
            }
        };
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(WEBHOOK_TIMEOUT_SECS))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .resolve(url.host_str().unwrap_or_default(), addr)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Webhook client build failed: {}", e);
                return;
            }
        };

        if !include_pii {
            scrub_pii(&mut data);
        }
        let payload = WebhookPayload {
            event: event.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            data,
        };

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay =
                    std::time::Duration::from_secs(BASE_RETRY_DELAY_SECS * 2u64.pow(attempt - 1));
                tracing::debug!(
                    "Webhook retry {}/{} for {} -> {} (delay: {:?})",
                    attempt,
                    MAX_RETRIES,
                    event,
                    target,
                    delay
                );
                tokio::time::sleep(delay).await;
            }

            match client
                .post(url.clone())
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
                            target
                        );
                    } else {
                        tracing::debug!("Webhook sent: {} -> {}", event, target);
                    }
                    return; // Success, done
                }
                Ok(resp) => {
                    let status = resp.status();
                    // Don't retry client errors (4xx) except 429, nor
                    // redirects (which are deliberately not followed).
                    if (status.is_client_error() && status.as_u16() != 429)
                        || status.is_redirection()
                    {
                        tracing::warn!(
                            "Webhook rejected ({}): {} -> {} — not retrying",
                            status,
                            event,
                            target
                        );
                        return;
                    }
                    tracing::warn!(
                        "Webhook failed (attempt {}/{}): {} -> {} (status: {})",
                        attempt + 1,
                        MAX_RETRIES + 1,
                        event,
                        target,
                        status
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Webhook error (attempt {}/{}): {} -> {} ({})",
                        attempt + 1,
                        MAX_RETRIES + 1,
                        event,
                        target,
                        e.without_url()
                    );
                }
            }
        }

        tracing::error!(
            "Webhook delivery failed after {} attempts: {} -> {}",
            MAX_RETRIES + 1,
            event,
            target
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_https() {
        assert!(validate_webhook_url("https://hooks.example.com/abc", false).is_ok());
        assert!(validate_webhook_url("https://8.8.8.8/hook", false).is_ok());
    }

    #[test]
    fn rejects_non_https() {
        assert!(validate_webhook_url("http://hooks.example.com/abc", false).is_err());
        assert!(validate_webhook_url("ftp://hooks.example.com/abc", false).is_err());
        assert!(validate_webhook_url("not a url", false).is_err());
        // https is required even when private targets are allowed.
        assert!(validate_webhook_url("http://10.0.0.1/", true).is_err());
    }

    #[test]
    fn rejects_internal_literals() {
        for u in [
            "https://127.0.0.1/",
            "https://10.1.2.3/",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[fd00::1]/",
            "https://localhost/",
            "https://api.localhost./",
        ] {
            assert!(
                validate_webhook_url(u, false).is_err(),
                "{u} must be rejected"
            );
        }
    }

    #[test]
    fn private_allowed_only_with_opt_in() {
        assert!(validate_webhook_url("https://10.1.2.3/", true).is_ok());
        assert!(validate_webhook_url("https://localhost/", true).is_ok());
    }

    #[test]
    fn rejects_userinfo() {
        assert!(validate_webhook_url("https://user:pw@hooks.example.com/", false).is_err());
    }

    #[test]
    fn scrub_removes_pii_recursively() {
        let mut v = serde_json::json!({
            "user_id": 7,
            "client_ip": "1.2.3.4",
            "Target_Host": "secret.example",
            "details": [{"client_addr": "1.2.3.4:5", "bytes": 10}],
        });
        scrub_pii(&mut v);
        assert_eq!(
            v,
            serde_json::json!({"user_id": 7, "details": [{"bytes": 10}]})
        );
    }

    #[test]
    fn redacted_drops_path_and_query() {
        let u = reqwest::Url::parse("https://hooks.example.com/T0K3N?sig=abc").unwrap();
        assert_eq!(redacted(&u), "https://hooks.example.com");
    }

    #[tokio::test]
    async fn resolve_rejects_internal_answer() {
        let u = reqwest::Url::parse("https://127.0.0.1/").unwrap();
        assert!(resolve_vetted(&u, false).await.is_err());
        assert!(resolve_vetted(&u, true).await.is_ok());
    }
}
