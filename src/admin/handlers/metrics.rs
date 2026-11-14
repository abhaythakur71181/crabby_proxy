use crate::app_state::AppState;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// Prometheus metrics endpoint.
///
/// When `[metrics] scrape_token` is set, the scraper must send
/// `Authorization: Bearer <scrape_token>`; otherwise the endpoint stays open
/// (backwards compatible) and the admin server logs a warning at boot if it
/// is bound to a non-loopback address.
pub async fn prometheus_metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let expected = state.config.load().metrics.scrape_token.clone();
    if let Some(expected) = expected.filter(|t| !t.is_empty()) {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("");
        if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer realm=\"metrics\"")],
            )
                .into_response();
        }
    }
    let metrics_output = crate::metrics::export_metrics();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics_output,
    )
        .into_response()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether `/metrics` is reachable without credentials from beyond the host:
/// no scrape token configured and the admin API bound to a non-loopback
/// address (an unparsable bind is treated as exposed).
pub fn metrics_exposed_without_auth(admin_bind: &str, scrape_token: Option<&str>) -> bool {
    if scrape_token.is_some_and(|t| !t.is_empty()) {
        return false;
    }
    match admin_bind.parse::<std::net::SocketAddr>() {
        Ok(addr) => !addr.ip().is_loopback(),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_check() {
        assert!(!metrics_exposed_without_auth("127.0.0.1:8081", None));
        assert!(!metrics_exposed_without_auth("[::1]:8081", None));
        assert!(metrics_exposed_without_auth("0.0.0.0:8081", None));
        assert!(metrics_exposed_without_auth("0.0.0.0:8081", Some("")));
        assert!(!metrics_exposed_without_auth("0.0.0.0:8081", Some("tok")));
        assert!(metrics_exposed_without_auth("not-an-addr", None));
    }

    #[test]
    fn ct_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
