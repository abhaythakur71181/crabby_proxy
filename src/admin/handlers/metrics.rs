use crate::app_state::AppState;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// How `/metrics` may be scraped under the current config (#22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricsAccess {
    /// `[metrics] scrape_token` is set: require `Authorization: Bearer <token>`.
    Token(String),
    /// No token, but the admin API is on loopback (or the operator opted in
    /// with `allow_unauthenticated = true`): serve without credentials.
    Open,
    /// No token, a non-loopback admin bind and no opt-in: refuse to serve.
    Refused,
}

/// Decide how `/metrics` may be scraped. Secure by default: without a scrape
/// token the endpoint only answers when the admin API is bound to loopback,
/// unless `allow_unauthenticated` explicitly opts out. An unparsable bind
/// counts as exposed.
pub fn metrics_access(
    admin_bind: &str,
    scrape_token: Option<&str>,
    allow_unauthenticated: bool,
) -> MetricsAccess {
    if let Some(token) = scrape_token.filter(|t| !t.is_empty()) {
        return MetricsAccess::Token(token.to_string());
    }
    if allow_unauthenticated || crate::config_env::is_loopback_bind(admin_bind) {
        MetricsAccess::Open
    } else {
        MetricsAccess::Refused
    }
}

/// Prometheus metrics endpoint. See [`metrics_access`] for the access rules.
pub async fn prometheus_metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let access = {
        let config = state.config.load();
        metrics_access(
            &config.server.admin_bind,
            config.metrics.scrape_token.as_deref(),
            config.metrics.allow_unauthenticated,
        )
    };
    match access {
        MetricsAccess::Open => {}
        MetricsAccess::Token(expected) => {
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
        MetricsAccess::Refused => {
            return (
                StatusCode::FORBIDDEN,
                "metrics disabled: the admin API is not bound to loopback and no \
                 [metrics] scrape_token is set (or set [metrics] allow_unauthenticated = true)\n",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_rules() {
        let tok = ["scrape", "tok"].join("-");
        let open = MetricsAccess::Open;
        let refused = MetricsAccess::Refused;
        // Loopback without a token stays open (local setups keep working).
        assert_eq!(metrics_access("127.0.0.1:8081", None, false), open);
        assert_eq!(metrics_access("[::1]:8081", None, false), open);
        assert_eq!(metrics_access("localhost:8081", None, false), open);
        // Non-loopback without a token is refused unless opted in.
        assert_eq!(metrics_access("0.0.0.0:8081", None, false), refused);
        assert_eq!(metrics_access("0.0.0.0:8081", Some(""), false), refused);
        assert_eq!(metrics_access("not-an-addr", None, false), refused);
        assert_eq!(metrics_access("0.0.0.0:8081", None, true), open);
        // A token always applies, on any bind.
        assert_eq!(
            metrics_access("0.0.0.0:8081", Some(&tok), false),
            MetricsAccess::Token(tok.clone())
        );
        assert_eq!(
            metrics_access("127.0.0.1:8081", Some(&tok), true),
            MetricsAccess::Token(tok)
        );
    }

    #[test]
    fn ct_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
