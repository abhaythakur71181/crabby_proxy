use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
    Encoder, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, TextEncoder,
};

lazy_static! {
    /// Active connections by protocol
    pub static ref ACTIVE_CONNECTIONS: IntGaugeVec = register_int_gauge_vec!(
        "proxy_active_connections",
        "Number of currently active proxy connections",
        &["protocol"]
    )
    .unwrap();

    /// Total requests by protocol and status
    pub static ref REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "proxy_requests_total",
        "Total number of proxy requests",
        &["protocol", "status"]
    )
    .unwrap();

    /// Authentication results
    pub static ref AUTH_TOTAL: IntCounterVec = register_int_counter_vec!(
        "proxy_auth_total",
        "Total authentication attempts",
        &["protocol", "result"]
    )
    .unwrap();

    /// Bytes transferred
    pub static ref BYTES_TRANSFERRED: IntCounterVec = register_int_counter_vec!(
        "proxy_bytes_transferred_total",
        "Total bytes transferred",
        &["direction"] // "sent" or "received"
    )
    .unwrap();

    /// IP filter actions
    pub static ref IP_FILTER_ACTIONS: IntCounterVec = register_int_counter_vec!(
        "proxy_ip_filter_actions_total",
        "Total IP filter actions",
        &["action"] // "allowed" or "blocked"
    )
    .unwrap();

    /// Rate limit exceeded events
    pub static ref RATE_LIMIT_EXCEEDED: IntCounterVec = register_int_counter_vec!(
        "proxy_rate_limit_exceeded_total",
        "Total rate limit exceeded events",
        &["type"] // "ip" or "user"
    )
    .unwrap();

    /// Authentication failures
    pub static ref AUTH_FAILURES: IntCounterVec = register_int_counter_vec!(
        "proxy_auth_failures_total",
        "Total authentication failures",
        &["reason"] // "invalid_credentials", "socks4_disabled", etc.
    )
    .unwrap();

    /// Connection duration histogram (seconds)
    pub static ref CONNECTION_DURATION: HistogramVec = register_histogram_vec!(
        "proxy_connection_duration_seconds",
        "Duration of proxy connections in seconds",
        &["protocol"],
        vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0]
    )
    .unwrap();

    /// Connection setup latency (seconds) — auth + target parsing
    pub static ref CONNECTION_SETUP_DURATION: HistogramVec = register_histogram_vec!(
        "proxy_connection_setup_seconds",
        "Time to authenticate and parse target",
        &["protocol"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0]
    )
    .unwrap();

    /// Upstream connect latency (seconds)
    pub static ref UPSTREAM_CONNECT_DURATION: HistogramVec = register_histogram_vec!(
        "proxy_upstream_connect_seconds",
        "Time to connect to upstream target",
        &["protocol"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 10.0]
    )
    .unwrap();

    /// Whether the proxy is currently draining (1 = draining, 0 = normal)
    pub static ref DRAINING: IntGauge = register_int_gauge!(
        "proxy_draining",
        "Whether the proxy is in shutdown drain mode (1 = draining)"
    )
    .unwrap();

    /// Connections still active during shutdown drain
    pub static ref DRAINING_CONNECTIONS: IntGauge = register_int_gauge!(
        "proxy_draining_connections",
        "Number of connections remaining during shutdown drain"
    )
    .unwrap();
}

/// Export all metrics in Prometheus format.
/// Returns an empty string if encoding fails (instead of panicking).
pub fn export_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!("Failed to encode Prometheus metrics: {}", e);
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_else(|e| {
        tracing::error!("Prometheus metrics produced invalid UTF-8: {}", e);
        String::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        // Just accessing the metrics should not panic
        let _ = &*ACTIVE_CONNECTIONS;
        let _ = &*REQUESTS_TOTAL;
        let _ = &*AUTH_TOTAL;
        let _ = &*BYTES_TRANSFERRED;
        let _ = &*IP_FILTER_ACTIONS;
    }

    #[test]
    fn test_active_connections_gauge() {
        // Test increment and decrement
        ACTIVE_CONNECTIONS.with_label_values(&["http"]).inc();
        ACTIVE_CONNECTIONS.with_label_values(&["http"]).inc();
        ACTIVE_CONNECTIONS.with_label_values(&["http"]).dec();

        // Can't easily assert exact value due to global state,
        // but we can verify it doesn't panic
    }

    #[test]
    fn test_requests_total_counter() {
        // Test incrementing
        REQUESTS_TOTAL.with_label_values(&["http", "success"]).inc();
        REQUESTS_TOTAL.with_label_values(&["https", "failed"]).inc();

        // Verify no panic
    }

    #[test]
    fn test_auth_total_counter() {
        AUTH_TOTAL.with_label_values(&["socks5", "success"]).inc();
        AUTH_TOTAL.with_label_values(&["socks5", "failed"]).inc();
    }

    #[test]
    fn test_ip_filter_actions_counter() {
        IP_FILTER_ACTIONS.with_label_values(&["allowed"]).inc();
        IP_FILTER_ACTIONS.with_label_values(&["blocked"]).inc();
    }

    #[test]
    fn test_export_metrics() {
        // Record some metrics
        ACTIVE_CONNECTIONS.with_label_values(&["test"]).inc();
        REQUESTS_TOTAL.with_label_values(&["test", "success"]).inc();

        let output = export_metrics();

        // Should be in Prometheus format
        assert!(output.contains("proxy_active_connections"));
        assert!(output.contains("proxy_requests_total"));
        assert!(output.contains("TYPE"));
        assert!(output.contains("HELP"));
    }
}
