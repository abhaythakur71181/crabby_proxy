use lazy_static::lazy_static;
use prometheus::{
    register_int_counter_vec, register_int_gauge_vec, Encoder, IntCounterVec, IntGaugeVec,
    TextEncoder,
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
}

/// Export all metrics in Prometheus format
pub fn export_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
