use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::app_state::AppState;

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub version: String,
}

#[derive(Serialize, Deserialize)]
pub struct StatsResponse {
    pub uptime_seconds: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_bandwidth: u64,
}

pub async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        uptime_seconds: state.uptime().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Deep health check that verifies database and state backend connectivity.
#[derive(Serialize)]
pub struct DeepHealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub version: String,
    pub checks: HealthChecks,
}

#[derive(Serialize)]
pub struct HealthChecks {
    pub database: ComponentHealth,
    pub state_backend: ComponentHealth,
    pub dns_cache: ComponentHealth,
}

#[derive(Serialize)]
pub struct ComponentHealth {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// GET /api/health/deep — Verify connectivity to all backing services.
pub async fn deep_health_check(State(state): State<Arc<AppState>>) -> Json<DeepHealthResponse> {
    // Check SQLite
    let db_health = match sqlx::query("SELECT 1")
        .fetch_one(&state.db_pool)
        .await
    {
        Ok(_) => ComponentHealth {
            status: "ok".to_string(),
            detail: None,
        },
        Err(e) => ComponentHealth {
            status: "error".to_string(),
            detail: Some(e.to_string()),
        },
    };

    // Check state backend (memory or Redis)
    let state_health = match state.state.count_connections().await {
        Ok(_) => ComponentHealth {
            status: "ok".to_string(),
            detail: None,
        },
        Err(e) => ComponentHealth {
            status: "error".to_string(),
            detail: Some(e.to_string()),
        },
    };

    // Check DNS cache
    let (dns_entries, dns_addrs) = state.dns_cache.stats();
    let dns_health = ComponentHealth {
        status: "ok".to_string(),
        detail: Some(format!("{} entries, {} addresses cached", dns_entries, dns_addrs)),
    };

    let all_ok = db_health.status == "ok" && state_health.status == "ok";

    Json(DeepHealthResponse {
        status: if all_ok {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        uptime_seconds: state.uptime().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        checks: HealthChecks {
            database: db_health,
            state_backend: state_health,
            dns_cache: dns_health,
        },
    })
}

/// Server statistics endpoint
pub async fn stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let active_count = state.state.count_connections().await.unwrap_or(0);
    let total_count = state
        .state
        .get_counter("total_connections")
        .await
        .unwrap_or(0);

    // Read bandwidth from Prometheus counters
    let bytes_sent = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["sent"])
        .get() as u64;
    let bytes_received = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["received"])
        .get() as u64;

    Json(StatsResponse {
        uptime_seconds: state.uptime().as_secs(),
        active_connections: active_count,
        total_connections: total_count,
        total_bytes_sent: bytes_sent,
        total_bytes_received: bytes_received,
        total_bandwidth: bytes_sent + bytes_received,
    })
}

/// Aggregate dashboard response
#[derive(Serialize)]
pub struct DashboardResponse {
    // System
    pub uptime_seconds: u64,
    pub version: String,
    pub status: String,
    // Connections
    pub active_connections: usize,
    pub total_connections: u64,
    // Bandwidth
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bandwidth: u64,
    // Usage (last 24h)
    pub bandwidth_24h: Option<i64>,
    pub connections_24h: Option<i64>,
    // Users
    pub total_users: i64,
    pub top_users_24h: Vec<TopUserDashboard>,
    // Tunnels
    pub active_tunnels: usize,
}

#[derive(Serialize)]
pub struct TopUserDashboard {
    pub user_id: i64,
    pub bandwidth: i64,
    pub connections: i64,
}

/// GET /api/dashboard — Aggregate dashboard data in a single call
pub async fn dashboard(State(state): State<Arc<AppState>>) -> Json<DashboardResponse> {
    let active_count = state.state.count_connections().await.unwrap_or(0);
    let total_count = state
        .state
        .get_counter("total_connections")
        .await
        .unwrap_or(0);
    let bytes_sent = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["sent"])
        .get() as u64;
    let bytes_received = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["received"])
        .get() as u64;
    // 24h usage stats
    let (bandwidth_24h, connections_24h) =
        match crate::db::usage::get_system_usage_stats(&state.db_pool, 1).await {
            Ok(stats) => (Some(stats.total_bandwidth), Some(stats.total_connections)),
            Err(_) => (None, None),
        };
    // Top users by bandwidth (24h, top 5)
    let top_users_24h =
        match crate::db::usage::get_top_users_by_bandwidth(&state.db_pool, 1, 5).await {
            Ok(users) => users
                .into_iter()
                .map(|u| TopUserDashboard {
                    user_id: u.user_id,
                    bandwidth: u.total_bandwidth,
                    connections: u.connection_count,
                })
                .collect(),
            Err(_) => vec![],
        };
    // Total users
    let total_users = match crate::db::users::count_users(&state.db_pool).await {
        Ok(count) => count,
        Err(_) => 0,
    };
    // Active tunnels
    let active_tunnels = state.tunnels.read().await.count_active();
    Json(DashboardResponse {
        uptime_seconds: state.uptime().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: "healthy".to_string(),
        active_connections: active_count,
        total_connections: total_count,
        bytes_sent,
        bytes_received,
        total_bandwidth: bytes_sent + bytes_received,
        bandwidth_24h,
        connections_24h,
        total_users,
        top_users_24h,
        active_tunnels,
    })
}

/// Structured JSON metrics response for the UI
#[derive(Serialize)]
pub struct JsonMetricsResponse {
    pub active_by_protocol: HashMap<String, i64>,
    pub bytes_transferred: BytesTransferred,
    pub requests_total: RequestsTotal,
    pub auth_failures_by_reason: HashMap<String, u64>,
    pub ip_filter: IpFilterStats,
    pub rate_limit_exceeded: RateLimitStats,
    pub connection_duration_p50: f64,
    pub connection_duration_p95: f64,
    pub connection_duration_p99: f64,
    pub draining: bool,
    pub draining_connections: i64,
}

#[derive(Serialize)]
pub struct BytesTransferred {
    pub sent: u64,
    pub received: u64,
}

#[derive(Serialize)]
pub struct RequestsTotal {
    pub success: u64,
    pub failed: u64,
}

#[derive(Serialize)]
pub struct IpFilterStats {
    pub allowed: u64,
    pub blocked: u64,
}

#[derive(Serialize)]
pub struct RateLimitStats {
    pub ip: u64,
    pub user: u64,
}

/// GET /api/metrics — Structured JSON metrics for the dashboard UI
pub async fn json_metrics(State(_state): State<Arc<AppState>>) -> Json<JsonMetricsResponse> {
    use prometheus::proto::MetricType;

    // Collect active connections by protocol
    let mut active_by_protocol = HashMap::new();
    let families = prometheus::gather();
    for fam in &families {
        if fam.get_name() == "proxy_active_connections" {
            for m in fam.get_metric() {
                let protocol = m.get_label().iter()
                    .find(|l| l.get_name() == "protocol")
                    .map(|l| l.get_value().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let val = m.get_gauge().get_value() as i64;
                if val != 0 {
                    active_by_protocol.insert(protocol, val);
                }
            }
        }
    }

    // Bytes transferred
    let bytes_sent = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["sent"])
        .get() as u64;
    let bytes_received = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["received"])
        .get() as u64;

    // Requests total
    let mut success: u64 = 0;
    let mut failed: u64 = 0;
    for fam in &families {
        if fam.get_name() == "proxy_requests_total" {
            for m in fam.get_metric() {
                let status = m.get_label().iter()
                    .find(|l| l.get_name() == "status")
                    .map(|l| l.get_value())
                    .unwrap_or("unknown");
                let val = m.get_counter().get_value() as u64;
                if status == "success" {
                    success += val;
                } else {
                    failed += val;
                }
            }
        }
    }

    // Auth failures by reason
    let mut auth_failures_by_reason = HashMap::new();
    for fam in &families {
        if fam.get_name() == "proxy_auth_failures_total" {
            for m in fam.get_metric() {
                let reason = m.get_label().iter()
                    .find(|l| l.get_name() == "reason")
                    .map(|l| l.get_value().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let val = m.get_counter().get_value() as u64;
                if val > 0 {
                    auth_failures_by_reason.insert(reason, val);
                }
            }
        }
    }

    // IP filter stats
    let ip_allowed = crate::metrics::IP_FILTER_ACTIONS
        .with_label_values(&["allowed"])
        .get() as u64;
    let ip_blocked = crate::metrics::IP_FILTER_ACTIONS
        .with_label_values(&["blocked"])
        .get() as u64;

    // Rate limit stats
    let rl_ip = crate::metrics::RATE_LIMIT_EXCEEDED
        .with_label_values(&["ip"])
        .get() as u64;
    let rl_user = crate::metrics::RATE_LIMIT_EXCEEDED
        .with_label_values(&["user"])
        .get() as u64;

    // Connection duration percentiles from histogram
    let (p50, p95, p99) = {
        let mut p50 = 0.0_f64;
        let mut p95 = 0.0_f64;
        let mut p99 = 0.0_f64;
        for fam in &families {
            if fam.get_name() == "proxy_connection_duration_seconds" && fam.get_field_type() == MetricType::HISTOGRAM {
                // Aggregate across all protocols
                let mut total_count: u64 = 0;
                let mut buckets: Vec<(f64, u64)> = Vec::new();
                for m in fam.get_metric() {
                    let h = m.get_histogram();
                    total_count += h.get_sample_count();
                    for (i, b) in h.get_bucket().iter().enumerate() {
                        if i >= buckets.len() {
                            buckets.push((b.get_upper_bound(), b.get_cumulative_count()));
                        } else {
                            buckets[i].1 += b.get_cumulative_count();
                        }
                    }
                }
                if total_count > 0 {
                    for (upper, cum) in &buckets {
                        let pct = *cum as f64 / total_count as f64;
                        if pct >= 0.5 && p50 == 0.0 { p50 = *upper; }
                        if pct >= 0.95 && p95 == 0.0 { p95 = *upper; }
                        if pct >= 0.99 && p99 == 0.0 { p99 = *upper; }
                    }
                }
            }
        }
        (p50, p95, p99)
    };

    let draining = crate::metrics::DRAINING.get() != 0;
    let draining_connections = crate::metrics::DRAINING_CONNECTIONS.get();

    Json(JsonMetricsResponse {
        active_by_protocol,
        bytes_transferred: BytesTransferred { sent: bytes_sent, received: bytes_received },
        requests_total: RequestsTotal { success, failed },
        auth_failures_by_reason,
        ip_filter: IpFilterStats { allowed: ip_allowed, blocked: ip_blocked },
        rate_limit_exceeded: RateLimitStats { ip: rl_ip, user: rl_user },
        connection_duration_p50: p50,
        connection_duration_p95: p95,
        connection_duration_p99: p99,
        draining,
        draining_connections,
    })
}
