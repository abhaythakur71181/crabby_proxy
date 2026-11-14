use super::models::ApiError;
use crate::admin::auth::AdminUser;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;
use crate::connection::ServiceType;
use crate::tunnel::manager::TunnelLimits;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[derive(Serialize)]
pub struct TunnelsListResponse {
    pub tunnels: Vec<crate::tunnel::manager::TunnelInfo>,
    pub total: usize,
}

#[derive(Deserialize)]
pub struct CreateTunnelRequest {
    pub service_type: String,
    pub port: Option<u16>,
    pub target_addr: Option<String>,
}

/// List all active tunnels
pub async fn list_tunnels(
    _admin: AdminUser,
    State(state): State<Arc<AppState>>,
) -> Json<TunnelsListResponse> {
    let tunnels = state.tunnels.read().await;
    let active = tunnels.list_active();
    let total = active.len();
    Json(TunnelsListResponse {
        tunnels: active,
        total,
    })
}

/// Create a new tunnel (if enabled in config)
pub async fn create_tunnel(
    _admin: AdminUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTunnelRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let config = state.config.load();
    if !config.features.reverse_tunnels {
        return Err(ApiError::forbidden("Reverse tunnels are disabled"));
    }

    let service_type = match req.service_type.to_lowercase().as_str() {
        "http" | "https" | "web" => ServiceType::WebService,
        "ssh" => ServiceType::SshService,
        "postgres" => ServiceType::Database(crate::connection::DbType::Postgres),
        "mysql" => ServiceType::Database(crate::connection::DbType::MySQL),
        "redis" => ServiceType::Database(crate::connection::DbType::Redis),
        "mongodb" => ServiceType::Database(crate::connection::DbType::MongoDB),
        other => ServiceType::Custom(other.to_string()),
    };
    let target_addr: SocketAddr = req
        .target_addr
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("target_addr is required"))?
        .parse()
        .map_err(|_| ApiError::bad_request("Invalid target address"))?;
    validate_tunnel_target(target_addr, &config.features.tunnel_allowed_targets)
        .map_err(ApiError::bad_request)?;
    let bind_ip: IpAddr = config
        .features
        .tunnel_bind_addr
        .parse()
        .map_err(|_| ApiError::internal("Invalid features.tunnel_bind_addr"))?;
    let idle_secs = config.server.idle_timeout_secs;
    let limits = TunnelLimits {
        idle_timeout: (idle_secs > 0).then(|| std::time::Duration::from_secs(idle_secs)),
        max_connections: config.features.tunnel_max_connections,
    };
    drop(config);

    // Reserve the port under the lock, bind with the lock released (so a slow
    // bind never blocks other tunnel operations), then register.
    let port = state
        .tunnels
        .write()
        .await
        .reserve_port(req.port)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let listener = match tokio::net::TcpListener::bind(SocketAddr::new(bind_ip, port)).await {
        Ok(l) => l,
        Err(e) => {
            state.tunnels.write().await.release_reserved_port(port);
            tracing::error!("Failed to bind tunnel port {}: {}", port, e);
            return Err(ApiError::internal("Failed to create tunnel"));
        }
    };
    let result =
        state
            .tunnels
            .write()
            .await
            .register_tunnel(service_type, listener, target_addr, limits);
    match result {
        Ok(info) => {
            tracing::info!(
                target: "audit",
                listen_port = info.listen_port,
                target = %target_addr,
                "Created tunnel via admin API"
            );
            Ok((StatusCode::CREATED, Json(info)))
        }
        Err(e) => {
            state.tunnels.write().await.release_reserved_port(port);
            tracing::error!("Failed to create tunnel: {}", e);
            Err(ApiError::internal("Failed to create tunnel"))
        }
    }
}

/// Check a reverse-tunnel target (#18). A tunnel relays raw TCP to its
/// target, so an unrestricted target turns a leaked admin token into an SSRF
/// pivot (cloud metadata, localhost admin ports, internal databases).
///
/// * Port 0, unspecified, multicast and broadcast targets are always refused.
/// * With a non-empty `allowed` list, the target IP must match an entry
///   (CIDR or bare IP): a strict allow-list.
/// * With an empty list, internal/non-routable targets (loopback, private,
///   link-local, CGNAT, ULA, ...) are refused; public targets are allowed.
pub(crate) fn validate_tunnel_target(target: SocketAddr, allowed: &[String]) -> Result<(), String> {
    let ip = target.ip();
    if target.port() == 0 {
        return Err("target_addr port must be non-zero".into());
    }
    let always_bad = match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    };
    if always_bad {
        return Err(format!("target address {ip} is not a valid tunnel target"));
    }
    if !allowed.is_empty() {
        let listed = allowed
            .iter()
            .any(|entry| match entry.parse::<ipnet::IpNet>() {
                Ok(net) => net.contains(&ip),
                Err(_) => entry.parse::<IpAddr>().map(|a| a == ip).unwrap_or(false),
            });
        return if listed {
            Ok(())
        } else {
            Err(format!(
                "target {ip} is not in features.tunnel_allowed_targets"
            ))
        };
    }
    if crate::self_loop::is_blocked_egress(ip) {
        return Err(format!(
            "target {ip} is an internal address; add it to features.tunnel_allowed_targets to permit it"
        ));
    }
    Ok(())
}

/// Close a tunnel
pub async fn close_tunnel(
    _admin: AdminUser,
    State(state): State<Arc<AppState>>,
    Path(port): Path<u16>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tunnels = state.tunnels.write().await;
    match tunnels.close_tunnel(port).await {
        Ok(_) => {
            tracing::info!("Closed tunnel on port {}", port);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(_) => Err(ApiError::not_found(format!(
            "Tunnel on port {} not found",
            port
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_tunnel_target;

    fn check(addr: &str, allowed: &[&str]) -> Result<(), String> {
        let allowed: Vec<String> = allowed.iter().map(|s| s.to_string()).collect();
        validate_tunnel_target(addr.parse().unwrap(), &allowed)
    }

    #[test]
    fn internal_targets_refused_by_default() {
        for t in [
            "127.0.0.1:5432",
            "169.254.169.254:80",
            "10.0.0.5:3306",
            "192.168.1.1:22",
            "[::1]:6379",
            "[fe80::1]:80",
            "[::ffff:127.0.0.1]:80",
        ] {
            assert!(check(t, &[]).is_err(), "{t} should be refused");
        }
        assert!(check("93.184.216.34:443", &[]).is_ok());
    }

    #[test]
    fn invalid_targets_always_refused() {
        assert!(check("127.0.0.1:0", &["127.0.0.0/8"]).is_err());
        assert!(check("0.0.0.0:80", &["0.0.0.0/0"]).is_err());
        assert!(check("224.0.0.1:80", &["0.0.0.0/0"]).is_err());
    }

    #[test]
    fn allow_list_permits_listed_and_is_strict() {
        let allowed = ["127.0.0.1", "10.1.0.0/16"];
        assert!(check("127.0.0.1:5432", &allowed).is_ok());
        assert!(check("10.1.2.3:22", &allowed).is_ok());
        assert!(check("10.2.0.1:22", &allowed).is_err());
        assert!(check("169.254.169.254:80", &allowed).is_err());
        // Non-empty list is strict: unlisted public targets are refused too.
        assert!(check("93.184.216.34:443", &allowed).is_err());
    }
}
