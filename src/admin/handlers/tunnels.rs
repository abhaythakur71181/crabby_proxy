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
    drop(config);

    let service_type = match req.service_type.to_lowercase().as_str() {
        "http" | "https" | "web" => ServiceType::WebService,
        "ssh" => ServiceType::SshService,
        "postgres" => ServiceType::Database(crate::connection::DbType::Postgres),
        "mysql" => ServiceType::Database(crate::connection::DbType::MySQL),
        "redis" => ServiceType::Database(crate::connection::DbType::Redis),
        "mongodb" => ServiceType::Database(crate::connection::DbType::MongoDB),
        other => ServiceType::Custom(other.to_string()),
    };
    let target_addr = req
        .target_addr
        .as_deref()
        .unwrap_or("127.0.0.1:0")
        .parse()
        .map_err(|_| ApiError::bad_request("Invalid target address"))?;
    let mut tunnels = state.tunnels.write().await;
    match tunnels
        .create_tunnel_admin(service_type, req.port, target_addr)
        .await
    {
        Ok(info) => {
            tracing::info!("Created tunnel on port {} via admin API", info.listen_port);
            Ok((StatusCode::CREATED, Json(info)))
        }
        Err(e) => {
            tracing::error!("Failed to create tunnel: {}", e);
            Err(ApiError::internal("Failed to create tunnel"))
        }
    }
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
