use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;

#[derive(Serialize, Deserialize)]
pub struct TunnelInfo {
    pub port: u16,
    pub service_type: String,
    pub active: bool,
}

#[derive(Serialize, Deserialize)]
pub struct TunnelsListResponse {
    pub tunnels: Vec<TunnelInfo>,
    pub total: usize,
}

#[derive(Serialize, Deserialize)]
pub struct CreateTunnelRequest {
    pub service_type: String,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateTunnelResponse {
    pub port: u16,
    pub message: String,
}

/// List all active tunnels
/// NOTE: TunnelManager doesn't expose active tunnels publicly yet
pub async fn list_tunnels(State(_state): State<AppState>) -> Json<TunnelsListResponse> {
    // TODO: Add list_active() method to TunnelManager
    Json(TunnelsListResponse {
        tunnels: vec![],
        total: 0,
    })
}

/// Create a new tunnel (if enabled in config)
/// NOTE: This is a simplified stub - full implementation requires connection context
pub async fn create_tunnel(
    State(state): State<AppState>,
    Json(_req): Json<CreateTunnelRequest>,
) -> Result<Json<CreateTunnelResponse>, StatusCode> {
    let config = state.config.read().await;

    if !config.features.reverse_tunnels {
        return Err(StatusCode::FORBIDDEN);
    }

    // TODO: Full tunnel creation requires client connection context
    // This is a placeholder response
    Ok(Json(CreateTunnelResponse {
        port: 0,
        message: "Tunnel creation requires client connection - use proxy protocol".to_string(),
    }))
}

/// Close a tunnel
pub async fn close_tunnel(State(state): State<AppState>, Path(port): Path<u16>) -> StatusCode {
    let mut tunnels = state.tunnels.write().await;
    match tunnels.close_tunnel(port).await {
        Ok(_) => {
            tracing::info!("Closed tunnel on port {}", port);
            StatusCode::NO_CONTENT
        }
        Err(_) => {
            tracing::warn!("Failed to close tunnel on port {} - not found", port);
            StatusCode::NOT_FOUND
        }
    }
}
