use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;

#[derive(Serialize, Deserialize)]
pub struct ConfigResponse {
    pub server: ServerConfigResponse,
    pub authentication: AuthConfigResponse,
    pub features: FeaturesConfigResponse,
}

#[derive(Serialize, Deserialize)]
pub struct ServerConfigResponse {
    pub proxy_bind: String,
    pub admin_bind: String,
    pub max_connections: usize,
}

#[derive(Serialize, Deserialize)]
pub struct AuthConfigResponse {
    pub enabled: bool,
    // Don't expose credentials
}

#[derive(Serialize, Deserialize)]
pub struct FeaturesConfigResponse {
    pub connection_approval: bool,
    pub reverse_tunnels: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ReloadResponse {
    pub success: bool,
    pub message: String,
}

/// Get current configuration (sensitive fields redacted)
pub async fn get_config(State(state): State<AppState>) -> Json<ConfigResponse> {
    let config = state.config.read().await;
    Json(ConfigResponse {
        server: ServerConfigResponse {
            proxy_bind: config.server.proxy_bind.clone(),
            admin_bind: config.server.admin_bind.clone(),
            max_connections: config.server.max_connections,
        },
        authentication: AuthConfigResponse {
            enabled: config.authentication.enabled,
        },
        features: FeaturesConfigResponse {
            connection_approval: config.features.connection_approval,
            reverse_tunnels: config.features.reverse_tunnels,
        },
    })
}

/// TODO: Reload configuration from file
pub async fn reload_config(
    State(_state): State<AppState>,
) -> Result<Json<ReloadResponse>, StatusCode> {
    // TODO: store the config path in AppState

    tracing::info!("Configuration reload requested");

    Ok(Json(ReloadResponse {
        success: false,
        message: "Config reload not fully implemented - needs config path in AppState".to_string(),
    }))

    // When implemented:
    // match Config::from_file(&config_path) {
    //     Ok(new_config) => {
    //         state.reload_config(new_config).await;
    //         Ok(Json(ReloadResponse {
    //             success: true,
    //             message: "Configuration reloaded successfully".to_string(),
    //         }))
    //     }
    //     Err(e) => {
    //         Err(StatusCode::INTERNAL_SERVER_ERROR)
    //     }
    // }
}
