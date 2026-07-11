use super::models::ApiError;
use crate::admin::auth::AdminUser;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;
use std::sync::Arc;

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

/// Build the redacted config response (no secrets).
fn config_response(config: &crate::config::Config) -> ConfigResponse {
    ConfigResponse {
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
    }
}

/// Get current configuration (sensitive fields redacted)
pub async fn get_config(
    _admin: AdminUser,
    State(state): State<Arc<AppState>>,
) -> Json<ConfigResponse> {
    Json(config_response(&state.config.load()))
}

#[derive(Deserialize)]
pub struct UpdateConfigRequest {
    pub max_connections: Option<usize>,
    pub connection_approval: Option<bool>,
    pub reverse_tunnels: Option<bool>,
}

/// PUT /api/config — Update the hot-reloadable, non-security config fields
/// (root_admin only). Applies in-memory immediately AND persists to the config
/// file. Security-critical fields (binds, secrets, auth toggle) are NOT editable
/// here — they require a restart by design.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(body): Json<UpdateConfigRequest>,
) -> Result<Json<ConfigResponse>, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    if current_user.role != "root_admin" {
        return Err(ApiError::forbidden(
            "Only root_admin can edit configuration",
        ));
    }

    let path = state
        .config_path
        .clone()
        .ok_or_else(|| ApiError::internal("No config file path available"))?;

    let apply = |cfg: &mut crate::config::Config| {
        if let Some(mc) = body.max_connections {
            cfg.server.max_connections = mc;
        }
        if let Some(ca) = body.connection_approval {
            cfg.features.connection_approval = ca;
        }
        if let Some(rt) = body.reverse_tunnels {
            cfg.features.reverse_tunnels = rt;
        }
    };

    // Persist to the file: re-read from disk (so we don't write env-injected
    // secrets that only live in memory), apply, write back.
    let mut file_cfg = crate::config::Config::from_file(&path)
        .map_err(|e| ApiError::internal(format!("read config: {e}")))?;
    apply(&mut file_cfg);
    let toml = toml::to_string_pretty(&file_cfg)
        .map_err(|e| ApiError::internal(format!("serialize config: {e}")))?;
    std::fs::write(&path, toml).map_err(|e| ApiError::internal(format!("write config: {e}")))?;

    // Apply in-memory (preserves the running env-resolved secrets).
    let mut mem = (*state.config.load_full()).clone();
    apply(&mut mem);
    let resp = config_response(&mem);
    state.config.store(Arc::new(mem));

    tracing::info!(target: "audit", user_id = current_user_id, "configuration updated");
    Ok(Json(resp))
}

/// Reload configuration from file
pub async fn reload_config(
    State(state): State<Arc<AppState>>,
    axum::Extension(current_user_id): axum::Extension<i64>,
) -> Result<Json<ReloadResponse>, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;
    tracing::info!(
        "Configuration reload requested by admin user {}",
        current_user_id
    );

    match state.reload_config().await {
        Ok(_) => {
            // Also reload TLS certificates if TLS is enabled
            if let Err(e) = state.reload_tls() {
                tracing::warn!("Config reloaded but TLS cert reload failed: {}", e);
            }
            Ok(Json(ReloadResponse {
                success: true,
                message: "Configuration and TLS certificates reloaded successfully".to_string(),
            }))
        }
        Err(e) => {
            // Return a real error status (was HTTP 200 with success:false, which
            // hid failures from monitoring) and don't leak the raw error
            // (filesystem paths / parser internals) to the client.
            tracing::error!("Failed to reload configuration: {}", e);
            Err(ApiError::internal("Failed to reload configuration"))
        }
    }
}
