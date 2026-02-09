use crate::app_state::AppState;
use crate::state::backend::ConnectionInfo;
use axum::{extract::State, http::StatusCode, Json};

/// GET /api/connections - List all active connections
pub async fn list_connections(
    State(state): State<AppState>,
) -> Result<Json<Vec<ConnectionInfo>>, StatusCode> {
    match state.state.list_connections().await {
        Ok(connections) => Ok(Json(connections)),
        Err(e) => {
            tracing::error!("Failed to list connections: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /api/connections/count - Get count of active connections
pub async fn count_connections(State(state): State<AppState>) -> Result<Json<usize>, StatusCode> {
    match state.state.count_connections().await {
        Ok(count) => Ok(Json(count)),
        Err(e) => {
            tracing::error!("Failed to count connections: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
