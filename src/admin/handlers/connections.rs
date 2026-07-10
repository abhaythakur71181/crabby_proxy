use super::models::ApiError;
use crate::admin::auth::AdminUser;
use crate::app_state::AppState;
use crate::state::backend::ConnectionInfo;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

/// GET /api/connections - List all active connections
pub async fn list_connections(
    _admin: AdminUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ConnectionInfo>>, ApiError> {
    match state.state.list_connections().await {
        Ok(connections) => Ok(Json(connections)),
        Err(e) => {
            tracing::error!("Failed to list connections: {}", e);
            Err(ApiError::internal("Failed to list connections"))
        }
    }
}

/// GET /api/connections/count - Get count of active connections
pub async fn count_connections(
    _admin: AdminUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<usize>, ApiError> {
    match state.state.count_connections().await {
        Ok(count) => Ok(Json(count)),
        Err(e) => {
            tracing::error!("Failed to count connections: {}", e);
            Err(ApiError::internal("Failed to count connections"))
        }
    }
}

/// DELETE /api/connections/:id - Terminate a live connection (admin).
/// Signals the relay to tear down and removes the tracked record. Returns 404
/// if the connection isn't currently active on this instance.
pub async fn terminate_connection(
    _admin: AdminUser,
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let known = state.conn_cancel.get(&id).map(|n| n.clone());
    match known {
        Some(notify) => {
            notify.notify_waiters();
            // Best-effort: drop the tracked record too (the relay also cleans up).
            let _ = state.state.delete_connection(id).await;
            tracing::info!(target: "audit", conn_id = %id, "admin terminated connection");
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(ApiError::not_found(format!(
            "Connection {} is not active on this instance",
            id
        ))),
    }
}

/// GET /api/connections/live - WebSocket for live connection events.
/// Sends a JSON snapshot of active connections every 2 seconds.
pub async fn live_connections(
    _admin: AdminUser,
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_live_connections(socket, state))
}

async fn handle_live_connections(mut socket: WebSocket, state: Arc<AppState>) {
    tracing::debug!("WebSocket client connected for live connections");

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut prev_count: Option<usize> = None;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let connections = match state.state.list_connections().await {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let count = connections.len();
                // Only send if count changed (or first message)
                if prev_count != Some(count) || prev_count.is_none() {
                    let payload = serde_json::json!({
                        "type": "connections",
                        "count": count,
                        "connections": connections,
                        "timestamp": chrono::Utc::now().timestamp(),
                    });

                    if let Err(e) = socket.send(Message::Text(payload.to_string())).await {
                        tracing::debug!("WebSocket send error (client disconnected?): {}", e);
                        break;
                    }
                    prev_count = Some(count);
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        tracing::debug!("WebSocket client disconnected");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    Some(Ok(_)) => {} // Ignore other messages
                    Some(Err(e)) => {
                        tracing::debug!("WebSocket recv error: {}", e);
                        break;
                    }
                }
            }
        }
    }
}
