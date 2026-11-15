use super::models::ApiError;
use crate::admin::auth::AdminUser;
use crate::app_state::AppState;
use crate::state::backend::ConnectionInfo;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, Query, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Live-feed tickets are short-lived single-use tokens. Browsers can't set an
/// Authorization header on a WebSocket handshake, so an authenticated admin
/// first mints a ticket here, then opens the WS with `?ticket=`.
const LIVE_TICKET_TTL: std::time::Duration = std::time::Duration::from_secs(30);

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
/// Signals the relay to tear down and removes the tracked record. A connection
/// relayed by another instance (visible through the shared Redis state) is
/// terminated there via the event bus and answered with 202 Accepted (#83).
/// Returns 404 if no instance is known to be relaying it.
pub async fn terminate_connection(
    _admin: AdminUser,
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    if crate::event_bus::terminate_local(&state, id) {
        // Best-effort: drop the tracked record too (the relay also cleans up).
        let _ = state.state.delete_connection(id).await;
        tracing::info!(target: "audit", conn_id = %id, "admin terminated connection");
        return Ok(StatusCode::NO_CONTENT);
    }
    if state.event_bus.is_some() && state.state.get_connection(id).await.is_ok() {
        state
            .broadcast(&crate::event_bus::ProxyEvent::TerminateConnection(id))
            .await;
        tracing::info!(target: "audit", conn_id = %id, "admin requested termination of a connection on another instance");
        return Ok(StatusCode::ACCEPTED);
    }
    Err(ApiError::not_found(format!(
        "Connection {} is not active on any reachable instance",
        id
    )))
}

/// POST /api/connections/live-ticket - Mint a short-lived single-use ticket
/// (admin) to open the live-connections WebSocket. Returns `{ticket,expires_in}`.
pub async fn issue_live_ticket(
    _admin: AdminUser,
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    use rand::Rng;
    let ticket: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    // Opportunistic prune of expired tickets, then store this one.
    state
        .ws_tickets
        .retain(|_, t| t.elapsed() < LIVE_TICKET_TTL);
    state
        .ws_tickets
        .insert(ticket.clone(), std::time::Instant::now());
    // Also in Redis, so the WebSocket may land on another instance (#83).
    if let Some(ref cache) = state.cache {
        cache
            .put_ws_ticket(&ticket, LIVE_TICKET_TTL.as_secs())
            .await;
    }
    Json(serde_json::json!({ "ticket": ticket, "expires_in": LIVE_TICKET_TTL.as_secs() }))
}

#[derive(Deserialize)]
pub struct LiveQuery {
    pub ticket: Option<String>,
}

/// GET /api/connections/live - WebSocket for live connection events (PUBLIC
/// route, authorized by a one-time `?ticket=` minted via live-ticket).
/// Sends a JSON snapshot of active connections every 2 seconds.
pub async fn live_connections(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(q): Query<LiveQuery>,
) -> impl IntoResponse {
    // Validate + consume the single-use ticket before upgrading.
    let valid = match q.ticket {
        Some(t) => {
            let local = state
                .ws_tickets
                .remove(&t)
                .map(|(_, issued)| issued.elapsed() < LIVE_TICKET_TTL);
            // Always consume the shared copy too, so the ticket stays
            // single-use across instances.
            let shared = match state.cache {
                Some(ref cache) => cache.take_ws_ticket(&t).await,
                None => false,
            };
            local.unwrap_or(shared)
        }
        None => false,
    };
    if !valid {
        return (StatusCode::UNAUTHORIZED, "invalid or expired live ticket").into_response();
    }
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
