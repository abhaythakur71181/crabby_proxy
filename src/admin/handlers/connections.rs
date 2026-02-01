use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;

#[derive(Serialize, Deserialize)]
pub struct ConnectionResponse {
    pub id: String,
    pub client_addr: String,
    pub protocol: String,
    pub connected_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionsListResponse {
    pub connections: Vec<ConnectionResponse>,
    pub total: usize,
}

#[derive(Serialize, Deserialize)]
pub struct CountResponse {
    pub count: usize,
}

/// List all active connections
pub async fn list_connections(State(state): State<AppState>) -> Json<ConnectionsListResponse> {
    match state.state.list_connections().await {
        Ok(connections) => {
            let total = connections.len();
            let connections = connections
                .into_iter()
                .map(|conn| ConnectionResponse {
                    id: conn.id.to_string(),
                    client_addr: conn.client_addr.to_string(),
                    protocol: conn.protocol.to_string(),
                    connected_at: conn.created_at.to_string(),
                })
                .collect();

            Json(ConnectionsListResponse { connections, total })
        }
        Err(_) => Json(ConnectionsListResponse {
            connections: vec![],
            total: 0,
        }),
    }
}

/// Get connection count
pub async fn count_connections(State(state): State<AppState>) -> Json<CountResponse> {
    let count = state.state.count_connections().await.unwrap_or(0);
    Json(CountResponse { count })
}
