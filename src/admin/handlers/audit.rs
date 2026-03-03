use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::app_state::AppState;
use crate::db::audit_log;

#[derive(Deserialize)]
pub struct AuditLogQuery {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
    pub user_id: Option<i64>,
    pub action: Option<String>,
}

#[derive(Serialize)]
pub struct AuditLogResponse {
    pub entries: Vec<audit_log::AuditEntry>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

/// GET /api/audit-log — List audit log entries with pagination and filtering
pub async fn list_audit_log(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, StatusCode> {
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);
    let entries = audit_log::get_audit_log(
        &state.db_pool,
        limit,
        offset,
        params.user_id,
        params.action.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to get audit log: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let total =
        audit_log::count_audit_entries(&state.db_pool, params.user_id, params.action.as_deref())
            .await
            .map_err(|e| {
                tracing::error!("Failed to count audit entries: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    Ok(Json(AuditLogResponse {
        entries,
        total,
        limit,
        offset,
    }))
}

/// GET /api/users/:id/sessions — List active sessions for a user
pub async fn list_user_sessions(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
) -> Result<Json<Vec<SessionInfo>>, StatusCode> {
    let sessions = crate::db::sessions::list_user_sessions(&state.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list sessions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(
        sessions
            .into_iter()
            .map(|s| SessionInfo {
                id: s.id,
                user_id: s.user_id,
                created_at: s.created_at,
                expires_at: s.expires_at,
                ip_address: s.ip_address,
                user_agent: s.user_agent,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub id: i64,
    pub user_id: i64,
    pub created_at: i64,
    pub expires_at: i64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// DELETE /api/users/:id/sessions — Force logout all sessions for user
pub async fn delete_user_sessions(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let deleted = crate::db::sessions::delete_user_sessions(&state.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete sessions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(serde_json::json!({
        "deleted": deleted,
        "user_id": user_id
    })))
}
