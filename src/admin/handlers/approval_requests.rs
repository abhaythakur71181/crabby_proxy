use super::models::ApiError;
use crate::app_state::AppState;
use crate::db::approval_requests;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreateRequestPayload {
    pub client_ip: String,
    pub duration_hours: i32,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DecisionPayload {
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RequestResponse {
    pub id: i64,
    pub user_id: i64,
    pub username: Option<String>,
    pub client_ip: String,
    pub duration_hours: i32,
    pub reason: Option<String>,
    pub status: String,
    pub requested_at: i64,
    pub decided_by: Option<i64>,
    pub decided_at: Option<i64>,
    pub decision_reason: Option<String>,
}

impl RequestResponse {
    fn from_record(r: approval_requests::ApprovalRequest, username: Option<String>) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            username,
            client_ip: r.client_ip,
            duration_hours: r.duration_hours,
            reason: r.reason,
            status: r.status,
            requested_at: r.requested_at,
            decided_by: r.decided_by,
            decided_at: r.decided_at,
            decision_reason: r.decision_reason,
        }
    }
}

async fn enrich_with_username(
    state: &AppState,
    records: Vec<approval_requests::ApprovalRequest>,
) -> Vec<RequestResponse> {
    let mut result = Vec::with_capacity(records.len());
    for r in records {
        let username = crate::db::users::get_user_by_id(&state.db_pool, r.user_id)
            .await
            .ok()
            .flatten()
            .map(|u| u.username);
        result.push(RequestResponse::from_record(r, username));
    }
    result
}

/// POST /api/approval-requests — Any authenticated user can request approval (for themselves)
pub async fn create_request(
    State(state): State<Arc<AppState>>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(payload): Json<CreateRequestPayload>,
) -> Result<impl IntoResponse, ApiError> {
    // User always requests for themselves
    let id = approval_requests::create_request(
        &state.db_pool,
        current_user_id,
        &payload.client_ip,
        payload.duration_hours,
        payload.reason.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create approval request: {}", e);
        ApiError::internal("Failed to create approval request")
    })?;

    // Audit log
    let _ = crate::db::audit_log::log_action(
        &state.db_pool,
        current_user_id,
        "approval_request_created",
        Some("approval_request"),
        Some(&id.to_string()),
        Some(&format!("IP: {}, duration: {}h", payload.client_ip, payload.duration_hours)),
        None,
    )
    .await;

    let now = chrono::Utc::now().timestamp();
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "user_id": current_user_id,
            "status": "pending",
            "requested_at": now,
        })),
    ))
}

/// GET /api/approval-requests — Admin sees all, regular user sees only their own
pub async fn list_requests(
    State(state): State<Arc<AppState>>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Query(params): Query<ListQuery>,
) -> Result<Json<Vec<RequestResponse>>, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;

    let records = if current_user.role == "root_admin" || current_user.role == "admin" {
        approval_requests::list_all_requests(&state.db_pool, params.status.as_deref()).await
    } else {
        approval_requests::list_user_requests(&state.db_pool, current_user_id).await
    }
    .map_err(|e| {
        tracing::error!("Failed to list approval requests: {}", e);
        ApiError::internal("Failed to list approval requests")
    })?;

    Ok(Json(enrich_with_username(&state, records).await))
}

/// POST /api/approval-requests/:id/approve — Admin only
pub async fn approve_request(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(payload): Json<DecisionPayload>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;

    let req = approval_requests::approve_request(
        &state.db_pool,
        request_id,
        current_user_id,
        payload.reason.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to approve request: {}", e);
        ApiError::internal("Failed to approve request")
    })?;

    match req {
        Some(r) => {
            // Invalidate approval cache so proxy picks up the new approval immediately
            state.invalidate_approval_cache(r.user_id).await;
            // Audit log
            let _ = crate::db::audit_log::log_action(
                &state.db_pool,
                current_user_id,
                "approval_request_approved",
                Some("approval_request"),
                Some(&request_id.to_string()),
                Some(&format!("Approved for user {}", r.user_id)),
                None,
            )
            .await;
            Ok(Json(serde_json::json!({
                "id": r.id,
                "status": "approved",
                "user_id": r.user_id,
            })))
        }
        None => Err(ApiError::not_found(
            "Request not found or already decided",
        )),
    }
}

/// POST /api/approval-requests/:id/reject — Admin only
pub async fn reject_request(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(payload): Json<DecisionPayload>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;

    let rejected = approval_requests::reject_request(
        &state.db_pool,
        request_id,
        current_user_id,
        payload.reason.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to reject request: {}", e);
        ApiError::internal("Failed to reject request")
    })?;

    if rejected {
        // Audit log
        let _ = crate::db::audit_log::log_action(
            &state.db_pool,
            current_user_id,
            "approval_request_rejected",
            Some("approval_request"),
            Some(&request_id.to_string()),
            payload.reason.as_deref(),
            None,
        )
        .await;
        Ok(Json(serde_json::json!({
            "id": request_id,
            "status": "rejected",
        })))
    } else {
        Err(ApiError::not_found(
            "Request not found or already decided",
        ))
    }
}
