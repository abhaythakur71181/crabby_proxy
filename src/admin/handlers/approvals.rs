use super::models::ApiError;
use crate::app_state::AppState;
use crate::db::approvals;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreateApprovalRequest {
    pub user_id: i64,
    pub client_ip: String,
    pub duration_hours: i32,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApprovalResponse {
    pub id: i64,
    pub user_id: i64,
    pub client_ip: String,
    pub approved_by: i64,
    pub approved_at: i64,
    pub expires_at: i64,
    pub reason: Option<String>,
    pub duration_hours: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TerminateRequest {
    pub reason: String,
}

/// POST /api/approvals - Create a new approval (admin only)
pub async fn create_approval(
    State(state): State<Arc<AppState>>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(payload): Json<CreateApprovalRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;

    // Bound the grant duration: negative -> expires in the past; huge -> effectively
    // permanent. Cap at 1..=8760 hours (1 year).
    if !(1..=8760).contains(&payload.duration_hours) {
        return Err(ApiError::bad_request(
            "duration_hours must be between 1 and 8760",
        ));
    }

    // Validate the client-IP pattern; reject invalid, warn (but allow) broad.
    let warning = crate::ip_pattern::validate_approval_pattern(&payload.client_ip)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let id = approvals::create_approval(
        &state.db_pool,
        payload.user_id,
        &payload.client_ip,
        current_user_id,
        payload.duration_hours,
        payload.reason.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create approval: {}", e);
        ApiError::internal("Failed to create approval")
    })?;

    // Invalidate cached approvals for this user so proxy picks up the new approval
    state.invalidate_approval_cache(payload.user_id).await;

    // Audit log
    let _ = crate::db::audit_log::log_action(
        &state.db_pool,
        current_user_id,
        "approval_created",
        Some("approval"),
        Some(&id.to_string()),
        Some(&format!(
            "User {}, duration: {}h{}",
            payload.user_id,
            payload.duration_hours,
            if warning.is_some() {
                ", broad_pattern=true"
            } else {
                ""
            }
        )),
        Some(&payload.client_ip),
    )
    .await;

    let now = chrono::Utc::now().timestamp();
    Ok((
        StatusCode::CREATED,
        Json(ApprovalResponse {
            id,
            user_id: payload.user_id,
            client_ip: payload.client_ip,
            approved_by: current_user_id,
            approved_at: now,
            expires_at: now + (payload.duration_hours as i64 * 3600),
            reason: payload.reason,
            duration_hours: payload.duration_hours,
            warning,
        }),
    ))
}

/// GET /api/approvals - List all active approvals (admin only)
pub async fn list_approvals(
    State(state): State<Arc<AppState>>,
    axum::Extension(current_user_id): axum::Extension<i64>,
) -> Result<Json<Vec<ApprovalResponse>>, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;

    let records = approvals::list_all_approvals(&state.db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list approvals: {}", e);
            ApiError::internal("Failed to list approvals")
        })?;

    Ok(Json(
        records
            .into_iter()
            .map(|r| ApprovalResponse {
                id: r.id,
                user_id: r.user_id,
                client_ip: r.client_ip,
                approved_by: r.approved_by,
                approved_at: r.approved_at,
                expires_at: r.expires_at,
                reason: r.reason,
                duration_hours: r.approval_duration_hours,
                warning: None,
            })
            .collect(),
    ))
}

/// GET /api/users/:id/approvals - List user's active approvals
pub async fn list_user_approvals(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
) -> Result<Json<Vec<ApprovalResponse>>, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    if !current_user.can_access_user(user_id) {
        return Err(ApiError::forbidden("Cannot access other users' approvals"));
    }

    let records = approvals::list_user_approvals(&state.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list user approvals: {}", e);
            ApiError::internal("Failed to list approvals")
        })?;

    Ok(Json(
        records
            .into_iter()
            .map(|r| ApprovalResponse {
                id: r.id,
                user_id: r.user_id,
                client_ip: r.client_ip,
                approved_by: r.approved_by,
                approved_at: r.approved_at,
                expires_at: r.expires_at,
                reason: r.reason,
                duration_hours: r.approval_duration_hours,
                warning: None,
            })
            .collect(),
    ))
}

/// DELETE /api/approvals/:id - Terminate an approval (admin only)
pub async fn terminate_approval(
    State(state): State<Arc<AppState>>,
    Path(approval_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(payload): Json<TerminateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;

    let terminated_user = approvals::terminate_approval(
        &state.db_pool,
        approval_id,
        current_user_id,
        &payload.reason,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to terminate approval: {}", e);
        ApiError::internal("Failed to terminate approval")
    })?;

    if let Some(approved_user_id) = terminated_user {
        // Invalidate the cached approval so the revoked client is denied
        // immediately rather than staying authorized until the in-memory +
        // Redis cache TTL expires.
        state.invalidate_approval_cache(approved_user_id).await;
        // Audit log
        let _ = crate::db::audit_log::log_action(
            &state.db_pool,
            current_user_id,
            "approval_terminated",
            Some("approval"),
            Some(&approval_id.to_string()),
            Some(&payload.reason),
            None,
        )
        .await;
        Ok(StatusCode::OK)
    } else {
        Err(ApiError::not_found(format!(
            "Approval {} not found",
            approval_id
        )))
    }
}
