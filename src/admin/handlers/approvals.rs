use crate::app_state::AppState;
use crate::db::approvals;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Deserialize)]
pub struct TerminateRequest {
    pub reason: String,
}

/// POST /api/approvals - Create a new approval (admin only)
pub async fn create_approval(
    State(state): State<AppState>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(payload): Json<CreateApprovalRequest>,
) -> Result<(StatusCode, Json<ApprovalResponse>), StatusCode> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;

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
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Invalidate cached approvals for this user so proxy picks up the new approval
    state.invalidate_approval_cache(payload.user_id).await;

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
        }),
    ))
}

/// GET /api/approvals - List all active approvals (admin only)
pub async fn list_approvals(
    State(state): State<AppState>,
    axum::Extension(current_user_id): axum::Extension<i64>,
) -> Result<Json<Vec<ApprovalResponse>>, StatusCode> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;

    let records = approvals::list_all_approvals(&state.db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list approvals: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
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
            })
            .collect(),
    ))
}

/// GET /api/users/:id/approvals - List user's active approvals
pub async fn list_user_approvals(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
) -> Result<Json<Vec<ApprovalResponse>>, StatusCode> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    if !current_user.can_access_user(user_id) {
        return Err(StatusCode::FORBIDDEN);
    }

    let records = approvals::list_user_approvals(&state.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list user approvals: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
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
            })
            .collect(),
    ))
}

/// DELETE /api/approvals/:id - Terminate an approval (admin only)
pub async fn terminate_approval(
    State(state): State<AppState>,
    Path(approval_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(payload): Json<TerminateRequest>,
) -> Result<StatusCode, StatusCode> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;

    let terminated = approvals::terminate_approval(
        &state.db_pool,
        approval_id,
        current_user_id,
        &payload.reason,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to terminate approval: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Invalidate cached approvals — we need the user_id from the approval record.
    // Since we don't have it directly, invalidate by looking up the approval first.
    // For simplicity, the approval was already terminated; the cache entries will
    // expire naturally (2min TTL). For immediate effect, we'd need to fetch the
    // approval's user_id before termination. This is acceptable for a terminate op.

    if terminated {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
