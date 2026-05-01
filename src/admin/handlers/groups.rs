use super::models::ApiError;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::app_state::AppState;
use crate::db::groups;

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub user_id: i64,
}

/// POST /api/groups — Create a new user group
pub async fn create_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let id = groups::create_group(&state.db_pool, &req.name, req.description.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("Failed to create group: {}", e);
            ApiError::internal("Failed to create group")
        })?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"id": id, "name": req.name})),
    ))
}

/// GET /api/groups — List all groups
pub async fn list_groups(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<groups::UserGroup>>, ApiError> {
    groups::list_groups(&state.db_pool)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to list groups: {}", e);
            ApiError::internal("Failed to list groups")
        })
}

/// GET /api/groups/:id — Get a single group
pub async fn get_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<groups::UserGroup>, ApiError> {
    groups::get_group(&state.db_pool, id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get group: {}", e);
            ApiError::internal("Failed to retrieve group")
        })?
        .ok_or_else(|| ApiError::not_found(format!("Group {} not found", id)))
        .map(Json)
}

/// DELETE /api/groups/:id — Delete a group
pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    groups::delete_group(&state.db_pool, id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete group: {}", e);
            ApiError::internal("Failed to delete group")
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/groups/:id/members — Add a user to a group
pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    Json(req): Json<AddMemberRequest>,
) -> Result<impl IntoResponse, ApiError> {
    groups::add_user_to_group(&state.db_pool, req.user_id, group_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to add member: {}", e);
            ApiError::internal("Failed to add member to group")
        })?;
    Ok(StatusCode::CREATED)
}

/// DELETE /api/groups/:id/members/:user_id — Remove a user from a group
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path((group_id, user_id)): Path<(i64, i64)>,
) -> Result<impl IntoResponse, ApiError> {
    groups::remove_user_from_group(&state.db_pool, user_id, group_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to remove member: {}", e);
            ApiError::internal("Failed to remove member from group")
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/groups/:id/members — List members of a group
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let members = groups::get_group_members(&state.db_pool, group_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list members: {}", e);
            ApiError::internal("Failed to list group members")
        })?;

    Ok(Json(serde_json::json!({
        "group_id": group_id,
        "members": members,
        "total": members.len()
    })))
}

/// GET /api/users/:id/groups — List groups a user belongs to
pub async fn list_user_groups(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
) -> Result<Json<Vec<groups::UserGroup>>, ApiError> {
    groups::get_user_groups(&state.db_pool, user_id)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to list user groups: {}", e);
            ApiError::internal("Failed to list user groups")
        })
}
