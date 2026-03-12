use axum::{
    extract::{Path, State},
    http::StatusCode,
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
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    let id = groups::create_group(&state.db_pool, &req.name, req.description.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("Failed to create group: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"id": id, "name": req.name})),
    ))
}

/// GET /api/groups — List all groups
pub async fn list_groups(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<groups::UserGroup>>, StatusCode> {
    groups::list_groups(&state.db_pool)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to list groups: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// GET /api/groups/:id — Get a single group
pub async fn get_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<groups::UserGroup>, StatusCode> {
    groups::get_group(&state.db_pool, id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get group: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)
        .map(Json)
}

/// DELETE /api/groups/:id — Delete a group
pub async fn delete_group(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> StatusCode {
    match groups::delete_group(&state.db_pool, id).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Failed to delete group: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// POST /api/groups/:id/members — Add a user to a group
pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    Json(req): Json<AddMemberRequest>,
) -> StatusCode {
    match groups::add_user_to_group(&state.db_pool, req.user_id, group_id).await {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            tracing::error!("Failed to add member: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// DELETE /api/groups/:id/members/:user_id — Remove a user from a group
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path((group_id, user_id)): Path<(i64, i64)>,
) -> StatusCode {
    match groups::remove_user_from_group(&state.db_pool, user_id, group_id).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Failed to remove member: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// GET /api/groups/:id/members — List members of a group
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let members = groups::get_group_members(&state.db_pool, group_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list members: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
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
) -> Result<Json<Vec<groups::UserGroup>>, StatusCode> {
    groups::get_user_groups(&state.db_pool, user_id)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to list user groups: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}
