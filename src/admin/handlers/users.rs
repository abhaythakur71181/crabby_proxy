use super::models::{
    ApiError, ApiKeyResponse, CreateApiKeyRequest, CreateApiKeyResponse, UpdateUserRequest,
    UserResponse,
};
use crate::app_state::AppState;
use crate::db::{api_keys_crud, models::Role, users};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Authorize creating a user with `requested` role, for a caller of `caller` role.
/// root_admin may create any role; admin may create only regular users; a plain
/// user may not create users.
fn authorize_create_user(caller: &Role, requested: &Role) -> Result<(), String> {
    match caller {
        Role::RootAdmin => Ok(()),
        Role::Admin => {
            if *requested == Role::User {
                Ok(())
            } else {
                Err("Admins can only create regular users".to_string())
            }
        }
        Role::User => Err("Only admins can create users".to_string()),
    }
}

/// Authorize an admin resetting `target`'s password (no current password needed).
/// root_admin may reset anyone; admin may reset only regular users; a plain user
/// may not reset others.
fn authorize_admin_reset(caller: &Role, target: &Role) -> Result<(), String> {
    match caller {
        Role::RootAdmin => Ok(()),
        Role::Admin => {
            if *target == Role::User {
                Ok(())
            } else {
                Err("Admins can only reset regular users' passwords".to_string())
            }
        }
        Role::User => Err("Only admins can reset other users' passwords".to_string()),
    }
}

/// Whether `caller` may use the self-service (current-password) reset. root_admin
/// is excluded — it changes its own password via the admin-reset endpoint.
fn self_reset_allowed(caller: &Role) -> bool {
    !matches!(caller, Role::RootAdmin)
}

/// Create a new user (root_admin only)
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    Extension(current_user_id): Extension<i64>,
    Json(request): Json<super::models::CreateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;
    authorize_create_user(&current_user.get_role(), &request.role)
        .map_err(ApiError::forbidden)?;
    crate::validation::validate_username(&request.username).map_err(ApiError::bad_request)?;
    crate::validation::validate_password(&request.password).map_err(ApiError::bad_request)?;
    if let Ok(Some(_)) = users::get_user_by_username(&state.db_pool, &request.username).await {
        return Err(ApiError::conflict(format!(
            "Username '{}' already exists",
            request.username
        )));
    }
    let db_request = crate::db::models::CreateUserRequest {
        username: request.username,
        password: request.password,
        role: request.role,
        max_connections: request.max_connections,
        bandwidth_limit_mb: request.bandwidth_limit_mb,
        rate_limit_enabled: Some(true),
        rate_limit_rps: Some(10),
        allowed_protocols: None,
        notes: None,
    };
    let user_id = users::create_user(&state.db_pool, &db_request, Some(current_user_id)).await?;
    let user = users::get_user_by_id(&state.db_pool, user_id)
        .await?
        .ok_or_else(|| ApiError::internal("Failed to retrieve created user"))?;
    Ok((StatusCode::CREATED, Json(UserResponse::from(user))))
}

/// List users. Admins see all users; regular users see only themselves.
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Extension(current_user_id): Extension<i64>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;

    // Regular users only see their own profile
    if current_user.get_role() == Role::User {
        let items = vec![UserResponse::from(current_user)];
        return Ok(Json(serde_json::json!({
            "items": items,
            "total": 1,
            "limit": 1,
            "offset": 0,
        })));
    }

    // Always return the same paginated envelope. Defaults apply when no params
    // are given, so the response shape never changes (previously this returned
    // a bare array without params and {items,...} with them, forcing clients to
    // branch on the type).
    let limit = pagination.limit.unwrap_or(50).min(200);
    let offset = pagination.offset.unwrap_or(0);
    let total = users::count_all_users(&state.db_pool).await?;
    let users_list = users::list_users_paginated(&state.db_pool, limit, offset).await?;
    let items: Vec<UserResponse> = users_list.into_iter().map(UserResponse::from).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

/// Get user details (admin+ or self)
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    Extension(current_user_id): Extension<i64>,
    Path(user_id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;

    // Allow if admin+ or viewing own profile
    if current_user.get_role() == Role::User && current_user_id != user_id {
        return Err(ApiError::forbidden("Cannot view other users"));
    }

    let user = users::get_user_by_id(&state.db_pool, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("User {} not found", user_id)))?;

    Ok(Json(UserResponse::from(user)))
}

/// Update user (root_admin or self for limited fields)
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    Extension(current_user_id): Extension<i64>,
    Path(user_id): Path<i64>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;

    let is_self = current_user_id == user_id;
    let is_root_admin = current_user.get_role() == Role::RootAdmin;

    // Regular users can only update their own password
    if !is_root_admin && !is_self {
        return Err(ApiError::forbidden("Cannot modify other users"));
    }

    // Self password changes must go through the current-password-verified
    // endpoint (POST /api/users/me/password), not this profile update.
    if request.password.is_some() && is_self && !is_root_admin {
        return Err(ApiError::forbidden(
            "Use the change-password endpoint to change your own password",
        ));
    }

    // Non-root users can't change role, quotas, or active status
    if !is_root_admin
        && (request.role.is_some()
            || request.max_connections.is_some()
            || request.bandwidth_limit_mb.is_some()
            || request.is_active.is_some())
    {
        return Err(ApiError::forbidden(
            "Only root_admin can change role, quotas, or active status",
        ));
    }

    // Validate password length if provided
    if let Some(ref pwd) = request.password {
        if pwd.len() < 8 {
            return Err(ApiError::bad_request(
                "Password must be at least 8 characters",
            ));
        }
    }

    let updated_user = users::update_user(
        &state.db_pool,
        user_id,
        request.password.as_deref(),
        request.role,
        request.max_connections,
        request.bandwidth_limit_mb,
        request.is_active,
    )
    .await?;

    state
        .invalidate_all_for_user(user_id, Some(&updated_user.username))
        .await;

    Ok(Json(UserResponse::from(updated_user)))
}

/// Delete user (root_admin only)
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Extension(current_user_id): Extension<i64>,
    Path(user_id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;

    if current_user.get_role() != Role::RootAdmin {
        return Err(ApiError::forbidden("Only root_admin can delete users"));
    }

    // Don't allow deleting yourself
    if current_user_id == user_id {
        return Err(ApiError::bad_request("Cannot delete yourself"));
    }

    // Fetch username before deletion for cache invalidation
    let target_user = users::get_user_by_id(&state.db_pool, user_id).await?;

    users::delete_user(&state.db_pool, user_id).await?;

    // Invalidate all caches for the deleted user
    let username = target_user.map(|u| u.username).unwrap_or_default();
    state
        .invalidate_all_for_user(user_id, Some(&username))
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Create API key for user
pub async fn create_api_key(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    Extension(current_user_id): Extension<i64>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Extract fields from request immediately to avoid holding non-Send types across .await
    let req_name = request.name;
    let req_expires = request.expires_in_days;

    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;

    // Allow if creating for self or if admin+
    let is_self = current_user_id == user_id;
    let is_admin_plus =
        current_user.get_role() == Role::RootAdmin || current_user.get_role() == Role::Admin;

    if !is_self && !is_admin_plus {
        return Err(ApiError::forbidden(
            "Cannot create API keys for other users",
        ));
    }

    let name = if req_name.is_empty() {
        None
    } else {
        Some(req_name)
    };
    let expires_in_days = if req_expires == 0 {
        None
    } else {
        Some(req_expires)
    };

    let (plaintext_key, api_key) =
        api_keys_crud::create_api_key(&state.db_pool, user_id, name, expires_in_days)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create API key: {}", e);
                ApiError::internal("Failed to create API key")
            })?;

    let response = CreateApiKeyResponse {
        key: plaintext_key,
        details: ApiKeyResponse::from(api_key),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// List API keys for user
pub async fn list_api_keys(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    Extension(current_user_id): Extension<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;

    // Allow if viewing own keys or if admin+
    let is_self = current_user_id == user_id;
    let is_admin_plus =
        current_user.get_role() == Role::RootAdmin || current_user.get_role() == Role::Admin;

    if !is_self && !is_admin_plus {
        return Err(ApiError::forbidden("Cannot view other users' API keys"));
    }

    let keys = api_keys_crud::list_api_keys(&state.db_pool, user_id).await?;

    let response: Vec<ApiKeyResponse> = keys.into_iter().map(ApiKeyResponse::from).collect();

    Ok(Json(response))
}

/// Revoke API key
pub async fn revoke_api_key(
    State(state): State<Arc<AppState>>,
    Path((user_id, key_id)): Path<(i64, i64)>,
    Extension(current_user_id): Extension<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;
    // Allow if revoking own key or if admin+
    let is_self = current_user_id == user_id;
    let is_admin_plus =
        current_user.get_role() == Role::RootAdmin || current_user.get_role() == Role::Admin;
    if !is_self && !is_admin_plus {
        return Err(ApiError::forbidden("Cannot revoke other users' API keys"));
    }
    api_keys_crud::revoke_api_key(&state.db_pool, key_id, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke API key: {}", e);
            ApiError::internal("Failed to revoke API key")
        })?;

    // Invalidate cached API key verifications for this user
    state.invalidate_api_key_cache(user_id).await;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/users/me/password — self-service password change.
/// Requires the caller's current password. root_admin is not allowed here
/// (it resets via the admin endpoint); available to `user` and `admin`.
pub async fn change_own_password(
    State(state): State<Arc<AppState>>,
    Extension(current_user_id): Extension<i64>,
    Json(request): Json<super::models::ChangeOwnPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;

    if !self_reset_allowed(&current_user.get_role()) {
        return Err(ApiError::forbidden(
            "root_admin changes password via the admin reset flow",
        ));
    }

    // Authenticate with the current password.
    let ok = users::verify_password(
        &state.db_pool,
        &current_user.username,
        &request.current_password,
    )
    .await?
    .is_some();
    if !ok {
        return Err(ApiError::unauthorized("Current password is incorrect"));
    }

    crate::validation::validate_password(&request.new_password).map_err(ApiError::bad_request)?;

    let updated = users::update_user(
        &state.db_pool,
        current_user_id,
        Some(&request.new_password),
        None,
        None,
        None,
        None,
    )
    .await?;

    state
        .invalidate_all_for_user(current_user_id, Some(&updated.username))
        .await;

    let _ = crate::db::audit_log::log_action(
        &state.db_pool,
        current_user_id,
        "password_self_reset",
        Some("user"),
        Some(&current_user_id.to_string()),
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod authz_tests {
    use super::{authorize_admin_reset, authorize_create_user, self_reset_allowed};
    use crate::db::models::Role;

    #[test]
    fn create_user_matrix() {
        // root_admin can create anything
        assert!(authorize_create_user(&Role::RootAdmin, &Role::User).is_ok());
        assert!(authorize_create_user(&Role::RootAdmin, &Role::Admin).is_ok());
        assert!(authorize_create_user(&Role::RootAdmin, &Role::RootAdmin).is_ok());
        // admin can create only regular users
        assert!(authorize_create_user(&Role::Admin, &Role::User).is_ok());
        assert!(authorize_create_user(&Role::Admin, &Role::Admin).is_err());
        assert!(authorize_create_user(&Role::Admin, &Role::RootAdmin).is_err());
        // plain user cannot create
        assert!(authorize_create_user(&Role::User, &Role::User).is_err());
    }

    #[test]
    fn admin_reset_matrix() {
        // root_admin can reset anyone
        assert!(authorize_admin_reset(&Role::RootAdmin, &Role::User).is_ok());
        assert!(authorize_admin_reset(&Role::RootAdmin, &Role::Admin).is_ok());
        assert!(authorize_admin_reset(&Role::RootAdmin, &Role::RootAdmin).is_ok());
        // admin can reset only regular users
        assert!(authorize_admin_reset(&Role::Admin, &Role::User).is_ok());
        assert!(authorize_admin_reset(&Role::Admin, &Role::Admin).is_err());
        assert!(authorize_admin_reset(&Role::Admin, &Role::RootAdmin).is_err());
        // plain user cannot reset others
        assert!(authorize_admin_reset(&Role::User, &Role::User).is_err());
    }

    #[test]
    fn self_reset_excludes_root_admin() {
        assert!(self_reset_allowed(&Role::User));
        assert!(self_reset_allowed(&Role::Admin));
        assert!(!self_reset_allowed(&Role::RootAdmin));
    }
}
