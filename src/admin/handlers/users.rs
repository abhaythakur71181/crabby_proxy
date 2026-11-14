use super::models::{
    ApiError, ApiKeyResponse, CreateApiKeyRequest, CreateApiKeyResponse, UpdateUserRequest,
    UserResponse,
};
use crate::admin::auth::{AuthSession, CurrentUser, RootAdminUser};
use crate::app_state::AppState;
use crate::db::{api_keys_crud, models::Role, sessions, users};
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

/// Revoke `target_id`'s admin sessions after a credential change. When the
/// caller changed its own account, the session it is using is kept (so the
/// UI does not log itself out) and every other session is ended.
async fn revoke_sessions(
    state: &AppState,
    target_id: i64,
    caller_id: i64,
    caller_session: Option<&AuthSession>,
) -> Result<(), ApiError> {
    let res = match caller_session {
        Some(s) if target_id == caller_id => {
            sessions::delete_user_sessions_except(&state.db_pool, target_id, &s.jti).await
        }
        _ => sessions::delete_user_sessions(&state.db_pool, target_id).await,
    };
    res.map(|_| ()).map_err(|e| {
        tracing::error!("Failed to revoke sessions for user {}: {}", target_id, e);
        ApiError::internal("Credential updated but failed to revoke sessions")
    })
}

/// Create a new user (root_admin only)
pub async fn create_user(
    current_user: CurrentUser,
    State(state): State<Arc<AppState>>,
    Json(request): Json<super::models::CreateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user_id = current_user.id;
    authorize_create_user(&current_user.role_enum(), &request.role).map_err(ApiError::forbidden)?;
    crate::validation::validate_username(&request.username).map_err(ApiError::bad_request)?;
    crate::validation::validate_password(&request.password).map_err(ApiError::bad_request)?;
    // No pre-check: the UNIQUE(username) constraint is the single source of
    // truth, so concurrent creates cannot both pass a check-then-insert race.
    // A violation is mapped to 409 below.
    let username = request.username.clone();
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
    let user_id = users::create_user(&state.db_pool, &db_request, Some(current_user_id))
        .await
        .map_err(|e| {
            if super::models::is_unique_violation(&e) {
                ApiError::conflict(format!("Username '{}' already exists", username))
            } else {
                ApiError::from(e)
            }
        })?;
    let user = users::get_user_by_id(&state.db_pool, user_id)
        .await?
        .ok_or_else(|| ApiError::internal("Failed to retrieve created user"))?;
    Ok((StatusCode::CREATED, Json(UserResponse::from(user))))
}

/// List users. Admins see all users; regular users see only themselves.
pub async fn list_users(
    current_user: CurrentUser,
    State(state): State<Arc<AppState>>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user_id = current_user.id;

    // Regular users only see their own profile
    if current_user.role_enum() == Role::User {
        let me = users::get_user_by_id(&state.db_pool, current_user_id)
            .await?
            .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;
        let items = vec![UserResponse::from(me)];
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
    current_user: CurrentUser,
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user_id = current_user.id;

    // Allow if admin+ or viewing own profile
    if current_user.role_enum() == Role::User && current_user_id != user_id {
        return Err(ApiError::forbidden("Cannot view other users"));
    }

    let user = users::get_user_by_id(&state.db_pool, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("User {} not found", user_id)))?;

    Ok(Json(UserResponse::from(user)))
}

/// Update user (root_admin or self for limited fields)
pub async fn update_user(
    current_user: CurrentUser,
    session: Option<Extension<AuthSession>>,
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user_id = current_user.id;

    let is_self = current_user_id == user_id;
    let is_root_admin = current_user.role_enum() == Role::RootAdmin;

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
    state.broadcast_user_invalidated(user_id).await;

    // A password change or deactivation ends the account's other sessions.
    if request.password.is_some() || request.is_active == Some(false) {
        revoke_sessions(&state, user_id, current_user_id, session.as_deref()).await?;
    }

    Ok(Json(UserResponse::from(updated_user)))
}

/// Delete user (root_admin only)
pub async fn delete_user(
    RootAdminUser(current_user): RootAdminUser,
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user_id = current_user.id;

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
    state.broadcast_user_invalidated(user_id).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Maximum number of active, unexpired API keys a single user may hold.
pub const MAX_API_KEYS_PER_USER: i64 = 25;
/// Maximum API key display-name length, in characters.
pub const MAX_API_KEY_NAME_LEN: usize = 64;
/// Maximum API key lifetime (10 years). `0` still means "never expires".
pub const MAX_API_KEY_EXPIRES_DAYS: i64 = 3650;

/// Validate and normalise a create-API-key request into
/// `(name, expires_in_days)` as stored. The name is trimmed (the column is NOT
/// NULL, so an empty name is stored as "" rather than NULL); 0 days -> None
/// (no expiry). Negative days (an already-expired key) and absurd lifetimes
/// are rejected, as are over-long names or names with control characters.
fn validate_api_key_request(
    name: String,
    expires_in_days: i64,
) -> Result<(String, Option<i64>), String> {
    let name = name.trim().to_string();
    if name.chars().count() > MAX_API_KEY_NAME_LEN {
        return Err(format!(
            "name must be at most {MAX_API_KEY_NAME_LEN} characters"
        ));
    }
    if name.chars().any(char::is_control) {
        return Err("name must not contain control characters".to_string());
    }
    if !(0..=MAX_API_KEY_EXPIRES_DAYS).contains(&expires_in_days) {
        return Err(format!(
            "expires_in_days must be between 0 (never) and {MAX_API_KEY_EXPIRES_DAYS}"
        ));
    }
    let expires = (expires_in_days != 0).then_some(expires_in_days);
    Ok((name, expires))
}

/// Create API key for user.
///
/// Authorization goes through `authorize_target`: a caller may create keys for
/// itself; root_admin for anyone; admin only for regular users. Previously any
/// admin could mint a working key for root_admin (or another admin) and
/// impersonate it on the proxy data plane.
pub async fn create_api_key(
    current_user: CurrentUser,
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    current_user.authorize_target(&state, user_id).await?;

    let (name, expires_in_days) = validate_api_key_request(request.name, request.expires_in_days)
        .map_err(ApiError::bad_request)?;

    let active = api_keys_crud::count_active_api_keys(&state.db_pool, user_id).await?;
    if active >= MAX_API_KEYS_PER_USER {
        return Err(ApiError::conflict(format!(
            "API key limit reached ({MAX_API_KEYS_PER_USER} active keys); revoke one first"
        )));
    }

    let (plaintext_key, api_key) =
        api_keys_crud::create_api_key(&state.db_pool, user_id, Some(name), expires_in_days)
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

/// List API keys for user (same target rules as creation).
pub async fn list_api_keys(
    current_user: CurrentUser,
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    Query(page): Query<super::models::PageQuery>,
) -> Result<impl IntoResponse, ApiError> {
    current_user.authorize_target(&state, user_id).await?;

    let keys = api_keys_crud::list_api_keys(&state.db_pool, user_id, page.page()).await?;

    let response: Vec<ApiKeyResponse> = keys.into_iter().map(ApiKeyResponse::from).collect();

    Ok(Json(response))
}

/// Revoke API key (same target rules as creation).
pub async fn revoke_api_key(
    current_user: CurrentUser,
    State(state): State<Arc<AppState>>,
    Path((user_id, key_id)): Path<(i64, i64)>,
) -> Result<impl IntoResponse, ApiError> {
    current_user.authorize_target(&state, user_id).await?;
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
    current_user: CurrentUser,
    session: Option<Extension<AuthSession>>,
    State(state): State<Arc<AppState>>,
    Json(request): Json<super::models::ChangeOwnPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user_id = current_user.id;

    if !self_reset_allowed(&current_user.role_enum()) {
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
    revoke_sessions(&state, current_user_id, current_user_id, session.as_deref()).await?;
    state.broadcast_user_invalidated(current_user_id).await;

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

/// POST /api/users/:id/password — admin resets another user's password (no
/// current password). root_admin may target anyone; admin may target only
/// regular users.
pub async fn admin_reset_password(
    current_user: CurrentUser,
    session: Option<Extension<AuthSession>>,
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    Json(request): Json<super::models::AdminResetPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user_id = current_user.id;
    let target = users::get_user_by_id(&state.db_pool, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    authorize_admin_reset(&current_user.role_enum(), &target.get_role())
        .map_err(ApiError::forbidden)?;

    crate::validation::validate_password(&request.new_password).map_err(ApiError::bad_request)?;

    let updated = users::update_user(
        &state.db_pool,
        user_id,
        Some(&request.new_password),
        None,
        None,
        None,
        None,
    )
    .await?;

    state
        .invalidate_all_for_user(user_id, Some(&updated.username))
        .await;
    revoke_sessions(&state, user_id, current_user_id, session.as_deref()).await?;
    state.broadcast_user_invalidated(user_id).await;

    let _ = crate::db::audit_log::log_action(
        &state.db_pool,
        current_user_id,
        "password_admin_reset",
        Some("user"),
        Some(&user_id.to_string()),
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
    fn api_key_request_validation() {
        use super::{
            validate_api_key_request as v, MAX_API_KEY_EXPIRES_DAYS, MAX_API_KEY_NAME_LEN,
        };
        assert_eq!(v(String::new(), 0).unwrap(), (String::new(), None));
        assert_eq!(
            v("  ci  ".into(), 30).unwrap(),
            ("ci".to_string(), Some(30))
        );
        assert!(v("k".into(), -1).is_err(), "negative expiry rejected");
        assert!(v("k".into(), MAX_API_KEY_EXPIRES_DAYS).is_ok());
        assert!(v("k".into(), MAX_API_KEY_EXPIRES_DAYS + 1).is_err());
        assert!(v("x".repeat(MAX_API_KEY_NAME_LEN), 0).is_ok());
        assert!(v("x".repeat(MAX_API_KEY_NAME_LEN + 1), 0).is_err());
        assert!(v("bad\nname".into(), 0).is_err());
    }

    #[test]
    fn self_reset_excludes_root_admin() {
        assert!(self_reset_allowed(&Role::User));
        assert!(self_reset_allowed(&Role::Admin));
        assert!(!self_reset_allowed(&Role::RootAdmin));
    }
}
