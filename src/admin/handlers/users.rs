use super::models::{
    ApiKeyResponse, CreateApiKeyRequest, CreateApiKeyResponse, UpdateUserRequest, UserResponse,
};
use crate::app_state::AppState;
use crate::db::{api_keys_crud, models::Role, users};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};

/// Create a new user (root_admin only)
pub async fn create_user(
    State(state): State<AppState>,
    Extension(current_user_id): Extension<i64>,
    Json(request): Json<super::models::CreateUserRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if current_user.get_role() != Role::RootAdmin {
        return Err(StatusCode::FORBIDDEN);
    }
    crate::validation::validate_username(&request.username).map_err(|_| StatusCode::BAD_REQUEST)?;
    crate::validation::validate_password(&request.password).map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Ok(Some(_)) = users::get_user_by_username(&state.db_pool, &request.username).await {
        return Err(StatusCode::CONFLICT);
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
    let user_id = users::create_user(&state.db_pool, &db_request, Some(current_user_id))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user = users::get_user_by_id(&state.db_pool, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::CREATED, Json(UserResponse::from(user))))
}

/// List all users (admin+)
pub async fn list_users(
    State(state): State<AppState>,
    Extension(current_user_id): Extension<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check if current user is at least admin
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if current_user.get_role() == Role::User {
        return Err(StatusCode::FORBIDDEN);
    }

    let users_list = users::list_users(&state.db_pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response: Vec<UserResponse> = users_list.into_iter().map(UserResponse::from).collect();

    Ok(Json(response))
}

/// Get user details (admin+ or self)
pub async fn get_user(
    State(state): State<AppState>,
    Extension(current_user_id): Extension<i64>,
    Path(user_id): Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Allow if admin+ or viewing own profile
    if current_user.get_role() == Role::User && current_user_id != user_id {
        return Err(StatusCode::FORBIDDEN);
    }

    let user = users::get_user_by_id(&state.db_pool, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(UserResponse::from(user)))
}

/// Update user (root_admin or self for limited fields)
pub async fn update_user(
    State(state): State<AppState>,
    Extension(current_user_id): Extension<i64>,
    Path(user_id): Path<i64>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let is_self = current_user_id == user_id;
    let is_root_admin = current_user.get_role() == Role::RootAdmin;

    // Regular users can only update their own password
    if !is_root_admin && !is_self {
        return Err(StatusCode::FORBIDDEN);
    }

    // Non-root users can't change role, quotas, or active status
    if !is_root_admin
        && (request.role.is_some()
            || request.max_connections.is_some()
            || request.bandwidth_limit_mb.is_some()
            || request.is_active.is_some())
    {
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate password length if provided
    if let Some(ref pwd) = request.password {
        if pwd.len() < 8 {
            return Err(StatusCode::BAD_REQUEST);
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
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(UserResponse::from(updated_user)))
}

/// Delete user (root_admin only)
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(current_user_id): Extension<i64>,
    Path(user_id): Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if current_user.get_role() != Role::RootAdmin {
        return Err(StatusCode::FORBIDDEN);
    }

    // Don't allow deleting yourself
    if current_user_id == user_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    users::delete_user(&state.db_pool, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Create API key for user
pub async fn create_api_key(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    Extension(current_user_id): Extension<i64>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), StatusCode> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Allow if creating for self or if admin+
    let is_self = current_user_id == user_id;
    let is_admin_plus =
        current_user.get_role() == Role::RootAdmin || current_user.get_role() == Role::Admin;

    if !is_self && !is_admin_plus {
        return Err(StatusCode::FORBIDDEN);
    }

    let name = if request.name.is_empty() {
        None
    } else {
        Some(request.name)
    };
    let expires_in_days = if request.expires_in_days == 0 {
        None
    } else {
        Some(request.expires_in_days)
    };

    let (plaintext_key, api_key) =
        api_keys_crud::create_api_key(&state.db_pool, user_id, name, expires_in_days)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = CreateApiKeyResponse {
        key: plaintext_key,
        details: ApiKeyResponse::from(api_key),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// List API keys for user
pub async fn list_api_keys(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    Extension(current_user_id): Extension<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Allow if viewing own keys or if admin+
    let is_self = current_user_id == user_id;
    let is_admin_plus =
        current_user.get_role() == Role::RootAdmin || current_user.get_role() == Role::Admin;

    if !is_self && !is_admin_plus {
        return Err(StatusCode::FORBIDDEN);
    }

    let keys = api_keys_crud::list_api_keys(&state.db_pool, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response: Vec<ApiKeyResponse> = keys.into_iter().map(ApiKeyResponse::from).collect();

    Ok(Json(response))
}

/// Revoke API key
pub async fn revoke_api_key(
    State(state): State<AppState>,
    Path((user_id, key_id)): Path<(i64, i64)>,
    Extension(current_user_id): Extension<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    // Allow if revoking own key or if admin+
    let is_self = current_user_id == user_id;
    let is_admin_plus =
        current_user.get_role() == Role::RootAdmin || current_user.get_role() == Role::Admin;
    if !is_self && !is_admin_plus {
        return Err(StatusCode::FORBIDDEN);
    }
    api_keys_crud::revoke_api_key(&state.db_pool, key_id, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}
