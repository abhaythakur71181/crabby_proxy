use crate::db::models::{ApiKey, Role, User};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

/// Structured error response for admin API endpoints.
/// Implements `IntoResponse` so handlers can return `Result<..., ApiError>`.
#[derive(Debug, Serialize)]
pub struct ApiError {
    #[serde(skip)]
    pub status: StatusCode,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: msg.into(),
            detail: None,
        }
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: msg.into(),
            detail: None,
        }
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error: msg.into(),
            detail: None,
        }
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: msg.into(),
            detail: None,
        }
    }
    #[allow(dead_code)]
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            error: msg.into(),
            detail: None,
        }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: msg.into(),
            detail: None,
        }
    }
    #[allow(dead_code)]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = axum::Json(serde_json::json!({
            "error": self.error,
            "detail": self.detail,
        }));
        (self.status, body).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("Database error: {}", e);
        Self::internal("Database error")
    }
}

// User creation/update requests
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: Role,
    pub max_connections: Option<i32>,
    pub bandwidth_limit_mb: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub password: Option<String>,
    pub role: Option<Role>,
    pub max_connections: Option<i32>,
    pub bandwidth_limit_mb: Option<i64>,
    pub is_active: Option<bool>,
}

// User responses
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub username: String,
    pub role: Role,
    pub max_connections: i32,
    pub bandwidth_limit_mb: i64,
    pub is_active: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<UserStats>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        let role = user.get_role();
        Self {
            id: user.id,
            username: user.username,
            role,
            max_connections: user.max_connections,
            bandwidth_limit_mb: user.bandwidth_limit_mb,
            is_active: user.is_active,
            created_at: user.created_at,
            last_login_at: user.last_login_at,
            stats: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserStats {
    pub active_connections: i32,
    pub total_bandwidth_mb: i64,
    pub api_keys_count: i32,
}

// API Key responses
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub is_active: bool,
}

impl From<ApiKey> for ApiKeyResponse {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            prefix: key.prefix,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
            expires_at: key.expires_at,
            is_active: key.is_active,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub key: String, // Full key, shown only once
    pub details: ApiKeyResponse,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub expires_in_days: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::{ApiKey, Role, User};

    fn test_user() -> User {
        User {
            id: 42,
            username: "testuser".to_string(),
            password_hash: "hash".to_string(),
            role: "admin".to_string(),
            created_by: Some(1),
            created_at: 1700000000,
            updated_at: 1700000100,
            is_active: true,
            max_connections: 50,
            bandwidth_limit_mb: 5000,
            bandwidth_rate_bps: 0,
            rate_limit_enabled: true,
            rate_limit_rps: 10,
            rate_limit_burst: 20,
            allowed_protocols: Some("[\"http\",\"https\"]".to_string()),
            ip_whitelist: None,
            allowed_targets: None,
            blocked_targets: None,
            access_schedule: None,
            notes: Some("test notes".to_string()),
            last_login_at: Some(1700000050),
        }
    }

    fn test_api_key() -> ApiKey {
        ApiKey {
            id: 7,
            user_id: 42,
            key_hash: "argon2hash".to_string(),
            prefix: "abcd".to_string(),
            name: "my-key".to_string(),
            created_at: 1700000000,
            expires_at: Some(1702592000),
            last_used_at: Some(1700100000),
            is_active: true,
        }
    }

    // === UserResponse From<User> Tests ===

    #[test]
    fn test_user_response_from_user() {
        let user = test_user();
        let response: UserResponse = user.into();

        assert_eq!(response.id, 42);
        assert_eq!(response.username, "testuser");
        assert_eq!(response.role, Role::Admin);
        assert_eq!(response.max_connections, 50);
        assert_eq!(response.bandwidth_limit_mb, 5000);
        assert!(response.is_active);
        assert_eq!(response.created_at, 1700000000);
        assert_eq!(response.last_login_at, Some(1700000050));
        assert!(response.stats.is_none()); // Always None from conversion
    }

    #[test]
    fn test_user_response_from_root_admin() {
        let mut user = test_user();
        user.role = "root_admin".to_string();
        let response: UserResponse = user.into();
        assert_eq!(response.role, Role::RootAdmin);
    }

    #[test]
    fn test_user_response_from_regular_user() {
        let mut user = test_user();
        user.role = "user".to_string();
        let response: UserResponse = user.into();
        assert_eq!(response.role, Role::User);
    }

    #[test]
    fn test_user_response_from_unknown_role_defaults_to_user() {
        let mut user = test_user();
        user.role = "unknown_role".to_string();
        let response: UserResponse = user.into();
        assert_eq!(response.role, Role::User);
    }

    #[test]
    fn test_user_response_with_no_last_login() {
        let mut user = test_user();
        user.last_login_at = None;
        let response: UserResponse = user.into();
        assert!(response.last_login_at.is_none());
    }

    // === ApiKeyResponse From<ApiKey> Tests ===

    #[test]
    fn test_api_key_response_from_api_key() {
        let key = test_api_key();
        let response: ApiKeyResponse = key.into();

        assert_eq!(response.id, 7);
        assert_eq!(response.prefix, "abcd");
        assert_eq!(response.created_at, 1700000000);
        assert_eq!(response.last_used_at, Some(1700100000));
        assert_eq!(response.expires_at, Some(1702592000));
        assert!(response.is_active);
    }

    #[test]
    fn test_api_key_response_without_expiration() {
        let mut key = test_api_key();
        key.expires_at = None;
        let response: ApiKeyResponse = key.into();
        assert!(response.expires_at.is_none());
    }

    #[test]
    fn test_api_key_response_never_used() {
        let mut key = test_api_key();
        key.last_used_at = None;
        let response: ApiKeyResponse = key.into();
        assert!(response.last_used_at.is_none());
    }

    #[test]
    fn test_api_key_response_inactive() {
        let mut key = test_api_key();
        key.is_active = false;
        let response: ApiKeyResponse = key.into();
        assert!(!response.is_active);
    }

    // === Serialization Tests ===

    #[test]
    fn test_user_response_serializes_to_json() {
        let user = test_user();
        let response: UserResponse = user.into();
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"username\":\"testuser\""));
        assert!(json.contains("\"is_active\":true"));
        // stats should be skipped when None
        assert!(!json.contains("\"stats\""));
    }

    #[test]
    fn test_api_key_response_serializes_to_json() {
        let key = test_api_key();
        let response: ApiKeyResponse = key.into();
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"id\":7"));
        assert!(json.contains("\"prefix\":\"abcd\""));
        assert!(json.contains("\"is_active\":true"));
    }

    // === Deserialization Tests ===

    #[test]
    fn test_create_user_request_deserializes() {
        let json = r#"{"username":"newuser","password":"pass123!","role":"user"}"#;
        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "newuser");
        assert_eq!(req.password, "pass123!");
        assert_eq!(req.role, Role::User);
        assert!(req.max_connections.is_none());
        assert!(req.bandwidth_limit_mb.is_none());
    }

    #[test]
    fn test_create_user_request_with_optional_fields() {
        let json = r#"{"username":"admin","password":"secure1!","role":"admin","max_connections":100,"bandwidth_limit_mb":10000}"#;
        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.max_connections, Some(100));
        assert_eq!(req.bandwidth_limit_mb, Some(10000));
    }

    #[test]
    fn test_update_user_request_all_none() {
        let json = "{}";
        let req: UpdateUserRequest = serde_json::from_str(json).unwrap();
        assert!(req.password.is_none());
        assert!(req.role.is_none());
        assert!(req.max_connections.is_none());
        assert!(req.bandwidth_limit_mb.is_none());
        assert!(req.is_active.is_none());
    }

    #[test]
    fn test_update_user_request_partial() {
        let json = r#"{"password":"newpass1!","is_active":false}"#;
        let req: UpdateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.password, Some("newpass1!".to_string()));
        assert_eq!(req.is_active, Some(false));
        assert!(req.role.is_none());
    }

    #[test]
    fn test_create_api_key_request_defaults() {
        let json = "{}";
        let req: CreateApiKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "");
        assert_eq!(req.expires_in_days, 0);
    }

    #[test]
    fn test_create_api_key_request_with_values() {
        let json = r#"{"name":"prod-key","expires_in_days":90}"#;
        let req: CreateApiKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "prod-key");
        assert_eq!(req.expires_in_days, 90);
    }
}
