use crate::db::models::{ApiKey, Role, User};
use serde::{Deserialize, Serialize};

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
