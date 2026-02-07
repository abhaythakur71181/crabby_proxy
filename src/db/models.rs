use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
pub enum Role {
    #[serde(rename = "root_admin")]
    RootAdmin,
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "user")]
    User,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    #[sqlx(rename = "role")]
    pub role: String,
    pub created_by: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub is_active: bool,

    // Limits
    pub max_connections: i32,
    pub bandwidth_limit_mb: i64,

    // Rate limiting
    pub rate_limit_enabled: bool,
    pub rate_limit_rps: i32,
    pub rate_limit_burst: i32,

    // Config
    pub allowed_protocols: Option<String>,
    pub ip_whitelist: Option<String>,

    // Metadata
    pub notes: Option<String>,
    pub last_login_at: Option<i64>,
}

impl User {
    /// Get role as enum
    pub fn get_role(&self) -> Role {
        match self.role.as_str() {
            "root_admin" => Role::RootAdmin,
            "admin" => Role::Admin,
            _ => Role::User,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: Role,
    pub max_connections: Option<i32>,
    pub bandwidth_limit_mb: Option<i64>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_rps: Option<i32>,
    pub allowed_protocols: Option<Vec<String>>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Approval {
    pub id: i64,
    pub user_id: i64,
    pub client_ip: String,
    pub approved_by: i64,
    pub approved_at: i64,
    pub expires_at: i64,
    pub is_expired: bool,
    pub is_terminated: bool,
    pub terminated_by: Option<i64>,
    pub terminated_at: Option<i64>,
    pub termination_reason: Option<String>,
    pub reason: Option<String>,
    pub approval_duration_hours: i32,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Usage {
    pub id: i64,
    pub user_id: i64,
    pub connection_id: String,
    pub client_ip: String,
    pub target_host: String,
    pub protocol: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub duration_seconds: Option<i32>,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub status: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKey {
    pub id: i64,
    pub user_id: i64,
    pub key_hash: String,
    #[sqlx(rename = "key_prefix")]
    pub prefix: String,
    pub name: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub is_active: bool,
}
