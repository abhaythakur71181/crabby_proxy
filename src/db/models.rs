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

    // Target filtering (per-user)
    pub allowed_targets: Option<String>, // JSON: ["*.example.com"]
    pub blocked_targets: Option<String>, // JSON: ["*.malware.org"]

    // Time-based access
    pub access_schedule: Option<String>, // JSON: {"days":["mon"...],"start_hour":9,"end_hour":18,"timezone":"UTC"}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user_with_role(role: &str) -> User {
        User {
            id: 1,
            username: "testuser".to_string(),
            password_hash: "hash".to_string(),
            role: role.to_string(),
            created_by: None,
            created_at: 1700000000,
            updated_at: 1700000000,
            is_active: true,
            max_connections: 5,
            bandwidth_limit_mb: 1000,
            rate_limit_enabled: true,
            rate_limit_rps: 10,
            rate_limit_burst: 20,
            allowed_protocols: None,
            ip_whitelist: None,
            allowed_targets: None,
            blocked_targets: None,
            access_schedule: None,
            notes: None,
            last_login_at: None,
        }
    }

    // === Role enum Tests ===

    #[test]
    fn test_role_equality() {
        assert_eq!(Role::RootAdmin, Role::RootAdmin);
        assert_eq!(Role::Admin, Role::Admin);
        assert_eq!(Role::User, Role::User);
        assert_ne!(Role::RootAdmin, Role::Admin);
        assert_ne!(Role::Admin, Role::User);
        assert_ne!(Role::RootAdmin, Role::User);
    }

    #[test]
    fn test_role_clone() {
        let role = Role::Admin;
        let cloned = role.clone();
        assert_eq!(role, cloned);
    }

    #[test]
    fn test_role_debug() {
        assert_eq!(format!("{:?}", Role::RootAdmin), "RootAdmin");
        assert_eq!(format!("{:?}", Role::Admin), "Admin");
        assert_eq!(format!("{:?}", Role::User), "User");
    }

    #[test]
    fn test_role_serialization() {
        let json = serde_json::to_string(&Role::RootAdmin).unwrap();
        assert_eq!(json, "\"root_admin\"");

        let json = serde_json::to_string(&Role::Admin).unwrap();
        assert_eq!(json, "\"admin\"");

        let json = serde_json::to_string(&Role::User).unwrap();
        assert_eq!(json, "\"user\"");
    }

    #[test]
    fn test_role_deserialization() {
        let role: Role = serde_json::from_str("\"root_admin\"").unwrap();
        assert_eq!(role, Role::RootAdmin);

        let role: Role = serde_json::from_str("\"admin\"").unwrap();
        assert_eq!(role, Role::Admin);

        let role: Role = serde_json::from_str("\"user\"").unwrap();
        assert_eq!(role, Role::User);
    }

    #[test]
    fn test_role_serialization_roundtrip() {
        for role in &[Role::RootAdmin, Role::Admin, Role::User] {
            let json = serde_json::to_string(role).unwrap();
            let deserialized: Role = serde_json::from_str(&json).unwrap();
            assert_eq!(*role, deserialized);
        }
    }

    // === User::get_role Tests ===

    #[test]
    fn test_get_role_root_admin() {
        let user = test_user_with_role("root_admin");
        assert_eq!(user.get_role(), Role::RootAdmin);
    }

    #[test]
    fn test_get_role_admin() {
        let user = test_user_with_role("admin");
        assert_eq!(user.get_role(), Role::Admin);
    }

    #[test]
    fn test_get_role_user() {
        let user = test_user_with_role("user");
        assert_eq!(user.get_role(), Role::User);
    }

    #[test]
    fn test_get_role_unknown_defaults_to_user() {
        let user = test_user_with_role("moderator");
        assert_eq!(user.get_role(), Role::User);
    }

    #[test]
    fn test_get_role_empty_string_defaults_to_user() {
        let user = test_user_with_role("");
        assert_eq!(user.get_role(), Role::User);
    }

    #[test]
    fn test_get_role_case_sensitive() {
        // "Admin" (capitalized) should NOT match "admin"
        let user = test_user_with_role("Admin");
        assert_eq!(user.get_role(), Role::User); // Defaults to User
    }

    // === CreateUserRequest Tests ===

    #[test]
    fn test_create_user_request_serialization() {
        let req = CreateUserRequest {
            username: "newuser".to_string(),
            password: "pass123!".to_string(),
            role: Role::User,
            max_connections: Some(10),
            bandwidth_limit_mb: Some(500),
            rate_limit_enabled: Some(true),
            rate_limit_rps: Some(20),
            allowed_protocols: Some(vec!["http".to_string(), "https".to_string()]),
            notes: Some("test user".to_string()),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"username\":\"newuser\""));
        assert!(json.contains("\"role\":\"user\""));
    }

    #[test]
    fn test_create_user_request_deserialization() {
        let json = r#"{
            "username": "alice",
            "password": "secure123!",
            "role": "admin",
            "max_connections": 25
        }"#;

        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "alice");
        assert_eq!(req.password, "secure123!");
        assert_eq!(req.role, Role::Admin);
        assert_eq!(req.max_connections, Some(25));
        assert!(req.bandwidth_limit_mb.is_none());
        assert!(req.notes.is_none());
    }

    #[test]
    fn test_create_user_request_clone() {
        let req = CreateUserRequest {
            username: "clone_test".to_string(),
            password: "pass123!".to_string(),
            role: Role::User,
            max_connections: None,
            bandwidth_limit_mb: None,
            rate_limit_enabled: None,
            rate_limit_rps: None,
            allowed_protocols: None,
            notes: None,
        };
        let cloned = req.clone();
        assert_eq!(cloned.username, "clone_test");
    }

    // === User struct tests ===

    #[test]
    fn test_user_clone() {
        let user = test_user_with_role("admin");
        let cloned = user.clone();
        assert_eq!(cloned.id, user.id);
        assert_eq!(cloned.username, user.username);
        assert_eq!(cloned.role, user.role);
    }

    #[test]
    fn test_user_optional_fields_none() {
        let user = test_user_with_role("user");
        assert!(user.created_by.is_none());
        assert!(user.allowed_protocols.is_none());
        assert!(user.ip_whitelist.is_none());
        assert!(user.notes.is_none());
        assert!(user.last_login_at.is_none());
    }

    #[test]
    fn test_user_optional_fields_some() {
        let mut user = test_user_with_role("user");
        user.created_by = Some(1);
        user.allowed_protocols = Some("[\"http\"]".to_string());
        user.ip_whitelist = Some("10.0.0.0/8".to_string());
        user.notes = Some("test notes".to_string());
        user.last_login_at = Some(1700000000);

        assert_eq!(user.created_by, Some(1));
        assert!(user.allowed_protocols.unwrap().contains("http"));
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
