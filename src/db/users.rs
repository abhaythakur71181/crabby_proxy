use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sqlx::SqlitePool;

use super::models::{CreateUserRequest, Role, User};

/// Create a new user
pub async fn create_user(
    pool: &SqlitePool,
    request: &CreateUserRequest,
    created_by: Option<i64>,
) -> Result<i64, sqlx::Error> {
    // Hash the password
    let password_hash = hash_password(&request.password)
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("Password hashing failed: {}", e)))?;

    let now = chrono::Utc::now().timestamp();
    let role_str = match request.role {
        Role::RootAdmin => "root_admin",
        Role::Admin => "admin",
        Role::User => "user",
    };

    let max_connections = request.max_connections.unwrap_or(100);
    let bandwidth_limit_mb = request.bandwidth_limit_mb.unwrap_or(1000);
    let rate_limit_enabled = request.rate_limit_enabled.unwrap_or(true);
    let rate_limit_rps = request.rate_limit_rps.unwrap_or(10);
    let rate_limit_burst = rate_limit_rps * 2;

    let allowed_protocols = request
        .allowed_protocols
        .as_ref()
        .map(|p| serde_json::to_string(p).unwrap());

    let result = sqlx::query(
        r#"
        INSERT INTO users (
            username, password_hash, role, created_by, created_at, updated_at,
            max_connections, bandwidth_limit_mb, rate_limit_enabled,
            rate_limit_rps, rate_limit_burst, allowed_protocols, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&request.username)
    .bind(&password_hash)
    .bind(role_str)
    .bind(created_by)
    .bind(now)
    .bind(now)
    .bind(max_connections)
    .bind(bandwidth_limit_mb)
    .bind(rate_limit_enabled)
    .bind(rate_limit_rps)
    .bind(rate_limit_burst)
    .bind(allowed_protocols)
    .bind(&request.notes)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Get user by username
pub async fn get_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

/// Get user by ID
pub async fn get_user_by_id(pool: &SqlitePool, id: i64) -> Result<Option<User>, sqlx::Error> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

/// Verify user password
pub async fn verify_password(
    pool: &SqlitePool,
    username: &str,
    password: &str,
) -> Result<Option<User>, sqlx::Error> {
    let user = get_user_by_username(pool, username).await?;

    if let Some(user) = user {
        if verify_password_hash(password, &user.password_hash).await {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

/// Update last login time
pub async fn update_last_login(pool: &SqlitePool, user_id: i64) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();

    sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?")
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Generate a secure random password with guaranteed character diversity
fn generate_secure_password(length: usize) -> String {
    use rand::Rng;
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &[u8] = b"0123456789";
    const SPECIAL: &[u8] = b"!@#$%^&*";
    const ALL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    let length = length.max(4);
    let mut password: Vec<u8> = Vec::with_capacity(length);
    password.push(UPPERCASE[rng.gen_range(0..UPPERCASE.len())]);
    password.push(LOWERCASE[rng.gen_range(0..LOWERCASE.len())]);
    password.push(DIGITS[rng.gen_range(0..DIGITS.len())]);
    password.push(SPECIAL[rng.gen_range(0..SPECIAL.len())]);
    for _ in 4..length {
        password.push(ALL[rng.gen_range(0..ALL.len())]);
    }
    for i in (1..password.len()).rev() {
        let j = rng.gen_range(0..=i);
        password.swap(i, j);
    }
    String::from_utf8(password).unwrap_or_else(|_| "Fallback_P@ss1".to_string())
}

/// Create root admin if none exists
pub async fn ensure_root_admin(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'root_admin'")
        .fetch_one(pool)
        .await?;
    if count.0 == 0 {
        // Try env var first, then generate random password
        let password =
            std::env::var("CRABBY_ROOT_PASSWORD").unwrap_or_else(|_| generate_secure_password(16));

        let request = CreateUserRequest {
            username: "root".to_string(),
            password: password.clone(),
            role: Role::RootAdmin,
            max_connections: Some(100),
            bandwidth_limit_mb: Some(10000),
            rate_limit_enabled: Some(false),
            rate_limit_rps: Some(1000),
            allowed_protocols: None,
            notes: Some("Root admin account".to_string()),
        };
        create_user(pool, &request, None).await?;

        tracing::warn!("╔════════════════════════════════════════════════════════════╗");
        tracing::warn!("║          ROOT ADMIN ACCOUNT CREATED                        ║");
        tracing::warn!("╠════════════════════════════════════════════════════════════╣");
        tracing::warn!("║  Username: root                                            ║");
        tracing::warn!("║  Password: {:<48}║", password);
        tracing::warn!("╠════════════════════════════════════════════════════════════╣");
        tracing::warn!("║  *** SAVE THIS PASSWORD - IT WON'T BE SHOWN AGAIN ***      ║");
        tracing::warn!("║  To set a custom password, use env var:                    ║");
        tracing::warn!("║  CRABBY_ROOT_PASSWORD=yourpassword                         ║");
        tracing::warn!("╚════════════════════════════════════════════════════════════╝");

        Ok(true)
    } else {
        Ok(false)
    }
}

// Password hashing helpers
async fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let password = password.to_string();
    tokio::task::spawn_blocking(move || {
        use argon2::password_hash::rand_core::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(password_hash.to_string())
    })
    .await
    .map_err(|_| argon2::password_hash::Error::Password)?
}

async fn verify_password_hash(password: &str, hash: &str) -> bool {
    let password = password.to_string();
    let hash = hash.to_string();
    tokio::task::spawn_blocking(move || {
        let parsed_hash = match PasswordHash::new(&hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    })
    .await
    .unwrap_or(false)
}

/// Update user details
pub async fn update_user(
    pool: &SqlitePool,
    user_id: i64,
    password: Option<&str>,
    role: Option<Role>,
    max_connections: Option<i32>,
    bandwidth_limit_mb: Option<i64>,
    is_active: Option<bool>,
) -> Result<User, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();

    // Build update query dynamically based on what fields are provided
    let user = get_user_by_id(pool, user_id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;

    let password_hash = if let Some(pwd) = password {
        Some(
            hash_password(pwd)
                .await
                .map_err(|e| sqlx::Error::Protocol(format!("Password hashing failed: {}", e)))?,
        )
    } else {
        None
    };

    let role_str = role.map(|r| match r {
        Role::RootAdmin => "root_admin",
        Role::Admin => "admin",
        Role::User => "user",
    });

    sqlx::query(
        r#"
        UPDATE users SET
            password_hash = COALESCE(?, password_hash),
            role = COALESCE(?, role),
            max_connections = COALESCE(?, max_connections),
            bandwidth_limit_mb = COALESCE(?, bandwidth_limit_mb),
            is_active = COALESCE(?, is_active),
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(password_hash)
    .bind(role_str)
    .bind(max_connections)
    .bind(bandwidth_limit_mb)
    .bind(is_active)
    .bind(now)
    .bind(user_id)
    .execute(pool)
    .await?;

    get_user_by_id(pool, user_id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

/// Soft delete user (set is_active = false)
pub async fn delete_user(pool: &SqlitePool, user_id: i64) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    sqlx::query("UPDATE api_keys SET is_active = 0 WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// List all users (excluding password hashes)
pub async fn list_users(pool: &SqlitePool) -> Result<Vec<User>, sqlx::Error> {
    let users = sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC")
        .fetch_all(pool)
        .await?;
    Ok(users)
}

/// List users with pagination.
pub async fn list_users_paginated(
    pool: &SqlitePool,
    limit: i32,
    offset: i32,
) -> Result<Vec<User>, sqlx::Error> {
    let users = sqlx::query_as::<_, User>(
        "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(users)
}

/// Count total users.
pub async fn count_all_users(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Count active users
pub async fn count_users(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query("SELECT COUNT(*) FROM users WHERE is_active = 1")
        .fetch_one(pool)
        .await?;
    Ok(sqlx::Row::get(&row, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_by INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                max_connections INTEGER NOT NULL DEFAULT 100,
                bandwidth_limit_mb INTEGER NOT NULL DEFAULT 1000,
                rate_limit_enabled BOOLEAN NOT NULL DEFAULT 1,
                rate_limit_rps INTEGER NOT NULL DEFAULT 10,
                rate_limit_burst INTEGER NOT NULL DEFAULT 20,
                allowed_protocols TEXT,
                ip_whitelist TEXT,
                allowed_targets TEXT,
                blocked_targets TEXT,
                access_schedule TEXT,
                notes TEXT,
                last_login_at INTEGER,
                monthly_bandwidth_quota INTEGER,
                bandwidth_rate_bps INTEGER NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_hash TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                last_used_at INTEGER,
                is_active BOOLEAN NOT NULL DEFAULT 1
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    fn test_create_user_request(username: &str) -> CreateUserRequest {
        CreateUserRequest {
            username: username.to_string(),
            password: "TestPass123!".to_string(),
            role: Role::User,
            max_connections: None,
            bandwidth_limit_mb: None,
            rate_limit_enabled: None,
            rate_limit_rps: None,
            allowed_protocols: None,
            notes: None,
        }
    }

    // === create_user Tests ===

    #[tokio::test]
    async fn test_create_user_returns_positive_id() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("testuser");
        let id = create_user(&pool, &req, None).await.unwrap();
        assert!(id > 0);
    }

    #[tokio::test]
    async fn test_create_user_with_defaults() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("alice");
        let id = create_user(&pool, &req, None).await.unwrap();

        let user = get_user_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.max_connections, 100); // default
        assert_eq!(user.bandwidth_limit_mb, 1000); // default
        assert!(user.rate_limit_enabled); // default true
        assert_eq!(user.rate_limit_rps, 10); // default
        assert_eq!(user.rate_limit_burst, 20); // burst = rps * 2
        assert!(user.is_active);
    }

    #[tokio::test]
    async fn test_create_user_with_custom_limits() {
        let pool = setup_test_db().await;
        let req = CreateUserRequest {
            username: "bob".to_string(),
            password: "BobPass123!".to_string(),
            role: Role::Admin,
            max_connections: Some(50),
            bandwidth_limit_mb: Some(5000),
            rate_limit_enabled: Some(false),
            rate_limit_rps: Some(100),
            allowed_protocols: Some(vec!["http".to_string(), "https".to_string()]),
            notes: Some("Test admin".to_string()),
        };
        let id = create_user(&pool, &req, Some(1)).await.unwrap();

        let user = get_user_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(user.max_connections, 50);
        assert_eq!(user.bandwidth_limit_mb, 5000);
        assert!(!user.rate_limit_enabled);
        assert_eq!(user.rate_limit_rps, 100);
        assert_eq!(user.rate_limit_burst, 200); // 100 * 2
        assert!(user.notes.as_ref().unwrap().contains("Test admin"));
        assert_eq!(user.created_by, Some(1));
    }

    #[tokio::test]
    async fn test_create_duplicate_username_fails() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("duplicate");
        create_user(&pool, &req, None).await.unwrap();

        let result = create_user(&pool, &req, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_user_with_all_roles() {
        let pool = setup_test_db().await;

        let req1 = CreateUserRequest {
            role: Role::RootAdmin,
            ..test_create_user_request("root")
        };
        let id1 = create_user(&pool, &req1, None).await.unwrap();
        let u1 = get_user_by_id(&pool, id1).await.unwrap().unwrap();
        assert_eq!(u1.role, "root_admin");

        let req2 = CreateUserRequest {
            role: Role::Admin,
            ..test_create_user_request("admin")
        };
        let id2 = create_user(&pool, &req2, None).await.unwrap();
        let u2 = get_user_by_id(&pool, id2).await.unwrap().unwrap();
        assert_eq!(u2.role, "admin");

        let req3 = test_create_user_request("user");
        let id3 = create_user(&pool, &req3, None).await.unwrap();
        let u3 = get_user_by_id(&pool, id3).await.unwrap().unwrap();
        assert_eq!(u3.role, "user");
    }

    // === get_user_by_username Tests ===

    #[tokio::test]
    async fn test_get_user_by_username_found() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("findme");
        create_user(&pool, &req, None).await.unwrap();

        let user = get_user_by_username(&pool, "findme").await.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().username, "findme");
    }

    #[tokio::test]
    async fn test_get_user_by_username_not_found() {
        let pool = setup_test_db().await;
        let user = get_user_by_username(&pool, "nonexistent").await.unwrap();
        assert!(user.is_none());
    }

    // === get_user_by_id Tests ===

    #[tokio::test]
    async fn test_get_user_by_id_found() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("byid");
        let id = create_user(&pool, &req, None).await.unwrap();

        let user = get_user_by_id(&pool, id).await.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().id, id);
    }

    #[tokio::test]
    async fn test_get_user_by_id_not_found() {
        let pool = setup_test_db().await;
        let user = get_user_by_id(&pool, 99999).await.unwrap();
        assert!(user.is_none());
    }

    // === verify_password Tests ===

    #[tokio::test]
    async fn test_verify_password_correct() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("verify_user");
        create_user(&pool, &req, None).await.unwrap();

        let result = verify_password(&pool, "verify_user", "TestPass123!")
            .await
            .unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().username, "verify_user");
    }

    #[tokio::test]
    async fn test_verify_password_wrong_password() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("wrong_pw_user");
        create_user(&pool, &req, None).await.unwrap();

        let result = verify_password(&pool, "wrong_pw_user", "WrongPass999!")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_verify_password_nonexistent_user() {
        let pool = setup_test_db().await;
        let result = verify_password(&pool, "ghost", "password123")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    // === update_last_login Tests ===

    #[tokio::test]
    async fn test_update_last_login() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("login_user");
        let id = create_user(&pool, &req, None).await.unwrap();

        // Initially null
        let user = get_user_by_id(&pool, id).await.unwrap().unwrap();
        assert!(user.last_login_at.is_none());

        // Update
        update_last_login(&pool, id).await.unwrap();

        let user = get_user_by_id(&pool, id).await.unwrap().unwrap();
        assert!(user.last_login_at.is_some());
    }

    // === update_user Tests ===

    #[tokio::test]
    async fn test_update_user_password() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("update_pw");
        let id = create_user(&pool, &req, None).await.unwrap();

        let updated = update_user(&pool, id, Some("NewPass456!"), None, None, None, None)
            .await
            .unwrap();

        // Verify new password works
        let result = verify_password(&pool, "update_pw", "NewPass456!")
            .await
            .unwrap();
        assert!(result.is_some());

        // Verify old password doesn't work
        let result = verify_password(&pool, "update_pw", "TestPass123!")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update_user_role() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("update_role");
        let id = create_user(&pool, &req, None).await.unwrap();

        let updated = update_user(&pool, id, None, Some(Role::Admin), None, None, None)
            .await
            .unwrap();
        assert_eq!(updated.role, "admin");
    }

    #[tokio::test]
    async fn test_update_user_max_connections() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("update_conn");
        let id = create_user(&pool, &req, None).await.unwrap();

        let updated = update_user(&pool, id, None, None, Some(100), None, None)
            .await
            .unwrap();
        assert_eq!(updated.max_connections, 100);
    }

    #[tokio::test]
    async fn test_update_user_deactivate() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("deactivate_me");
        let id = create_user(&pool, &req, None).await.unwrap();

        let updated = update_user(&pool, id, None, None, None, None, Some(false))
            .await
            .unwrap();
        assert!(!updated.is_active);
    }

    #[tokio::test]
    async fn test_update_nonexistent_user_fails() {
        let pool = setup_test_db().await;
        let result = update_user(&pool, 99999, None, None, None, None, None).await;
        assert!(result.is_err());
    }

    // === delete_user Tests ===

    #[tokio::test]
    async fn test_delete_user_soft_deletes() {
        let pool = setup_test_db().await;
        let req = test_create_user_request("delete_me");
        let id = create_user(&pool, &req, None).await.unwrap();

        delete_user(&pool, id).await.unwrap();

        // User still exists but is inactive
        let user = get_user_by_id(&pool, id).await.unwrap().unwrap();
        assert!(!user.is_active);
    }

    // === list_users Tests ===

    #[tokio::test]
    async fn test_list_users_empty() {
        let pool = setup_test_db().await;
        let users = list_users(&pool).await.unwrap();
        assert!(users.is_empty());
    }

    #[tokio::test]
    async fn test_list_users_multiple() {
        let pool = setup_test_db().await;
        create_user(&pool, &test_create_user_request("user1"), None)
            .await
            .unwrap();
        create_user(&pool, &test_create_user_request("user2"), None)
            .await
            .unwrap();
        create_user(&pool, &test_create_user_request("user3"), None)
            .await
            .unwrap();

        let users = list_users(&pool).await.unwrap();
        assert_eq!(users.len(), 3);
    }

    // === ensure_root_admin Tests ===

    #[tokio::test]
    async fn test_ensure_root_admin_creates_when_none_exists() {
        let pool = setup_test_db().await;
        let created = ensure_root_admin(&pool).await.unwrap();
        assert!(created);

        let root = get_user_by_username(&pool, "root").await.unwrap();
        assert!(root.is_some());
        assert_eq!(root.unwrap().role, "root_admin");
    }

    #[tokio::test]
    async fn test_ensure_root_admin_does_not_recreate() {
        let pool = setup_test_db().await;

        // Create root admin first time
        let created1 = ensure_root_admin(&pool).await.unwrap();
        assert!(created1);

        // Second call should not create another
        let created2 = ensure_root_admin(&pool).await.unwrap();
        assert!(!created2);
    }

    // === generate_secure_password Tests ===

    #[test]
    fn test_generate_secure_password_minimum_length() {
        let pw = generate_secure_password(4);
        assert!(pw.len() >= 4);
    }

    #[test]
    fn test_generate_secure_password_shorter_than_4_clamped() {
        let pw = generate_secure_password(2);
        assert!(pw.len() >= 4); // clamped to 4 minimum
    }

    #[test]
    fn test_generate_secure_password_diversity() {
        let pw = generate_secure_password(16);
        assert!(pw.len() == 16);
        // Should contain at least one of each character class
        assert!(pw.chars().any(|c| c.is_uppercase()));
        assert!(pw.chars().any(|c| c.is_lowercase()));
        assert!(pw.chars().any(|c| c.is_numeric()));
        assert!(pw.chars().any(|c| "!@#$%^&*".contains(c)));
    }

    #[test]
    fn test_generate_secure_password_is_valid_utf8() {
        for _ in 0..100 {
            let pw = generate_secure_password(20);
            assert!(pw.is_ascii());
        }
    }
}
