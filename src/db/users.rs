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
        .map_err(|e| sqlx::Error::Protocol(format!("Password hashing failed: {}", e)))?;

    let now = chrono::Utc::now().timestamp();
    let role_str = match request.role {
        Role::RootAdmin => "root_admin",
        Role::Admin => "admin",
        Role::User => "user",
    };

    let max_connections = request.max_connections.unwrap_or(5);
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
        if verify_password_hash(password, &user.password_hash) {
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

/// Create root admin if none exists
pub async fn ensure_root_admin(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'root_admin'")
        .fetch_one(pool)
        .await?;
    if count.0 == 0 {
        let request = CreateUserRequest {
            username: "root".to_string(),
            password: "changeme123".to_string(),
            role: Role::RootAdmin,
            max_connections: Some(100),
            bandwidth_limit_mb: Some(10000),
            rate_limit_enabled: Some(false),
            rate_limit_rps: Some(1000),
            allowed_protocols: None,
            notes: Some("Default root admin - CHANGE PASSWORD IMMEDIATELY".to_string()),
        };
        create_user(pool, &request, None).await?;
        tracing::warn!("⚠️  Created default root admin account:");
        tracing::warn!("   Username: root");
        tracing::warn!("   Password: changeme123");
        tracing::warn!("   *** CHANGE THIS PASSWORD IMMEDIATELY ***");

        Ok(true)
    } else {
        Ok(false)
    }
}

// Password hashing helpers
fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::password_hash::rand_core::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

fn verify_password_hash(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
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
