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

/// The (first, active) root_admin account. Config-file credentials resolve to
/// this user. Looked up by role, since the bootstrap account is named "root"
/// (see `ensure_root_admin`), not "root_admin".
pub async fn get_root_admin(pool: &SqlitePool) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE role = 'root_admin' AND is_active = 1 ORDER BY id LIMIT 1",
    )
    .fetch_optional(pool)
    .await
}

/// Get user by ID
pub async fn get_user_by_id(pool: &SqlitePool, id: i64) -> Result<Option<User>, sqlx::Error> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

/// Verify user password.
///
/// Does the same Argon2 work whether or not the username exists: on the
/// not-found path it verifies against a fixed dummy hash, so response timing
/// does not reveal which usernames exist (the generic "invalid credentials"
/// message would otherwise be undone by a measurable timing gap).
///
/// On success, a hash made with older or different Argon2 parameters is
/// transparently re-hashed with the current ones.
pub async fn verify_password(
    pool: &SqlitePool,
    username: &str,
    password: &str,
) -> Result<Option<User>, sqlx::Error> {
    let user = get_user_by_username(pool, username).await?;

    let Some(user) = user else {
        let _ = verify_password_hash(password, dummy_password_hash().await).await;
        return Ok(None);
    };
    if !verify_password_hash(password, &user.password_hash).await {
        return Ok(None);
    }
    if needs_rehash(&user.password_hash) {
        upgrade_password_hash(pool, &user, password).await;
    }
    Ok(Some(user))
}

/// Re-hash a verified password with the current parameters. Best effort: a
/// failure just leaves the old (still valid) hash in place. The `WHERE` on the
/// old hash avoids clobbering a password change that raced with this login.
async fn upgrade_password_hash(pool: &SqlitePool, user: &User, password: &str) {
    let new_hash = match hash_password(password).await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("Password re-hash for user {} failed: {}", user.id, e);
            return;
        }
    };
    match sqlx::query("UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?")
        .bind(&new_hash)
        .bind(user.id)
        .bind(&user.password_hash)
        .execute(pool)
        .await
    {
        Ok(_) => tracing::info!("Upgraded password hash parameters for user {}", user.id),
        Err(e) => tracing::warn!("Storing re-hashed password for {} failed: {}", user.id, e),
    }
}

/// A valid Argon2 hash of a random, never-disclosed password, made with the
/// current parameters. Used only to equalise timing on the user-not-found
/// path; nothing can ever verify against it.
async fn dummy_password_hash() -> &'static str {
    static DUMMY: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
    DUMMY
        .get_or_init(|| async {
            let secret = generate_secure_password(32);
            hash_password(&secret)
                .await
                .unwrap_or_else(|_| String::from("$argon2id$v=19$m=19456,t=2,p=1$invalid"))
        })
        .await
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

/// Default file the generated first-boot root password is written to when
/// there is no interactive terminal. Override with CRABBY_ROOT_PASSWORD_FILE.
#[cfg(not(test))]
const ROOT_PASSWORD_FILE: &str = "initial_root_password.txt";

/// Hand a generated root password to the operator WITHOUT going through the
/// `tracing` pipeline: anything logged there ends up in log shippers /
/// journald / container logs, in cleartext, for as long as logs are kept.
///
/// - Interactive terminal on stderr: print it there directly.
/// - Otherwise (service, container): write it to a new file readable only by
///   the service user (0600) and log only the file's path. The file is never
///   overwritten; delete it after saving the password.
/// - If the file cannot be written, fall back to raw stderr (still outside
///   the structured log pipeline).
#[cfg(not(test))]
fn disclose_generated_root_password(password: &str) {
    use std::io::{IsTerminal, Write};

    let banner = format!(
        "\n\
         ==============================================================\n\
         ROOT ADMIN ACCOUNT CREATED\n\
         Username: root\n\
         Password: {password}\n\
         Save this password now; it will not be shown again.\n\
         To choose it yourself, set CRABBY_ROOT_PASSWORD before first start.\n\
         ==============================================================\n"
    );
    if std::io::stderr().is_terminal() {
        eprint!("{}", banner);
        tracing::warn!("Root admin account 'root' created; the generated password was printed to the terminal (not to the logs)");
        return;
    }

    let path = std::env::var("CRABBY_ROOT_PASSWORD_FILE")
        .unwrap_or_else(|_| ROOT_PASSWORD_FILE.to_string());
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts
        .open(&path)
        .and_then(|mut f| writeln!(f, "username: root\npassword: {}", password))
    {
        Ok(()) => tracing::warn!(
            "Root admin account 'root' created; the generated password was written to {} (mode 0600). Save it and delete the file.",
            path
        ),
        Err(e) => {
            tracing::warn!(
                "Root admin account 'root' created; could not write the password file {} ({}), printing the password to stderr instead",
                path,
                e
            );
            eprint!("{}", banner);
        }
    }
}

/// Unit tests create many throwaway databases; don't litter files or stderr.
#[cfg(test)]
fn disclose_generated_root_password(_password: &str) {}

/// Create root admin if none exists
pub async fn ensure_root_admin(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'root_admin'")
        .fetch_one(pool)
        .await?;
    if count.0 == 0 {
        // Try env var first, then generate random password
        let from_env = std::env::var("CRABBY_ROOT_PASSWORD").ok();
        let generated = from_env.is_none();
        let password = from_env.unwrap_or_else(|| generate_secure_password(16));

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

        if generated {
            disclose_generated_root_password(&password);
        } else {
            tracing::warn!(
                "Root admin account 'root' created with the password from CRABBY_ROOT_PASSWORD"
            );
        }

        Ok(true)
    } else {
        Ok(false)
    }
}

// Password hashing helpers
//
// Argon2 parameters are pinned explicitly rather than taken from
// `Argon2::default()`, so a change of crate defaults can never silently
// weaken (or change) hashing. Values are the OWASP-recommended Argon2id
// baseline (19 MiB, 2 passes, 1 lane), which is also what the 0.5 crate
// default was when existing hashes were created. Raising them later is safe:
// `verify_password` re-hashes on the next successful login.

/// Argon2id memory cost in KiB.
pub(crate) const ARGON2_M_COST: u32 = 19 * 1024;
/// Argon2id iterations.
pub(crate) const ARGON2_T_COST: u32 = 2;
/// Argon2id parallelism.
pub(crate) const ARGON2_P_COST: u32 = 1;

/// The Argon2id instance used for every new password hash.
pub(crate) fn argon2_hasher() -> Argon2<'static> {
    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("pinned Argon2 parameters are valid");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

/// True if `hash` is not an Argon2id v19 hash with exactly the current
/// parameters (and should therefore be re-hashed once the password is known).
pub(crate) fn needs_rehash(hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false; // not a PHC string; nothing we can upgrade
    };
    if parsed.algorithm != argon2::Algorithm::Argon2id.ident() || parsed.version != Some(0x13) {
        return true;
    }
    match argon2::Params::try_from(&parsed) {
        Ok(p) => {
            p.m_cost() != ARGON2_M_COST
                || p.t_cost() != ARGON2_T_COST
                || p.p_cost() != ARGON2_P_COST
        }
        Err(_) => true,
    }
}

pub(crate) async fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let password = password.to_string();
    tokio::task::spawn_blocking(move || {
        use argon2::password_hash::rand_core::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = argon2_hasher().hash_password(password.as_bytes(), &salt)?;
        Ok(password_hash.to_string())
    })
    .await
    .map_err(|_| argon2::password_hash::Error::Password)?
}

/// Verify `password` against a PHC-format Argon2 hash. The parameters are
/// read from the hash itself, so older hashes keep verifying.
pub(crate) async fn verify_password_hash(password: &str, hash: &str) -> bool {
    let password = password.to_string();
    let hash = hash.to_string();
    tokio::task::spawn_blocking(move || {
        let parsed_hash = match PasswordHash::new(&hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        argon2_hasher()
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

    // Hash the password (if any) before opening the transaction — argon2 is slow
    // and we don't want to hold a write lock across it.
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

    // Update and read-back in one transaction so the returned row reflects this
    // update (no interleaving with a concurrent writer) and existence is checked
    // via rows_affected rather than a separate pre-SELECT.
    let mut tx = pool.begin().await?;

    let res = sqlx::query(
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
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        tx.rollback().await?;
        return Err(sqlx::Error::RowNotFound);
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(user)
}

/// Soft delete user (set is_active = false)
pub async fn delete_user(pool: &SqlitePool, user_id: i64) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    // One transaction: deactivating the account, its API keys, and revoking its
    // sessions must all land together. Previously these were separate
    // statements, so a failure after the first left a "deleted" user whose API
    // keys still authenticated; sessions were never revoked at all, so an
    // existing admin token kept working until natural expiry.
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE api_keys SET is_active = 0 WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// List users with pagination.
pub async fn list_users_paginated(
    pool: &SqlitePool,
    limit: i32,
    offset: i32,
) -> Result<Vec<User>, sqlx::Error> {
    let users =
        sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?")
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

        sqlx::query(
            r#"
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT,
                created_at INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL DEFAULT 0,
                ip_address TEXT,
                user_agent TEXT
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

    #[tokio::test]
    async fn test_dummy_hash_is_a_real_current_hash() {
        // The not-found path must cost a full Argon2 verify, so the dummy has
        // to be a parseable hash with the current parameters.
        let dummy = dummy_password_hash().await;
        assert!(PasswordHash::new(dummy).is_ok());
        assert!(!needs_rehash(dummy));
        assert!(!verify_password_hash("password123", dummy).await);
    }

    #[tokio::test]
    async fn test_new_hashes_use_pinned_params() {
        let hash = hash_password("pw").await.unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{}",
            hash
        );
        assert!(!needs_rehash(&hash));
    }

    #[test]
    fn test_needs_rehash_detects_other_params() {
        use argon2::password_hash::rand_core::OsRng;
        let weak = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(8 * 1024, 1, 1, None).unwrap(),
        )
        .hash_password(b"pw", &SaltString::generate(&mut OsRng))
        .unwrap()
        .to_string();
        assert!(needs_rehash(&weak));
        let argon2i = Argon2::new(
            argon2::Algorithm::Argon2i,
            argon2::Version::V0x13,
            argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None).unwrap(),
        )
        .hash_password(b"pw", &SaltString::generate(&mut OsRng))
        .unwrap()
        .to_string();
        assert!(needs_rehash(&argon2i));
        assert!(!needs_rehash("not-a-phc-string"));
    }

    #[tokio::test]
    async fn test_verify_password_rehashes_outdated_hash() {
        use argon2::password_hash::rand_core::OsRng;
        let pool = setup_test_db().await;
        let req = test_create_user_request("rehash_user");
        let id = create_user(&pool, &req, None).await.unwrap();
        let weak = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(8 * 1024, 1, 1, None).unwrap(),
        )
        .hash_password(b"TestPass123!", &SaltString::generate(&mut OsRng))
        .unwrap()
        .to_string();
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(&weak)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(verify_password(&pool, "rehash_user", "TestPass123!")
            .await
            .unwrap()
            .is_some());
        let stored = get_user_by_id(&pool, id).await.unwrap().unwrap();
        assert_ne!(stored.password_hash, weak);
        assert!(!needs_rehash(&stored.password_hash));
        // And the upgraded hash still verifies.
        assert!(verify_password(&pool, "rehash_user", "TestPass123!")
            .await
            .unwrap()
            .is_some());
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

        let _updated = update_user(&pool, id, Some("NewPass456!"), None, None, None, None)
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
        let users = list_users_paginated(&pool, 50, 0).await.unwrap();
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

        let users = list_users_paginated(&pool, 50, 0).await.unwrap();
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
