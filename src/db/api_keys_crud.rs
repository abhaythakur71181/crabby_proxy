use crate::db::models::ApiKey;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use base64::Engine;
use sqlx::SqlitePool;

/// Create a new API key for a user
/// Returns (plaintext_key, stored_api_key_model)
pub async fn create_api_key(
    pool: &SqlitePool,
    user_id: i64,
    name: Option<String>,
    expires_in_days: Option<i64>,
) -> Result<(String, ApiKey), sqlx::Error> {
    use rand::Rng;
    let (full_key, prefix) = {
        let mut rng = rand::thread_rng();
        let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&random_bytes);
        let prefix_bytes: Vec<u8> = (0..4).map(|_| rng.gen()).collect();
        let prefix = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&prefix_bytes);
        let full_key = format!("{}.{}", prefix, secret);
        (full_key, prefix)
    };
    let key_hash = hash_api_key(&full_key)
        .map_err(|e| sqlx::Error::Protocol(format!("API key hashing failed: {}", e)))?;
    let now = chrono::Utc::now().timestamp();
    let expires_at = expires_in_days.map(|days| now + (days * 86400));
    let result = sqlx::query(
        r#"
        INSERT INTO api_keys (user_id, key_hash, key_prefix, name, created_at, expires_at, is_active)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        "#,
    )
    .bind(user_id)
    .bind(&key_hash)
    .bind(&prefix)
    .bind(name)
    .bind(now)
    .bind(expires_at)
    .execute(pool)
    .await?;
    let key_id = result.last_insert_rowid();
    let api_key = sqlx::query_as::<_, ApiKey>("SELECT * FROM api_keys WHERE id = ?")
        .bind(key_id)
        .fetch_one(pool)
        .await?;
    Ok((full_key, api_key))
}

/// List all API keys for a user
pub async fn list_api_keys(pool: &SqlitePool, user_id: i64) -> Result<Vec<ApiKey>, sqlx::Error> {
    let keys = sqlx::query_as::<_, ApiKey>(
        "SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(keys)
}

/// Revoke an API key (soft delete)
pub async fn revoke_api_key(
    pool: &SqlitePool,
    key_id: i64,
    user_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ?")
        .bind(key_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

fn hash_api_key(key: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::password_hash::rand_core::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let key_hash = argon2.hash_password(key.as_bytes(), &salt)?;
    Ok(key_hash.to_string())
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
                max_connections INTEGER NOT NULL DEFAULT 5,
                bandwidth_limit_mb INTEGER NOT NULL DEFAULT 1000,
                rate_limit_enabled BOOLEAN NOT NULL DEFAULT 1,
                rate_limit_rps INTEGER NOT NULL DEFAULT 10,
                rate_limit_burst INTEGER NOT NULL DEFAULT 20,
                allowed_protocols TEXT,
                ip_whitelist TEXT,
                notes TEXT,
                last_login_at INTEGER,
                monthly_bandwidth_quota INTEGER
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

        // Insert a test user
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO users (username, password_hash, role, created_at, updated_at) VALUES ('testuser', 'hash', 'user', ?, ?)"
        )
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    // === create_api_key Tests ===

    #[tokio::test]
    async fn test_create_api_key_returns_key_and_model() {
        let pool = setup_test_db().await;
        let (full_key, api_key) = create_api_key(&pool, 1, Some("test-key".to_string()), None)
            .await
            .unwrap();

        assert!(!full_key.is_empty());
        assert!(full_key.contains('.')); // prefix.secret format
        assert_eq!(api_key.user_id, 1);
        assert_eq!(api_key.name, "test-key");
        assert!(api_key.is_active);
        assert!(api_key.expires_at.is_none());
    }

    #[tokio::test]
    async fn test_create_api_key_with_expiration() {
        let pool = setup_test_db().await;
        let (_, api_key) = create_api_key(&pool, 1, Some("expiring".to_string()), Some(30))
            .await
            .unwrap();

        assert!(api_key.expires_at.is_some());
        let now = chrono::Utc::now().timestamp();
        let expected_expiry = now + (30 * 86400);
        // Allow 5 second tolerance
        assert!((api_key.expires_at.unwrap() - expected_expiry).abs() < 5);
    }

    #[tokio::test]
    async fn test_create_api_key_without_name_fails_not_null() {
        let pool = setup_test_db().await;
        // Passing None for name inserts NULL, which violates the NOT NULL constraint
        let result = create_api_key(&pool, 1, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_multiple_api_keys_for_same_user() {
        let pool = setup_test_db().await;
        let (key1, _) = create_api_key(&pool, 1, Some("key1".to_string()), None)
            .await
            .unwrap();
        let (key2, _) = create_api_key(&pool, 1, Some("key2".to_string()), None)
            .await
            .unwrap();

        assert_ne!(key1, key2); // Keys should be unique
    }

    #[tokio::test]
    async fn test_create_api_key_prefix_matches() {
        let pool = setup_test_db().await;
        let (full_key, api_key) = create_api_key(&pool, 1, Some("prefix-test".to_string()), None)
            .await
            .unwrap();

        let prefix = full_key.split('.').next().unwrap();
        assert_eq!(prefix, api_key.prefix);
    }

    // === list_api_keys Tests ===

    #[tokio::test]
    async fn test_list_api_keys_empty() {
        let pool = setup_test_db().await;
        let keys = list_api_keys(&pool, 1).await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn test_list_api_keys_returns_all_for_user() {
        let pool = setup_test_db().await;
        create_api_key(&pool, 1, Some("k1".to_string()), None)
            .await
            .unwrap();
        create_api_key(&pool, 1, Some("k2".to_string()), None)
            .await
            .unwrap();
        create_api_key(&pool, 1, Some("k3".to_string()), None)
            .await
            .unwrap();

        let keys = list_api_keys(&pool, 1).await.unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[tokio::test]
    async fn test_list_api_keys_only_returns_user_keys() {
        let pool = setup_test_db().await;

        // Add a second user
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO users (username, password_hash, role, created_at, updated_at) VALUES ('user2', 'hash', 'user', ?, ?)"
        )
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        create_api_key(&pool, 1, Some("user1key".to_string()), None)
            .await
            .unwrap();
        create_api_key(&pool, 2, Some("user2key".to_string()), None)
            .await
            .unwrap();

        let user1_keys = list_api_keys(&pool, 1).await.unwrap();
        assert_eq!(user1_keys.len(), 1);
        assert_eq!(user1_keys[0].name, "user1key");

        let user2_keys = list_api_keys(&pool, 2).await.unwrap();
        assert_eq!(user2_keys.len(), 1);
        assert_eq!(user2_keys[0].name, "user2key");
    }

    // === revoke_api_key Tests ===

    #[tokio::test]
    async fn test_revoke_api_key_deactivates() {
        let pool = setup_test_db().await;
        let (_, api_key) = create_api_key(&pool, 1, Some("revoke-me".to_string()), None)
            .await
            .unwrap();

        revoke_api_key(&pool, api_key.id, 1).await.unwrap();

        let keys = list_api_keys(&pool, 1).await.unwrap();
        let revoked = keys.iter().find(|k| k.id == api_key.id).unwrap();
        assert!(!revoked.is_active);
    }

    #[tokio::test]
    async fn test_revoke_api_key_wrong_user_does_nothing() {
        let pool = setup_test_db().await;
        let (_, api_key) = create_api_key(&pool, 1, Some("safe-key".to_string()), None)
            .await
            .unwrap();

        // Try revoking with wrong user_id
        revoke_api_key(&pool, api_key.id, 999).await.unwrap();

        // Key should still be active
        let keys = list_api_keys(&pool, 1).await.unwrap();
        let key = keys.iter().find(|k| k.id == api_key.id).unwrap();
        assert!(key.is_active);
    }

    // === hash_api_key Tests ===

    #[test]
    fn test_hash_api_key_produces_argon2_hash() {
        let hash = hash_api_key("test_key_value").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(hash.len() > 50);
    }

    #[test]
    fn test_hash_api_key_different_hashes_for_same_input() {
        let hash1 = hash_api_key("same_key").unwrap();
        let hash2 = hash_api_key("same_key").unwrap();
        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);
    }
}
