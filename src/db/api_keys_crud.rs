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

    // Generate a random API key with prefix
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&random_bytes);

    // Generate a short prefix for identification
    let prefix_bytes: Vec<u8> = (0..4).map(|_| rng.gen()).collect();
    let prefix = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&prefix_bytes);
    let full_key = format!("{}.{}", prefix, secret);

    // Hash the full key
    let key_hash = hash_api_key(&full_key)
        .map_err(|e| sqlx::Error::Protocol(format!("API key hashing failed: {}", e)))?;
    let now = chrono::Utc::now().timestamp();
    let expires_at = expires_in_days.map(|days| now + (days * 86400));
    let result = sqlx::query(
        r#"
        INSERT INTO api_keys (user_id, key_hash, prefix, name, created_at, expires_at, is_active)
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
