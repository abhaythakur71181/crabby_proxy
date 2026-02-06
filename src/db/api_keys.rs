use super::models::ApiKey;
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use sqlx::SqlitePool;

pub async fn verify_api_key(
    pool: &SqlitePool,
    user_id: i64,
    key_value: &str,
) -> Result<bool, sqlx::Error> {
    // TODO:
    // 1. Get all active API keys for the user
    // We have to check all of them because we don't know which one it is (hashes are salted)
    // unless we required a prefix in the input, but the design didn't strictly mandate that for the auth input.
    // Optimally, the input key would be `prefix.secret` and we could filter by prefix.
    // Let's assume for now we check all active keys.

    let keys = sqlx::query_as::<_, ApiKey>(
        r#"
        SELECT * FROM api_keys 
        WHERE user_id = ? AND is_active = 1 
        AND (expires_at IS NULL OR expires_at > ?)
        "#,
    )
    .bind(user_id)
    .bind(chrono::Utc::now().timestamp())
    .fetch_all(pool)
    .await?;
    for key in keys {
        if verify_hash(key_value, &key.key_hash) {
            let _ = update_last_used(pool, key.id).await;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Update last used timestamp
async fn update_last_used(pool: &SqlitePool, key_id: i64) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
        .bind(now)
        .bind(key_id)
        .execute(pool)
        .await?;
    Ok(())
}

fn verify_hash(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}
