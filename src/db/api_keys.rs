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
    let prefix = match key_value.split_once('.') {
        Some((p, _)) => p,
        None => {
            tracing::debug!("API key missing prefix separator");
            return Ok(false);
        }
    };
    let keys = sqlx::query_as::<_, ApiKey>(
        r#"
        SELECT * FROM api_keys 
        WHERE user_id = ? 
        AND prefix = ?
        AND is_active = 1 
        AND (expires_at IS NULL OR expires_at > ?)
        "#,
    )
    .bind(user_id)
    .bind(prefix)
    .bind(chrono::Utc::now().timestamp())
    .fetch_all(pool)
    .await?;

    // Verify against matching keys (typically 0 or 1 result)
    for key in keys {
        if verify_hash(key_value, &key.key_hash).await {
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

async fn verify_hash(password: &str, hash: &str) -> bool {
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
