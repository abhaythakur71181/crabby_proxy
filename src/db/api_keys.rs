//! API key verification.
//!
//! API keys are 256 bits of CSPRNG output, so they do not need a slow,
//! memory-hard password hash: nobody can brute-force a 256-bit secret from
//! its SHA-256 digest. Keys are stored as `sha256:<hex digest>` and looked up
//! directly by that digest (the UNIQUE index on `key_hash`), which makes
//! verification one indexed query instead of an Argon2 run per proxy
//! connection. Argon2 stays reserved for user passwords.
//!
//! Keys created before this scheme are stored as Argon2 PHC strings. They are
//! still accepted (looked up by user id + key prefix) and are rewritten to the
//! digest form the first time they verify, so the slow path runs at most once
//! per legacy key.

use super::models::ApiKey;
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;

/// Prefix marking a digest-format `key_hash` (vs. a legacy `$argon2...` hash).
const DIGEST_PREFIX: &str = "sha256:";

/// The stored form of an API key: `sha256:<lowercase hex>`.
pub(crate) fn api_key_digest(key_value: &str) -> String {
    let digest = Sha256::digest(key_value.as_bytes());
    let mut out = String::with_capacity(DIGEST_PREFIX.len() + 64);
    out.push_str(DIGEST_PREFIX);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub async fn verify_api_key(
    pool: &SqlitePool,
    user_id: i64,
    key_value: &str,
) -> Result<bool, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let digest = api_key_digest(key_value);

    // Fast path: direct lookup by digest.
    let key = sqlx::query_as::<_, ApiKey>(
        r#"
        SELECT * FROM api_keys
        WHERE key_hash = ?
        AND user_id = ?
        AND is_active = 1
        AND (expires_at IS NULL OR expires_at > ?)
        "#,
    )
    .bind(&digest)
    .bind(user_id)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    if let Some(key) = key {
        // The index lookup already matched; compare again in constant time so
        // correctness never depends on how the database compares strings.
        if bool::from(key.key_hash.as_bytes().ct_eq(digest.as_bytes())) {
            let _ = update_last_used(pool, key.id).await;
            return Ok(true);
        }
    }

    // Legacy path: Argon2-hashed keys created before the digest scheme.
    let prefix = match key_value.split_once('.') {
        Some((p, _)) => p,
        None => {
            tracing::debug!("API key missing prefix separator");
            return Ok(false);
        }
    };
    let legacy = sqlx::query_as::<_, ApiKey>(
        r#"
        SELECT * FROM api_keys
        WHERE user_id = ?
        AND key_prefix = ?
        AND key_hash LIKE '$argon2%'
        AND is_active = 1
        AND (expires_at IS NULL OR expires_at > ?)
        "#,
    )
    .bind(user_id)
    .bind(prefix)
    .bind(now)
    .fetch_all(pool)
    .await?;
    for key in legacy {
        if verify_legacy_hash(key_value, &key.key_hash).await {
            // Upgrade in place so this key never takes the slow path again.
            if let Err(e) = sqlx::query("UPDATE api_keys SET key_hash = ? WHERE id = ?")
                .bind(&digest)
                .bind(key.id)
                .execute(pool)
                .await
            {
                tracing::warn!("Failed to upgrade legacy API key {} hash: {}", key.id, e);
            }
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

async fn verify_legacy_hash(password: &str, hash: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::api_keys_crud::{create_api_key, revoke_api_key};

    async fn setup() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO users (username, password_hash, role, created_at, updated_at) VALUES ('k', 'x', 'user', ?, ?)",
        )
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[test]
    fn digest_format() {
        let d = api_key_digest("abc");
        assert_eq!(
            d,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn new_key_verifies_by_digest() {
        let pool = setup().await;
        let (key, model) = create_api_key(&pool, 1, Some("t".into()), None)
            .await
            .unwrap();
        assert!(model.key_hash.starts_with(DIGEST_PREFIX));
        assert!(verify_api_key(&pool, 1, &key).await.unwrap());
        // Wrong user, wrong secret, missing separator.
        assert!(!verify_api_key(&pool, 2, &key).await.unwrap());
        let (prefix, _) = key.split_once('.').unwrap();
        assert!(!verify_api_key(&pool, 1, &format!("{}.nope", prefix))
            .await
            .unwrap());
        assert!(!verify_api_key(&pool, 1, "garbage").await.unwrap());
    }

    #[tokio::test]
    async fn revoked_and_expired_keys_fail() {
        let pool = setup().await;
        let (key, model) = create_api_key(&pool, 1, Some("t".into()), None)
            .await
            .unwrap();
        revoke_api_key(&pool, model.id, 1).await.unwrap();
        assert!(!verify_api_key(&pool, 1, &key).await.unwrap());

        let (key2, model2) = create_api_key(&pool, 1, Some("t2".into()), None)
            .await
            .unwrap();
        sqlx::query("UPDATE api_keys SET expires_at = 1 WHERE id = ?")
            .bind(model2.id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!verify_api_key(&pool, 1, &key2).await.unwrap());
    }

    #[tokio::test]
    async fn legacy_argon2_key_verifies_and_is_upgraded() {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let pool = setup().await;
        let key = "AbCd.legacysecretvalue";
        let hash = Argon2::default()
            .hash_password(key.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        sqlx::query(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, name, created_at, is_active) VALUES (1, ?, 'AbCd', 'old', 0, 1)",
        )
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();

        assert!(!verify_api_key(&pool, 1, "AbCd.wrong").await.unwrap());
        assert!(verify_api_key(&pool, 1, key).await.unwrap());

        let stored: (String,) =
            sqlx::query_as("SELECT key_hash FROM api_keys WHERE key_prefix = 'AbCd'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored.0, api_key_digest(key));
        // Still verifies after the upgrade (now via the digest path).
        assert!(verify_api_key(&pool, 1, key).await.unwrap());
    }
}
