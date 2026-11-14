//! Checking the static credentials configured in the config file
//! (`admin.admin_username` / `admin.admin_password` for the admin API and
//! `authentication.username` / `authentication.password` for the proxy).
//!
//! - The configured secret may be plaintext or an Argon2 PHC string
//!   (`$argon2id$...`, e.g. generated with `argon2` CLI or any PHC tool), so
//!   operators can avoid keeping the plaintext credential in the config file.
//! - Plaintext secrets and usernames are compared in constant time over
//!   SHA-256 digests, so neither content nor length leaks through timing.
//! - An empty configured secret disables the credential entirely (it can
//!   never match, not even an empty password).

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// True if `value` looks like an Argon2 PHC hash rather than a plaintext secret.
pub fn is_password_hash(value: &str) -> bool {
    value.starts_with("$argon2")
}

fn ct_eq_digest(a: &str, b: &str) -> bool {
    let da = Sha256::digest(a.as_bytes());
    let db = Sha256::digest(b.as_bytes());
    let (da, db): ([u8; 32], [u8; 32]) = (da.into(), db.into());
    bool::from(da.ct_eq(&db))
}

/// Does `(username, password)` match the configured static credential?
pub async fn config_credential_matches(
    expected_username: &str,
    expected_secret: &str,
    username: &str,
    password: &str,
) -> bool {
    if expected_secret.is_empty() {
        return false;
    }
    let user_ok = ct_eq_digest(username, expected_username);
    let secret_ok = if is_password_hash(expected_secret) {
        // Always run the verify (even if the username is wrong) so timing does
        // not reveal whether the username matched.
        crate::db::users::verify_password_hash(password, expected_secret).await
    } else {
        ct_eq_digest(password, expected_secret)
    };
    user_ok & secret_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plaintext_match() {
        assert!(config_credential_matches("admin", "s3cret", "admin", "s3cret").await);
        assert!(!config_credential_matches("admin", "s3cret", "admin", "s3cre").await);
        assert!(!config_credential_matches("admin", "s3cret", "admin2", "s3cret").await);
    }

    #[tokio::test]
    async fn empty_secret_disables_credential() {
        assert!(!config_credential_matches("admin", "", "admin", "").await);
        assert!(!config_credential_matches("", "", "", "").await);
    }

    #[tokio::test]
    async fn argon2_hash_secret() {
        let hash = crate::db::users::hash_password("correct horse")
            .await
            .unwrap();
        assert!(is_password_hash(&hash));
        assert!(config_credential_matches("admin", &hash, "admin", "correct horse").await);
        assert!(!config_credential_matches("admin", &hash, "admin", "wrong").await);
        assert!(!config_credential_matches("admin", &hash, "other", "correct horse").await);
        // The hash string itself is not accepted as the password.
        assert!(!config_credential_matches("admin", &hash, "admin", &hash).await);
    }
}
