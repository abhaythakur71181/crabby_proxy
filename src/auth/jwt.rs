use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// Minimum acceptable JWT signing secret length, in bytes.
///
/// Below this size HMAC-SHA256 keys are trivially brute-forceable. We
/// enforce it at every entry point: at config load (so the process refuses
/// to start with a weak secret) and inside `create_jwt`/`validate_jwt` as
/// defense-in-depth so test code or future call sites cannot accidentally
/// fall through to a weak signing key.
pub const MIN_JWT_SECRET_LEN: usize = 32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,  // Subject (username)
    pub user_id: i64, // User ID
    pub role: String, // User Role
    pub exp: usize,   // Expiration time (timestamp)
    pub iat: usize,   // Issued at
}

#[derive(Debug, Clone)]
pub struct AuthError(pub String);

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AuthError {}

#[inline]
fn ensure_strong_secret(secret: &str) -> Result<(), AuthError> {
    if secret.len() < MIN_JWT_SECRET_LEN {
        return Err(AuthError(format!(
            "JWT secret too short: {} bytes (minimum {})",
            secret.len(),
            MIN_JWT_SECRET_LEN
        )));
    }
    Ok(())
}

pub fn create_jwt(
    user_id: i64,
    username: &str,
    role: &str,
    secret: &str,
    expiration_seconds: u64,
) -> Result<String, AuthError> {
    ensure_strong_secret(secret)?;
    let now = Utc::now();
    let expiration = now + Duration::seconds(expiration_seconds as i64);
    let claims = Claims {
        sub: username.to_owned(),
        user_id,
        role: role.to_owned(),
        exp: expiration.timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    let header = Header::default();
    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AuthError(format!("Token creation failed: {}", e)))
}

pub fn validate_jwt(token: &str, secret: &str) -> Result<Claims, AuthError> {
    ensure_strong_secret(secret)?;
    let validation = Validation::default();
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| AuthError(format!("Token validation failed: {}", e)))?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Original Tests ===

    #[test]
    fn test_create_jwt() {
        let token = create_jwt(1, "testuser", "admin", "supersecret_key_at_least_32_bytes_long", 3600).unwrap();
        assert!(!token.is_empty());
        assert!(token.contains('.')); // JWT format has dots
    }

    #[test]
    fn test_validate_jwt_valid() {
        let token = create_jwt(1, "testuser", "admin", "supersecret_key_at_least_32_bytes_long", 3600).unwrap();
        let claims = validate_jwt(&token, "supersecret_key_at_least_32_bytes_long").unwrap();

        assert_eq!(claims.sub, "testuser");
        assert_eq!(claims.user_id, 1);
        assert_eq!(claims.role, "admin");
    }

    #[test]
    fn test_validate_jwt_wrong_secret() {
        let token = create_jwt(1, "testuser", "admin", "supersecret_key_at_least_32_bytes_long", 3600).unwrap();
        let result = validate_jwt(&token, "wrongsecret_key_at_least_32_bytes_long_xx");

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_invalid_token() {
        let result = validate_jwt("invalid.token.here", "supersecret_key_at_least_32_bytes_long");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_expired() {
        // Create a token that's already expired by making expiration in the past
        let now = Utc::now();
        let past = now - Duration::seconds(120); // 120 seconds ago (exceeds jsonwebtoken's 60s default leeway)

        let claims = Claims {
            sub: "testuser".to_owned(),
            user_id: 1,
            role: "admin".to_owned(),
            exp: past.timestamp() as usize,
            iat: (past - Duration::seconds(60)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("supersecret_key_at_least_32_bytes_long".as_bytes()),
        )
        .unwrap();

        let result = validate_jwt(&token, "supersecret_key_at_least_32_bytes_long");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_claims_extraction() {
        let token = create_jwt(42, "alice", "user", "mysecret_key_at_least_32_bytes_long_xxxx", 7200).unwrap();
        let claims = validate_jwt(&token, "mysecret_key_at_least_32_bytes_long_xxxx").unwrap();

        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.user_id, 42);
        assert_eq!(claims.role, "user");
        assert!(claims.exp > claims.iat); // Expiration should be after issuance
    }

    // === New Tests ===

    #[test]
    fn test_jwt_has_three_segments() {
        let token = create_jwt(1, "user", "admin", "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();
        let segments: Vec<&str> = token.split('.').collect();
        assert_eq!(segments.len(), 3);
    }

    #[test]
    fn test_jwt_different_users_produce_different_tokens() {
        let token1 = create_jwt(1, "user1", "admin", "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();
        let token2 = create_jwt(2, "user2", "user", "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_jwt_expiration_is_correct() {
        let before = Utc::now().timestamp() as usize;
        let token = create_jwt(1, "user", "admin", "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();
        let after = Utc::now().timestamp() as usize;

        let claims = validate_jwt(&token, "secret_key_at_least_32_bytes_long_xxxxxx").unwrap();

        // exp should be ~3600 seconds from now
        assert!(claims.exp >= before + 3600);
        assert!(claims.exp <= after + 3600 + 1);
    }

    #[test]
    fn test_jwt_iat_is_reasonable() {
        let before = Utc::now().timestamp() as usize;
        let token = create_jwt(1, "user", "admin", "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();
        let after = Utc::now().timestamp() as usize;

        let claims = validate_jwt(&token, "secret_key_at_least_32_bytes_long_xxxxxx").unwrap();
        assert!(claims.iat >= before);
        assert!(claims.iat <= after);
    }

    #[test]
    fn test_jwt_all_roles() {
        for role in &["root_admin", "admin", "user"] {
            let token = create_jwt(1, "test", role, "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();
            let claims = validate_jwt(&token, "secret_key_at_least_32_bytes_long_xxxxxx").unwrap();
            assert_eq!(claims.role, *role);
        }
    }

    #[test]
    fn test_jwt_long_expiration() {
        // 30 days
        let token = create_jwt(1, "user", "admin", "secret_key_at_least_32_bytes_long_xxxxxx", 86400 * 30).unwrap();
        let claims = validate_jwt(&token, "secret_key_at_least_32_bytes_long_xxxxxx").unwrap();
        assert!(claims.exp > claims.iat + 86400 * 29);
    }

    #[test]
    fn test_jwt_short_expiration() {
        // 1 second
        let token = create_jwt(1, "user", "admin", "secret_key_at_least_32_bytes_long_xxxxxx", 1).unwrap();
        let claims = validate_jwt(&token, "secret_key_at_least_32_bytes_long_xxxxxx").unwrap();
        assert!(claims.exp - claims.iat <= 2); // 1 second + tolerance
    }

    #[test]
    fn test_jwt_rejects_empty_secret() {
        let result = create_jwt(1, "user", "admin", "", 3600);
        assert!(result.is_err());
        let validate_result = validate_jwt("any.token.here", "");
        assert!(validate_result.is_err());
    }

    #[test]
    fn test_jwt_rejects_short_secret() {
        let short = "x".repeat(MIN_JWT_SECRET_LEN - 1);
        let result = create_jwt(1, "user", "admin", &short, 3600);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_jwt_special_characters_in_username() {
        let token = create_jwt(1, "user@example.com", "admin", "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();
        let claims = validate_jwt(&token, "secret_key_at_least_32_bytes_long_xxxxxx").unwrap();
        assert_eq!(claims.sub, "user@example.com");
    }

    #[test]
    fn test_jwt_negative_user_id() {
        // Config-based auth uses -1 as sentinel
        let token = create_jwt(-1, "config_user", "admin", "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();
        let claims = validate_jwt(&token, "secret_key_at_least_32_bytes_long_xxxxxx").unwrap();
        assert_eq!(claims.user_id, -1);
    }

    #[test]
    fn test_jwt_zero_user_id() {
        let token = create_jwt(0, "zero", "user", "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();
        let claims = validate_jwt(&token, "secret_key_at_least_32_bytes_long_xxxxxx").unwrap();
        assert_eq!(claims.user_id, 0);
    }

    #[test]
    fn test_jwt_empty_string_token() {
        let result = validate_jwt("", "secret_key_at_least_32_bytes_long_xxxxxx");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_malformed_base64() {
        let result = validate_jwt("not.valid.base64!!!", "secret_key_at_least_32_bytes_long_xxxxxx");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_tampered_payload() {
        let token = create_jwt(1, "user", "admin", "secret_key_at_least_32_bytes_long_xxxxxx", 3600).unwrap();

        // Split and modify the payload
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.dGFtcGVyZWQ.{}", parts[0], parts[2]);

        let result = validate_jwt(&tampered, "secret_key_at_least_32_bytes_long_xxxxxx");
        assert!(result.is_err());
    }

    // === AuthError Tests ===

    #[test]
    fn test_auth_error_display() {
        let err = AuthError("Something went wrong".to_string());
        assert_eq!(err.to_string(), "Something went wrong");
    }

    #[test]
    fn test_auth_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(AuthError("test error".to_string()));
        assert_eq!(err.to_string(), "test error");
    }

    #[test]
    fn test_auth_error_clone() {
        let err1 = AuthError("clone me".to_string());
        let err2 = err1.clone();
        assert_eq!(err1.0, err2.0);
    }

    #[test]
    fn test_auth_error_debug() {
        let err = AuthError("debug test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("debug test"));
    }
}
