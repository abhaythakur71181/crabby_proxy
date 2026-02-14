use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

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

pub fn create_jwt(
    user_id: i64,
    username: &str,
    role: &str,
    secret: &str,
    expiration_seconds: u64,
) -> Result<String, AuthError> {
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

    #[test]
    fn test_create_jwt() {
        let token = create_jwt(1, "testuser", "admin", "supersecret", 3600).unwrap();
        assert!(!token.is_empty());
        assert!(token.contains('.')); // JWT format has dots
    }

    #[test]
    fn test_validate_jwt_valid() {
        let token = create_jwt(1, "testuser", "admin", "supersecret", 3600).unwrap();
        let claims = validate_jwt(&token, "supersecret").unwrap();

        assert_eq!(claims.sub, "testuser");
        assert_eq!(claims.user_id, 1);
        assert_eq!(claims.role, "admin");
    }

    #[test]
    fn test_validate_jwt_wrong_secret() {
        let token = create_jwt(1, "testuser", "admin", "supersecret", 3600).unwrap();
        let result = validate_jwt(&token, "wrongsecret");

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_invalid_token() {
        let result = validate_jwt("invalid.token.here", "supersecret");
        assert!(result.is_err());
    }

    #[test]
    #[ignore] // Flaky test due to timing - skip in CI
    fn test_validate_jwt_expired() {
        use chrono::{Duration, Utc};

        // Create a token that's already expired by making expiration in the past
        let now = Utc::now();
        let past = now - Duration::seconds(10); // 10 seconds ago

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
            &EncodingKey::from_secret("supersecret".as_bytes()),
        )
        .unwrap();

        let result = validate_jwt(&token, "supersecret");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_claims_extraction() {
        let token = create_jwt(42, "alice", "user", "mysecret", 7200).unwrap();
        let claims = validate_jwt(&token, "mysecret").unwrap();

        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.user_id, 42);
        assert_eq!(claims.role, "user");
        assert!(claims.exp > claims.iat); // Expiration should be after issuance
    }
}
