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
