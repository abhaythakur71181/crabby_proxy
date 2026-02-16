use crate::config::Config;

/// Extension trait for Config to apply environment variable overrides
pub trait ConfigEnvExt {
    fn apply_env_overrides(&mut self);
}

impl ConfigEnvExt for Config {
    /// Apply environment variable overrides for sensitive configuration
    /// Prioritizes env vars over config file values and warns if using defaults
    fn apply_env_overrides(&mut self) {
        use std::env;

        // JWT Secret - prioritize env var
        if let Ok(env_secret) = env::var("CRABBY_JWT_SECRET") {
            tracing::info!("Using JWT secret from CRABBY_JWT_SECRET environment variable");
            self.authentication.jwt_secret = env_secret;
        } else if self.authentication.jwt_secret == "change_me_to_a_secure_random_string" {
            tracing::warn!(
                "⚠️  JWT secret is using default value! Set CRABBY_JWT_SECRET for production."
            );
        }

        // Admin Password - prioritize env var
        if let Ok(env_password) = env::var("CRABBY_ADMIN_PASSWORD") {
            tracing::info!("Using admin password from CRABBY_ADMIN_PASSWORD environment variable");
            self.admin.admin_password = env_password;
        } else if self.admin.admin_password == "secure_admin_password" {
            tracing::warn!(
                "⚠️  Admin password is using default value! Set CRABBY_ADMIN_PASSWORD for production."
            );
        }

        // Basic Auth Password - prioritize env var
        if let Ok(env_password) = env::var("CRABBY_BASIC_AUTH_PASSWORD") {
            tracing::info!(
                "Using basic auth password from CRABBY_BASIC_AUTH_PASSWORD environment variable"
            );
            self.authentication.password = env_password;
        } else if self.authentication.password == "changeme" {
            tracing::warn!(
                "⚠️  Basic auth password is using default value! Set CRABBY_BASIC_AUTH_PASSWORD for production."
            );
        }
    }
}
