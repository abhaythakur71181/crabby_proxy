use crate::auth::jwt::MIN_JWT_SECRET_LEN;
use crate::config::Config;

/// Extension trait for Config to apply environment variable overrides
pub trait ConfigEnvExt {
    fn apply_env_overrides(&mut self);
}

impl ConfigEnvExt for Config {
    /// Apply environment variable overrides for sensitive configuration
    /// Prioritizes env vars over config file values and warns if using defaults.
    ///
    /// Panics if the resulting JWT secret is shorter than `MIN_JWT_SECRET_LEN`
    /// — better to fail boot than to run with a forgeable signing key.
    fn apply_env_overrides(&mut self) {
        use std::env;

        // JWT Secret - prioritize env var
        if let Ok(env_secret) = env::var("CRABBY_JWT_SECRET") {
            tracing::info!("Using JWT secret from CRABBY_JWT_SECRET environment variable");
            self.authentication.jwt_secret = env_secret;
        } else if self.authentication.jwt_secret == "change_me_to_a_secure_random_string"
            || self.authentication.jwt_secret.is_empty()
        {
            // INFO: Auto-generate a random secret instead of running with default
            use rand::Rng;
            let secret: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(64)
                .map(char::from)
                .collect();
            self.authentication.jwt_secret = secret;
            tracing::warn!(
                "⚠️  JWT secret was default/empty — auto-generated a random one. Set CRABBY_JWT_SECRET for persistent sessions across restarts."
            );
        }

        // Hard fail if the resulting secret is too short to be safe.
        if self.authentication.jwt_secret.len() < MIN_JWT_SECRET_LEN {
            panic!(
                "JWT secret is {} bytes; minimum required is {}. Refusing to start with a weak signing key. Set CRABBY_JWT_SECRET to a strong random value.",
                self.authentication.jwt_secret.len(),
                MIN_JWT_SECRET_LEN
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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Helper: a 32+ byte secret so config validation passes.
    fn strong_secret() -> &'static str {
        "my_test_secret_at_least_32_bytes_long"
    }

    #[test]
    #[serial]
    fn test_apply_env_jwt_secret_override() {
        std::env::set_var("CRABBY_JWT_SECRET", strong_secret());
        let mut config = Config::default();
        config.apply_env_overrides();
        assert_eq!(config.authentication.jwt_secret, strong_secret());
        std::env::remove_var("CRABBY_JWT_SECRET");
    }

    #[test]
    #[serial]
    #[should_panic(expected = "JWT secret is")]
    fn test_apply_env_panics_on_weak_jwt_secret() {
        std::env::set_var("CRABBY_JWT_SECRET", "too_short");
        let mut config = Config::default();
        // This should panic — defense against forgeable signing keys.
        config.apply_env_overrides();
        std::env::remove_var("CRABBY_JWT_SECRET");
    }

    #[test]
    #[serial]
    fn test_apply_env_admin_password_override() {
        std::env::set_var("CRABBY_ADMIN_PASSWORD", "super_secure_pw");
        let mut config = Config::default();
        config.apply_env_overrides();
        assert_eq!(config.admin.admin_password, "super_secure_pw");
        std::env::remove_var("CRABBY_ADMIN_PASSWORD");
    }

    #[test]
    #[serial]
    fn test_apply_env_basic_auth_password_override() {
        std::env::set_var("CRABBY_BASIC_AUTH_PASSWORD", "basic_pw_123");
        let mut config = Config::default();
        config.apply_env_overrides();
        assert_eq!(config.authentication.password, "basic_pw_123");
        std::env::remove_var("CRABBY_BASIC_AUTH_PASSWORD");
    }

    #[test]
    #[serial]
    fn test_apply_env_no_overrides_keeps_defaults() {
        std::env::remove_var("CRABBY_JWT_SECRET");
        std::env::remove_var("CRABBY_ADMIN_PASSWORD");
        std::env::remove_var("CRABBY_BASIC_AUTH_PASSWORD");

        let mut config = Config::default();
        // Change to non-default so the warning branches don't trigger
        config.authentication.jwt_secret = "custom_secret_at_least_32_bytes_long_xx".to_string();
        config.admin.admin_password = "custom_admin_pw".to_string();
        config.authentication.password = "custom_basic_pw".to_string();

        config.apply_env_overrides();

        // Without env vars, non-default values should be preserved
        assert_eq!(
            config.authentication.jwt_secret,
            "custom_secret_at_least_32_bytes_long_xx"
        );
        assert_eq!(config.admin.admin_password, "custom_admin_pw");
        assert_eq!(config.authentication.password, "custom_basic_pw");
    }

    #[test]
    #[serial]
    fn test_apply_env_all_overrides_at_once() {
        std::env::set_var("CRABBY_JWT_SECRET", "jwt_env_at_least_32_bytes_long_xxxxxx");
        std::env::set_var("CRABBY_ADMIN_PASSWORD", "admin_env");
        std::env::set_var("CRABBY_BASIC_AUTH_PASSWORD", "basic_env");

        let mut config = Config::default();
        config.apply_env_overrides();

        assert_eq!(
            config.authentication.jwt_secret,
            "jwt_env_at_least_32_bytes_long_xxxxxx"
        );
        assert_eq!(config.admin.admin_password, "admin_env");
        assert_eq!(config.authentication.password, "basic_env");

        std::env::remove_var("CRABBY_JWT_SECRET");
        std::env::remove_var("CRABBY_ADMIN_PASSWORD");
        std::env::remove_var("CRABBY_BASIC_AUTH_PASSWORD");
    }

    #[test]
    #[serial]
    fn test_apply_env_defaults_trigger_warning_paths() {
        // Ensure env vars are not set so the default-value warning paths execute
        std::env::remove_var("CRABBY_JWT_SECRET");
        std::env::remove_var("CRABBY_ADMIN_PASSWORD");
        std::env::remove_var("CRABBY_BASIC_AUTH_PASSWORD");

        let mut config = Config::default();
        // Should not panic even when defaults are used
        config.apply_env_overrides();

        // S2: JWT secret should be auto-generated (no longer the default)
        assert_ne!(
            config.authentication.jwt_secret,
            "change_me_to_a_secure_random_string"
        );
        assert_eq!(config.authentication.jwt_secret.len(), 64); // Auto-generated is 64 chars
        assert_eq!(config.admin.admin_password, "secure_admin_password");
        assert_eq!(config.authentication.password, "changeme");
    }
}
