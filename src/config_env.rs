use crate::auth::jwt::MIN_JWT_SECRET_LEN;
use crate::config::Config;

/// JWT secrets that ship in this repository's sample configs and docs. They
/// are long enough to pass the length check, so without this list a config
/// copied from the examples (the Dockerfile copies config.example.toml) would
/// sign admin tokens with a publicly known key.
const KNOWN_PLACEHOLDER_JWT_SECRETS: &[&str] = &[
    "change_me_to_a_secure_random_string",
    "REPLACE_ME_WITH_A_32_BYTE_RANDOM_SECRET",
];

/// True for an empty secret, a known shipped placeholder, or anything that
/// is obviously a placeholder (starts with "replace_me" / "change_me" /
/// "changeme", case-insensitively).
pub fn is_placeholder_jwt_secret(secret: &str) -> bool {
    let s = secret.trim();
    if s.is_empty() || KNOWN_PLACEHOLDER_JWT_SECRETS.contains(&s) {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    [
        "replace_me",
        "replace-me",
        "change_me",
        "change-me",
        "changeme",
    ]
    .iter()
    .any(|p| lower.starts_with(p))
}

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
            // An explicitly supplied placeholder is a deployment mistake, not
            // a request for an ephemeral key: refuse rather than guess.
            if is_placeholder_jwt_secret(&env_secret) {
                panic!(
                    "CRABBY_JWT_SECRET is a published placeholder value. Refusing to start with a publicly known signing key. Set it to a strong random value (e.g. `openssl rand -hex 32`)."
                );
            }
            tracing::info!("Using JWT secret from CRABBY_JWT_SECRET environment variable");
            self.authentication.jwt_secret = env_secret;
        } else if is_placeholder_jwt_secret(&self.authentication.jwt_secret) {
            // INFO: Auto-generate a random secret instead of running with default
            use rand::Rng;
            let secret: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(64)
                .map(char::from)
                .collect();
            self.authentication.jwt_secret = secret;
            tracing::warn!(
                "⚠️  JWT secret was empty or a shipped placeholder — auto-generated a random one. Set CRABBY_JWT_SECRET for persistent sessions across restarts."
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

        // Default credentials are refused at boot the same way a weak JWT
        // secret is — a warning is too easy to miss and leaves the admin API
        // guessable. Set CRABBY_ALLOW_DEFAULT_PASSWORDS=1 to bypass for local
        // development only.
        let allow_defaults = env::var("CRABBY_ALLOW_DEFAULT_PASSWORDS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // Admin Password - prioritize env var
        if let Ok(env_password) = env::var("CRABBY_ADMIN_PASSWORD") {
            tracing::info!("Using admin password from CRABBY_ADMIN_PASSWORD environment variable");
            self.admin.admin_password = env_password;
        } else if self.admin.admin_password == "secure_admin_password" && !allow_defaults {
            panic!(
                "Admin password is the built-in default. Refusing to start with a guessable admin credential. Set CRABBY_ADMIN_PASSWORD (or CRABBY_ALLOW_DEFAULT_PASSWORDS=1 for local dev)."
            );
        } else if self.admin.admin_password == "secure_admin_password" {
            tracing::warn!(
                "⚠️  Admin password is the default value — allowed only because CRABBY_ALLOW_DEFAULT_PASSWORDS is set."
            );
        }

        // Basic Auth Password - prioritize env var
        if let Ok(env_password) = env::var("CRABBY_BASIC_AUTH_PASSWORD") {
            tracing::info!(
                "Using basic auth password from CRABBY_BASIC_AUTH_PASSWORD environment variable"
            );
            self.authentication.password = env_password;
        } else if self.authentication.password == "changeme" && !allow_defaults {
            panic!(
                "Basic auth password is the built-in default ('changeme'). Refusing to start. Set CRABBY_BASIC_AUTH_PASSWORD (or CRABBY_ALLOW_DEFAULT_PASSWORDS=1 for local dev)."
            );
        } else if self.authentication.password == "changeme" {
            tracing::warn!(
                "⚠️  Basic auth password is the default value — allowed only because CRABBY_ALLOW_DEFAULT_PASSWORDS is set."
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
        std::env::set_var("CRABBY_ALLOW_DEFAULT_PASSWORDS", "1");
        let mut config = Config::default();
        config.apply_env_overrides();
        assert_eq!(config.authentication.jwt_secret, strong_secret());
        std::env::remove_var("CRABBY_JWT_SECRET");
        std::env::remove_var("CRABBY_ALLOW_DEFAULT_PASSWORDS");
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
        std::env::set_var("CRABBY_ALLOW_DEFAULT_PASSWORDS", "1"); // basic pw stays default
        let mut config = Config::default();
        config.apply_env_overrides();
        assert_eq!(config.admin.admin_password, "super_secure_pw");
        std::env::remove_var("CRABBY_ADMIN_PASSWORD");
        std::env::remove_var("CRABBY_ALLOW_DEFAULT_PASSWORDS");
    }

    #[test]
    #[serial]
    fn test_apply_env_basic_auth_password_override() {
        std::env::set_var("CRABBY_BASIC_AUTH_PASSWORD", "basic_pw_123");
        std::env::set_var("CRABBY_ALLOW_DEFAULT_PASSWORDS", "1"); // admin pw stays default
        let mut config = Config::default();
        config.apply_env_overrides();
        assert_eq!(config.authentication.password, "basic_pw_123");
        std::env::remove_var("CRABBY_BASIC_AUTH_PASSWORD");
        std::env::remove_var("CRABBY_ALLOW_DEFAULT_PASSWORDS");
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
        // Allow defaults so we exercise the warn path rather than the panic.
        std::env::set_var("CRABBY_ALLOW_DEFAULT_PASSWORDS", "1");

        let mut config = Config::default();
        config.apply_env_overrides();

        // S2: JWT secret should be auto-generated (no longer the default)
        assert_ne!(
            config.authentication.jwt_secret,
            "change_me_to_a_secure_random_string"
        );
        assert_eq!(config.authentication.jwt_secret.len(), 64); // Auto-generated is 64 chars
        assert_eq!(config.admin.admin_password, "secure_admin_password");
        assert_eq!(config.authentication.password, "changeme");
        std::env::remove_var("CRABBY_ALLOW_DEFAULT_PASSWORDS");
    }

    #[test]
    #[serial]
    #[should_panic(expected = "Admin password is the built-in default")]
    fn test_apply_env_panics_on_default_admin_password() {
        // Note: no env vars set here. The cleanup after a panic never runs, so
        // setting any env var would leak into other #[serial] tests. The JWT
        // secret auto-generates from the default, so the panic is reached at
        // the admin-password check without needing CRABBY_JWT_SECRET.
        std::env::remove_var("CRABBY_ADMIN_PASSWORD");
        std::env::remove_var("CRABBY_ALLOW_DEFAULT_PASSWORDS");
        let mut config = Config::default(); // admin_password = default
        config.apply_env_overrides(); // should panic — guessable admin credential
    }

    #[test]
    fn test_placeholder_jwt_secret_detection() {
        for s in [
            "",
            "   ",
            "change_me_to_a_secure_random_string",
            "REPLACE_ME_WITH_A_32_BYTE_RANDOM_SECRET",
            "replace_me_with_something_at_least_32_bytes",
            "CHANGEME-0123456789-0123456789-0123456789",
        ] {
            assert!(
                is_placeholder_jwt_secret(s),
                "{s:?} should be a placeholder"
            );
        }
        assert!(!is_placeholder_jwt_secret(strong_secret()));
        assert!(!is_placeholder_jwt_secret(
            "9f2c1e7b4a6d8e0f3b5a7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f"
        ));
    }

    #[test]
    fn test_shipped_example_config_secret_is_a_placeholder() {
        // Whatever config.example.toml ships (a placeholder, or empty) must
        // never be accepted as a real signing key.
        let raw = include_str!("../config.example.toml");
        let v: toml::Value = toml::from_str(raw).unwrap();
        let secret = v["authentication"]["jwt_secret"].as_str().unwrap_or("");
        assert!(
            is_placeholder_jwt_secret(secret),
            "example secret {secret:?}"
        );
    }

    #[test]
    #[serial]
    fn test_placeholder_jwt_secret_in_file_is_replaced() {
        std::env::remove_var("CRABBY_JWT_SECRET");
        std::env::set_var("CRABBY_ALLOW_DEFAULT_PASSWORDS", "1");
        let mut config = Config::default();
        config.authentication.jwt_secret = "REPLACE_ME_WITH_A_32_BYTE_RANDOM_SECRET".to_string();
        config.apply_env_overrides();
        std::env::remove_var("CRABBY_ALLOW_DEFAULT_PASSWORDS");
        assert_ne!(
            config.authentication.jwt_secret,
            "REPLACE_ME_WITH_A_32_BYTE_RANDOM_SECRET"
        );
        assert_eq!(config.authentication.jwt_secret.len(), 64);
        assert!(!is_placeholder_jwt_secret(
            &config.authentication.jwt_secret
        ));
    }

    #[test]
    #[serial]
    fn test_placeholder_jwt_secret_from_env_is_refused() {
        std::env::set_var(
            "CRABBY_JWT_SECRET",
            "REPLACE_ME_WITH_A_32_BYTE_RANDOM_SECRET",
        );
        // catch_unwind so the env var is always cleaned up for other tests.
        let result = std::panic::catch_unwind(|| {
            let mut config = Config::default();
            config.apply_env_overrides();
        });
        std::env::remove_var("CRABBY_JWT_SECRET");
        let err = result.expect_err("placeholder from env must refuse to boot");
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(msg.contains("placeholder"), "unexpected panic: {msg}");
    }
}
