use std::net::IpAddr;

/// Validates a username according to security requirements
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() {
        return Err("Username cannot be empty");
    }
    if username.len() > 64 {
        return Err("Username must be 64 characters or less");
    }
    // Only allow alphanumeric, underscore, and hyphen
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Username can only contain letters, numbers, underscore, and hyphen");
    }
    // Must start with a letter or number
    if !username.chars().next().unwrap().is_alphanumeric() {
        return Err("Username must start with a letter or number");
    }
    Ok(())
}

/// Validates a password according to security requirements
pub fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters");
    }
    if password.len() > 128 {
        return Err("Password too long (max 128 characters)");
    }
    // Check for at least one letter and one number
    let has_letter = password.chars().any(|c| c.is_alphabetic());
    let has_number = password.chars().any(|c| c.is_numeric());
    if !has_letter || !has_number {
        return Err("Password must contain at least one letter and one number");
    }
    Ok(())
}

/// Validates a port number
pub fn validate_port(port: u16) -> Result<(), &'static str> {
    if port == 0 {
        return Err("Port cannot be 0");
    }
    if port < 1024 {
        return Err("Port must be 1024 or higher (privileged ports not allowed)");
    }
    Ok(())
}

/// Validates an IP address or CIDR range
pub fn validate_ip_or_cidr(input: &str) -> Result<(), &'static str> {
    // Try parsing as plain IP first
    if input.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    // Try parsing as CIDR
    let parts: Vec<&str> = input.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid IP or CIDR format");
    }
    // Validate IP part
    let ip = parts[0]
        .parse::<IpAddr>()
        .map_err(|_| "Invalid IP address")?;
    // Validate prefix length
    let prefix: u8 = parts[1].parse().map_err(|_| "Invalid prefix length")?;
    match ip {
        IpAddr::V4(_) => {
            if prefix > 32 {
                return Err("IPv4 prefix must be 0-32");
            }
        }
        IpAddr::V6(_) => {
            if prefix > 128 {
                return Err("IPv6 prefix must be 0-128");
            }
        }
    }
    Ok(())
}

/// Validates a hostname
pub fn validate_hostname(hostname: &str) -> Result<(), &'static str> {
    if hostname.is_empty() {
        return Err("Hostname cannot be empty");
    }

    if hostname.len() > 253 {
        return Err("Hostname too long (max 253 characters)");
    }

    // Check each label
    for label in hostname.split('.') {
        if label.is_empty() {
            return Err("Hostname label cannot be empty");
        }

        if label.len() > 63 {
            return Err("Hostname label too long (max 63 characters)");
        }

        // Labels must start and end with alphanumeric
        let first = label.chars().next().unwrap();
        let last = label.chars().last().unwrap();

        if !first.is_alphanumeric() || !last.is_alphanumeric() {
            return Err("Hostname label must start and end with letter or number");
        }

        // Only alphanumeric and hyphens allowed
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return Err("Hostname can only contain letters, numbers, dots, and hyphens");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Username Tests ===

    #[test]
    fn test_validate_username_valid_cases() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test_user").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("a").is_ok());
        assert!(validate_username("A").is_ok());
        assert!(validate_username("1user").is_ok());
        assert!(validate_username("user_name-123").is_ok());
    }

    #[test]
    fn test_validate_username_empty() {
        let result = validate_username("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Username cannot be empty");
    }

    #[test]
    fn test_validate_username_too_long() {
        let result = validate_username(&"a".repeat(65));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Username must be 64 characters or less"
        );
    }

    #[test]
    fn test_validate_username_exactly_64_chars() {
        assert!(validate_username(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn test_validate_username_special_chars_rejected() {
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user.name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user!name").is_err());
        assert!(validate_username("user#name").is_err());
        assert!(validate_username("user/name").is_err());
    }

    #[test]
    fn test_validate_username_must_start_with_alphanumeric() {
        assert!(validate_username("_username").is_err());
        assert!(validate_username("-username").is_err());
    }

    #[test]
    fn test_validate_username_unicode_accepted() {
        // Rust's char::is_alphanumeric() returns true for Unicode letters,
        // so Unicode usernames are accepted by the current implementation.
        assert!(validate_username("üser").is_ok());
        assert!(validate_username("用户").is_ok());
    }

    // === Password Tests ===

    #[test]
    fn test_validate_password_valid_cases() {
        assert!(validate_password("password123").is_ok());
        assert!(validate_password("MyPass1!").is_ok());
        assert!(validate_password("abcdefg1").is_ok());
        assert!(validate_password("1abcdefg").is_ok());
        assert!(validate_password("P@ssw0rd!#$%").is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        let result = validate_password("short1");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Password must be at least 8 characters"
        );
    }

    #[test]
    fn test_validate_password_exactly_8_chars() {
        assert!(validate_password("abcdefg1").is_ok());
    }

    #[test]
    fn test_validate_password_no_digits() {
        let result = validate_password("nodigits");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Password must contain at least one letter and one number"
        );
    }

    #[test]
    fn test_validate_password_no_letters() {
        let result = validate_password("12345678");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Password must contain at least one letter and one number"
        );
    }

    #[test]
    fn test_validate_password_too_long() {
        let long_pw = "a".repeat(127) + "1";
        assert!(long_pw.len() == 128);
        assert!(validate_password(&long_pw).is_ok());

        let too_long = "a".repeat(128) + "1";
        assert!(validate_password(&too_long).is_err());
    }

    #[test]
    fn test_validate_password_only_special_chars() {
        assert!(validate_password("!@#$%^&*").is_err());
    }

    #[test]
    fn test_validate_password_empty() {
        assert!(validate_password("").is_err());
    }

    // === Port Tests ===

    #[test]
    fn test_validate_port_valid_cases() {
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(65535).is_ok());
        assert!(validate_port(1024).is_ok());
        assert!(validate_port(3000).is_ok());
    }

    #[test]
    fn test_validate_port_zero() {
        let result = validate_port(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Port cannot be 0");
    }

    #[test]
    fn test_validate_port_privileged() {
        assert!(validate_port(80).is_err());
        assert!(validate_port(443).is_err());
        assert!(validate_port(22).is_err());
        assert!(validate_port(1023).is_err());
        assert!(validate_port(1).is_err());
    }

    #[test]
    fn test_validate_port_boundary_1024() {
        assert!(validate_port(1023).is_err());
        assert!(validate_port(1024).is_ok());
    }

    // === IP/CIDR Tests ===

    #[test]
    fn test_validate_ip_or_cidr_ipv4() {
        assert!(validate_ip_or_cidr("192.168.1.1").is_ok());
        assert!(validate_ip_or_cidr("10.0.0.0").is_ok());
        assert!(validate_ip_or_cidr("0.0.0.0").is_ok());
        assert!(validate_ip_or_cidr("255.255.255.255").is_ok());
    }

    #[test]
    fn test_validate_ip_or_cidr_ipv6() {
        assert!(validate_ip_or_cidr("::1").is_ok());
        assert!(validate_ip_or_cidr("::").is_ok());
        assert!(validate_ip_or_cidr("2001:db8::1").is_ok());
        assert!(validate_ip_or_cidr("fe80::1").is_ok());
    }

    #[test]
    fn test_validate_ip_or_cidr_valid_cidr() {
        assert!(validate_ip_or_cidr("192.168.1.0/24").is_ok());
        assert!(validate_ip_or_cidr("10.0.0.0/8").is_ok());
        assert!(validate_ip_or_cidr("192.168.1.1/32").is_ok());
        assert!(validate_ip_or_cidr("0.0.0.0/0").is_ok());
        assert!(validate_ip_or_cidr("2001:db8::/32").is_ok());
    }

    #[test]
    fn test_validate_ip_or_cidr_invalid_prefix_ipv4() {
        assert!(validate_ip_or_cidr("192.168.1.0/33").is_err());
    }

    #[test]
    fn test_validate_ip_or_cidr_invalid_prefix_ipv6() {
        assert!(validate_ip_or_cidr("::1/129").is_err());
    }

    #[test]
    fn test_validate_ip_or_cidr_invalid_formats() {
        assert!(validate_ip_or_cidr("invalid").is_err());
        assert!(validate_ip_or_cidr("").is_err());
        assert!(validate_ip_or_cidr("not/an/ip").is_err());
        assert!(validate_ip_or_cidr("192.168.1.0/abc").is_err());
        assert!(validate_ip_or_cidr("300.300.300.300").is_err());
    }

    // === Hostname Tests ===

    #[test]
    fn test_validate_hostname_valid_cases() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("my-server.local").is_ok());
        assert!(validate_hostname("a.b.c.d.e").is_ok());
        assert!(validate_hostname("host123").is_ok());
        assert!(validate_hostname("123host").is_ok());
        assert!(validate_hostname("a").is_ok());
        assert!(validate_hostname("test-host-name.example.co.uk").is_ok());
    }

    #[test]
    fn test_validate_hostname_empty() {
        let result = validate_hostname("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Hostname cannot be empty");
    }

    #[test]
    fn test_validate_hostname_too_long() {
        let long = format!("{}.com", "a".repeat(250));
        assert!(validate_hostname(&long).is_err());
    }

    #[test]
    fn test_validate_hostname_label_too_long() {
        let result = validate_hostname(&"a".repeat(64));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Hostname label too long (max 63 characters)"
        );
    }

    #[test]
    fn test_validate_hostname_label_exactly_63_chars() {
        assert!(validate_hostname(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn test_validate_hostname_starts_with_hyphen() {
        assert!(validate_hostname("-invalid.com").is_err());
    }

    #[test]
    fn test_validate_hostname_ends_with_hyphen() {
        assert!(validate_hostname("invalid-.com").is_err());
    }

    #[test]
    fn test_validate_hostname_empty_label() {
        assert!(validate_hostname("..com").is_err());
        assert!(validate_hostname("host..com").is_err());
    }

    #[test]
    fn test_validate_hostname_special_chars() {
        assert!(validate_hostname("host_name.com").is_err());
        assert!(validate_hostname("host@name.com").is_err());
        assert!(validate_hostname("host name.com").is_err());
    }

    #[test]
    fn test_validate_hostname_trailing_dot() {
        // Trailing dot creates an empty label
        assert!(validate_hostname("example.com.").is_err());
    }

    #[test]
    fn test_validate_hostname_leading_dot() {
        assert!(validate_hostname(".example.com").is_err());
    }
}
