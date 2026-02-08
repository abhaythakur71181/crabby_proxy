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

    #[test]
    fn test_validate_username() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test_user").is_ok());
        assert!(validate_username("user-name").is_ok());

        assert!(validate_username("").is_err());
        assert!(validate_username("a".repeat(65).as_str()).is_err());
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("_username").is_err());
    }

    #[test]
    fn test_validate_password() {
        assert!(validate_password("password123").is_ok());
        assert!(validate_password("MyPass1!").is_ok());

        assert!(validate_password("short1").is_err());
        assert!(validate_password("nodigits").is_err());
        assert!(validate_password("12345678").is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(65535).is_ok());

        assert!(validate_port(0).is_err());
        assert!(validate_port(80).is_err());
        assert!(validate_port(1023).is_err());
    }

    #[test]
    fn test_validate_ip_or_cidr() {
        assert!(validate_ip_or_cidr("192.168.1.1").is_ok());
        assert!(validate_ip_or_cidr("192.168.1.0/24").is_ok());
        assert!(validate_ip_or_cidr("::1").is_ok());
        assert!(validate_ip_or_cidr("2001:db8::/32").is_ok());

        assert!(validate_ip_or_cidr("invalid").is_err());
        assert!(validate_ip_or_cidr("192.168.1.0/33").is_err());
        assert!(validate_ip_or_cidr("::1/129").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("my-server.local").is_ok());

        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("-invalid.com").is_err());
        assert!(validate_hostname("invalid-.com").is_err());
        assert!(validate_hostname("a".repeat(64).as_str()).is_err());
    }
}
