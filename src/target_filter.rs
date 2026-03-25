use serde::Deserialize;

/// Check if a target host matches a glob pattern
/// Supports: "*.example.com", "api.github.com", "*" (match all)
fn matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.to_lowercase();
    let pattern = pattern.to_lowercase();
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard subdomain: *.example.com matches foo.example.com and example.com
        host == suffix || host.ends_with(&format!(".{}", suffix))
    } else {
        // Exact match
        host == pattern
    }
}

/// Check if a host matches any pattern in a list
fn matches_any(host: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| matches_pattern(host, p))
}

/// Resolve effective target filtering for a connection
/// Returns true if the target is allowed, false if blocked
///
/// Logic:
/// 1. Global blocklist → always denied
/// 2. Per-user blocklist → denied for this user
/// 3. If global allowlist OR per-user allowlist is set → target must match union
/// 4. If both allowlists are empty → allow all
pub fn is_target_allowed(
    host: &str,
    global_allowed: &[String],
    global_blocked: &[String],
    user_allowed: Option<&str>,
    user_blocked: Option<&str>,
) -> bool {
    // Step 1: Global blocklist — always wins
    if matches_any(host, global_blocked) {
        return false;
    }
    // Step 2: Parse per-user lists
    let user_allowed_list: Vec<String> = user_allowed
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let user_blocked_list: Vec<String> = user_blocked
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    // Step 3: Per-user blocklist
    if matches_any(host, &user_blocked_list) {
        return false;
    }
    // Step 4: Check allowlists (union of global + per-user)
    let has_allowlist = !global_allowed.is_empty() || !user_allowed_list.is_empty();
    if has_allowlist {
        matches_any(host, global_allowed) || matches_any(host, &user_allowed_list)
    } else {
        // No allowlists set → allow all
        true
    }
}

/// Access schedule for time-based restrictions
#[derive(Debug, Clone, Deserialize)]
pub struct AccessSchedule {
    pub days: Vec<String>, // "mon", "tue", "wed", "thu", "fri", "sat", "sun"
    pub start_hour: u32,   // 0-23
    pub end_hour: u32,     // 0-23
    #[serde(default = "default_tz")]
    pub timezone: String, // e.g. "UTC", "Asia/Kolkata"
}

fn default_tz() -> String {
    "UTC".to_string()
}

/// Check if current time is within the access schedule.
/// Returns true if access is allowed right now.
/// Respects the `timezone` field (e.g. "Asia/Kolkata", "US/Eastern"); defaults to UTC.
pub fn is_within_schedule(schedule_json: &str) -> bool {
    let schedule: AccessSchedule = match serde_json::from_str(schedule_json) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Invalid access schedule JSON, denying access (fail-closed): {}", e);
            return false;
        }
    };

    // Convert current time to the configured timezone
    let now_utc = chrono::Utc::now();
    let now = if schedule.timezone.eq_ignore_ascii_case("utc") {
        now_utc.naive_utc()
    } else {
        match schedule.timezone.parse::<chrono_tz::Tz>() {
            Ok(tz) => {
                use chrono::TimeZone;
                tz.from_utc_datetime(&now_utc.naive_utc()).naive_local()
            }
            Err(_) => {
                tracing::warn!(
                    "Unknown timezone '{}' in access schedule, falling back to UTC",
                    schedule.timezone
                );
                now_utc.naive_utc()
            }
        }
    };

    let hour = now.format("%H").to_string().parse::<u32>().unwrap_or(0);
    let day = now.format("%a").to_string().to_lowercase();
    let day_short = &day[..3]; // "mon", "tue", etc.

    // Check day
    if !schedule.days.iter().any(|d| d.to_lowercase() == day_short) {
        return false;
    }
    // Check hour range (handles same-day ranges like 9-18)
    if schedule.start_hour <= schedule.end_hour {
        hour >= schedule.start_hour && hour < schedule.end_hour
    } else {
        // Overnight range like 22-06
        hour >= schedule.start_hour || hour < schedule.end_hour
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_pattern_exact() {
        assert!(matches_pattern("api.github.com", "api.github.com"));
        assert!(!matches_pattern("api.github.com", "github.com"));
    }

    #[test]
    fn test_matches_pattern_wildcard() {
        assert!(matches_pattern("foo.example.com", "*.example.com"));
        assert!(matches_pattern("example.com", "*.example.com"));
        assert!(matches_pattern("bar.baz.example.com", "*.example.com"));
        assert!(!matches_pattern("example.org", "*.example.com"));
    }

    #[test]
    fn test_matches_pattern_star() {
        assert!(matches_pattern("anything.com", "*"));
    }

    #[test]
    fn test_matches_pattern_case_insensitive() {
        assert!(matches_pattern("API.GitHub.Com", "api.github.com"));
        assert!(matches_pattern("foo.Example.COM", "*.example.com"));
    }

    #[test]
    fn test_is_target_allowed_no_restrictions() {
        assert!(is_target_allowed("anything.com", &[], &[], None, None));
    }

    #[test]
    fn test_global_blocklist_always_wins() {
        let blocked = vec!["*.malware.org".to_string()];
        let allowed = vec!["*.malware.org".to_string()]; // even if in allowlist
        assert!(!is_target_allowed(
            "evil.malware.org",
            &allowed,
            &blocked,
            None,
            None
        ));
    }

    #[test]
    fn test_global_allowlist_restricts() {
        let allowed = vec!["*.github.com".to_string()];
        assert!(is_target_allowed(
            "api.github.com",
            &allowed,
            &[],
            None,
            None
        ));
        assert!(!is_target_allowed("google.com", &allowed, &[], None, None));
    }

    #[test]
    fn test_user_allowlist_union() {
        let global_allowed = vec!["*.github.com".to_string()];
        let user_allowed = Some(r#"["*.internal.corp"]"#);
        assert!(is_target_allowed(
            "api.github.com",
            &global_allowed,
            &[],
            user_allowed,
            None
        ));
        assert!(is_target_allowed(
            "app.internal.corp",
            &global_allowed,
            &[],
            user_allowed,
            None
        ));
        assert!(!is_target_allowed(
            "google.com",
            &global_allowed,
            &[],
            user_allowed,
            None
        ));
    }

    #[test]
    fn test_user_blocklist_overrides() {
        let global_allowed = vec!["*.github.com".to_string(), "*.google.com".to_string()];
        let user_blocked = Some(r#"["*.github.com"]"#);
        assert!(!is_target_allowed(
            "api.github.com",
            &global_allowed,
            &[],
            None,
            user_blocked
        ));
        assert!(is_target_allowed(
            "google.com",
            &global_allowed,
            &[],
            None,
            user_blocked
        ));
    }

    #[test]
    fn test_full_union_flow() {
        // Global allows github + google, global blocks malware
        // User additionally allows internal, user blocks github
        let global_allowed = vec!["*.github.com".to_string(), "*.google.com".to_string()];
        let global_blocked = vec!["*.malware.org".to_string()];
        let user_allowed = Some(r#"["*.internal.corp"]"#);
        let user_blocked = Some(r#"["*.github.com"]"#);

        // google.com: global allowed, not blocked → OK
        assert!(is_target_allowed(
            "google.com",
            &global_allowed,
            &global_blocked,
            user_allowed,
            user_blocked
        ));
        // internal.corp: user allowed → OK
        assert!(is_target_allowed(
            "app.internal.corp",
            &global_allowed,
            &global_blocked,
            user_allowed,
            user_blocked
        ));
        // github.com: user blocked → denied
        assert!(!is_target_allowed(
            "api.github.com",
            &global_allowed,
            &global_blocked,
            user_allowed,
            user_blocked
        ));
        // malware.org: global blocked → denied
        assert!(!is_target_allowed(
            "evil.malware.org",
            &global_allowed,
            &global_blocked,
            user_allowed,
            user_blocked
        ));
        // random.com: not in any allowlist → denied
        assert!(!is_target_allowed(
            "random.com",
            &global_allowed,
            &global_blocked,
            user_allowed,
            user_blocked
        ));
    }

    #[test]
    fn test_schedule_parsing_invalid_fails_closed() {
        assert!(!is_within_schedule("invalid json"));
        // Empty object has default fields — days will be empty so access is denied
        assert!(!is_within_schedule("{}"));
    }
}
