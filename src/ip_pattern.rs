//! Client-IP approval patterns: exact IP, octet-wildcard IPv4, CIDR, or "any".
//!
//! Approvals are keyed on the connecting client IP. Mobile clients rotate IPs
//! constantly, so an approval may be stored as a pattern (`140.11.11.*`,
//! `140.11.0.0/16`, `*`) and matched against the concrete connecting IP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A parsed client-IP approval pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpPattern {
    /// `*` (or `*.*.*.*`) — matches every IP, v4 and v6.
    Any,
    /// IPv4 octet wildcard: `Some(v)` is a fixed octet, `None` a wildcard.
    /// Only produced with 1..=3 fixed octets (0 → `Any`, 4 → `Exact`).
    V4Octets([Option<u8>; 4]),
    /// CIDR range, v4 or v6.
    Cidr(ipnet::IpNet),
    /// A single fully-specified IP address.
    Exact(IpAddr),
}

/// Invalid-pattern error carrying a human-readable reason.
#[derive(Debug, PartialEq, Eq)]
pub struct IpPatternError(pub String);

impl std::fmt::Display for IpPatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid IP pattern: {}", self.0)
    }
}

impl IpPattern {
    /// Parse a pattern string. Precedence: `*` → Any; contains `/` → CIDR;
    /// contains `:` → IPv6 exact; 4 dotted octets (each `*` or 0..=255) →
    /// octet form (collapsing to Any/Exact at the extremes); else error.
    pub fn parse(s: &str) -> Result<IpPattern, IpPatternError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(IpPatternError("empty pattern".into()));
        }
        if s == "*" {
            return Ok(IpPattern::Any);
        }
        if s.contains('/') {
            return s
                .parse::<ipnet::IpNet>()
                .map(IpPattern::Cidr)
                .map_err(|e| IpPatternError(format!("bad CIDR '{s}': {e}")));
        }
        if s.contains(':') {
            return s
                .parse::<Ipv6Addr>()
                .map(|a| IpPattern::Exact(IpAddr::V6(a)))
                .map_err(|e| IpPatternError(format!("bad IPv6 address '{s}': {e}")));
        }
        // IPv4: exactly 4 dotted parts, each "*" or 0..=255.
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(IpPatternError(format!("expected 4 octets or '*' in '{s}'")));
        }
        let mut octets: [Option<u8>; 4] = [None; 4];
        let mut fixed = 0;
        for (i, p) in parts.iter().enumerate() {
            if *p == "*" {
                octets[i] = None;
            } else {
                let v: u8 = p
                    .parse()
                    .map_err(|_| IpPatternError(format!("bad octet '{p}' in '{s}'")))?;
                octets[i] = Some(v);
                fixed += 1;
            }
        }
        match fixed {
            0 => Ok(IpPattern::Any),
            4 => Ok(IpPattern::Exact(IpAddr::V4(Ipv4Addr::new(
                octets[0].unwrap(),
                octets[1].unwrap(),
                octets[2].unwrap(),
                octets[3].unwrap(),
            )))),
            _ => Ok(IpPattern::V4Octets(octets)),
        }
    }

    /// True if `ip` falls in this pattern. An IPv4 pattern never matches an
    /// IPv6 address and vice versa.
    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            IpPattern::Any => true,
            IpPattern::Exact(a) => *a == ip,
            IpPattern::Cidr(net) => net.contains(&ip),
            IpPattern::V4Octets(pat) => match ip {
                IpAddr::V4(v4) => {
                    let actual = v4.octets();
                    pat.iter().zip(actual.iter()).all(|(p, a)| match p {
                        Some(v) => v == a,
                        None => true,
                    })
                }
                IpAddr::V6(_) => false,
            },
        }
    }

    /// True when the pattern approves a very large address space (advisory —
    /// used to warn an operator, not to reject).
    pub fn is_broad(&self) -> bool {
        match self {
            IpPattern::Any => true,
            IpPattern::Exact(_) => false,
            // 1 fixed octet ⇒ ~/8; 0 would have been Any.
            IpPattern::V4Octets(pat) => pat.iter().filter(|o| o.is_some()).count() <= 1,
            IpPattern::Cidr(net) => match net {
                ipnet::IpNet::V4(n) => n.prefix_len() <= 8,
                ipnet::IpNet::V6(n) => n.prefix_len() <= 32,
            },
        }
    }
}

/// Validate a client-IP pattern submitted for an approval request or grant.
/// Returns `Ok(Some(warning))` when the pattern is broad (approves a very large
/// address space — surfaced to the operator but still allowed), `Ok(None)` when
/// the pattern is fine, and `Err` when the pattern is syntactically invalid.
pub fn validate_approval_pattern(client_ip: &str) -> Result<Option<String>, IpPatternError> {
    let pat = IpPattern::parse(client_ip)?;
    Ok(pat.is_broad().then(|| {
        format!(
            "pattern '{}' approves this user from a very large IP range",
            client_ip.trim()
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_star_as_any() {
        assert_eq!(IpPattern::parse("*").unwrap(), IpPattern::Any);
        assert_eq!(IpPattern::parse("*.*.*.*").unwrap(), IpPattern::Any);
    }

    #[test]
    fn parses_octet_wildcard() {
        assert_eq!(
            IpPattern::parse("140.11.11.*").unwrap(),
            IpPattern::V4Octets([Some(140), Some(11), Some(11), None])
        );
        assert_eq!(
            IpPattern::parse("140.*.*.*").unwrap(),
            IpPattern::V4Octets([Some(140), None, None, None])
        );
    }

    #[test]
    fn full_ipv4_is_exact() {
        assert_eq!(
            IpPattern::parse("140.11.11.5").unwrap(),
            IpPattern::Exact(ip("140.11.11.5"))
        );
    }

    #[test]
    fn parses_cidr_v4_and_v6() {
        assert!(matches!(
            IpPattern::parse("140.11.0.0/16").unwrap(),
            IpPattern::Cidr(_)
        ));
        assert!(matches!(
            IpPattern::parse("2401:4900::/32").unwrap(),
            IpPattern::Cidr(_)
        ));
    }

    #[test]
    fn parses_ipv6_exact() {
        assert_eq!(
            IpPattern::parse("2401:4900::1234").unwrap(),
            IpPattern::Exact(ip("2401:4900::1234"))
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(IpPattern::parse("").is_err());
        assert!(IpPattern::parse("not-an-ip").is_err());
        assert!(IpPattern::parse("140.11.*").is_err()); // only 3 parts
        assert!(IpPattern::parse("999.1.1.1").is_err()); // octet out of range
        assert!(IpPattern::parse("140.11.0.0/99").is_err()); // bad prefix
    }

    #[test]
    fn octet_wildcard_matching() {
        let p = IpPattern::parse("140.11.11.*").unwrap();
        assert!(p.matches(ip("140.11.11.5")));
        assert!(p.matches(ip("140.11.11.255")));
        assert!(!p.matches(ip("140.11.12.5")));
        // never matches v6
        assert!(!p.matches(ip("2401:4900::1")));
    }

    #[test]
    fn cidr_matching_is_family_sensitive() {
        let p = IpPattern::parse("140.11.0.0/16").unwrap();
        assert!(p.matches(ip("140.11.99.99")));
        assert!(!p.matches(ip("140.12.0.1")));
        assert!(!p.matches(ip("2401:4900::1"))); // v4 net, v6 ip
    }

    #[test]
    fn any_matches_both_families() {
        let p = IpPattern::Any;
        assert!(p.matches(ip("8.8.8.8")));
        assert!(p.matches(ip("2401:4900::1")));
    }

    #[test]
    fn broad_detection_boundaries() {
        assert!(IpPattern::parse("*").unwrap().is_broad());
        assert!(IpPattern::parse("140.*.*.*").unwrap().is_broad()); // 1 fixed octet
        assert!(!IpPattern::parse("140.11.*.*").unwrap().is_broad()); // 2 fixed
        assert!(!IpPattern::parse("140.11.11.5").unwrap().is_broad());
        assert!(IpPattern::parse("10.0.0.0/8").unwrap().is_broad());
        assert!(!IpPattern::parse("10.0.0.0/9").unwrap().is_broad());
        assert!(IpPattern::parse("2401::/32").unwrap().is_broad());
        assert!(!IpPattern::parse("2401::/33").unwrap().is_broad());
    }

    #[test]
    fn validate_returns_warning_for_broad() {
        let w = validate_approval_pattern("*").unwrap();
        assert!(w.is_some());
        let w = validate_approval_pattern("140.*.*.*").unwrap();
        assert!(w.is_some());
    }

    #[test]
    fn validate_no_warning_for_narrow() {
        assert_eq!(validate_approval_pattern("140.11.11.5").unwrap(), None);
        assert_eq!(validate_approval_pattern("140.11.11.*").unwrap(), None);
    }

    #[test]
    fn validate_errors_on_invalid() {
        assert!(validate_approval_pattern("not-an-ip").is_err());
    }
}
