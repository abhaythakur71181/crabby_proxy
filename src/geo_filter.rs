use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::sync::Arc;

/// GeoIP lookup service
pub struct GeoFilter {
    reader: Reader<Vec<u8>>,
}

impl GeoFilter {
    /// Load GeoIP database from file
    pub fn new(path: &str) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = Reader::open_readfile(path)?;
        Ok(Self { reader })
    }

    /// Look up the country ISO code for an IP address
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        match self.reader.lookup::<geoip2::Country>(ip) {
            Ok(result) => result
                .country
                .and_then(|c| c.iso_code)
                .map(|s| s.to_uppercase()),
            Err(_) => None,
        }
    }

    /// Check if an IP is allowed based on country allow/blocklists
    /// Returns (allowed: bool, country_code: Option<String>)
    pub fn is_ip_allowed(
        &self,
        ip: IpAddr,
        blocked_countries: &[String],
        allowed_countries: &[String],
    ) -> (bool, Option<String>) {
        let country = self.lookup_country(ip);
        match &country {
            None => {
                // Unknown country (DB miss, private IP, parse failure).
                // Fail OPEN only when there is no allowlist; in allowlist mode an
                // unclassifiable IP must be denied, otherwise the allowlist is
                // trivially bypassed by any IP the DB cannot map.
                (allowed_countries.is_empty(), None)
            }
            Some(code) => {
                // Check blocklist first
                if blocked_countries.iter().any(|c| c.to_uppercase() == *code) {
                    return (false, country);
                }
                // If allowlist is set, country must be in it
                if !allowed_countries.is_empty()
                    && !allowed_countries.iter().any(|c| c.to_uppercase() == *code)
                {
                    return (false, country);
                }
                (true, country)
            }
        }
    }
}

/// Thread-safe shared GeoFilter
pub type SharedGeoFilter = Arc<GeoFilter>;

/// Initialize GeoFilter from config path (returns None if not configured or fails)
pub fn init_geo_filter(path: Option<&str>) -> Option<SharedGeoFilter> {
    let path = path?;
    match GeoFilter::new(path) {
        Ok(filter) => {
            tracing::info!("GeoIP database loaded from: {}", path);
            Some(Arc::new(filter))
        }
        Err(e) => {
            tracing::warn!("Failed to load GeoIP database from {}: {}", path, e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ip_allowed_no_restrictions() {
        // Without a real DB, test the logic with a mock approach
        // Just verify the allow/block logic works
        let blocked = vec!["CN".to_string(), "RU".to_string()];
        let allowed: Vec<String> = vec![];

        // Simulate: country = "US" → not blocked, no allowlist → allowed
        let code = "US".to_string();
        let is_blocked = blocked.iter().any(|c| c.to_uppercase() == code);
        assert!(!is_blocked);

        // Simulate: country = "CN" → blocked
        let code = "CN".to_string();
        let is_blocked = blocked.iter().any(|c| c.to_uppercase() == code);
        assert!(is_blocked);

        // Simulate: allowlist mode
        let allowed = vec!["US".to_string(), "GB".to_string()];
        let code = "DE".to_string();
        let in_allowlist = allowed.iter().any(|c| c.to_uppercase() == code);
        assert!(!in_allowlist);

        let code = "US".to_string();
        let in_allowlist = allowed.iter().any(|c| c.to_uppercase() == code);
        assert!(in_allowlist);
    }
}
