use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::sync::Arc;

/// GeoIP lookup service
pub struct GeoFilter {
    reader: Reader<Vec<u8>>,
}

impl GeoFilter {
    /// Load GeoIP database from file
    pub fn new(path: &str) -> Result<Self, maxminddb::MaxMindDbError> {
        let reader = Reader::open_readfile(path)?;
        Ok(Self { reader })
    }

    /// Look up the country ISO code for an IP address
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        // Canonicalise so a dual-stack client (`::ffff:a.b.c.d`) is looked up
        // by its IPv4 address (#52).
        let ip = crate::ip_filter::canonical_ip(ip);
        let result = self.reader.lookup(ip).ok()?;
        let country: geoip2::Country = result.decode().ok()??;
        country.country.iso_code.map(|s| s.to_uppercase())
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

/// Initialise the GeoFilter from config.
///
/// When `geo_blocking_enabled` is true the database is mandatory: a missing
/// path or a load failure is returned as an error so the proxy refuses to
/// start instead of silently disabling every country restriction (#55).
/// When geo blocking is disabled a configured-but-unloadable database is only
/// a warning (nothing depends on it).
pub fn init_geo_filter(
    path: Option<&str>,
    geo_blocking_enabled: bool,
) -> Result<Option<SharedGeoFilter>, String> {
    let path = path.map(str::trim).filter(|p| !p.is_empty());
    let result = match path {
        None if geo_blocking_enabled => Err(
            "filtering.geo_blocking_enabled = true but filtering.geoip_database_path is not set; \
             set the path to a MaxMind GeoLite2-Country .mmdb or disable geo blocking"
                .to_string(),
        ),
        None => Ok(None),
        Some(path) => match GeoFilter::new(path) {
            Ok(filter) => {
                tracing::info!("GeoIP database loaded from: {}", path);
                Ok(Some(Arc::new(filter)))
            }
            Err(e) if geo_blocking_enabled => Err(format!(
                "filtering.geo_blocking_enabled = true but the GeoIP database at '{}' \
                 could not be loaded: {}",
                path, e
            )),
            Err(e) => {
                tracing::warn!(
                    "Failed to load GeoIP database from {} (geo blocking disabled): {}",
                    path,
                    e
                );
                Ok(None)
            }
        },
    };
    crate::metrics::GEO_FILTER_LOADED.set(matches!(result, Ok(Some(_))) as i64);
    result
}

#[cfg(test)]
mod tests {
    use super::init_geo_filter;

    #[test]
    fn enabled_without_path_is_an_error() {
        assert!(init_geo_filter(None, true).is_err());
        assert!(init_geo_filter(Some("  "), true).is_err());
    }

    #[test]
    fn enabled_with_unloadable_db_is_an_error() {
        let err = init_geo_filter(Some("/nonexistent/GeoLite2-Country.mmdb"), true)
            .err()
            .expect("must fail closed");
        assert!(err.contains("could not be loaded"));
    }

    #[test]
    fn disabled_tolerates_missing_or_bad_db() {
        assert!(init_geo_filter(None, false).unwrap().is_none());
        assert!(init_geo_filter(Some("/nonexistent/x.mmdb"), false)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_is_ip_allowed_no_restrictions() {
        // Without a real DB, test the logic with a mock approach
        // Just verify the allow/block logic works
        let blocked = ["CN".to_string(), "RU".to_string()];

        // Simulate: country = "US" → not blocked, no allowlist → allowed
        let code = "US".to_string();
        let is_blocked = blocked.iter().any(|c| c.to_uppercase() == code);
        assert!(!is_blocked);

        // Simulate: country = "CN" → blocked
        let code = "CN".to_string();
        let is_blocked = blocked.iter().any(|c| c.to_uppercase() == code);
        assert!(is_blocked);

        // Simulate: allowlist mode
        let allowed = ["US".to_string(), "GB".to_string()];
        let code = "DE".to_string();
        let in_allowlist = allowed.iter().any(|c| c.to_uppercase() == code);
        assert!(!in_allowlist);

        let code = "US".to_string();
        let in_allowlist = allowed.iter().any(|c| c.to_uppercase() == code);
        assert!(in_allowlist);
    }
}
