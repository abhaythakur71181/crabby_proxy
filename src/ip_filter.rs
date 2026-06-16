use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum FilterMode {
    /// Block mode: Allow all except those in block_list
    #[default]
    BlockList,
    /// Allow mode: Block all except those in allow_list
    AllowList,
}

#[derive(Debug, Clone)]
pub struct IpFilter {
    mode: FilterMode,
    block_list: Vec<IpNet>,
    allow_list: Vec<IpNet>,
}

impl IpFilter {
    pub fn new(
        mode: FilterMode,
        block_list: Vec<String>,
        allow_list: Vec<String>,
    ) -> Result<Self, String> {
        let block_nets = Self::parse_ip_list(&block_list)?;
        let allow_nets = Self::parse_ip_list(&allow_list)?;

        Ok(Self {
            mode,
            block_list: block_nets,
            allow_list: allow_nets,
        })
    }

    fn parse_ip_list(list: &[String]) -> Result<Vec<IpNet>, String> {
        list.iter()
            .map(|s| IpNet::from_str(s).map_err(|e| format!("Invalid IP/CIDR '{}': {}", s, e)))
            .collect()
    }

    /// Check if an IP address is allowed by the filter
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        match self.mode {
            FilterMode::BlockList => {
                // Block mode: deny if in block_list
                !self.block_list.iter().any(|net| net.contains(&ip))
            }
            FilterMode::AllowList => {
                // Allow mode: allow only if in allow_list
                if self.allow_list.is_empty() {
                    // If allow list is empty in allow mode, allow all
                    true
                } else {
                    self.allow_list.iter().any(|net| net.contains(&ip))
                }
            }
        }
    }

    pub fn add_to_block_list(&mut self, ip: IpNet) {
        if !self.block_list.contains(&ip) {
            self.block_list.push(ip);
        }
    }

    pub fn add_to_allow_list(&mut self, ip: IpNet) {
        if !self.allow_list.contains(&ip) {
            self.allow_list.push(ip);
        }
    }

    pub fn remove_from_block_list(&mut self, ip: &IpNet) {
        self.block_list.retain(|net| net != ip);
    }

    pub fn remove_from_allow_list(&mut self, ip: &IpNet) {
        self.allow_list.retain(|net| net != ip);
    }

    pub fn get_block_list(&self) -> &[IpNet] {
        &self.block_list
    }

    pub fn get_allow_list(&self) -> &[IpNet] {
        &self.allow_list
    }

    pub fn get_mode(&self) -> &FilterMode {
        &self.mode
    }

    pub fn set_mode(&mut self, mode: FilterMode) {
        self.mode = mode;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // === Original Tests (kept) ===

    #[test]
    fn test_block_list_mode() {
        let filter = IpFilter::new(
            FilterMode::BlockList,
            vec!["192.168.1.0/24".to_string(), "10.0.0.5/32".to_string()],
            vec![],
        )
        .unwrap();

        // Should block IPs in block_list
        assert!(!filter.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(!filter.is_allowed("10.0.0.5".parse().unwrap()));

        // Should allow IPs not in block_list
        assert!(filter.is_allowed("8.8.8.8".parse().unwrap()));
        assert!(filter.is_allowed("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_allow_list_mode() {
        let filter = IpFilter::new(
            FilterMode::AllowList,
            vec![],
            vec!["192.168.1.0/24".to_string(), "10.0.0.5/32".to_string()],
        )
        .unwrap();

        // Should allow IPs in allow_list
        assert!(filter.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(filter.is_allowed("10.0.0.5".parse().unwrap()));

        // Should block IPs not in allow_list
        assert!(!filter.is_allowed("8.8.8.8".parse().unwrap()));
        assert!(!filter.is_allowed("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_ranges() {
        let filter = IpFilter::new(
            FilterMode::BlockList,
            vec!["192.168.0.0/16".to_string()],
            vec![],
        )
        .unwrap();

        // Should block entire 192.168.0.0/16 range
        assert!(!filter.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(!filter.is_allowed("192.168.255.255".parse().unwrap()));

        // Should allow outside range
        assert!(filter.is_allowed("192.169.1.1".parse().unwrap()));
    }

    // === New Tests ===

    // --- Construction and validation ---

    #[test]
    fn test_new_empty_lists() {
        let filter = IpFilter::new(FilterMode::BlockList, vec![], vec![]).unwrap();
        // Empty blocklist means everything is allowed
        assert!(filter.is_allowed("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_new_invalid_ip_in_block_list() {
        let result = IpFilter::new(FilterMode::BlockList, vec!["not_an_ip".to_string()], vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid IP/CIDR"));
    }

    #[test]
    fn test_new_invalid_ip_in_allow_list() {
        let result = IpFilter::new(FilterMode::AllowList, vec![], vec!["garbage".to_string()]);
        assert!(result.is_err());
    }

    // --- AllowList edge cases ---

    #[test]
    fn test_allow_list_empty_allows_all() {
        let filter = IpFilter::new(FilterMode::AllowList, vec![], vec![]).unwrap();
        // Empty allowlist in allow mode should allow all
        assert!(filter.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(filter.is_allowed("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_allow_list_single_ip() {
        let filter = IpFilter::new(
            FilterMode::AllowList,
            vec![],
            vec!["10.0.0.1/32".to_string()],
        )
        .unwrap();

        assert!(filter.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(!filter.is_allowed("10.0.0.2".parse().unwrap()));
    }

    // --- BlockList edge cases ---

    #[test]
    fn test_block_list_single_ip() {
        let filter = IpFilter::new(
            FilterMode::BlockList,
            vec!["1.2.3.4/32".to_string()],
            vec![],
        )
        .unwrap();

        assert!(!filter.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(filter.is_allowed("1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn test_block_list_multiple_ranges() {
        let filter = IpFilter::new(
            FilterMode::BlockList,
            vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            vec![],
        )
        .unwrap();

        // All private ranges blocked
        assert!(!filter.is_allowed("10.1.2.3".parse().unwrap()));
        assert!(!filter.is_allowed("172.20.1.1".parse().unwrap()));
        assert!(!filter.is_allowed("192.168.1.1".parse().unwrap()));

        // Public IPs allowed
        assert!(filter.is_allowed("8.8.8.8".parse().unwrap()));
        assert!(filter.is_allowed("1.1.1.1".parse().unwrap()));
    }

    // --- IPv6 Tests ---

    #[test]
    fn test_block_list_ipv6() {
        let filter = IpFilter::new(
            FilterMode::BlockList,
            vec!["::1/128".to_string(), "fe80::/10".to_string()],
            vec![],
        )
        .unwrap();

        assert!(!filter.is_allowed("::1".parse().unwrap()));
        assert!(!filter.is_allowed("fe80::1".parse().unwrap()));
        assert!(filter.is_allowed("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_allow_list_ipv6() {
        let filter = IpFilter::new(
            FilterMode::AllowList,
            vec![],
            vec!["2001:db8::/32".to_string()],
        )
        .unwrap();

        assert!(filter.is_allowed("2001:db8::1".parse().unwrap()));
        assert!(!filter.is_allowed("2001:db9::1".parse().unwrap()));
        assert!(!filter.is_allowed("::1".parse().unwrap()));
    }

    // --- add_to / remove_from list Tests ---

    #[test]
    fn test_add_to_block_list() {
        let mut filter = IpFilter::new(FilterMode::BlockList, vec![], vec![]).unwrap();
        let ip: IpAddr = "5.5.5.5".parse().unwrap();

        assert!(filter.is_allowed(ip));

        let net: IpNet = "5.5.5.5/32".parse().unwrap();
        filter.add_to_block_list(net);

        assert!(!filter.is_allowed(ip));
    }

    #[test]
    fn test_add_to_block_list_no_duplicates() {
        let mut filter = IpFilter::new(FilterMode::BlockList, vec![], vec![]).unwrap();
        let net: IpNet = "5.5.5.0/24".parse().unwrap();

        filter.add_to_block_list(net);
        filter.add_to_block_list(net); // Duplicate
        assert_eq!(filter.get_block_list().len(), 1);
    }

    #[test]
    fn test_remove_from_block_list() {
        let mut filter = IpFilter::new(
            FilterMode::BlockList,
            vec!["5.5.5.5/32".to_string()],
            vec![],
        )
        .unwrap();

        let ip: IpAddr = "5.5.5.5".parse().unwrap();
        assert!(!filter.is_allowed(ip));

        let net: IpNet = "5.5.5.5/32".parse().unwrap();
        filter.remove_from_block_list(&net);
        assert!(filter.is_allowed(ip));
    }

    #[test]
    fn test_add_to_allow_list() {
        let mut filter = IpFilter::new(FilterMode::AllowList, vec![], vec![]).unwrap();
        let net: IpNet = "10.0.0.0/8".parse().unwrap();

        filter.add_to_allow_list(net);
        assert_eq!(filter.get_allow_list().len(), 1);
    }

    #[test]
    fn test_add_to_allow_list_no_duplicates() {
        let mut filter = IpFilter::new(FilterMode::AllowList, vec![], vec![]).unwrap();
        let net: IpNet = "10.0.0.0/8".parse().unwrap();

        filter.add_to_allow_list(net);
        filter.add_to_allow_list(net);
        assert_eq!(filter.get_allow_list().len(), 1);
    }

    #[test]
    fn test_remove_from_allow_list() {
        let mut filter = IpFilter::new(
            FilterMode::AllowList,
            vec![],
            vec!["10.0.0.0/8".to_string()],
        )
        .unwrap();

        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        filter.remove_from_allow_list(&net);
        assert!(filter.get_allow_list().is_empty());
    }

    // --- Mode getters/setters ---

    #[test]
    fn test_get_mode() {
        let filter = IpFilter::new(FilterMode::BlockList, vec![], vec![]).unwrap();
        assert_eq!(*filter.get_mode(), FilterMode::BlockList);
    }

    #[test]
    fn test_set_mode() {
        let mut filter = IpFilter::new(FilterMode::BlockList, vec![], vec![]).unwrap();
        filter.set_mode(FilterMode::AllowList);
        assert_eq!(*filter.get_mode(), FilterMode::AllowList);
    }

    #[test]
    fn test_switching_mode_changes_behavior() {
        let mut filter = IpFilter::new(
            FilterMode::BlockList,
            vec!["1.2.3.4/32".to_string()],
            vec!["5.6.7.8/32".to_string()],
        )
        .unwrap();

        let blocked_ip: IpAddr = "1.2.3.4".parse().unwrap();
        let allowed_ip: IpAddr = "5.6.7.8".parse().unwrap();
        let other_ip: IpAddr = "9.9.9.9".parse().unwrap();

        // BlockList mode: block 1.2.3.4, allow everything else
        assert!(!filter.is_allowed(blocked_ip));
        assert!(filter.is_allowed(allowed_ip));
        assert!(filter.is_allowed(other_ip));

        // Switch to AllowList mode: only allow 5.6.7.8
        filter.set_mode(FilterMode::AllowList);
        assert!(!filter.is_allowed(blocked_ip));
        assert!(filter.is_allowed(allowed_ip));
        assert!(!filter.is_allowed(other_ip));
    }

    // --- FilterMode tests ---

    #[test]
    fn test_filter_mode_default() {
        assert_eq!(FilterMode::default(), FilterMode::BlockList);
    }

    #[test]
    fn test_filter_mode_equality() {
        assert_eq!(FilterMode::BlockList, FilterMode::BlockList);
        assert_eq!(FilterMode::AllowList, FilterMode::AllowList);
        assert_ne!(FilterMode::BlockList, FilterMode::AllowList);
    }

    #[test]
    fn test_filter_mode_clone() {
        let mode = FilterMode::AllowList;
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    // --- Boundary CIDR Tests ---

    #[test]
    fn test_cidr_boundary_first_ip() {
        let filter = IpFilter::new(
            FilterMode::BlockList,
            vec!["10.0.0.0/24".to_string()],
            vec![],
        )
        .unwrap();
        assert!(!filter.is_allowed("10.0.0.0".parse().unwrap()));
    }

    #[test]
    fn test_cidr_boundary_last_ip() {
        let filter = IpFilter::new(
            FilterMode::BlockList,
            vec!["10.0.0.0/24".to_string()],
            vec![],
        )
        .unwrap();
        assert!(!filter.is_allowed("10.0.0.255".parse().unwrap()));
    }

    #[test]
    fn test_cidr_boundary_just_outside() {
        let filter = IpFilter::new(
            FilterMode::BlockList,
            vec!["10.0.0.0/24".to_string()],
            vec![],
        )
        .unwrap();
        assert!(filter.is_allowed("10.0.1.0".parse().unwrap()));
    }
}
