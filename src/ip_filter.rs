use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FilterMode {
    /// Block mode: Allow all except those in block_list
    BlockList,
    /// Allow mode: Block all except those in allow_list
    AllowList,
}

impl Default for FilterMode {
    fn default() -> Self {
        FilterMode::BlockList
    }
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
}
