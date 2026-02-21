use std::collections::{HashSet, VecDeque};
use thiserror::Error;

/// Custom error types for port allocation
#[derive(Debug, Error)]
pub enum PortAllocError {
    #[error("Port {0} is out of allowed range ({1}-{2})")]
    PortOutOfRange(u16, u16, u16),

    #[error("Port {0} is already allocated")]
    PortUnavailable(u16),

    #[error("No available ports in the range {0}-{1}")]
    NoPortsAvailable(u16, u16),

    #[error("Port {0} is not currently allocated")]
    PortNotAllocated(u16),
}

/// Manages port allocation within a specified range
pub struct PortAllocator {
    min_port: u16,
    max_port: u16,
    allocated_ports: HashSet<u16>,
    available_ports: VecDeque<u16>,
    next_port: u16,
}

impl PortAllocator {
    /// Creates a new PortAllocator with the specified range
    ///
    /// # Arguments
    /// * `min_port` - Minimum port in the range (inclusive)
    /// * `max_port` - Maximum port in the range (inclusive)
    ///
    /// # Panics
    /// Panics if min_port > max_port or if range is empty
    pub fn new(min_port: u16, max_port: u16) -> Self {
        assert!(min_port > 0, "Ports must be > 0");
        assert!(min_port <= max_port, "Invalid port range");

        // Create a deque with all ports in range for O(1) allocation
        let all_ports: VecDeque<u16> = (min_port..=max_port).collect();

        PortAllocator {
            min_port,
            max_port,
            allocated_ports: HashSet::new(),
            available_ports: all_ports,
            next_port: min_port,
        }
    }

    /// Allocates a port, preferring the requested port if available
    ///
    /// # Arguments
    /// * `preferred` - Optional preferred port number
    ///
    /// # Returns
    /// Allocated port number
    pub fn allocate_port(&mut self, preferred: Option<u16>) -> Result<u16, PortAllocError> {
        if let Some(port) = preferred {
            return self.allocate_specific(port);
        }
        self.allocate_next()
    }

    /// Allocates a specific port if available
    ///
    /// # Arguments
    /// * `port` - Port number to allocate
    pub fn allocate_specific(&mut self, port: u16) -> Result<u16, PortAllocError> {
        // Validate port is in range
        if port < self.min_port || port > self.max_port {
            return Err(PortAllocError::PortOutOfRange(
                port,
                self.min_port,
                self.max_port,
            ));
        }

        // Check if port is available
        if self.allocated_ports.contains(&port) {
            return Err(PortAllocError::PortUnavailable(port));
        }

        // Allocate the port
        self.allocated_ports.insert(port);
        self.available_ports.retain(|&p| p != port);

        Ok(port)
    }

    /// Allocates the next available port in the range
    pub fn allocate_next(&mut self) -> Result<u16, PortAllocError> {
        if let Some(port) = self.available_ports.pop_front() {
            self.allocated_ports.insert(port);
            self.next_port = if port == self.max_port {
                self.min_port
            } else {
                port + 1
            };
            return Ok(port);
        }

        Err(PortAllocError::NoPortsAvailable(
            self.min_port,
            self.max_port,
        ))
    }

    /// Releases a previously allocated port
    ///
    /// # Arguments
    /// * `port` - Port number to release
    pub fn release_port(&mut self, port: u16) -> Result<(), PortAllocError> {
        if !self.allocated_ports.contains(&port) {
            return Err(PortAllocError::PortNotAllocated(port));
        }

        // Release the port
        self.allocated_ports.remove(&port);

        // Maintain sorted order when re-adding to available ports
        if port < self.next_port {
            self.available_ports.push_front(port);
        } else {
            self.available_ports.push_back(port);
        }

        Ok(())
    }

    /// Checks if a port is currently allocated
    pub fn is_allocated(&self, port: u16) -> bool {
        self.allocated_ports.contains(&port)
    }

    /// Checks if a port is within the allocator's range
    pub fn is_in_range(&self, port: u16) -> bool {
        port >= self.min_port && port <= self.max_port
    }

    /// Gets the number of available ports
    pub fn available_count(&self) -> usize {
        self.available_ports.len()
    }

    /// Gets the number of allocated ports
    pub fn allocated_count(&self) -> usize {
        self.allocated_ports.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Construction Tests ===

    #[test]
    fn test_new_valid_range() {
        let alloc = PortAllocator::new(10000, 10010);
        assert_eq!(alloc.available_count(), 11); // 10000..=10010
        assert_eq!(alloc.allocated_count(), 0);
    }

    #[test]
    fn test_new_single_port_range() {
        let alloc = PortAllocator::new(8080, 8080);
        assert_eq!(alloc.available_count(), 1);
        assert_eq!(alloc.allocated_count(), 0);
    }

    #[test]
    #[should_panic(expected = "Ports must be > 0")]
    fn test_new_zero_min_port_panics() {
        PortAllocator::new(0, 100);
    }

    #[test]
    #[should_panic(expected = "Invalid port range")]
    fn test_new_inverted_range_panics() {
        PortAllocator::new(10010, 10000);
    }

    // === allocate_next Tests ===

    #[test]
    fn test_allocate_next_returns_first_port() {
        let mut alloc = PortAllocator::new(10000, 10010);
        let port = alloc.allocate_next().unwrap();
        assert_eq!(port, 10000);
        assert!(alloc.is_allocated(10000));
        assert_eq!(alloc.allocated_count(), 1);
        assert_eq!(alloc.available_count(), 10);
    }

    #[test]
    fn test_allocate_next_sequential() {
        let mut alloc = PortAllocator::new(10000, 10002);
        assert_eq!(alloc.allocate_next().unwrap(), 10000);
        assert_eq!(alloc.allocate_next().unwrap(), 10001);
        assert_eq!(alloc.allocate_next().unwrap(), 10002);
    }

    #[test]
    fn test_allocate_next_exhausts_all_ports() {
        let mut alloc = PortAllocator::new(10000, 10002);
        alloc.allocate_next().unwrap();
        alloc.allocate_next().unwrap();
        alloc.allocate_next().unwrap();
        let result = alloc.allocate_next();
        assert!(result.is_err());
        match result.unwrap_err() {
            PortAllocError::NoPortsAvailable(min, max) => {
                assert_eq!(min, 10000);
                assert_eq!(max, 10002);
            }
            e => panic!("Expected NoPortsAvailable, got {:?}", e),
        }
    }

    // === allocate_specific Tests ===

    #[test]
    fn test_allocate_specific_valid_port() {
        let mut alloc = PortAllocator::new(10000, 10010);
        let port = alloc.allocate_specific(10005).unwrap();
        assert_eq!(port, 10005);
        assert!(alloc.is_allocated(10005));
        assert_eq!(alloc.available_count(), 10);
    }

    #[test]
    fn test_allocate_specific_first_port_in_range() {
        let mut alloc = PortAllocator::new(10000, 10010);
        assert_eq!(alloc.allocate_specific(10000).unwrap(), 10000);
    }

    #[test]
    fn test_allocate_specific_last_port_in_range() {
        let mut alloc = PortAllocator::new(10000, 10010);
        assert_eq!(alloc.allocate_specific(10010).unwrap(), 10010);
    }

    #[test]
    fn test_allocate_specific_below_range() {
        let mut alloc = PortAllocator::new(10000, 10010);
        let result = alloc.allocate_specific(9999);
        assert!(result.is_err());
        match result.unwrap_err() {
            PortAllocError::PortOutOfRange(port, min, max) => {
                assert_eq!(port, 9999);
                assert_eq!(min, 10000);
                assert_eq!(max, 10010);
            }
            e => panic!("Expected PortOutOfRange, got {:?}", e),
        }
    }

    #[test]
    fn test_allocate_specific_above_range() {
        let mut alloc = PortAllocator::new(10000, 10010);
        let result = alloc.allocate_specific(10011);
        assert!(result.is_err());
        match result.unwrap_err() {
            PortAllocError::PortOutOfRange(port, min, max) => {
                assert_eq!(port, 10011);
                assert_eq!(min, 10000);
                assert_eq!(max, 10010);
            }
            e => panic!("Expected PortOutOfRange, got {:?}", e),
        }
    }

    #[test]
    fn test_allocate_specific_already_allocated() {
        let mut alloc = PortAllocator::new(10000, 10010);
        alloc.allocate_specific(10005).unwrap();
        let result = alloc.allocate_specific(10005);
        assert!(result.is_err());
        match result.unwrap_err() {
            PortAllocError::PortUnavailable(port) => assert_eq!(port, 10005),
            e => panic!("Expected PortUnavailable, got {:?}", e),
        }
    }

    // === allocate_port Tests (preferred port dispatch) ===

    #[test]
    fn test_allocate_port_with_preferred() {
        let mut alloc = PortAllocator::new(10000, 10010);
        let port = alloc.allocate_port(Some(10005)).unwrap();
        assert_eq!(port, 10005);
    }

    #[test]
    fn test_allocate_port_without_preferred() {
        let mut alloc = PortAllocator::new(10000, 10010);
        let port = alloc.allocate_port(None).unwrap();
        assert_eq!(port, 10000); // allocate_next returns first available
    }

    #[test]
    fn test_allocate_port_preferred_out_of_range() {
        let mut alloc = PortAllocator::new(10000, 10010);
        let result = alloc.allocate_port(Some(5000));
        assert!(result.is_err());
    }

    // === release_port Tests ===

    #[test]
    fn test_release_port_valid() {
        let mut alloc = PortAllocator::new(10000, 10010);
        alloc.allocate_specific(10005).unwrap();
        assert!(alloc.is_allocated(10005));
        alloc.release_port(10005).unwrap();
        assert!(!alloc.is_allocated(10005));
        assert_eq!(alloc.available_count(), 11); // back to full
    }

    #[test]
    fn test_release_port_not_allocated() {
        let mut alloc = PortAllocator::new(10000, 10010);
        let result = alloc.release_port(10005);
        assert!(result.is_err());
        match result.unwrap_err() {
            PortAllocError::PortNotAllocated(port) => assert_eq!(port, 10005),
            e => panic!("Expected PortNotAllocated, got {:?}", e),
        }
    }

    #[test]
    fn test_release_and_reallocate() {
        let mut alloc = PortAllocator::new(10000, 10002);
        // Allocate all
        alloc.allocate_next().unwrap(); // 10000
        alloc.allocate_next().unwrap(); // 10001
        alloc.allocate_next().unwrap(); // 10002
        assert!(alloc.allocate_next().is_err());

        // Release middle port
        alloc.release_port(10001).unwrap();
        // Should be able to allocate again
        let port = alloc.allocate_next().unwrap();
        assert_eq!(port, 10001);
    }

    #[test]
    fn test_double_release_fails() {
        let mut alloc = PortAllocator::new(10000, 10010);
        alloc.allocate_specific(10005).unwrap();
        alloc.release_port(10005).unwrap();
        let result = alloc.release_port(10005);
        assert!(result.is_err());
    }

    // === is_in_range Tests ===

    #[test]
    fn test_is_in_range() {
        let alloc = PortAllocator::new(10000, 10010);
        assert!(alloc.is_in_range(10000));
        assert!(alloc.is_in_range(10005));
        assert!(alloc.is_in_range(10010));
        assert!(!alloc.is_in_range(9999));
        assert!(!alloc.is_in_range(10011));
        assert!(!alloc.is_in_range(1));
    }

    // === is_allocated Tests ===

    #[test]
    fn test_is_allocated() {
        let mut alloc = PortAllocator::new(10000, 10010);
        assert!(!alloc.is_allocated(10005));
        alloc.allocate_specific(10005).unwrap();
        assert!(alloc.is_allocated(10005));
        alloc.release_port(10005).unwrap();
        assert!(!alloc.is_allocated(10005));
    }

    // === Count consistency Tests ===

    #[test]
    fn test_counts_remain_consistent() {
        let mut alloc = PortAllocator::new(10000, 10004);
        assert_eq!(alloc.available_count() + alloc.allocated_count(), 5);

        alloc.allocate_next().unwrap();
        assert_eq!(alloc.available_count() + alloc.allocated_count(), 5);

        alloc.allocate_specific(10003).unwrap();
        assert_eq!(alloc.available_count() + alloc.allocated_count(), 5);

        alloc.release_port(10000).unwrap();
        assert_eq!(alloc.available_count() + alloc.allocated_count(), 5);
    }

    // === Error Display Tests ===

    #[test]
    fn test_error_display_messages() {
        let e1 = PortAllocError::PortOutOfRange(5000, 10000, 10010);
        assert_eq!(
            e1.to_string(),
            "Port 5000 is out of allowed range (10000-10010)"
        );

        let e2 = PortAllocError::PortUnavailable(10005);
        assert_eq!(e2.to_string(), "Port 10005 is already allocated");

        let e3 = PortAllocError::NoPortsAvailable(10000, 10010);
        assert_eq!(
            e3.to_string(),
            "No available ports in the range 10000-10010"
        );

        let e4 = PortAllocError::PortNotAllocated(10005);
        assert_eq!(e4.to_string(), "Port 10005 is not currently allocated");
    }
}
