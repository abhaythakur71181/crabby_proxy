use std::io;
use thiserror::Error;

/// Defines errors that can occur during tunnel operations
#[derive(Debug, Error)]
pub enum TunnelError {
    /// Failed to bind to tunnel port
    #[error("Failed to bind to port {0}: {1}")]
    BindError(u16, String),

    /// Failed to connect to client for tunneling
    #[error("Failed to connect to client {0}: {1}")]
    ClientConnectionError(String, String),

    /// Port allocation failure
    #[error("Port allocation failed: {0}")]
    AllocationError(String),

    /// Requested port is already in use
    #[error("Port {0} is already in use by another tunnel")]
    PortInUse(u16),

    /// Requested port is outside allowed range
    #[error("Port {0} is outside allowed range ({1}-{2})")]
    PortOutOfRange(u16, u16, u16),

    /// No ports available in allocation range
    #[error("No available ports in range {0}-{1}")]
    NoPortsAvailable(u16, u16),

    /// Tunnel not found when attempting to close
    #[error("Tunnel on port {0} not found")]
    TunnelNotFound(u16),

    /// Failed to release tunnel port
    #[error("Failed to release port {0}: {1}")]
    PortReleaseError(u16, String),

    /// Error during tunnel data transfer
    #[error("Tunnel data transfer failed: {0}")]
    DataTransferError(String),

    /// I/O error during tunnel operation
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// General tunnel operation failure
    #[error("Tunnel operation failed: {0}")]
    OperationFailed(String),
}

// Convert PortAllocError to TunnelError
impl From<super::port_allocator::PortAllocError> for TunnelError {
    fn from(err: super::port_allocator::PortAllocError) -> Self {
        match err {
            super::port_allocator::PortAllocError::PortOutOfRange(port, min, max) => {
                TunnelError::PortOutOfRange(port, min, max)
            }
            super::port_allocator::PortAllocError::PortUnavailable(port) => {
                TunnelError::PortInUse(port)
            }
            super::port_allocator::PortAllocError::NoPortsAvailable(min, max) => {
                TunnelError::NoPortsAvailable(min, max)
            }
            e => TunnelError::AllocationError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::port_allocator::PortAllocError;
    use super::*;

    // === Display / Error message tests ===

    #[test]
    fn test_bind_error_display() {
        let e = TunnelError::BindError(8080, "address in use".to_string());
        assert_eq!(e.to_string(), "Failed to bind to port 8080: address in use");
    }

    #[test]
    fn test_client_connection_error_display() {
        let e = TunnelError::ClientConnectionError("10.0.0.1".to_string(), "refused".to_string());
        assert_eq!(
            e.to_string(),
            "Failed to connect to client 10.0.0.1: refused"
        );
    }

    #[test]
    fn test_allocation_error_display() {
        let e = TunnelError::AllocationError("no ports left".to_string());
        assert_eq!(e.to_string(), "Port allocation failed: no ports left");
    }

    #[test]
    fn test_port_in_use_display() {
        let e = TunnelError::PortInUse(9090);
        assert_eq!(
            e.to_string(),
            "Port 9090 is already in use by another tunnel"
        );
    }

    #[test]
    fn test_port_out_of_range_display() {
        let e = TunnelError::PortOutOfRange(5000, 10000, 10999);
        assert_eq!(
            e.to_string(),
            "Port 5000 is outside allowed range (10000-10999)"
        );
    }

    #[test]
    fn test_no_ports_available_display() {
        let e = TunnelError::NoPortsAvailable(10000, 10999);
        assert_eq!(e.to_string(), "No available ports in range 10000-10999");
    }

    #[test]
    fn test_tunnel_not_found_display() {
        let e = TunnelError::TunnelNotFound(8080);
        assert_eq!(e.to_string(), "Tunnel on port 8080 not found");
    }

    #[test]
    fn test_port_release_error_display() {
        let e = TunnelError::PortReleaseError(8080, "not allocated".to_string());
        assert_eq!(e.to_string(), "Failed to release port 8080: not allocated");
    }

    #[test]
    fn test_data_transfer_error_display() {
        let e = TunnelError::DataTransferError("broken pipe".to_string());
        assert_eq!(e.to_string(), "Tunnel data transfer failed: broken pipe");
    }

    #[test]
    fn test_io_error_display() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let e = TunnelError::IoError(io_err);
        assert_eq!(e.to_string(), "I/O error: connection refused");
    }

    #[test]
    fn test_operation_failed_display() {
        let e = TunnelError::OperationFailed("timeout".to_string());
        assert_eq!(e.to_string(), "Tunnel operation failed: timeout");
    }

    // === From<PortAllocError> conversion tests ===

    #[test]
    fn test_from_port_out_of_range() {
        let alloc_err = PortAllocError::PortOutOfRange(5000, 10000, 10999);
        let tunnel_err: TunnelError = alloc_err.into();
        match tunnel_err {
            TunnelError::PortOutOfRange(port, min, max) => {
                assert_eq!(port, 5000);
                assert_eq!(min, 10000);
                assert_eq!(max, 10999);
            }
            e => panic!("Expected PortOutOfRange, got {:?}", e),
        }
    }

    #[test]
    fn test_from_port_unavailable() {
        let alloc_err = PortAllocError::PortUnavailable(10005);
        let tunnel_err: TunnelError = alloc_err.into();
        match tunnel_err {
            TunnelError::PortInUse(port) => assert_eq!(port, 10005),
            e => panic!("Expected PortInUse, got {:?}", e),
        }
    }

    #[test]
    fn test_from_no_ports_available() {
        let alloc_err = PortAllocError::NoPortsAvailable(10000, 10999);
        let tunnel_err: TunnelError = alloc_err.into();
        match tunnel_err {
            TunnelError::NoPortsAvailable(min, max) => {
                assert_eq!(min, 10000);
                assert_eq!(max, 10999);
            }
            e => panic!("Expected NoPortsAvailable, got {:?}", e),
        }
    }

    #[test]
    fn test_from_port_not_allocated() {
        let alloc_err = PortAllocError::PortNotAllocated(10005);
        let tunnel_err: TunnelError = alloc_err.into();
        match tunnel_err {
            TunnelError::AllocationError(msg) => {
                assert!(msg.contains("10005"));
                assert!(msg.contains("not currently allocated"));
            }
            e => panic!("Expected AllocationError, got {:?}", e),
        }
    }

    // === From<io::Error> conversion test ===

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::AddrInUse, "address in use");
        let tunnel_err: TunnelError = io_err.into();
        match tunnel_err {
            TunnelError::IoError(e) => {
                assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
            }
            e => panic!("Expected IoError, got {:?}", e),
        }
    }

    // === std::error::Error trait test ===

    #[test]
    fn test_tunnel_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(TunnelError::TunnelNotFound(8080));
        assert_eq!(e.to_string(), "Tunnel on port 8080 not found");
    }
}
