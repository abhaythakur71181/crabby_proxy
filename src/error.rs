#[derive(Debug)]
pub enum ProxyError {
    ConnectionRefused,
    IPv6NotSupported, // not supported by Socks4
    InternalError,
    BadRequest,
    Timeout,
    PayloadTooLarge,
    BadGateway(anyhow::Error),
    Disconnected(anyhow::Error),
    QuotaExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_error_connection_refused() {
        let err = ProxyError::ConnectionRefused;
        let debug = format!("{:?}", err);
        assert!(debug.contains("ConnectionRefused"));
    }

    #[test]
    fn test_proxy_error_ipv6_not_supported() {
        let err = ProxyError::IPv6NotSupported;
        let debug = format!("{:?}", err);
        assert!(debug.contains("IPv6NotSupported"));
    }

    #[test]
    fn test_proxy_error_internal_error() {
        let err = ProxyError::InternalError;
        let debug = format!("{:?}", err);
        assert!(debug.contains("InternalError"));
    }

    #[test]
    fn test_proxy_error_bad_request() {
        let err = ProxyError::BadRequest;
        let debug = format!("{:?}", err);
        assert!(debug.contains("BadRequest"));
    }

    #[test]
    fn test_proxy_error_timeout() {
        let err = ProxyError::Timeout;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Timeout"));
    }

    #[test]
    fn test_proxy_error_payload_too_large() {
        let err = ProxyError::PayloadTooLarge;
        let debug = format!("{:?}", err);
        assert!(debug.contains("PayloadTooLarge"));
    }

    #[test]
    fn test_proxy_error_bad_gateway() {
        let inner = anyhow::anyhow!("upstream failed");
        let err = ProxyError::BadGateway(inner);
        let debug = format!("{:?}", err);
        assert!(debug.contains("BadGateway"));
        assert!(debug.contains("upstream failed"));
    }

    #[test]
    fn test_proxy_error_disconnected() {
        let inner = anyhow::anyhow!("client went away");
        let err = ProxyError::Disconnected(inner);
        let debug = format!("{:?}", err);
        assert!(debug.contains("Disconnected"));
        assert!(debug.contains("client went away"));
    }

    #[test]
    fn test_proxy_error_quota_exceeded() {
        let err = ProxyError::QuotaExceeded;
        let debug = format!("{:?}", err);
        assert!(debug.contains("QuotaExceeded"));
    }

    #[test]
    fn test_all_variants_are_constructable() {
        // Ensures no variant was accidentally removed
        let _errors: Vec<ProxyError> = vec![
            ProxyError::ConnectionRefused,
            ProxyError::IPv6NotSupported,
            ProxyError::InternalError,
            ProxyError::BadRequest,
            ProxyError::Timeout,
            ProxyError::PayloadTooLarge,
            ProxyError::BadGateway(anyhow::anyhow!("test")),
            ProxyError::Disconnected(anyhow::anyhow!("test")),
            ProxyError::QuotaExceeded,
        ];
        assert_eq!(_errors.len(), 9);
    }
}
