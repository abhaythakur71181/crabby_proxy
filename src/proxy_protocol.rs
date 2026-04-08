//! HAProxy PROXY protocol v1 parser.
//!
//! Parses the text-based PROXY protocol v1 header to extract the real
//! client IP address when the proxy sits behind a load balancer.
//!
//! Format: `PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n`
//!         `PROXY TCP6 <src_ip> <dst_ip> <src_port> <dst_port>\r\n`
//!         `PROXY UNKNOWN\r\n`

use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Maximum length of a PROXY protocol v1 header line (spec says 108 bytes).
const MAX_PROXY_HEADER_LEN: usize = 108;

/// Parse a PROXY protocol v1 header from the stream.
/// Returns the real client address if successfully parsed, or None if
/// the header is `PROXY UNKNOWN`.
///
/// This consumes bytes from the stream — call before any other reads.
pub async fn parse_proxy_protocol_v1(
    stream: &mut TcpStream,
) -> Result<Option<SocketAddr>, ProxyProtocolError> {
    let mut buf = Vec::with_capacity(MAX_PROXY_HEADER_LEN);
    let mut byte = [0u8; 1];

    // Read until \r\n or max length
    loop {
        if buf.len() >= MAX_PROXY_HEADER_LEN {
            return Err(ProxyProtocolError::HeaderTooLong);
        }
        match tokio::time::timeout(
            crate::constants::PEEK_TIMEOUT,
            stream.read_exact(&mut byte),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(ProxyProtocolError::Io(e)),
            Err(_) => return Err(ProxyProtocolError::Timeout),
        }
        buf.push(byte[0]);
        if buf.len() >= 2 && buf[buf.len() - 2] == b'\r' && buf[buf.len() - 1] == b'\n' {
            break;
        }
    }

    // Remove trailing \r\n
    buf.truncate(buf.len() - 2);
    let line =
        std::str::from_utf8(&buf).map_err(|_| ProxyProtocolError::InvalidFormat("not UTF-8"))?;

    // Must start with "PROXY "
    if !line.starts_with("PROXY ") {
        return Err(ProxyProtocolError::InvalidFormat("missing PROXY prefix"));
    }

    let parts: Vec<&str> = line.split(' ').collect();

    // PROXY UNKNOWN\r\n — valid but no address info
    if parts.len() >= 2 && parts[1] == "UNKNOWN" {
        return Ok(None);
    }

    // PROXY TCP4/TCP6 <src_ip> <dst_ip> <src_port> <dst_port>
    if parts.len() != 6 {
        return Err(ProxyProtocolError::InvalidFormat("expected 6 fields"));
    }

    let proto = parts[1];
    if proto != "TCP4" && proto != "TCP6" {
        return Err(ProxyProtocolError::InvalidFormat("unsupported protocol"));
    }

    let src_ip: IpAddr = parts[2]
        .parse()
        .map_err(|_| ProxyProtocolError::InvalidFormat("invalid source IP"))?;
    let src_port: u16 = parts[4]
        .parse()
        .map_err(|_| ProxyProtocolError::InvalidFormat("invalid source port"))?;

    Ok(Some(SocketAddr::new(src_ip, src_port)))
}

#[derive(Debug)]
pub enum ProxyProtocolError {
    HeaderTooLong,
    Timeout,
    Io(std::io::Error),
    InvalidFormat(&'static str),
}

impl std::fmt::Display for ProxyProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderTooLong => write!(f, "PROXY header exceeds 108 bytes"),
            Self::Timeout => write!(f, "PROXY header read timeout"),
            Self::Io(e) => write!(f, "PROXY header I/O error: {}", e),
            Self::InvalidFormat(msg) => write!(f, "Invalid PROXY header: {}", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_protocol_error_display() {
        assert!(format!("{}", ProxyProtocolError::HeaderTooLong).contains("108 bytes"));
        assert!(format!("{}", ProxyProtocolError::Timeout).contains("timeout"));
        assert!(format!("{}", ProxyProtocolError::InvalidFormat("bad")).contains("bad"));
    }
}
