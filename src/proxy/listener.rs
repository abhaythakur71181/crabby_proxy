use super::protocol::ProxyTarget;
use crate::app_state::AppState;
use crate::proxy::protocol::ProxyProtocol;
use crate::stream::{
    create_bidirectional_tunnel, BufferedClientStream, ClientStream, TunnelStream,
};
use crate::utils;
use std::net::SocketAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{
    self, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

// Error classification
#[derive(Debug, PartialEq)]
enum ErrorType {
    Handshake,
    Connection,
    Response,
    Timeout,
    Tunnel,
}

pub async fn run_proxy_server(state: AppState, addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            return;
        }
    };

    tracing::info!("Proxy server listening on {}", addr);

    while let Ok((client_stream, client_addr)) = listener.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            handle_client(client_stream, client_addr, state).await;
        });
    }
}

// Helper function to send error responses
async fn send_error_response(
    protocol: &ProxyProtocol,
    stream: &mut ClientStream,
    error_type: ErrorType,
) -> io::Result<()> {
    match (protocol, error_type) {
        (ProxyProtocol::HTTP, ErrorType::Handshake) => {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await
        }
        (ProxyProtocol::HTTP, ErrorType::Connection) => {
            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await
        }
        (ProxyProtocol::HTTP, ErrorType::Timeout) => {
            stream
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
                .await
        }
        (ProxyProtocol::SOCKS4, _) => utils::send_socks4_response(stream, false).await,
        (ProxyProtocol::SOCKS5, _) => utils::send_socks5_response(stream, false).await,
        _ => Ok(()), // Unknown protocols don't send responses
    }
}

async fn handle_client(mut client_stream: TcpStream, client_addr: SocketAddr, state: AppState) {
    let mut protocol;
    let protocol_detection_result = detect_client_protocol(&mut client_stream).await;
    if let Err(e) = protocol_detection_result {
        tracing::error!("Protocol detection failed for {}: {}", client_addr, e);
        return;
    } else {
        protocol = protocol_detection_result.unwrap();
    }

    // If protocol is HTTPS and we have TLS support, upgrade the connection
    let stream: ClientStream = if protocol == ProxyProtocol::HTTPS {
        match &state.tls_acceptor {
            Some(tls_acceptor) => match tls_acceptor.accept(client_stream).await {
                Ok(tls_stream) => {
                    tracing::debug!("TLS handshake successful for {}", client_addr);
                    ClientStream::Tls(tls_stream)
                }
                Err(e) => {
                    tracing::error!("TLS handshake failed for {}: {}", client_addr, e);
                    return;
                }
            },
            None => {
                tracing::error!(
                    "HTTPS protocol detected but no TLS configuration available for {}",
                    client_addr
                );
                return;
            }
        }
    } else {
        ClientStream::Plain(client_stream)
    };

    // Wrap stream in buffered wrapper for TLS peek support
    let mut buffered_stream = BufferedClientStream::new(stream);

    // If credentials are required, perform protocol-specific authentication
    if state.require_creds {
        match protocol.authenticate(&mut buffered_stream, &state).await {
            Ok(true) => {
                tracing::debug!(
                    "{} authenticated successfully via {}",
                    &client_addr,
                    protocol
                );
            }
            Ok(false) => {
                // Authentication required for this protocol
                tracing::error!(
                    "Authentication required for {} via {}",
                    &client_addr,
                    protocol
                );
                return;
            }
            Err(e) => {
                tracing::error!("Auth failed for {} via {}: {}", client_addr, protocol, e);
                return;
            }
        }
    } else {
        tracing::debug!("Skipping authentication (--no-creds)");
    }

    // INFO: For HTTP/HTTPS, we need to parse the target from the buffered stream
    // to preserve any data read during authentication
    let (target, mut stream) = if matches!(protocol, ProxyProtocol::HTTP | ProxyProtocol::HTTPS) {
        match parse_target_from_buffered(&mut buffered_stream, &protocol).await {
            Ok(t) => (t, buffered_stream.into_inner()),
            Err(e) => {
                tracing::error!("Failed to parse target: {}", e);
                let _ = send_error_response(
                    &protocol,
                    &mut buffered_stream.into_inner(),
                    ErrorType::Handshake,
                )
                .await;
                return;
            }
        }
    } else {
        let mut stream = buffered_stream.into_inner();
        match parse_target_by_protocol(&mut stream, &protocol).await {
            Ok(t) => (t, stream),
            Err(e) => {
                tracing::error!("Failed to parse target: {}", e);
                let _ = send_error_response(&protocol, &mut stream, ErrorType::Handshake).await;
                return;
            }
        }
    };

    let result =
        async_handle_client_with_target(&mut stream, client_addr, &mut protocol, target).await;

    if let Err((e, error_type)) = result {
        tracing::error!(
            "Error [{}] for {}: {}",
            match error_type {
                ErrorType::Handshake => "handshake",
                ErrorType::Connection => "connection",
                ErrorType::Response => "response",
                ErrorType::Timeout => "timeout",
                ErrorType::Tunnel => "tunnel",
            },
            client_addr,
            e
        );

        if error_type != ErrorType::Tunnel {
            let _ = send_error_response(&protocol, &mut stream, error_type).await;
        }
    }
}

async fn detect_client_protocol(client_stream: &mut TcpStream) -> Result<ProxyProtocol, io::Error> {
    let mut peek_buf = [0u8; 4];

    match timeout(Duration::from_secs(5), client_stream.peek(&mut peek_buf)).await {
        Ok(Ok(_)) => Ok(detect_protocol(&peek_buf)
            .await
            .unwrap_or(ProxyProtocol::TCP)),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(ProxyProtocol::TCP),
    }
}

/// Parse target from buffered stream (for HTTP/HTTPS to preserve auth data)
async fn parse_target_from_buffered(
    stream: &mut BufferedClientStream,
    protocol: &ProxyProtocol,
) -> io::Result<ProxyTarget> {
    match protocol {
        ProxyProtocol::HTTP => {
            // Read request line and consume all headers up to \r\n\r\n
            // This is important because after CONNECT, we switch to raw TCP tunneling
            let mut request_line = Vec::new();
            let mut buf = [0u8; 1];

            // Read request line (until \r\n)
            loop {
                stream.read_exact(&mut buf).await?;
                request_line.push(buf[0]);
                if request_line.len() >= 2
                    && request_line[request_line.len() - 2..] == [b'\r', b'\n']
                {
                    break;
                }
            }

            let request_line_str = String::from_utf8(request_line).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in request line")
            })?;

            let parts: Vec<&str> = request_line_str.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid HTTP request",
                ));
            }

            let method = parts[0];
            let url = parts[1];

            // For CONNECT requests, we need to consume all headers until \r\n\r\n
            // to prepare for raw TCP tunneling. Otherwise, leftover headers will
            // be sent to the target server, breaking the connection.
            if method == "CONNECT" {
                // Read and discard headers until we hit the empty line (\r\n\r\n)
                let mut header_buf = Vec::new();
                let mut last_four = [0u8; 4];

                loop {
                    let mut byte = [0u8; 1];
                    stream.read_exact(&mut byte).await?;
                    header_buf.push(byte[0]);

                    // Update sliding window
                    if header_buf.len() >= 4 {
                        last_four.copy_from_slice(&header_buf[header_buf.len() - 4..]);
                    }

                    // Check if we've seen \r\n\r\n
                    if header_buf.len() >= 4 && last_four == [b'\r', b'\n', b'\r', b'\n'] {
                        break;
                    }
                }
                parse_connect_target(url)
            } else {
                parse_http_target(url)
            }
        }
        ProxyProtocol::HTTPS => {
            // For HTTPS, read from the buffered stream to extract SNI
            let mut buf = vec![0u8; 512];
            let n = stream.read(&mut buf).await?;
            if let Some(sni) = extract_sni_from_tls(&buf[..n]) {
                Ok(ProxyTarget {
                    host: sni,
                    port: 443,
                })
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to extract SNI from TLS handshake",
                ))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "This function only supports HTTP/HTTPS",
        )),
    }
}

async fn async_handle_client_with_target(
    client_stream: &mut ClientStream,
    client_addr: SocketAddr,
    protocol: &mut ProxyProtocol,
    target: ProxyTarget,
) -> Result<(), (io::Error, ErrorType)> {
    let target_addr = format!("{}:{}", target.host, target.port);
    let target_stream = timeout(Duration::from_secs(10), TcpStream::connect(&target_addr))
        .await
        .map_err(|_| {
            (
                io::Error::new(io::ErrorKind::TimedOut, "Connection timeout"),
                ErrorType::Timeout,
            )
        })?
        .map_err(|e| (e, ErrorType::Connection))?;

    tracing::info!(
        "[{}]: Connection established to {} by {}",
        &protocol,
        target_addr,
        client_addr
    );

    // Send success response
    match *protocol {
        ProxyProtocol::HTTP => utils::send_http_connect_response(client_stream).await,
        ProxyProtocol::SOCKS4 => utils::send_socks4_response(client_stream, true).await,
        ProxyProtocol::SOCKS5 => utils::send_socks5_response(client_stream, true).await,
        _ => Ok(()),
    }
    .map_err(|e| (e, ErrorType::Response))?;

    let client_halves = io::split(client_stream);
    let target_halves = io::split(target_stream);

    let label_c2t = format!("[{}]: C[{}]->T[{}]", protocol, client_addr, target_addr);
    let label_t2c = format!("[{}]: T[{}]->C[{}]", protocol, target_addr, client_addr);

    match create_bidirectional_tunnel(client_halves, target_halves, &label_c2t, &label_t2c).await {
        Ok((c2t, t2c)) => {
            tracing::info!(
                "[{}]: Closed tunnel {} <-> {} (sent: {}, received: {})",
                &protocol,
                client_addr,
                target_addr,
                c2t,
                t2c
            );
            Ok(())
        }
        Err(e) => {
            tracing::warn!("[{}]: Tunnel error: {}", &protocol, e);
            Err((e, ErrorType::Tunnel))
        }
    }
}

/// Relay data using TunnelStream
///
/// label is a tag for the direction, e.g., "C->T" (client to target).
async fn relay_with_tunnel_stream<R, W>(
    mut tunnel: TunnelStream<R, W>,
    label: &str,
) -> tokio::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 1024];
    let mut total = 0;

    loop {
        let n = tunnel.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        tracing::debug!("{}", label);

        tunnel.write_all(&buf[..n]).await?;
        total += n as u64;
    }

    tunnel.shutdown().await?;
    Ok(total)
}

async fn detect_protocol(peek_buf: &[u8; 4]) -> io::Result<ProxyProtocol> {
    // HTTP methods start with ASCII letters
    if peek_buf.starts_with(b"GET ")
        || peek_buf.starts_with(b"POST")
        || peek_buf.starts_with(b"PUT ")
        || peek_buf.starts_with(b"HEAD")
        || peek_buf.starts_with(b"DELE")
        || peek_buf.starts_with(b"CONN")
    {
        return Ok(ProxyProtocol::HTTP);
    }

    // HTTPS/TLS starts with 0x16 (handshake)
    if peek_buf[0] == 0x16 {
        return Ok(ProxyProtocol::HTTPS);
    }

    // SOCKS5 starts with version 0x05
    if peek_buf[0] == 0x05 {
        return Ok(ProxyProtocol::SOCKS5);
    }

    // SOCKS4 starts with version 0x04
    if peek_buf[0] == 0x04 {
        return Ok(ProxyProtocol::SOCKS4);
    }

    // Default to TCP for unknown protocols
    Ok(ProxyProtocol::TCP)
}

async fn parse_target_by_protocol(
    stream: &mut ClientStream,
    protocol: &ProxyProtocol,
) -> io::Result<ProxyTarget> {
    match protocol {
        ProxyProtocol::HTTP => parse_http_target_from_stream(stream).await,
        ProxyProtocol::HTTPS => parse_https_target_from_stream(stream).await,
        ProxyProtocol::SOCKS4 => parse_socks4_target(stream).await,
        ProxyProtocol::SOCKS5 => parse_socks5_target(stream).await,
        ProxyProtocol::TCP => parse_target(stream).await, // Your original function
    }
}

async fn parse_http_target_from_stream(stream: &mut ClientStream) -> io::Result<ProxyTarget> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid HTTP request",
        ));
    }

    let method = parts[0];
    let url = parts[1];

    if method == "CONNECT" {
        parse_connect_target(url)
    } else {
        parse_http_target(url)
    }
}

async fn parse_https_target_from_stream(stream: &mut ClientStream) -> io::Result<ProxyTarget> {
    // For HTTPS, we need to parse SNI from TLS handshake
    // This is a simplified version - you'd need full TLS parsing for production
    let mut buf = vec![0u8; 512];
    // Use peek equivalent for our stream type
    let n = match stream {
        ClientStream::Plain(stream) => stream.peek(&mut buf).await?,
        ClientStream::Tls(stream) => {
            // For TLS streams, we need to read instead of peek
            // Note: This consumes data from the stream, but SNI extraction
            // happens before we need to relay data, so it's acceptable
            stream.read(&mut buf).await?
        }
    };

    if let Some(sni) = extract_sni_from_tls(&buf[..n]) {
        Ok(ProxyTarget {
            host: sni,
            port: 443,
        })
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to extract SNI from TLS handshake",
        ))
    }
}

async fn parse_socks4_target(stream: &mut ClientStream) -> io::Result<ProxyTarget> {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).await?;

    let version = buf[0];
    let command = buf[1];
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip = Ipv4Addr::from([buf[4], buf[5], buf[6], buf[7]]);

    if version != 0x04 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SOCKS4 version",
        ));
    }

    if command != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Only CONNECT supported",
        ));
    }

    // Read user ID (null-terminated)
    let mut user_id = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        if byte[0] == 0 {
            break;
        }
        user_id.push(byte[0]);
    }

    Ok(ProxyTarget {
        host: ip.to_string(),
        port,
    })
}

async fn parse_socks5_target(stream: &mut ClientStream) -> io::Result<ProxyTarget> {
    // Authentication has already been handled in authenticate_socks5,
    // so we can directly read the connection request
    // Read connection request
    let mut req_buf = [0u8; 4];
    stream.read_exact(&mut req_buf).await?;

    let version = req_buf[0];
    let command = req_buf[1];
    let _reserved = req_buf[2];
    let addr_type = req_buf[3];

    if version != 0x05 || command != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SOCKS5 request",
        ));
    }

    let target = match addr_type {
        0x01 => {
            // IPv4
            let mut addr_buf = [0u8; 6];
            stream.read_exact(&mut addr_buf).await?;
            let ip = Ipv4Addr::from([addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]]);
            let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);
            ProxyTarget {
                host: ip.to_string(),
                port,
            }
        }
        0x03 => {
            // Domain name
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;

            let mut domain_buf = vec![0u8; len];
            stream.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid domain"))?;

            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);

            ProxyTarget { host: domain, port }
        }
        0x04 => {
            // IPv6
            let mut addr_buf = [0u8; 18];
            stream.read_exact(&mut addr_buf).await?;
            let ip_bytes: [u8; 16] = addr_buf[0..16].try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid IPv6 address length")
            })?;
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);
            ProxyTarget {
                host: ip.to_string(),
                port,
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported address type",
            ));
        }
    };

    Ok(target)
}

// Simplified SNI extraction (you'd want a proper TLS parser for production)
fn extract_sni_from_tls(data: &[u8]) -> Option<String> {
    // This is a very basic SNI extraction - in production you'd use a proper TLS library
    if data.len() < 43 || data[0] != 0x16 {
        return None;
    }

    // Look for SNI extension in TLS handshake
    // This is simplified and may not work for all cases
    for i in 0..data.len().saturating_sub(10) {
        if data[i..i + 4] == [0x00, 0x00, 0x00, 0x00] {
            // Server name extension
            if let Some(len_pos) = i.checked_add(9) {
                if len_pos < data.len() {
                    let name_len = data[len_pos] as usize;
                    if let Some(name_start) = len_pos.checked_add(1) {
                        if name_start + name_len <= data.len() {
                            if let Ok(hostname) =
                                String::from_utf8(data[name_start..name_start + name_len].to_vec())
                            {
                                return Some(hostname);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

async fn parse_target(stream: &mut ClientStream) -> io::Result<ProxyTarget> {
    // Robust parsing with timeout and error handling
    let timeout = tokio::time::Duration::from_secs(5);

    let target = tokio::time::timeout(timeout, async {
        let mut length_buf = [0u8; 2];
        match stream.read_exact(&mut length_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Client disconnected before sending length",
                ));
            }
            Err(e) => return Err(e),
        }

        let length = u16::from_be_bytes(length_buf) as usize;
        if length == 0 || length > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid target length",
            ));
        }

        let mut target_buf = vec![0u8; length];
        match stream.read_exact(&mut target_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Client disconnected while sending target data (expected {} bytes)",
                        length
                    ),
                ));
            }
            Err(e) => return Err(e),
        }

        let target_str = String::from_utf8(target_buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in target"))?;

        let parts: Vec<&str> = target_str.split(':').collect();
        if parts.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid target format (expected host:port)",
            ));
        }

        let host = parts[0].to_string();
        let port = parts[1]
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid port number"))?;

        Ok(ProxyTarget { host, port })
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Timeout reading target"))??;

    Ok(target)
}

fn parse_connect_target(url: &str) -> io::Result<ProxyTarget> {
    let parts: Vec<&str> = url.split(':').collect();
    if parts.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid CONNECT target",
        ));
    }

    let host = parts[0].to_string();
    let port = parts[1]
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid port"))?;

    Ok(ProxyTarget { host, port })
}

fn parse_http_target(url: &str) -> io::Result<ProxyTarget> {
    if url.starts_with("http://") {
        let url_without_scheme = &url[7..];
        let parts: Vec<&str> = url_without_scheme
            .split('/')
            .next()
            .unwrap()
            .split(':')
            .collect();
        let host = parts[0].to_string();
        let port = if parts.len() > 1 {
            parts[1].parse::<u16>().unwrap_or(80)
        } else {
            80
        };
        Ok(ProxyTarget { host, port })
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid HTTP URL",
        ))
    }
}
