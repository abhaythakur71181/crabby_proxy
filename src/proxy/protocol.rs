use crate::app_state::AppState;
use crate::stream::{BufferedClientStream, ClientStream};
use base64::Engine;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProxyProtocol {
    TCP,
    HTTP,
    HTTPS,
    SOCKS4,
    SOCKS5,
}

impl std::fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ProxyProtocol::TCP => "TCP",
            ProxyProtocol::HTTP => "HTTP",
            ProxyProtocol::HTTPS => "HTTPS",
            ProxyProtocol::SOCKS4 => "SOCKS4",
            ProxyProtocol::SOCKS5 => "SOCKS5",
        };
        write!(f, "{}", s)
    }
}

type AuthResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl ProxyProtocol {
    /// Authenticate client based on the protocol
    pub async fn authenticate(
        &self,
        client_stream: &mut BufferedClientStream,
        state: &AppState,
    ) -> AuthResult<bool> {
        match self {
            ProxyProtocol::HTTP | ProxyProtocol::HTTPS => {
                Self::authenticate_http_or_https(client_stream, state).await
            }
            ProxyProtocol::SOCKS5 => Self::authenticate_socks5(client_stream, state).await,
            ProxyProtocol::SOCKS4 => Self::authenticate_socks4(client_stream, state).await,
            _ => {
                // For TCP and other protocols that don't support authentication
                // We can reject them without auth
                tracing::warn!(
                    "Protocol {} doesn't support proxy, rejecting connection",
                    self
                );
                Ok(false)
            }
        }
    }

    async fn authenticate_http_or_https(
        client_stream: &mut BufferedClientStream,
        state: &AppState,
    ) -> AuthResult<bool> {
        let mut buffer = [0u8; 4096];
        let n = client_stream.peek(&mut buffer).await?;
        if n == 0 {
            return Err("Connection closed by client".into());
        }
        let request_data = String::from_utf8_lossy(&buffer[..n]);
        // Extract Proxy-Authorization header from HTTP request
        if let Some(auth_header) = Self::extract_proxy_auth_header(&request_data) {
            if Self::validate_auth_header(auth_header, state).is_ok() {
                return Ok(true);
            }
        }

        // Authentication failed - send 407 response
        let _ = Self::send_http_auth_required_response(client_stream).await;
        Err("HTTP authentication required".into())
    }

    async fn authenticate_socks4(
        _client_stream: &mut BufferedClientStream,
        _state: &AppState,
    ) -> AuthResult<bool> {
        // SOCKS4 doesn't have proper authentication mechanism.
        Ok(true)
    }

    async fn authenticate_socks5(
        client_stream: &mut BufferedClientStream,
        state: &AppState,
    ) -> AuthResult<bool> {
        // Read SOCKS5 handshake
        let mut handshake_buf = [0u8; 2];
        client_stream.read_exact(&mut handshake_buf).await?;

        let version = handshake_buf[0];
        let num_methods = handshake_buf[1];

        if version != 0x05 {
            return Err("Invalid SOCKS version".into());
        }

        let mut methods_buf = vec![0u8; num_methods as usize];
        client_stream.read_exact(&mut methods_buf).await?;

        // Check if username/password auth is supported by client
        let supports_auth = methods_buf.contains(&0x02);

        if state.require_creds && supports_auth {
            // Tell client to use username/password auth
            client_stream.write_all(&[0x05, 0x02]).await?;

            // Read auth request
            let mut auth_buf = [0u8; 2];
            client_stream.read_exact(&mut auth_buf).await?;

            let auth_version = auth_buf[0];
            if auth_version != 0x01 {
                return Err("Unsupported SOCKS5 auth version".into());
            }

            let username_len = auth_buf[1] as usize;
            let mut username_buf = vec![0u8; username_len];
            client_stream.read_exact(&mut username_buf).await?;

            let mut pass_len_buf = [0u8; 1];
            client_stream.read_exact(&mut pass_len_buf).await?;
            let password_len = pass_len_buf[0] as usize;

            let mut password_buf = vec![0u8; password_len];
            client_stream.read_exact(&mut password_buf).await?;

            let username = String::from_utf8(username_buf)?;
            let password = String::from_utf8(password_buf)?;

            // Validate credentials
            if Self::validate_credentials(&username, &password, state) {
                client_stream.write_all(&[0x01, 0x00]).await?; // Success
                Ok(true)
            } else {
                client_stream.write_all(&[0x01, 0x01]).await?; // Failure
                Err("SOCKS5 authentication failed".into())
            }
        } else if state.require_creds {
            // Client doesn't support auth but we require it
            client_stream.write_all(&[0x05, 0xFF]).await?; // No acceptable methods
            Err("SOCKS5 authentication required but not supported by client".into())
        } else {
            // No auth required
            client_stream.write_all(&[0x05, 0x00]).await?; // No authentication
            Ok(false)
        }
    }

    fn extract_proxy_auth_header(request_data: &str) -> Option<&str> {
        for line in request_data.lines() {
            if line.to_lowercase().starts_with("proxy-authorization:") {
                return Some(line.trim_start_matches("Proxy-Authorization:").trim());
            }
        }
        None
    }

    async fn send_http_auth_required_response(
        client_stream: &mut BufferedClientStream,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                       Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\
                       Content-Length: 0\r\n\
                       Connection: close\r\n\
                       \r\n";

        client_stream.write_all(response.as_bytes()).await?;
        client_stream.flush().await?;
        Ok(())
    }

    fn validate_auth_header(
        auth_header: &str,
        state: &AppState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if auth_header.starts_with("Basic ") {
            let encoded = &auth_header[6..]; // Skip "Basic " bytes
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "Invalid base64 encoding")?;

            let credentials =
                String::from_utf8(decoded).map_err(|_| "Invalid UTF-8 in credentials")?;

            let mut parts = credentials.splitn(2, ':');
            let username = parts.next().ok_or("Missing username")?;
            let password = parts.next().ok_or("Missing password")?;

            if Self::validate_credentials(username, password, state) {
                Ok(())
            } else {
                Err("Invalid credentials".into())
            }
        } else {
            Err("Unsupported authentication method".into())
        }
    }

    fn validate_credentials(username: &str, password: &str, state: &AppState) -> bool {
        let (expected_username, expected_password) = match (&state.username, &state.password) {
            (Some(user), Some(pass)) => (user, pass),
            _ => return false,
        };
        let username_ok = bool::from(expected_username.as_bytes().eq(username.as_bytes()));
        let password_ok = bool::from(expected_password.as_bytes().eq(password.as_bytes()));
        username_ok && password_ok
    }

    /// Detect the protocol from a client stream
    pub async fn detect_from_stream(client_stream: &mut TcpStream) -> Result<Self, io::Error> {
        let mut peek_buf = [0u8; 4];
        match timeout(Duration::from_secs(5), client_stream.peek(&mut peek_buf)).await {
            Ok(Ok(_)) => Ok(Self::detect_from_peek(&peek_buf)
                .await
                .unwrap_or(ProxyProtocol::TCP)),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(ProxyProtocol::TCP),
        }
    }

    /// Detect the protocol from a peek buffer
    pub async fn detect_from_peek(peek_buf: &[u8; 4]) -> io::Result<Self> {
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

    /// Parse target from a stream based on the protocol
    pub async fn parse_target_from_stream(
        &self,
        stream: &mut ClientStream,
    ) -> io::Result<ProxyTarget> {
        match self {
            ProxyProtocol::HTTP => Self::parse_http_target_from_stream(stream).await,
            ProxyProtocol::HTTPS => Self::parse_https_target_from_stream(stream).await,
            ProxyProtocol::SOCKS4 => Self::parse_socks4_target(stream).await,
            ProxyProtocol::SOCKS5 => Self::parse_socks5_target(stream).await,
            ProxyProtocol::TCP => Self::parse_tcp_target(stream).await,
        }
    }

    /// Parse target from buffered stream (for HTTP/HTTPS to preserve auth data)
    pub async fn parse_target_from_buffered(
        &self,
        stream: &mut BufferedClientStream,
    ) -> io::Result<ProxyTarget> {
        match self {
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
                    Self::parse_connect_target(url)
                } else {
                    Self::parse_http_target(url)
                }
            }
            ProxyProtocol::HTTPS => {
                // For HTTPS, read from the buffered stream to extract SNI
                let mut buf = vec![0u8; 512];
                let n = stream.read(&mut buf).await?;
                if let Some(sni) = Self::extract_sni_from_tls(&buf[..n]) {
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
            Self::parse_connect_target(url)
        } else {
            Self::parse_http_target(url)
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

        if let Some(sni) = Self::extract_sni_from_tls(&buf[..n]) {
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

    async fn parse_tcp_target(stream: &mut ClientStream) -> io::Result<ProxyTarget> {
        // Robust parsing with timeout and error handling
        let timeout_duration = Duration::from_secs(5);

        let target = timeout(timeout_duration, async {
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

            let target_str = String::from_utf8(target_buf).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in target")
            })?;

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
            let host_and_port = url_without_scheme
                .split('/')
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP URL"))?;

            let parts: Vec<&str> = host_and_port.split(':').collect();
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
                                if let Ok(hostname) = String::from_utf8(
                                    data[name_start..name_start + name_len].to_vec(),
                                ) {
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
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyTarget {
    pub host: String,
    pub port: u16,
}

pub struct MultiProtocolProxy {
    listener: TcpListener,
}

impl MultiProtocolProxy {
    pub async fn new(bind_addr: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(bind_addr).await?;
        println!("Multi-protocol proxy listening on {}", bind_addr);
        Ok(Self { listener })
    }

    // pub async fn run(&self) -> io::Result<()> {
    //     loop {
    //         let (stream, addr) = self.listener.accept().await?;
    //         tokio::spawn(async move {
    //             if let Err(e) = handle_connection(stream, addr).await {
    //                 eprintln!("Error handling connection from {}: {}", addr, e);
    //             }
    //         });
    //     }
    // }
}
