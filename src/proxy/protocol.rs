use crate::app_state::AppState;
use crate::db::{api_keys, users};
use crate::stream::{BufferedClientStream, ClientStream};
use base64::Engine;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProxyProtocol {
    TCP,
    HTTP,
    HTTPS,
    HTTP2,
    SOCKS4,
    SOCKS5,
}

impl ProxyProtocol {
    /// Zero-allocation label for metrics / logging.
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyProtocol::TCP => "TCP",
            ProxyProtocol::HTTP => "HTTP",
            ProxyProtocol::HTTPS => "HTTPS",
            ProxyProtocol::HTTP2 => "HTTP2",
            ProxyProtocol::SOCKS4 => "SOCKS4",
            ProxyProtocol::SOCKS5 => "SOCKS5",
        }
    }

    /// Lowercase label for protocol restriction checks.
    #[inline]
    pub fn as_str_lower(&self) -> &'static str {
        match self {
            ProxyProtocol::TCP => "tcp",
            ProxyProtocol::HTTP => "http",
            ProxyProtocol::HTTPS => "https",
            ProxyProtocol::HTTP2 => "h2",
            ProxyProtocol::SOCKS4 => "socks4",
            ProxyProtocol::SOCKS5 => "socks5",
        }
    }
}

impl std::fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

type AuthResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl ProxyProtocol {
    /// Authenticate client based on the protocol
    /// Returns (authenticated, user_id)
    pub async fn authenticate(
        &self,
        client_stream: &mut BufferedClientStream,
        state: &AppState,
    ) -> AuthResult<(bool, Option<i64>)> {
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
                Ok((false, None))
            }
        }
    }

    async fn authenticate_http_or_https(
        client_stream: &mut BufferedClientStream,
        state: &AppState,
    ) -> AuthResult<(bool, Option<i64>)> {
        let mut buffer = [0u8; 4096];
        let n = client_stream.peek(&mut buffer).await?;
        if n == 0 {
            return Err("Connection closed by client".into());
        }
        let request_data = String::from_utf8_lossy(&buffer[..n]);
        // Extract Proxy-Authorization header from HTTP request
        if let Some(auth_header) = Self::extract_proxy_auth_header(&request_data) {
            let user_id = Self::extract_user_id_from_header(auth_header, state).await;
            if user_id.is_some() {
                return Ok((true, user_id));
            }
            if Self::validate_auth_header(auth_header, state).await.is_ok() {
                return Ok((true, None));
            }
        }

        // Authentication failed - send 407 response
        let _ = Self::send_http_auth_required_response(client_stream).await;
        Err("HTTP authentication required".into())
    }

    async fn authenticate_socks4(
        _client_stream: &mut BufferedClientStream,
        _state: &AppState,
    ) -> AuthResult<(bool, Option<i64>)> {
        // SOCKS4 doesn't have proper authentication mechanism.
        Ok((true, None))
    }

    async fn authenticate_socks5(
        client_stream: &mut BufferedClientStream,
        state: &AppState,
    ) -> AuthResult<(bool, Option<i64>)> {
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

        // Check if auth is enabled in config
        let auth_enabled = {
            let config = state.config.load();
            config.authentication.enabled
        };

        if auth_enabled && supports_auth {
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

            // Validate credentials and capture user_id
            let user_id = Self::validate_credentials(&username, &password, state).await;
            if user_id.is_some() {
                client_stream.write_all(&[0x01, 0x00]).await?; // Success
                Ok((true, user_id))
            } else {
                client_stream.write_all(&[0x01, 0x01]).await?; // Failure
                Err("SOCKS5 authentication failed".into())
            }
        } else if auth_enabled {
            // Client doesn't support auth but we require it
            client_stream.write_all(&[0x05, 0xFF]).await?; // No acceptable methods
            Err("SOCKS5 authentication required but not supported by client".into())
        } else {
            // No auth required
            client_stream.write_all(&[0x05, 0x00]).await?; // No authentication
            Ok((false, None))
        }
    }

    fn extract_proxy_auth_header(request_data: &str) -> Option<&str> {
        for line in request_data.lines() {
            let lower_line = line.to_lowercase();
            if lower_line.starts_with("proxy-authorization:") {
                return line.split_once(':').map(|x| x.1).map(|v| v.trim());
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

    async fn validate_auth_header(
        auth_header: &str,
        state: &AppState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(encoded) = auth_header.strip_prefix("Basic ") {
            // Skip "Basic " bytes
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "Invalid base64 encoding")?;

            let credentials =
                String::from_utf8(decoded).map_err(|_| "Invalid UTF-8 in credentials")?;

            let mut parts = credentials.splitn(2, ':');
            let username = parts.next().ok_or("Missing username")?;
            let password = parts.next().ok_or("Missing password")?;

            if Self::validate_credentials(username, password, state)
                .await
                .is_some()
            {
                Ok(())
            } else {
                Err("Invalid credentials".into())
            }
        } else {
            Err("Unsupported authentication method".into())
        }
    }

    /// Helper to extract user_id from HTTP auth header
    async fn extract_user_id_from_header(auth_header: &str, state: &AppState) -> Option<i64> {
        if let Some(encoded) = auth_header.strip_prefix("Basic ") {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                if let Ok(credentials) = String::from_utf8(decoded) {
                    let mut parts = credentials.splitn(2, ':');
                    if let (Some(username), Some(password)) = (parts.next(), parts.next()) {
                        return Self::validate_credentials(username, password, state).await;
                    }
                }
            }
        }
        None
    }

    /// Validate credentials and return user_id.
    /// Returns Some(user_id) for DB users, Some(-1) for config-based auth, None on failure.
    async fn validate_credentials(username: &str, password: &str, state: &AppState) -> Option<i64> {
        // ── In-process auth cache (avoids DB + argon2 on repeat connections) ──
        // Key = (username, password) tuple — avoids hash collision risk.
        // 60-second TTL.  API-key auth has its own Redis-backed cache so we skip it here.
        let cache_key = (username.to_string(), password.to_string());
        if let Some(entry) = state.auth_cache.get(&cache_key) {
            let (uid, cached_at) = entry.value();
            if cached_at.elapsed() < std::time::Duration::from_secs(60) {
                return Some(*uid);
            }
        }
        // Negative cache: short-circuit known-bad credentials for 5s so a
        // burst of bad attempts hits argon2 only once.
        const NEG_TTL: std::time::Duration = std::time::Duration::from_secs(5);
        const NEG_CAP: usize = 10_000;
        if let Some(entry) = state.auth_negative_cache.get(&cache_key) {
            if entry.value().elapsed() < NEG_TTL {
                return None;
            }
            drop(entry);
            state.auth_negative_cache.remove(&cache_key);
        }

        // Check for API Key format: user@apikey
        if let Some(actual_username) = username.strip_suffix("@apikey") {
            // Redis -> DB with auto-populate via cached_user_by_username
            let user = state
                .cached_user_by_username(actual_username)
                .await
                .map(|cu| (cu.id, cu.username.clone()));

            if let Some((user_id, _)) = user {
                // Try API key verification cache
                if let Some(ref cache) = state.cache {
                    if let Some(verified) = cache.get_api_key_verified(user_id, password).await {
                        if verified {
                            state
                                .auth_cache
                                .insert(cache_key, (user_id, std::time::Instant::now()));
                            return Some(user_id);
                        } else {
                            return None;
                        }
                    }
                }
                // Cache miss: verify via DB (expensive argon2)
                let verified = api_keys::verify_api_key(&state.db_pool, user_id, password)
                    .await
                    .unwrap_or(false);
                if let Some(ref cache) = state.cache {
                    cache
                        .set_api_key_verified(user_id, password, verified)
                        .await;
                }
                if verified {
                    state
                        .auth_cache
                        .insert(cache_key, (user_id, std::time::Instant::now()));
                    return Some(user_id);
                }
            }
        } else {
            // Regular password authentication
            // auth_cache (checked above) handles repeat connections.
            // On miss, we must hit the DB for argon2 verification (password_hash
            // is intentionally excluded from CachedUser for security).
            if let Ok(Some(user)) = users::verify_password(&state.db_pool, username, password).await
            {
                state.populate_user_cache(&user).await;
                state
                    .auth_cache
                    .insert(cache_key, (user.id, std::time::Instant::now()));
                return Some(user.id);
            }
        }

        // Fallback to Config credentials if enabled
        let config_match = {
            let config = state.config.load();
            username == config.authentication.username && password == config.authentication.password
        };
        if config_match {
            // Config-based auth: use sentinel -1 to distinguish from failure (None)
            // Can be cached too
            state
                .auth_cache
                .insert(cache_key, (-1, std::time::Instant::now()));
            return Some(-1);
        }

        // Authentication failed — record in negative cache (bounded).
        if state.auth_negative_cache.len() < NEG_CAP {
            state
                .auth_negative_cache
                .insert(cache_key, std::time::Instant::now());
        }
        None
    }

    /// Public wrapper around `validate_credentials` for use by the HTTP/2 handler.
    pub async fn validate_credentials_public(
        username: &str,
        password: &str,
        state: &AppState,
    ) -> Option<i64> {
        Self::validate_credentials(username, password, state).await
    }

    /// Detect the protocol from a client stream
    pub async fn detect_from_stream(client_stream: &mut TcpStream) -> Result<Self, io::Error> {
        let mut peek_buf = [0u8; 4];
        match timeout(
            crate::constants::PEEK_TIMEOUT,
            client_stream.peek(&mut peek_buf),
        )
        .await
        {
            Ok(Ok(_)) => Ok(Self::detect_from_peek(&peek_buf).unwrap_or(ProxyProtocol::TCP)),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(ProxyProtocol::TCP),
        }
    }

    /// Detect the protocol from a peek buffer (synchronous - no I/O needed)
    pub fn detect_from_peek(peek_buf: &[u8; 4]) -> io::Result<Self> {
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

        // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        // First 4 bytes: "PRI " (0x50 0x52 0x49 0x20)
        if peek_buf.starts_with(b"PRI ") {
            return Ok(ProxyProtocol::HTTP2);
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
            ProxyProtocol::HTTP2 => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HTTP/2 targets are parsed by the h2 handler",
            )),
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
                        if header_buf.len() >= crate::constants::MAX_HTTP_HEADER_SIZE {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "HTTP headers exceed 16KB limit",
                            ));
                        }

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

        // Read user ID (null-terminated, max 255 bytes)
        const MAX_SOCKS4_USER_ID: usize = 255;
        let mut user_id = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await?;
            if byte[0] == 0 {
                break;
            }

            if user_id.len() >= MAX_SOCKS4_USER_ID {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS4 user ID exceeds 255 bytes",
                ));
            }

            user_id.push(byte[0]);
        }

        // SOCKS4a: If IP is 0.0.0.x (x != 0), the hostname follows the user ID
        let host = if ip.octets()[0] == 0
            && ip.octets()[1] == 0
            && ip.octets()[2] == 0
            && ip.octets()[3] != 0
        {
            // Read null-terminated domain name (max 255 bytes)
            const MAX_DOMAIN_LEN: usize = 255;
            let mut domain = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await?;
                if byte[0] == 0 {
                    break;
                }
                if domain.len() >= MAX_DOMAIN_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SOCKS4a domain name exceeds 255 bytes",
                    ));
                }
                domain.push(byte[0]);
            }
            String::from_utf8(domain).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid SOCKS4a domain name encoding",
                )
            })?
        } else {
            ip.to_string()
        };

        Ok(ProxyTarget { host, port })
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
        let target = timeout(crate::constants::PEEK_TIMEOUT, async {
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
        // Handle IPv6 bracket notation per RFC 7230 (e.g., [::1]:443)
        if let Some(bracket_end) = url.find(']') {
            if url.starts_with('[') {
                let host = url[1..bracket_end].to_string();
                let rest = &url[bracket_end + 1..];
                if let Some(port_str) = rest.strip_prefix(':') {
                    let port = port_str
                        .parse::<u16>()
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid port"))?;
                    return Ok(ProxyTarget { host, port });
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPv6 address missing port",
                ));
            }
        }

        // Standard host:port parsing for IPv4/domain names
        let parts: Vec<&str> = url.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid CONNECT target",
            ));
        }

        let host = parts[1].to_string();
        let port = parts[0]
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid port"))?;

        Ok(ProxyTarget { host, port })
    }

    fn parse_http_target(url: &str) -> io::Result<ProxyTarget> {
        if let Some(url_without_scheme) = url.strip_prefix("http://") {
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

    /// Extract SNI (Server Name Indication) from a TLS ClientHello message.
    /// Follows RFC 5246 (TLS 1.2) / RFC 8446 (TLS 1.3) handshake structure
    /// and RFC 6066 for the SNI extension format.
    fn extract_sni_from_tls(data: &[u8]) -> Option<String> {
        // Minimum TLS record: 5 (record header) + 4 (handshake header) + 34 (version + random)
        if data.len() < 43 || data[0] != 0x16 {
            return None; // Not a TLS handshake record
        }

        // TLS Record Header: ContentType(1) + ProtocolVersion(2) + Length(2)
        // let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

        // Handshake Header: HandshakeType(1) + Length(3)
        if data[5] != 0x01 {
            return None; // Not a ClientHello
        }
        // let handshake_length = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | (data[8] as usize);

        // ClientHello: ProtocolVersion(2) + Random(32) = starts at offset 9
        let mut pos = 9 + 2 + 32; // Skip version + random = offset 43

        // Session ID: Length(1) + Data(variable)
        if pos >= data.len() {
            return None;
        }
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher Suites: Length(2) + Data(variable)
        if pos + 2 > data.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        // Compression Methods: Length(1) + Data(variable)
        if pos >= data.len() {
            return None;
        }
        let compression_len = data[pos] as usize;
        pos += 1 + compression_len;

        // Extensions: Length(2) + Data(variable)
        if pos + 2 > data.len() {
            return None;
        }
        let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;

        // Parse extensions looking for SNI (type 0x0000)
        while pos + 4 <= extensions_end && pos + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if ext_type == 0x0000 {
                // SNI extension found
                // ServerNameList: Length(2)
                if pos + 2 > data.len() {
                    return None;
                }
                // let _list_len = u16::from_be_bytes([data[pos], data[pos + 1]]);
                pos += 2;

                // ServerName: NameType(1) + Length(2) + HostName(variable)
                if pos + 3 > data.len() {
                    return None;
                }
                let name_type = data[pos];
                let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
                pos += 3;

                if name_type == 0x00 && pos + name_len <= data.len() {
                    // host_name type
                    return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
                }
                return None;
            }

            pos += ext_len;
        }

        None
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyTarget {
    pub host: String,
    pub port: u16,
}

#[allow(dead_code)]
pub struct MultiProtocolProxy {
    listener: tokio::net::TcpListener,
}

#[allow(dead_code)]
impl MultiProtocolProxy {
    pub async fn new(bind_addr: &str) -> io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        println!("Multi-protocol proxy listening on {}", bind_addr);
        Ok(Self { listener })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === ProxyProtocol Display Tests ===

    #[test]
    fn test_protocol_display_tcp() {
        assert_eq!(ProxyProtocol::TCP.to_string(), "TCP");
    }

    #[test]
    fn test_protocol_display_http() {
        assert_eq!(ProxyProtocol::HTTP.to_string(), "HTTP");
    }

    #[test]
    fn test_protocol_display_https() {
        assert_eq!(ProxyProtocol::HTTPS.to_string(), "HTTPS");
    }

    #[test]
    fn test_protocol_display_socks4() {
        assert_eq!(ProxyProtocol::SOCKS4.to_string(), "SOCKS4");
    }

    #[test]
    fn test_protocol_display_socks5() {
        assert_eq!(ProxyProtocol::SOCKS5.to_string(), "SOCKS5");
    }

    // === ProxyProtocol Equality Tests ===

    #[test]
    fn test_protocol_equality() {
        assert_eq!(ProxyProtocol::HTTP, ProxyProtocol::HTTP);
        assert_ne!(ProxyProtocol::HTTP, ProxyProtocol::HTTPS);
        assert_ne!(ProxyProtocol::SOCKS4, ProxyProtocol::SOCKS5);
    }

    // === detect_from_peek Tests ===

    #[test]
    fn test_detect_http_get() {
        let buf = [b'G', b'E', b'T', b' '];
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::HTTP);
    }

    #[test]
    fn test_detect_http_post() {
        let buf = [b'P', b'O', b'S', b'T'];
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::HTTP);
    }

    #[test]
    fn test_detect_http_put() {
        let buf = [b'P', b'U', b'T', b' '];
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::HTTP);
    }

    #[test]
    fn test_detect_http_head() {
        let buf = [b'H', b'E', b'A', b'D'];
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::HTTP);
    }

    #[test]
    fn test_detect_http_delete() {
        let buf = [b'D', b'E', b'L', b'E'];
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::HTTP);
    }

    #[test]
    fn test_detect_http_connect() {
        let buf = [b'C', b'O', b'N', b'N'];
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::HTTP);
    }

    #[test]
    fn test_detect_https_tls_handshake() {
        let buf = [0x16, 0x03, 0x01, 0x00]; // TLS record header
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::HTTPS);
    }

    #[test]
    fn test_detect_socks5() {
        let buf = [0x05, 0x01, 0x00, 0x00]; // SOCKS5 version
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::SOCKS5);
    }

    #[test]
    fn test_detect_socks4() {
        let buf = [0x04, 0x01, 0x00, 0x50]; // SOCKS4 CONNECT to port 80
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::SOCKS4);
    }

    #[test]
    fn test_detect_unknown_defaults_to_tcp() {
        let buf = [0xFF, 0xFF, 0xFF, 0xFF];
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::TCP);
    }

    #[test]
    fn test_detect_zeros_defaults_to_tcp() {
        let buf = [0x00, 0x00, 0x00, 0x00];
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::TCP);
    }

    #[test]
    fn test_detect_binary_data_defaults_to_tcp() {
        let buf = [0xAB, 0xCD, 0xEF, 0x12];
        let protocol = ProxyProtocol::detect_from_peek(&buf).unwrap();
        assert_eq!(protocol, ProxyProtocol::TCP);
    }

    // === parse_connect_target Tests ===

    #[test]
    fn test_parse_connect_target_valid() {
        let target = ProxyProtocol::parse_connect_target("example.com:443").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn test_parse_connect_target_with_ip() {
        let target = ProxyProtocol::parse_connect_target("192.168.1.1:8080").unwrap();
        assert_eq!(target.host, "192.168.1.1");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn test_parse_connect_target_port_80() {
        let target = ProxyProtocol::parse_connect_target("example.com:80").unwrap();
        assert_eq!(target.port, 80);
    }

    #[test]
    fn test_parse_connect_target_missing_port() {
        let result = ProxyProtocol::parse_connect_target("example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_connect_target_invalid_port() {
        let result = ProxyProtocol::parse_connect_target("example.com:notaport");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_connect_target_empty_string() {
        let result = ProxyProtocol::parse_connect_target("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_connect_target_bare_ipv6() {
        // With rsplitn, bare ::1:443 parses correctly (host = ::1, port = 443)
        let target = ProxyProtocol::parse_connect_target("::1:443").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn test_parse_connect_target_bracketed_ipv6() {
        // B7: Bracketed IPv6 per RFC 7230
        let target = ProxyProtocol::parse_connect_target("[::1]:443").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn test_parse_connect_target_bracketed_ipv6_no_port() {
        let result = ProxyProtocol::parse_connect_target("[::1]");
        assert!(result.is_err());
    }

    // === parse_http_target Tests ===

    #[test]
    fn test_parse_http_target_valid_url() {
        let target = ProxyProtocol::parse_http_target("http://example.com/path").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn test_parse_http_target_with_port() {
        let target = ProxyProtocol::parse_http_target("http://example.com:8080/path").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn test_parse_http_target_no_path() {
        let target = ProxyProtocol::parse_http_target("http://example.com").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn test_parse_http_target_ip_address() {
        let target = ProxyProtocol::parse_http_target("http://10.0.0.1:3000/api").unwrap();
        assert_eq!(target.host, "10.0.0.1");
        assert_eq!(target.port, 3000);
    }

    #[test]
    fn test_parse_http_target_invalid_scheme() {
        let result = ProxyProtocol::parse_http_target("https://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_http_target_no_scheme() {
        let result = ProxyProtocol::parse_http_target("example.com");
        assert!(result.is_err());
    }

    // === extract_proxy_auth_header Tests ===

    #[test]
    fn test_extract_proxy_auth_header_present() {
        let request = "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nHost: example.com\r\n\r\n";
        let header = ProxyProtocol::extract_proxy_auth_header(request);
        assert!(header.is_some());
        assert_eq!(header.unwrap(), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_extract_proxy_auth_header_case_insensitive() {
        let request = "GET / HTTP/1.1\r\nproxy-authorization: Basic abc123\r\n\r\n";
        let header = ProxyProtocol::extract_proxy_auth_header(request);
        assert!(header.is_some());
        assert_eq!(header.unwrap(), "Basic abc123");
    }

    #[test]
    fn test_extract_proxy_auth_header_not_present() {
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let header = ProxyProtocol::extract_proxy_auth_header(request);
        assert!(header.is_none());
    }

    #[test]
    fn test_extract_proxy_auth_header_empty_request() {
        let header = ProxyProtocol::extract_proxy_auth_header("");
        assert!(header.is_none());
    }

    #[test]
    fn test_extract_proxy_auth_header_with_authorization_not_proxy() {
        // Should NOT match regular Authorization header
        let request = "GET / HTTP/1.1\r\nAuthorization: Basic abc123\r\n\r\n";
        let header = ProxyProtocol::extract_proxy_auth_header(request);
        assert!(header.is_none());
    }

    // === extract_sni_from_tls Tests ===

    #[test]
    fn test_extract_sni_too_short_data() {
        let data = vec![0x16, 0x03, 0x01]; // Too short
        let sni = ProxyProtocol::extract_sni_from_tls(&data);
        assert!(sni.is_none());
    }

    #[test]
    fn test_extract_sni_not_handshake() {
        let mut data = vec![0x17; 100]; // Application data, not handshake
        let sni = ProxyProtocol::extract_sni_from_tls(&data);
        assert!(sni.is_none());
    }

    #[test]
    fn test_extract_sni_not_client_hello() {
        let mut data = vec![0u8; 100];
        data[0] = 0x16; // Handshake
        data[5] = 0x02; // ServerHello, not ClientHello
        let sni = ProxyProtocol::extract_sni_from_tls(&data);
        assert!(sni.is_none());
    }

    #[test]
    fn test_extract_sni_valid_client_hello() {
        // Construct a minimal valid TLS ClientHello with SNI
        let hostname = b"example.com";
        let hostname_len = hostname.len();

        let mut data = Vec::new();

        // TLS Record Header
        data.push(0x16); // ContentType: Handshake
        data.push(0x03);
        data.push(0x01); // ProtocolVersion: TLS 1.0
                         // Record length placeholder (will calculate)
        let record_len_pos = data.len();
        data.push(0x00);
        data.push(0x00);

        // Handshake Header
        data.push(0x01); // HandshakeType: ClientHello
                         // Handshake length placeholder
        let hs_len_pos = data.len();
        data.push(0x00);
        data.push(0x00);
        data.push(0x00);

        // ClientHello body
        let client_hello_start = data.len();
        data.push(0x03);
        data.push(0x03); // ProtocolVersion: TLS 1.2
        data.extend_from_slice(&[0u8; 32]); // Random

        // Session ID (empty)
        data.push(0x00);

        // Cipher Suites (one cipher)
        data.push(0x00);
        data.push(0x02); // Length: 2
        data.push(0x00);
        data.push(0x2F); // TLS_RSA_WITH_AES_128_CBC_SHA

        // Compression Methods
        data.push(0x01); // Length: 1
        data.push(0x00); // null compression

        // Extensions
        // SNI Extension
        let sni_ext_data_len = 2 + 1 + 2 + hostname_len; // list_len(2) + type(1) + name_len(2) + name
        let extensions_len = 4 + sni_ext_data_len; // ext_type(2) + ext_len(2) + data

        data.push((extensions_len >> 8) as u8);
        data.push((extensions_len & 0xFF) as u8);

        // SNI extension type (0x0000)
        data.push(0x00);
        data.push(0x00);
        // SNI extension data length
        data.push((sni_ext_data_len >> 8) as u8);
        data.push((sni_ext_data_len & 0xFF) as u8);

        // Server Name List
        let name_list_len = 1 + 2 + hostname_len; // type(1) + len(2) + name
        data.push((name_list_len >> 8) as u8);
        data.push((name_list_len & 0xFF) as u8);

        // Server Name
        data.push(0x00); // NameType: host_name
        data.push((hostname_len >> 8) as u8);
        data.push((hostname_len & 0xFF) as u8);
        data.extend_from_slice(hostname);

        // Fill in lengths
        let client_hello_len = data.len() - client_hello_start;
        let record_len = data.len() - 5; // Exclude TLS record header

        data[record_len_pos] = (record_len >> 8) as u8;
        data[record_len_pos + 1] = (record_len & 0xFF) as u8;

        data[hs_len_pos] = ((client_hello_len >> 16) & 0xFF) as u8;
        data[hs_len_pos + 1] = ((client_hello_len >> 8) & 0xFF) as u8;
        data[hs_len_pos + 2] = (client_hello_len & 0xFF) as u8;

        let sni = ProxyProtocol::extract_sni_from_tls(&data);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    // === ProxyTarget Tests ===

    #[test]
    fn test_proxy_target_clone() {
        let target = ProxyTarget {
            host: "test.com".to_string(),
            port: 8080,
        };
        let cloned = target.clone();
        assert_eq!(cloned.host, "test.com");
        assert_eq!(cloned.port, 8080);
    }

    #[test]
    fn test_proxy_target_debug() {
        let target = ProxyTarget {
            host: "debug.com".to_string(),
            port: 443,
        };
        let debug = format!("{:?}", target);
        assert!(debug.contains("debug.com"));
        assert!(debug.contains("443"));
    }

    // === ProxyProtocol serialization ===

    #[test]
    fn test_protocol_serialization_roundtrip() {
        let protocols = vec![
            ProxyProtocol::TCP,
            ProxyProtocol::HTTP,
            ProxyProtocol::HTTPS,
            ProxyProtocol::SOCKS4,
            ProxyProtocol::SOCKS5,
        ];

        for proto in protocols {
            let json = serde_json::to_string(&proto).unwrap();
            let deserialized: ProxyProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(proto, deserialized);
        }
    }
}
