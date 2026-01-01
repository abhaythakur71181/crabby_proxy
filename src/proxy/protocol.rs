use crate::app_state::AppState;
use crate::stream::BufferedClientStream;
use base64::Engine;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

#[derive(Debug, Clone)]
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
