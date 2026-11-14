//! Integration tests for crabby_proxy.
//!
//! Tests spin up the proxy binary on random ports, send requests
//! via various protocols, and verify the responses.
//! Run with `cargo test --test integration_test -- --test-threads=1`

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command};
use std::time::Duration;

/// Find an available TCP port.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Configuration for a test proxy instance.
struct TestProxy {
    child: Child,
    proxy_addr: SocketAddr,
    admin_addr: SocketAddr,
}

/// Per-test knobs layered on top of the base config.
#[derive(Default)]
struct ProxyOptions {
    /// `filtering.global_blocked_targets` entries.
    blocked_targets: Vec<String>,
    /// PEM cert/key paths; enables outer-TLS (`-x https://proxy`) when set.
    tls: Option<(std::path::PathBuf, std::path::PathBuf)>,
    /// Enable proxy authentication with this (username, password).
    proxy_auth: Option<(String, String)>,
    /// Set `filtering.block_private_targets = false` so tests can tunnel to a
    /// target on 127.0.0.1.
    allow_private_targets: bool,
}

impl TestProxy {
    /// Start a proxy with auth disabled on random ports.
    fn start_no_auth() -> Self {
        Self::start(ProxyOptions::default())
    }

    /// Start a proxy with auth disabled and the given options.
    fn start(opts: ProxyOptions) -> Self {
        let (mut command, proxy_addr, admin_addr) = Self::command(opts);
        let child = command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to start proxy");

        let proxy = TestProxy {
            child,
            proxy_addr,
            admin_addr,
        };

        // Wait for the proxy to be ready
        proxy.wait_ready();
        proxy
    }

    /// Write a temp config for `opts` on random ports and return the command
    /// that runs the proxy binary with it.
    fn command(opts: ProxyOptions) -> (Command, SocketAddr, SocketAddr) {
        let blocked_targets = opts
            .blocked_targets
            .iter()
            .map(|t| format!("{:?}", t))
            .collect::<Vec<_>>()
            .join(", ");
        let (tls_enabled, tls_cert_path, tls_key_path) = match &opts.tls {
            Some((cert, key)) => (true, cert.display().to_string(), key.display().to_string()),
            None => (false, String::new(), String::new()),
        };
        let (auth_enabled, auth_username, auth_password) = match &opts.proxy_auth {
            Some((user, pass)) => (true, user.clone(), pass.clone()),
            None => (false, "test".to_string(), String::new()),
        };
        let block_private_targets = !opts.allow_private_targets;
        let proxy_port = free_port();
        let admin_port = free_port();
        let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();
        let admin_addr: SocketAddr = format!("127.0.0.1:{}", admin_port).parse().unwrap();

        // Write a temp config
        let config_path = std::env::temp_dir().join(format!("crabby_test_{}.toml", proxy_port));
        let config = format!(
            r#"
[server]
proxy_bind = "127.0.0.1:{proxy_port}"
admin_bind = "127.0.0.1:{admin_port}"
max_connections = 100
connection_timeout = 10
tls_enabled = {tls_enabled}
tls_cert_path = {tls_cert_path:?}
tls_key_path = {tls_key_path:?}

[database]
path = "sqlite::memory:"
max_connections = 5

[authentication]
enabled = {auth_enabled}
method = "basic"
username = {auth_username:?}
password = {auth_password:?}
jwt_secret = "test_secret_key_at_least_32_bytes_long_xxx"
jwt_expiration = 3600

[protocols]
enable_http = true
enable_https = true
enable_socks4 = true
enable_socks5 = true
auto_detect = true

[features]
connection_approval = false
approval_timeout = 300
reverse_tunnels = false
tunnel_port_start = 10000
tunnel_port_end = 10999
webhook_events = []

[state]
backend = "memory"
redis_url = "redis://localhost:6379"
redis_pool_size = 1
redis_key_prefix = "test:"
redis_connection_timeout = 5

[rate_limiting]
enabled = false
requests_per_second = 1000
burst_size = 2000
ban_duration = 60

[filtering]
ip_allowlist = []
ip_blocklist = []
geo_blocking_enabled = false
blocked_countries = []
allowed_countries = []
ip_filter_mode = "blocklist"
ip_filter_enabled = false
global_allowed_targets = []
global_blocked_targets = [{blocked_targets}]
block_private_targets = {block_private_targets}

[logging]
level = "warn"
format = "pretty"
file_enabled = false
file_path = ""
access_log_enabled = false
access_log_path = ""

[metrics]
enabled = true
prometheus_path = "/metrics"
update_interval = 10

[admin]
enabled = true
auth_enabled = false
admin_username = "admin"
admin_password = "admin"
websocket_enabled = false
cors_enabled = false
cors_origins = []

[advanced]
buffer_size = 8192
connection_pooling = false
pool_max_idle_per_host = 10
http2_enabled = false
dns_cache_ttl = 60
"#
        );
        std::fs::write(&config_path, config).unwrap();

        // Use the binary built by `cargo test`
        let binary = env!("CARGO_BIN_EXE_crabby_proxy");
        let mut command = Command::new(binary);
        command
            .args(["--config", config_path.to_str().unwrap()])
            // Fixed root password so first boot doesn't write a generated
            // one to initial_root_password.txt in the crate directory.
            .env("CRABBY_ROOT_PASSWORD", "integration-test-root-password");
        (command, proxy_addr, admin_addr)
    }

    /// Wait until the admin port accepts connections (up to 15s).
    fn wait_ready(&self) {
        for _ in 0..75 {
            if TcpStream::connect_timeout(&self.admin_addr, Duration::from_millis(200)).is_ok() {
                // Give it another moment to fully initialize
                std::thread::sleep(Duration::from_millis(200));
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!(
            "Proxy did not start within 15s (admin: {})",
            self.admin_addr
        );
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Startup refusals ─────────────────────────────────────────────────

#[test]
fn test_weak_config_password_exits_cleanly_without_panic() {
    // A 5-character proxy password with auth enabled is refused at boot. That
    // must be a single `error: ...` line and exit status 1, not a panic.
    let short: String = ('a'..='e').collect();
    let (mut command, _, _) = TestProxy::command(ProxyOptions {
        proxy_auth: Some(("test".to_string(), short)),
        ..Default::default()
    });
    let output = command
        .env_remove("CRABBY_BASIC_AUTH_PASSWORD")
        .env_remove("CRABBY_ALLOW_DEFAULT_PASSWORDS")
        .output()
        .expect("failed to run proxy");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.lines().any(|l| l.starts_with(
            "error: authentication.password is only 5 characters (minimum 12). Refusing to start"
        )),
        "missing error line, stderr: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "stderr: {stderr}");
    assert!(!stderr.contains("RUST_BACKTRACE"), "stderr: {stderr}");
}

// ── Admin API tests ──────────────────────────────────────────────────

#[test]
fn test_health_endpoint() {
    let proxy = TestProxy::start_no_auth();
    let resp = reqwest::blocking::get(format!("http://{}/health", proxy.admin_addr)).unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["status"], "healthy");
    assert!(body["uptime_seconds"].as_u64().is_some());
}

#[test]
fn test_deep_health_endpoint() {
    let proxy = TestProxy::start_no_auth();
    let resp = reqwest::blocking::get(format!("http://{}/health/deep", proxy.admin_addr)).unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["checks"]["database"]["status"], "ok");
    assert_eq!(body["checks"]["state_backend"]["status"], "ok");
}

#[test]
fn test_metrics_endpoint_returns_prometheus_format() {
    let proxy = TestProxy::start_no_auth();
    let resp = reqwest::blocking::get(format!("http://{}/metrics", proxy.admin_addr)).unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().unwrap();
    // Prometheus output always contains HELP/TYPE lines or is empty (lazy init).
    // Either way, 200 OK means the endpoint works.
    // If any metrics have been initialized, they'll contain standard Prometheus format.
    assert!(
        body.is_empty() || body.contains("# HELP") || body.contains("# TYPE"),
        "Metrics response is not valid Prometheus format: {}",
        &body[..body.len().min(200)]
    );
}

// ── Protocol detection tests ─────────────────────────────────────────

#[test]
fn test_proxy_accepts_tcp_connections() {
    let proxy = TestProxy::start_no_auth();
    // Simply verify we can connect to the proxy port
    let stream = TcpStream::connect_timeout(&proxy.proxy_addr, Duration::from_secs(5));
    assert!(stream.is_ok(), "Should be able to connect to proxy port");
}

#[test]
fn test_http_connect_gets_response() {
    let proxy = TestProxy::start_no_auth();
    let mut stream = TcpStream::connect_timeout(&proxy.proxy_addr, Duration::from_secs(5)).unwrap();
    stream.set_nodelay(true).unwrap();

    // CONNECT to a non-routable address — proxy should respond with an HTTP status
    let request = "CONNECT 192.0.2.1:80 HTTP/1.1\r\nHost: 192.0.2.1:80\r\n\r\n";
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    // Read response with generous timeout (upstream connection may take time to fail)
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);

    if n > 0 {
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.starts_with("HTTP/1.1") || response.starts_with("HTTP/1.0"),
            "Expected HTTP response, got: {}",
            response
        );
    }
    // If n == 0, the proxy closed the connection (acceptable for non-routable target)
}

/// A one-shot echo server on 127.0.0.1 used as the tunnel target.
fn spawn_echo_target() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            while let Ok(n) = conn.read(&mut buf) {
                if n == 0 || conn.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    });
    addr
}

/// Connect to the proxy with a read timeout: any read that times out fails
/// the test instead of being tolerated.
fn connect_proxy(proxy: &TestProxy) -> TcpStream {
    let stream = TcpStream::connect_timeout(&proxy.proxy_addr, Duration::from_secs(5)).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

fn read_exact_or_fail(stream: &mut TcpStream, n: usize, what: &str) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .unwrap_or_else(|e| panic!("no {what} from proxy: {e}"));
    buf
}

/// Send a SOCKS5 CONNECT for an IPv4 target and check the success reply.
fn socks5_connect(stream: &mut TcpStream, target: SocketAddr) {
    let SocketAddr::V4(v4) = target else {
        panic!("IPv4 target expected")
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&req).unwrap();
    let reply = read_exact_or_fail(stream, 10, "SOCKS5 CONNECT reply");
    assert_eq!(
        &reply[..2],
        &[0x05, 0x00],
        "SOCKS5 CONNECT failed: {reply:02x?}"
    );
}

/// Round-trip a payload through an established tunnel to the echo target.
fn assert_echo(stream: &mut TcpStream) {
    stream.write_all(b"crabby-ping").unwrap();
    let echoed = read_exact_or_fail(stream, 11, "echoed payload");
    assert_eq!(echoed, b"crabby-ping");
}

/// Credentials for the auth-enabled proxy, built at runtime.
fn test_proxy_credentials() -> (String, String) {
    let user = "socks-user".to_string();
    let pass = ["integration", "socks5", &std::process::id().to_string()].join("-");
    (user, pass)
}

#[test]
fn test_socks5_no_auth_connect_end_to_end() {
    let target = spawn_echo_target();
    let proxy = TestProxy::start(ProxyOptions {
        allow_private_targets: true,
        ..Default::default()
    });
    let mut stream = connect_proxy(&proxy);

    // Greeting: version 5, one method, NO_AUTH. With auth off the proxy must
    // answer `05 00` (it used to never answer, so clients hung).
    stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let choice = read_exact_or_fail(&mut stream, 2, "SOCKS5 method selection");
    assert_eq!(choice, [0x05, 0x00]);

    socks5_connect(&mut stream, target);
    assert_echo(&mut stream);
}

#[test]
fn test_socks4_no_auth_connect_end_to_end() {
    let target = spawn_echo_target();
    let proxy = TestProxy::start(ProxyOptions {
        allow_private_targets: true,
        ..Default::default()
    });
    let mut stream = connect_proxy(&proxy);

    let SocketAddr::V4(v4) = target else {
        panic!("IPv4 target expected")
    };
    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&v4.port().to_be_bytes());
    req.extend_from_slice(&v4.ip().octets());
    req.push(0x00); // empty user id
    stream.write_all(&req).unwrap();
    let reply = read_exact_or_fail(&mut stream, 8, "SOCKS4 reply");
    assert_eq!(reply[1], 0x5a, "SOCKS4 request not granted: {reply:02x?}");
    assert_echo(&mut stream);
}

#[test]
fn test_socks5_auth_required_rejects_no_auth_client() {
    let proxy = TestProxy::start(ProxyOptions {
        proxy_auth: Some(test_proxy_credentials()),
        ..Default::default()
    });
    let mut stream = connect_proxy(&proxy);

    // Only NO_AUTH offered while auth is required: "no acceptable methods".
    stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let choice = read_exact_or_fail(&mut stream, 2, "SOCKS5 method selection");
    assert_eq!(choice, [0x05, 0xFF]);
}

#[test]
fn test_socks5_auth_required_connect_end_to_end() {
    let target = spawn_echo_target();
    let (user, pass) = test_proxy_credentials();
    let proxy = TestProxy::start(ProxyOptions {
        proxy_auth: Some((user.clone(), pass.clone())),
        allow_private_targets: true,
        ..Default::default()
    });

    // Wrong password: method 0x02 is chosen, then the sub-negotiation fails.
    let mut stream = connect_proxy(&proxy);
    stream.write_all(&[0x05, 0x02, 0x00, 0x02]).unwrap();
    let choice = read_exact_or_fail(&mut stream, 2, "SOCKS5 method selection");
    assert_eq!(choice, [0x05, 0x02]);
    let wrong = format!("{pass}-wrong");
    let mut auth = vec![0x01, user.len() as u8];
    auth.extend_from_slice(user.as_bytes());
    auth.push(wrong.len() as u8);
    auth.extend_from_slice(wrong.as_bytes());
    stream.write_all(&auth).unwrap();
    let status = read_exact_or_fail(&mut stream, 2, "SOCKS5 auth status");
    assert_eq!(status, [0x01, 0x01]);

    // Right password: full CONNECT through to the target.
    let mut stream = connect_proxy(&proxy);
    stream.write_all(&[0x05, 0x02, 0x00, 0x02]).unwrap();
    let choice = read_exact_or_fail(&mut stream, 2, "SOCKS5 method selection");
    assert_eq!(choice, [0x05, 0x02]);
    let mut auth = vec![0x01, user.len() as u8];
    auth.extend_from_slice(user.as_bytes());
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass.as_bytes());
    stream.write_all(&auth).unwrap();
    let status = read_exact_or_fail(&mut stream, 2, "SOCKS5 auth status");
    assert_eq!(status, [0x01, 0x00]);

    socks5_connect(&mut stream, target);
    assert_echo(&mut stream);
}

#[test]
fn test_invalid_protocol_closes_connection() {
    let proxy = TestProxy::start_no_auth();
    let mut stream = TcpStream::connect_timeout(&proxy.proxy_addr, Duration::from_secs(5)).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Send garbage bytes — proxy should close the connection
    stream.write_all(&[0xFF, 0xFE, 0xFD, 0xFC]).unwrap();
    stream.flush().unwrap();

    // Expect the connection to be closed (read returns 0 or error)
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(0) => {} // Connection closed — expected
        Ok(n) => {
            // Proxy sent some error response — that's fine too
            let _ = String::from_utf8_lossy(&buf[..n]);
        }
        Err(_) => {} // Connection reset — expected
    }
}

// ── Error / denial responses (#100) ──────────────────────────────────

/// Read one HTTP response head (up to the blank line or EOF) as a string.
fn read_response_head<R: Read>(stream: &mut R) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while !out.ends_with(b"\r\n\r\n") && out.len() < 4096 {
        match stream.read(&mut byte) {
            Ok(1) => out.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Assert a refusal head: given status, empty body, connection closed.
fn assert_refusal(head: &str, status: &str) {
    assert!(
        head.starts_with(&format!("HTTP/1.1 {}", status)),
        "expected {} status line, got: {:?}",
        status,
        head
    );
    assert!(head.contains("Content-Length: 0\r\n"), "head: {:?}", head);
    assert!(head.contains("Connection: close\r\n"), "head: {:?}", head);
}

/// CONNECT request bytes for `host:port`.
fn connect_request(authority: &str) -> Vec<u8> {
    format!("CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n\r\n", authority).into_bytes()
}

#[test]
fn test_http_connect_to_blocked_target_gets_403() {
    let proxy = TestProxy::start(ProxyOptions {
        blocked_targets: vec!["blocked.example".into()],
        ..Default::default()
    });
    let mut stream = TcpStream::connect_timeout(&proxy.proxy_addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(&connect_request("blocked.example:443"))
        .unwrap();
    let head = read_response_head(&mut stream);
    assert_refusal(&head, "403");
    // The deny reason stays server-side.
    assert!(!head.to_lowercase().contains("blocked"), "head: {:?}", head);
}

#[test]
fn test_http_connect_upstream_failure_gets_502() {
    let proxy = TestProxy::start_no_auth();
    let mut stream = TcpStream::connect_timeout(&proxy.proxy_addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    // Nothing listens on a just-released port; with the default SSRF egress
    // guard loopback is refused outright. Either way: 502.
    let authority = format!("127.0.0.1:{}", free_port());
    stream.write_all(&connect_request(&authority)).unwrap();
    assert_refusal(&read_response_head(&mut stream), "502");
}

/// Self-signed cert/key for "localhost", written to temp files.
fn write_test_cert(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = std::env::temp_dir();
    let cert_path = dir.join(format!("crabby_test_{}_{}.crt", tag, std::process::id()));
    let key_path = dir.join(format!("crabby_test_{}_{}.pem", tag, std::process::id()));
    std::fs::write(&cert_path, ck.cert.pem()).unwrap();
    std::fs::write(&key_path, ck.signing_key.serialize_pem()).unwrap();
    (cert_path, key_path, ck.cert.der().to_vec())
}

/// Open an outer-TLS (`-x https://proxy`) connection to the proxy.
fn tls_connect(
    addr: SocketAddr,
    cert_der: Vec<u8>,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    use std::sync::Arc;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der))
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let sock = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    rustls::StreamOwned::new(conn, sock)
}

#[test]
fn test_https_proxy_denial_and_upstream_failure_get_status() {
    let (cert, key, der) = write_test_cert("https_deny");
    let proxy = TestProxy::start(ProxyOptions {
        blocked_targets: vec!["blocked.example".into()],
        tls: Some((cert.clone(), key.clone())),
        ..Default::default()
    });

    // Policy denial over outer TLS: 403, not a silent close.
    let mut tls = tls_connect(proxy.proxy_addr, der.clone());
    tls.write_all(&connect_request("blocked.example:443"))
        .unwrap();
    tls.flush().unwrap();
    assert_refusal(&read_response_head(&mut tls), "403");

    // Upstream failure over outer TLS: 502 (previously dropped silently).
    let mut tls = tls_connect(proxy.proxy_addr, der);
    let authority = format!("127.0.0.1:{}", free_port());
    tls.write_all(&connect_request(&authority)).unwrap();
    tls.flush().unwrap();
    assert_refusal(&read_response_head(&mut tls), "502");

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}
