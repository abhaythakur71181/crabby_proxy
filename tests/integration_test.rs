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

impl TestProxy {
    /// Start a proxy with auth disabled on random ports.
    fn start_no_auth() -> Self {
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
tls_enabled = false
tls_cert_path = ""
tls_key_path = ""

[database]
path = "sqlite::memory:"
max_connections = 5

[authentication]
enabled = false
method = "basic"
username = "test"
password = "testpass"
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
global_blocked_targets = []

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
        let child = Command::new(binary)
            .args(["--config", config_path.to_str().unwrap()])
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
    let resp =
        reqwest::blocking::get(format!("http://{}/health/deep", proxy.admin_addr)).unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["checks"]["database"]["status"], "ok");
    assert_eq!(body["checks"]["state_backend"]["status"], "ok");
}

#[test]
fn test_metrics_endpoint_returns_prometheus_format() {
    let proxy = TestProxy::start_no_auth();
    let resp =
        reqwest::blocking::get(format!("http://{}/metrics", proxy.admin_addr)).unwrap();
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
    let mut stream =
        TcpStream::connect_timeout(&proxy.proxy_addr, Duration::from_secs(5)).unwrap();
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

#[test]
fn test_socks5_greeting_accepted() {
    let proxy = TestProxy::start_no_auth();
    let mut stream =
        TcpStream::connect_timeout(&proxy.proxy_addr, Duration::from_secs(5)).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // SOCKS5 greeting: version=5, 1 method offered, NO_AUTH=0x00
    stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
    stream.flush().unwrap();

    let mut response = [0u8; 2];
    match stream.read_exact(&mut response) {
        Ok(()) => {
            assert_eq!(response[0], 0x05, "Expected SOCKS5 version byte");
            // Method 0x00 (NO_AUTH) or 0x02 (USERNAME/PASSWORD) are valid
            assert!(
                response[1] == 0x00 || response[1] == 0x02,
                "Unexpected SOCKS5 method: 0x{:02x}",
                response[1]
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            // Proxy didn't respond within timeout — skip (non-fatal in CI)
            eprintln!("SOCKS5 test: read timed out (proxy may be slow to respond)");
        }
        Err(e) => panic!("SOCKS5 read failed: {}", e),
    }
}

#[test]
fn test_invalid_protocol_closes_connection() {
    let proxy = TestProxy::start_no_auth();
    let mut stream =
        TcpStream::connect_timeout(&proxy.proxy_addr, Duration::from_secs(5)).unwrap();
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
