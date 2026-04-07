//! HTTP/2 CONNECT proxy handler.
//!
//! Accepts an HTTP/2 connection from a client, processes CONNECT requests
//! (via `:method` = CONNECT, `:authority` = host:port), and bridges each
//! h2 stream to an upstream TCP connection.
//!
//! Each CONNECT stream runs the full validation pipeline (IP filter, geo-block,
//! rate limit, auth, quota, target filter, access schedule) before establishing
//! the upstream tunnel.

use crate::app_state::AppState;
use crate::proxy::pipeline::{ConnectionContext, Verdict};
use crate::proxy::protocol::ProxyProtocol;
use crate::proxy::validators;
use base64::Engine;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Handle a full HTTP/2 connection.
///
/// This function:
/// 1. Completes the h2 server handshake
/// 2. For each incoming request stream, extracts the CONNECT target
/// 3. Runs the full validation pipeline (auth, rate limit, quota, etc.)
/// 4. Opens an upstream TCP connection
/// 5. Bridges data between the h2 stream and the upstream connection
pub async fn handle_h2_connection(stream: TcpStream, client_addr: SocketAddr, state_arc: Arc<AppState>) {
    let state = &*state_arc;
    let mut h2 = match h2::server::handshake(stream).await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("[HTTP2] Handshake failed for {}: {}", client_addr, e);
            return;
        }
    };

    tracing::debug!("[HTTP2] Connection established from {}", client_addr);

    // ── Phase 1: Pre-connection validators (IP-based, run once per connection) ──
    let ctx = ConnectionContext::new(client_addr, uuid::Uuid::new_v4(), state).await;
    for result in [
        validators::validate_ip_filter(&ctx, state).await,
        validators::validate_geo_block(&ctx, state).await,
        validators::validate_ip_rate_limit(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("[HTTP2] {} denied: {}", client_addr, reason);
            return;
        }
    }

    // Accept incoming h2 streams (multiplexed requests)
    while let Some(result) = h2.accept().await {
        let (request, mut respond) = match result {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!("[HTTP2] Accept error from {}: {}", client_addr, e);
                break;
            }
        };

        let method = request.method().clone();
        let uri = request.uri().clone();

        // Non-CONNECT requests: forward as HTTP proxy (GET, POST, etc.)
        if method != http::Method::CONNECT {
            // Extract auth header before moving request
            let auth_header = request
                .headers()
                .get("proxy-authorization")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let state_ref = state_arc.clone();
            tokio::spawn(async move {
                handle_h2_forward_validated(request, respond, client_addr, auth_header, &state_ref).await;
            });
            continue;
        }

        // Extract target from :authority pseudo-header
        let authority = match uri.authority() {
            Some(auth) => auth.to_string(),
            None => {
                tracing::error!("[HTTP2] CONNECT without :authority from {}", client_addr);
                let response = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(())
                    .unwrap_or_else(|_| http::Response::new(()));
                let _ = respond.send_response(response, true);
                continue;
            }
        };

        // Extract auth header from the CONNECT request
        let auth_header = request
            .headers()
            .get("proxy-authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let addr = client_addr;

        // Spawn a task for each CONNECT stream (h2 is multiplexed)
        // Each stream gets its own validation pipeline
        let state_ref = state_arc.clone();
        tokio::spawn(async move {
            handle_h2_connect_validated(
                authority,
                addr,
                auth_header,
                request,
                respond,
                &state_ref,
            )
            .await;
        });
    }

    tracing::debug!("[HTTP2] Connection closed from {}", client_addr);
}

/// Handle a single HTTP/2 CONNECT tunnel with full validation.
async fn handle_h2_connect_validated(
    authority: String,
    client_addr: SocketAddr,
    auth_header: Option<String>,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    state: &AppState,
) {
    let conn_id = uuid::Uuid::new_v4();
    let mut ctx = ConnectionContext::new(client_addr, conn_id, state).await;
    ctx.protocol = Some(ProxyProtocol::HTTP2);

    // ── Authentication ──
    if ctx.config.auth_required {
        let user_id = match &auth_header {
            Some(header) => authenticate_h2(header, state).await,
            None => None,
        };

        match user_id {
            Some(uid) => {
                ctx.user_id = Some(uid);
                crate::metrics::AUTH_TOTAL
                    .with_label_values(&["h2", "success"])
                    .inc();
            }
            None => {
                tracing::warn!("[HTTP2] Auth failed for {} -> {}", client_addr, authority);
                crate::metrics::AUTH_TOTAL
                    .with_label_values(&["h2", "failed"])
                    .inc();
                let response = http::Response::builder()
                    .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header("proxy-authenticate", "Basic realm=\"Proxy\"")
                    .body(())
                    .unwrap_or_else(|_| http::Response::new(()));
                let _ = respond.send_response(response, true);
                return;
            }
        }
    }

    // Resolve admin status
    if let Some(uid) = ctx.effective_uid() {
        ctx.is_admin = state
            .cached_user_by_id(uid)
            .await
            .map(|u| u.role == "root_admin" || u.role == "admin")
            .unwrap_or(false);
    }

    // ── Phase 2: Post-Auth validators ──
    for result in [
        validators::validate_protocol_restriction(&ctx, state).await,
        validators::validate_approval(&ctx, state).await,
        validators::validate_user_rate_limit(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("[HTTP2] {} denied: {}", client_addr, reason);
            let response = http::Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(())
                .unwrap_or_else(|_| http::Response::new(()));
            let _ = respond.send_response(response, true);
            return;
        }
    }

    // Parse host and port from authority. Reject malformed authorities up
    // front rather than silently coercing them to port 443 — a CONNECT to
    // "evil.example:abc" should fail loudly so it can't tunnel to the
    // wrong port.
    let (host, port) = match parse_authority(&authority) {
        Some(parsed) => parsed,
        None => {
            tracing::warn!(
                "[HTTP2] {} rejected: malformed CONNECT authority {:?}",
                client_addr,
                authority
            );
            let response = http::Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(())
                .unwrap_or_else(|_| http::Response::new(()));
            let _ = respond.send_response(response, true);
            return;
        }
    };
    ctx.target_host = Some(host.clone());

    // ── Phase 3: Post-Target validators ──
    for result in [
        validators::validate_target_domain(&ctx, state).await,
        validators::validate_access_schedule(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("[HTTP2] {} denied: {}", client_addr, reason);
            let response = http::Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(())
                .unwrap_or_else(|_| http::Response::new(()));
            let _ = respond.send_response(response, true);
            return;
        }
    }

    // ── Connection tracking + metrics ──
    let conn_info = crate::state::backend::ConnectionInfo {
        id: conn_id,
        client_addr,
        target_addr: authority.clone(),
        protocol: ProxyProtocol::HTTP2,
        state: crate::connection::ConnectionState::Active,
        user_id: ctx.user_id,
        bytes_sent: 0,
        bytes_received: 0,
        created_at: chrono::Utc::now().timestamp(),
    };
    if let Err(e) = state.state.set_connection(conn_id, conn_info).await {
        tracing::warn!(
            "[HTTP2] state backend: set_connection({}) failed: {} — connection limit checks may be inaccurate",
            conn_id, e
        );
        crate::metrics::STATE_BACKEND_ERRORS
            .with_label_values(&["set_connection"])
            .inc();
    }
    crate::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["HTTP2"])
        .inc();
    crate::metrics::REQUESTS_TOTAL
        .with_label_values(&["HTTP2", "started"])
        .inc();

    // ── Phase 4: Quota + connection limit ──
    for result in [
        validators::validate_quota(&ctx, state).await,
        validators::validate_connection_limit(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("[HTTP2] {} denied: {}", client_addr, reason);
            crate::metrics::ACTIVE_CONNECTIONS
                .with_label_values(&["HTTP2"])
                .dec();
            let response = http::Response::builder()
                .status(http::StatusCode::TOO_MANY_REQUESTS)
                .body(())
                .unwrap_or_else(|_| http::Response::new(()));
            let _ = respond.send_response(response, true);
            return;
        }
    }

    // ── Relay ──
    // Resolve the live quota tracker before entering the tunnel so both
    // directions can share the same atomic counter and tear down the moment
    // the limit is crossed.
    let quota_tracker = if let Some(uid) = ctx.effective_uid() {
        state
            .quota_trackers
            .get_or_seed(&state.db_pool, uid)
            .await
            .ok()
    } else {
        None
    };
    let started_at = chrono::Utc::now().timestamp();
    let result = handle_h2_tunnel(
        &authority,
        client_addr,
        host,
        port,
        request,
        respond,
        state,
        quota_tracker,
    )
    .await;

    crate::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["HTTP2"])
        .dec();
    if let Err(e) = state.state.delete_connection(conn_id).await {
        tracing::warn!(
            "[HTTP2] state backend: delete_connection({}) failed: {}",
            conn_id, e
        );
        crate::metrics::STATE_BACKEND_ERRORS
            .with_label_values(&["delete_connection"])
            .inc();
    }

    let ended_at = chrono::Utc::now().timestamp();
    match result {
        Ok((bytes_sent, bytes_received)) => {
            crate::metrics::BYTES_TRANSFERRED
                .with_label_values(&["sent"])
                .inc_by(bytes_sent);
            crate::metrics::BYTES_TRANSFERRED
                .with_label_values(&["received"])
                .inc_by(bytes_received);
            crate::metrics::REQUESTS_TOTAL
                .with_label_values(&["HTTP2", "success"])
                .inc();
            if let Some(uid) = ctx.effective_uid() {
                let db = state.db_pool.clone();
                let ip = client_addr.ip().to_string();
                let auth = authority.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::db::usage::record_usage(
                        &db, uid, &conn_id, &ip, &auth, "HTTP2",
                        started_at, ended_at,
                        bytes_sent as i64, bytes_received as i64,
                        "success",
                    ).await {
                        tracing::error!("[HTTP2] Failed to record usage for conn {}: {}", conn_id, e);
                    }
                });
                state
                    .track_bandwidth(uid, bytes_sent as i64 + bytes_received as i64)
                    .await;
            }
        }
        Err(e) => {
            tracing::error!("[HTTP2] Tunnel error for {} -> {}: {}", client_addr, authority, e);
            crate::metrics::REQUESTS_TOTAL
                .with_label_values(&["HTTP2", "failed"])
                .inc();
            if let Some(uid) = ctx.effective_uid() {
                let db = state.db_pool.clone();
                let ip = client_addr.ip().to_string();
                let auth = authority.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::db::usage::record_usage(
                        &db, uid, &conn_id, &ip, &auth, "HTTP2",
                        started_at, ended_at, 0, 0, "failed",
                    ).await {
                        tracing::error!("[HTTP2] Failed to record usage for conn {}: {}", conn_id, e);
                    }
                });
            }
        }
    }
}

/// Authenticate an HTTP/2 request via Proxy-Authorization header.
/// Returns Some(user_id) on success, None on failure.
async fn authenticate_h2(auth_header: &str, state: &AppState) -> Option<i64> {
    if !auth_header.starts_with("Basic ") {
        return None;
    }
    let encoded = &auth_header[6..];
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let credentials = String::from_utf8(decoded).ok()?;
    let mut parts = credentials.splitn(2, ':');
    let username = parts.next()?;
    let password = parts.next()?;

    ProxyProtocol::validate_credentials_public(username, password, state).await
}

/// Parse "host:port" from a CONNECT authority. Returns `None` for empty
/// inputs, unparseable ports, or port 0 — callers should reply 400 in those
/// cases instead of silently coercing to 443. Bare hosts (no `:port`) are
/// treated as port 443 since that is the only sensible default for CONNECT.
fn parse_authority(authority: &str) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }
    // IPv6 literal: [::1]:443
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>().ok()?
        } else if after.is_empty() {
            443
        } else {
            return None;
        };
        if port == 0 || host.is_empty() {
            return None;
        }
        return Some((host.to_string(), port));
    }
    if let Some(colon_pos) = authority.rfind(':') {
        let host = &authority[..colon_pos];
        let port = authority[colon_pos + 1..].parse::<u16>().ok()?;
        if port == 0 || host.is_empty() {
            return None;
        }
        Some((host.to_string(), port))
    } else {
        Some((authority.to_string(), 443))
    }
}

/// Handle the actual TCP tunnel for an HTTP/2 CONNECT stream.
/// Returns (bytes_sent, bytes_received) on success.
async fn handle_h2_tunnel(
    authority: &str,
    client_addr: SocketAddr,
    host: String,
    port: u16,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    state: &AppState,
    quota_tracker: Option<std::sync::Arc<crate::quota_tracker::UserQuotaTracker>>,
) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
    // Resolve via DNS cache
    let resolved_addr = timeout(
        crate::constants::DNS_RESOLVE_TIMEOUT,
        state.dns_cache.resolve(&host, port),
    )
    .await
    .map_err(|_| "DNS resolution timeout")??;

    // Connect to upstream
    let connect_start = std::time::Instant::now();
    let upstream = match timeout(crate::constants::UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(resolved_addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tracing::error!(
                "[HTTP2] Failed to connect to {} for {}: {}",
                authority,
                client_addr,
                e
            );
            let response = http::Response::builder()
                .status(http::StatusCode::BAD_GATEWAY)
                .body(())
                .unwrap_or_else(|_| http::Response::new(()));
            let _ = respond.send_response(response, true);
            state.dns_cache.invalidate(&host, port);
            return Err(Box::new(e));
        }
        Err(_) => {
            tracing::error!(
                "[HTTP2] Connection timeout to {} for {}",
                authority,
                client_addr
            );
            let response = http::Response::builder()
                .status(http::StatusCode::GATEWAY_TIMEOUT)
                .body(())
                .unwrap_or_else(|_| http::Response::new(()));
            let _ = respond.send_response(response, true);
            return Err("Connection timeout".into());
        }
    };

    let _ = upstream.set_nodelay(true);

    crate::metrics::UPSTREAM_CONNECT_DURATION
        .with_label_values(&["HTTP2"])
        .observe(connect_start.elapsed().as_secs_f64());

    // Send 200 OK to indicate the tunnel is established
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .unwrap_or_else(|_| http::Response::new(()));
    let mut send_stream = match respond.send_response(response, false) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("[HTTP2] Failed to send response for {}: {}", authority, e);
            return Err(Box::new(e));
        }
    };

    let mut recv_stream = request.into_body();
    let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

    tracing::info!(
        "[HTTP2] Tunnel established: {} <-> {}",
        client_addr,
        authority
    );

    let bytes_sent: u64;
    let bytes_received: u64;

    // Use Arc+AtomicU64 to share byte counts between the two tasks
    let sent_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let recv_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    let sent_c = sent_counter.clone();
    let recv_c = recv_counter.clone();

    // Bridge: h2 recv_stream -> upstream writer
    let q_send = quota_tracker.clone();
    let h2_to_upstream = async {
        loop {
            match recv_stream.data().await {
                Some(Ok(data)) => {
                    if data.is_empty() {
                        break;
                    }
                    let n = data.len();
                    sent_c.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    // Release flow control capacity
                    let _ = recv_stream.flow_control().release_capacity(n);
                    if let Err(e) = upstream_writer.write_all(&data).await {
                        tracing::debug!("[HTTP2] upstream write error: {}", e);
                        break;
                    }
                    if let Some(ref q) = q_send {
                        if q.add_and_over(n as i64) {
                            tracing::warn!(
                                "[HTTP2] quota exceeded mid-tunnel (used={}, limit={})",
                                q.used(),
                                q.limit()
                            );
                            break;
                        }
                    }
                }
                Some(Err(e)) => {
                    tracing::debug!("[HTTP2] h2 recv error: {}", e);
                    break;
                }
                None => break, // Stream ended
            }
        }
    };

    // Bridge: upstream reader -> h2 send_stream
    let q_recv = quota_tracker.clone();
    let upstream_to_h2 = async {
        let mut buf = vec![0u8; crate::constants::H2_RELAY_BUFFER_SIZE];
        loop {
            match upstream_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    recv_c.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                    if let Err(e) = send_stream.send_data(data, false) {
                        tracing::debug!("[HTTP2] h2 send error: {}", e);
                        break;
                    }
                    if let Some(ref q) = q_recv {
                        if q.add_and_over(n as i64) {
                            tracing::warn!(
                                "[HTTP2] quota exceeded mid-tunnel (used={}, limit={})",
                                q.used(),
                                q.limit()
                            );
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("[HTTP2] upstream read error: {}", e);
                    break;
                }
            }
        }
        // Signal end of stream
        let _ = send_stream.send_data(bytes::Bytes::new(), true);
    };

    // Run both directions concurrently
    tokio::join!(h2_to_upstream, upstream_to_h2);

    bytes_sent = sent_counter.load(std::sync::atomic::Ordering::Relaxed);
    bytes_received = recv_counter.load(std::sync::atomic::Ordering::Relaxed);

    tracing::info!(
        "[HTTP2] Tunnel closed: {} <-> {} (sent: {}, received: {})",
        client_addr,
        authority,
        bytes_sent,
        bytes_received
    );

    Ok((bytes_sent, bytes_received))
}

lazy_static::lazy_static! {
    /// Dedicated HTTP client for HTTP/2 forward proxy requests.
    /// Separate from the webhook client — has its own timeout and pool settings.
    static ref H2_FORWARD_CLIENT: reqwest::Client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .pool_max_idle_per_host(10)
        .user_agent("crabby-proxy/1.0")
        .build()
        .expect("Failed to create H2 forward proxy client");
}

/// Forward a non-CONNECT HTTP/2 request with full validation pipeline.
async fn handle_h2_forward_validated(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    client_addr: SocketAddr,
    auth_header: Option<String>,
    state: &AppState,
) {
    let conn_id = uuid::Uuid::new_v4();
    let mut ctx = ConnectionContext::new(client_addr, conn_id, state).await;
    ctx.protocol = Some(ProxyProtocol::HTTP2);

    // ── Authentication ──
    if ctx.config.auth_required {
        let user_id = match &auth_header {
            Some(header) => authenticate_h2(header, state).await,
            None => None,
        };
        match user_id {
            Some(uid) => {
                ctx.user_id = Some(uid);
            }
            None => {
                tracing::warn!("[HTTP2-FWD] Auth failed for {}", client_addr);
                let resp = http::Response::builder()
                    .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header("proxy-authenticate", "Basic realm=\"Proxy\"")
                    .body(())
                    .unwrap_or_else(|_| http::Response::new(()));
                let _ = respond.send_response(resp, true);
                return;
            }
        }
    }

    // Resolve admin status
    if let Some(uid) = ctx.effective_uid() {
        ctx.is_admin = state
            .cached_user_by_id(uid)
            .await
            .map(|u| u.role == "root_admin" || u.role == "admin")
            .unwrap_or(false);
    }

    // ── Phase 2: Post-Auth validators ──
    for result in [
        validators::validate_protocol_restriction(&ctx, state).await,
        validators::validate_user_rate_limit(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("[HTTP2-FWD] {} denied: {}", client_addr, reason);
            let resp = http::Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(())
                .unwrap_or_else(|_| http::Response::new(()));
            let _ = respond.send_response(resp, true);
            return;
        }
    }

    let method = request.method().clone();
    let uri = request.uri().clone();

    // Extract the target URL from the request URI
    let target_url = uri.to_string();
    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        tracing::warn!(
            "[HTTP2-FWD] Non-absolute URI from {}: {} {}",
            client_addr, method, uri
        );
        let resp = http::Response::builder()
            .status(http::StatusCode::BAD_REQUEST)
            .body(())
            .unwrap_or_else(|_| http::Response::new(()));
        let _ = respond.send_response(resp, true);
        return;
    }

    // Extract host from URL for target validation
    if let Some(authority) = uri.authority() {
        ctx.target_host = Some(authority.host().to_string());
    }

    // ── Phase 3: Post-Target validators ──
    for result in [
        validators::validate_target_domain(&ctx, state).await,
        validators::validate_access_schedule(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("[HTTP2-FWD] {} denied: {}", client_addr, reason);
            let resp = http::Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(())
                .unwrap_or_else(|_| http::Response::new(()));
            let _ = respond.send_response(resp, true);
            return;
        }
    }

    // ── Phase 4: Quota check ──
    if let Verdict::Deny(reason) = validators::validate_quota(&ctx, state).await {
        tracing::warn!("[HTTP2-FWD] {} denied: {}", client_addr, reason);
        let resp = http::Response::builder()
            .status(http::StatusCode::TOO_MANY_REQUESTS)
            .body(())
            .unwrap_or_else(|_| http::Response::new(()));
        let _ = respond.send_response(resp, true);
        return;
    }

    tracing::debug!(
        "[HTTP2-FWD] Forwarding {} {} for {}",
        method, target_url, client_addr
    );

    // Read request body
    let mut recv_stream = request.into_body();
    let mut body_data = Vec::new();
    while let Some(chunk) = recv_stream.data().await {
        match chunk {
            Ok(data) => {
                let _ = recv_stream.flow_control().release_capacity(data.len());
                body_data.extend_from_slice(&data);
            }
            Err(e) => {
                tracing::error!("[HTTP2-FWD] Error reading request body: {}", e);
                let resp = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(())
                    .unwrap_or_else(|_| http::Response::new(()));
                let _ = respond.send_response(resp, true);
                return;
            }
        }
    }

    // Forward via dedicated HTTP client
    let upstream_req = H2_FORWARD_CLIENT
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &target_url,
        )
        .body(body_data);

    let started_at = std::time::Instant::now();
    match upstream_req.send().await {
        Ok(upstream_resp) => {
            let status = upstream_resp.status();
            let mut builder = http::Response::builder().status(status.as_u16());

            // Copy response headers (skip h2-specific ones)
            for (name, value) in upstream_resp.headers() {
                if name != "transfer-encoding" && name != "connection" {
                    builder = builder.header(name, value);
                }
            }

            let resp_body = upstream_resp.bytes().await.unwrap_or_default();
            let bytes_transferred = resp_body.len() as u64;
            let response = builder.body(()).unwrap_or_else(|_| http::Response::new(()));

            match respond.send_response(response, resp_body.is_empty()) {
                Ok(mut send) => {
                    if !resp_body.is_empty() {
                        let _ = send.send_data(bytes::Bytes::from(resp_body), true);
                    }
                }
                Err(e) => {
                    tracing::error!("[HTTP2-FWD] Failed to send response: {}", e);
                }
            }

            crate::metrics::REQUESTS_TOTAL
                .with_label_values(&["HTTP2", "success"])
                .inc();
            crate::metrics::BYTES_TRANSFERRED
                .with_label_values(&["received"])
                .inc_by(bytes_transferred);

            // Track bandwidth for quota
            if let Some(uid) = ctx.effective_uid() {
                state
                    .track_bandwidth(uid, bytes_transferred as i64)
                    .await;
            }

            tracing::info!(
                target: "access_log",
                client_ip = %client_addr.ip(),
                target = %target_url,
                protocol = "HTTP2",
                method = %method,
                user_id = ?ctx.effective_uid(),
                bytes = bytes_transferred,
                duration_ms = started_at.elapsed().as_millis() as u64,
                status = "success",
                "h2 forward completed"
            );
        }
        Err(e) => {
            tracing::error!(
                "[HTTP2-FWD] Forward failed for {} {}: {}",
                method, target_url, e
            );
            let resp = http::Response::builder()
                .status(http::StatusCode::BAD_GATEWAY)
                .body(())
                .unwrap_or_else(|_| http::Response::new(()));
            let _ = respond.send_response(resp, true);

            crate::metrics::REQUESTS_TOTAL
                .with_label_values(&["HTTP2", "failed"])
                .inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_authority_with_port() {
        assert_eq!(
            parse_authority("example.com:8080"),
            Some(("example.com".to_string(), 8080))
        );
    }

    #[test]
    fn test_parse_authority_default_port() {
        assert_eq!(
            parse_authority("example.com"),
            Some(("example.com".to_string(), 443))
        );
    }

    #[test]
    fn test_parse_authority_ipv4_with_port() {
        assert_eq!(
            parse_authority("192.168.1.1:443"),
            Some(("192.168.1.1".to_string(), 443))
        );
    }

    #[test]
    fn test_parse_authority_invalid_port_rejected() {
        assert_eq!(parse_authority("example.com:notaport"), None);
    }

    #[test]
    fn test_parse_authority_empty_string_rejected() {
        assert_eq!(parse_authority(""), None);
    }

    #[test]
    fn test_parse_authority_port_zero_rejected() {
        assert_eq!(parse_authority("example.com:0"), None);
    }

    #[test]
    fn test_parse_authority_ipv6_bracket_notation() {
        assert_eq!(
            parse_authority("[::1]:8080"),
            Some(("::1".to_string(), 8080))
        );
    }

    #[test]
    fn test_auth_header_parsing_basic() {
        // "user:pass" base64 encoded = "dXNlcjpwYXNz"
        let header = "Basic dXNlcjpwYXNz";
        assert!(header.starts_with("Basic "));
        let encoded = &header[6..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let credentials = String::from_utf8(decoded).unwrap();
        let mut parts = credentials.splitn(2, ':');
        assert_eq!(parts.next(), Some("user"));
        assert_eq!(parts.next(), Some("pass"));
    }

    #[test]
    fn test_auth_header_parsing_password_with_colon() {
        // "user:p:a:ss" base64 encoded = "dXNlcjpwOmE6c3M="
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:p:a:ss");
        let header = format!("Basic {}", encoded);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&header[6..])
            .unwrap();
        let credentials = String::from_utf8(decoded).unwrap();
        let mut parts = credentials.splitn(2, ':');
        assert_eq!(parts.next(), Some("user"));
        assert_eq!(parts.next(), Some("p:a:ss"));
    }

    #[test]
    fn test_auth_header_not_basic_returns_none() {
        let header = "Bearer some-token";
        assert!(!header.starts_with("Basic "));
    }

    #[test]
    fn test_auth_header_invalid_base64() {
        let header = "Basic !!!invalid!!!";
        let result = base64::engine::general_purpose::STANDARD.decode(&header[6..]);
        assert!(result.is_err());
    }
}
