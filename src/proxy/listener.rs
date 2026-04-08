use super::protocol::ProxyTarget;
use crate::app_state::AppState;
use crate::proxy::protocol::ProxyProtocol;
use crate::stream::{
    create_bidirectional_tunnel, BufferedClientStream, ClientStream, TunnelStream,
};
use crate::utils;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    QuotaExceeded,
}

pub async fn run_proxy_server(state: Arc<AppState>, addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            return;
        }
    };

    let mut shutdown_rx = state.shutdown_tx.subscribe();
    let max_global_conns = {
        let config = state.config.load();
        config.server.max_connections
    };
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_global_conns));
    tracing::info!(
        "Proxy server listening on {} (max {} connections)",
        addr,
        max_global_conns
    );
    loop {
        tokio::select! {
            // Accept new connections
            Ok((mut client_stream, client_addr)) = listener.accept() => {
                let _ = client_stream.set_nodelay(true);
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!("Global connection limit reached, rejecting {}", client_addr);
                        drop(client_stream);
                        continue;
                    }
                };

                // Parse PROXY protocol header if enabled (extracts real client IP)
                let proxy_protocol_enabled = state.config.load().server.proxy_protocol_enabled;
                let real_addr = if proxy_protocol_enabled {
                    match crate::proxy_protocol::parse_proxy_protocol_v1(&mut client_stream).await {
                        Ok(Some(addr)) => {
                            tracing::debug!("PROXY protocol: real client {} (socket: {})", addr, client_addr);
                            addr
                        }
                        Ok(None) => client_addr, // PROXY UNKNOWN
                        Err(e) => {
                            tracing::warn!("PROXY protocol parse error from {}: {}", client_addr, e);
                            drop(client_stream);
                            continue;
                        }
                    }
                } else {
                    client_addr
                };

                let state = state.clone();
                tokio::spawn(async move {
                    let _permit = permit; // Hold permit until task completes
                    // Generate unique connection ID for tracking
                    let conn_id = uuid::Uuid::new_v4();
                    // Notify: New connection accepted
                    let _ = state.notify_tx.send(crate::app_state::ConnectionEvent::NewConnection(conn_id)).await;
                    // Handle the client connection (using real_addr from PROXY protocol or socket addr)
                    handle_client(client_stream, real_addr, state.clone(), conn_id).await;
                    // Directly clean up connection state (belt-and-suspenders with event system)
                    let _ = state.state.delete_connection(conn_id).await;
                    // Notify: Connection closed
                    let _ = state.notify_tx.send(crate::app_state::ConnectionEvent::ConnectionClosed(conn_id)).await;
                });
            }
            // Shutdown signal received
            _ = shutdown_rx.recv() => {
                tracing::info!("Proxy listener stopping - no longer accepting new connections");
                break;
            }
        }
    }
    tracing::info!("Proxy listener stopped");
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
        (ProxyProtocol::HTTP, ErrorType::QuotaExceeded) => stream
            .write_all(
                b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 18\r\n\r\nQuota exceeded\r\n",
            )
            .await,
        (ProxyProtocol::SOCKS4, _) => utils::send_socks4_response(stream, false).await,
        (ProxyProtocol::SOCKS5, _) => utils::send_socks5_response(stream, false).await,
        _ => Ok(()), // Unknown protocols don't send responses
    }
}

/// Main connection handler — orchestrates the validation pipeline.
///
/// Flow: Config snapshot → Phase 1 (IP validators) → Protocol detect/TLS/Auth
///     → Phase 2 (user validators) → Target parse → Phase 3 (target validators)
///     → Connection tracking → Phase 4 (quota validators) → Relay + record usage
async fn handle_client(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    state_arc: Arc<AppState>,
    conn_id: uuid::Uuid,
) {
    use super::pipeline::Verdict;
    use super::validators;
    let state: &AppState = &state_arc;
    let mut ctx = super::pipeline::ConnectionContext::new(client_addr, conn_id, state).await;
    // ── Phase 1: Pre-Connection (IP-based, no stream needed) ────────────
    for result in [
        validators::validate_ip_filter(&ctx, state).await,
        validators::validate_geo_block(&ctx, state).await,
        validators::validate_ip_rate_limit(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("{} denied: {}", client_addr, reason);
            return;
        }
    }
    // ── Processing: Protocol detection ──────────────────────────────────
    let protocol = match ProxyProtocol::detect_from_stream(&mut client_stream).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Protocol detection failed for {}: {}", client_addr, e);
            return;
        }
    };

    // HTTP/2: hand off to dedicated h2 handler (multiplexed streams)
    if protocol == ProxyProtocol::HTTP2 {
        if ctx.config.http2_enabled {
            super::http2_handler::handle_h2_connection(client_stream, client_addr, state_arc)
                .await;
        } else {
            tracing::warn!("{}: HTTP/2 detected but disabled in config", client_addr);
        }
        return;
    }
    // ── Processing: TLS upgrade (for HTTPS) ─────────────────────────────
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
                    "HTTPS detected but no TLS config available for {}",
                    client_addr
                );
                return;
            }
        }
    } else {
        ClientStream::Plain(client_stream)
    };
    let mut buffered_stream = BufferedClientStream::new(stream);
    // ── Processing: Authentication ──────────────────────────────────────
    let user_id = if ctx.config.auth_required {
        match protocol.authenticate(&mut buffered_stream, state).await {
            Ok((true, uid)) => {
                tracing::debug!("{} authenticated via {}", client_addr, protocol);
                uid
            }
            Ok((false, _)) => {
                tracing::error!("Auth required for {} via {}", client_addr, protocol);
                return;
            }
            Err(e) => {
                tracing::error!("Auth failed for {} via {}: {}", client_addr, protocol, e);
                return;
            }
        }
    } else {
        tracing::debug!("Skipping authentication (--no-creds)");
        None
    };
    // Update context with auth results
    ctx.user_id = user_id;
    ctx.protocol = Some(protocol.clone());
    if let Some(uid) = ctx.effective_uid() {
        ctx.is_admin = state
            .cached_user_by_id(uid)
            .await
            .map(|u| u.role == "root_admin" || u.role == "admin")
            .unwrap_or(false);
    }
    // ── Phase 2: Post-Auth validators ───────────────────────────────────
    for result in [
        validators::validate_protocol_restriction(&ctx, state).await,
        validators::validate_approval(&ctx, state).await,
        validators::validate_user_rate_limit(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("{} denied: {}", client_addr, reason);
            return;
        }
    }
    // ── Processing: Parse target ────────────────────────────────────────
    let (target, mut stream) = if matches!(protocol, ProxyProtocol::HTTP | ProxyProtocol::HTTPS) {
        match protocol
            .parse_target_from_buffered(&mut buffered_stream)
            .await
        {
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
        match protocol.parse_target_from_stream(&mut stream).await {
            Ok(t) => (t, stream),
            Err(e) => {
                tracing::error!("Failed to parse target: {}", e);
                let _ = send_error_response(&protocol, &mut stream, ErrorType::Handshake).await;
                return;
            }
        }
    };
    // Update context with target
    ctx.target_host = Some(target.host.clone());
    // ── Phase 3: Post-Target validators ─────────────────────────────────
    for result in [
        validators::validate_target_domain(&ctx, state).await,
        validators::validate_access_schedule(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("{} denied: {}", client_addr, reason);
            return;
        }
    }
    // ── Connection tracking + metrics ───────────────────────────────────
    let proto_label = protocol.as_str();
    let conn_info = crate::state::backend::ConnectionInfo {
        id: conn_id,
        client_addr,
        target_addr: format!("{:?}", target),
        protocol,
        state: crate::connection::ConnectionState::Active,
        user_id,
        bytes_sent: 0,
        bytes_received: 0,
        created_at: chrono::Utc::now().timestamp(),
    };
    let _ = state.state.set_connection(conn_id, conn_info).await;
    crate::metrics::CONNECTION_SETUP_DURATION
        .with_label_values(&[proto_label])
        .observe(ctx.conn_start.elapsed().as_secs_f64());
    crate::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&[proto_label])
        .inc();
    crate::metrics::REQUESTS_TOTAL
        .with_label_values(&[proto_label, "started"])
        .inc();
    // ── Phase 4: Post-Setup validators (quota + connection limit) ───────
    for result in [
        validators::validate_quota(&ctx, state).await,
        validators::validate_connection_limit(&ctx, state).await,
    ] {
        if let Verdict::Deny(reason) = result {
            tracing::warn!("{} denied: {}", client_addr, reason);
            crate::metrics::ACTIVE_CONNECTIONS
                .with_label_values(&[proto_label])
                .dec();
            let _ = send_error_response(
                ctx.protocol.as_ref().unwrap(),
                &mut stream,
                ErrorType::QuotaExceeded,
            )
            .await;
            return;
        }
    }
    // ── Relay + record usage ────────────────────────────────────────────
    let started_at = chrono::Utc::now().timestamp();
    let relay_start = std::time::Instant::now();
    let target_addr_str = format!("{}:{}", target.host, target.port);
    let mut protocol = ctx.protocol.take().unwrap();
    let result =
        async_handle_client_with_target(&mut stream, client_addr, &mut protocol, target, state)
            .await;

    crate::metrics::CONNECTION_DURATION
        .with_label_values(&[proto_label])
        .observe(relay_start.elapsed().as_secs_f64());
    crate::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&[proto_label])
        .dec();

    let ended_at = chrono::Utc::now().timestamp();
    let client_ip_str = client_addr.ip().to_string();
    match result {
        Ok((bytes_sent, bytes_received)) => {
            crate::metrics::BYTES_TRANSFERRED
                .with_label_values(&["sent"])
                .inc_by(bytes_sent);
            crate::metrics::BYTES_TRANSFERRED
                .with_label_values(&["received"])
                .inc_by(bytes_received);
            if let Some(uid) = ctx.effective_uid() {
                let _ = crate::db::usage::record_usage(
                    &state.db_pool,
                    uid,
                    &conn_id,
                    &client_ip_str,
                    &target_addr_str,
                    proto_label,
                    started_at,
                    ended_at,
                    bytes_sent as i64,
                    bytes_received as i64,
                    "success",
                )
                .await;
                state
                    .track_bandwidth(uid, bytes_sent as i64 + bytes_received as i64)
                    .await;
                state.invalidate_quota_cache(uid).await;
            }
            crate::metrics::REQUESTS_TOTAL
                .with_label_values(&[proto_label, "success"])
                .inc();
        }
        Err((e, error_type)) => {
            let error_label = match error_type {
                ErrorType::Handshake => "handshake",
                ErrorType::Connection => "connection",
                ErrorType::Response => "response",
                ErrorType::Timeout => "timeout",
                ErrorType::Tunnel => "tunnel",
                ErrorType::QuotaExceeded => "quota_exceeded",
            };
            tracing::error!("Error [{}] for {}: {}", error_label, client_addr, e);
            crate::metrics::REQUESTS_TOTAL
                .with_label_values(&[proto_label, "failed"])
                .inc();
            if let Some(uid) = ctx.effective_uid() {
                let _ = crate::db::usage::record_usage(
                    &state.db_pool,
                    uid,
                    &conn_id,
                    &client_ip_str,
                    &target_addr_str,
                    proto_label,
                    started_at,
                    ended_at,
                    0,
                    0,
                    error_label,
                )
                .await;
                state.invalidate_quota_cache(uid).await;
            }
            if error_type != ErrorType::Tunnel {
                let _ = send_error_response(&protocol, &mut stream, error_type).await;
            }
        }
    }
}

async fn async_handle_client_with_target(
    client_stream: &mut ClientStream,
    client_addr: SocketAddr,
    protocol: &mut ProxyProtocol,
    target: ProxyTarget,
    state: &AppState,
) -> Result<(u64, u64), (io::Error, ErrorType)> {
    let target_addr = format!("{}:{}", target.host, target.port);
    let upstream_start = std::time::Instant::now();

    // Resolve via DNS cache (avoids repeated DNS lookups for same host)
    let resolved_addr = timeout(
        crate::constants::DNS_RESOLVE_TIMEOUT,
        state.dns_cache.resolve(&target.host, target.port),
    )
    .await
    .map_err(|_| {
        (
            io::Error::new(io::ErrorKind::TimedOut, "DNS resolution timeout"),
            ErrorType::Timeout,
        )
    })?
    .map_err(|e| (e, ErrorType::Connection))?;

    let target_stream = if let Some(ref pool) = state.connection_pool {
        pool.get_or_connect(&target_addr, resolved_addr, Duration::from_secs(10))
            .await
            .map_err(|e| {
                state.dns_cache.invalidate(&target.host, target.port);
                (e, ErrorType::Connection)
            })?
    } else {
        // No connection pooling — direct connect
        timeout(Duration::from_secs(10), TcpStream::connect(resolved_addr))
            .await
            .map_err(|_| {
                state.dns_cache.invalidate(&target.host, target.port);
                (
                    io::Error::new(io::ErrorKind::TimedOut, "Connection timeout"),
                    ErrorType::Timeout,
                )
            })?
            .map_err(|e| {
                state.dns_cache.invalidate(&target.host, target.port);
                (e, ErrorType::Connection)
            })?
    };
    crate::metrics::UPSTREAM_CONNECT_DURATION
        .with_label_values(&[protocol.as_str()])
        .observe(upstream_start.elapsed().as_secs_f64());
    let _ = target_stream.set_nodelay(true);
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
            Ok((c2t, t2c))
        }
        Err(e) => {
            tracing::warn!("[{}]: Tunnel error: {}", &protocol, e);
            Err((e, ErrorType::Tunnel))
        }
    }
}
