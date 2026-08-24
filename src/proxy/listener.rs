use super::protocol::ProxyTarget;
use crate::app_state::AppState;
use crate::proxy::protocol::ProxyProtocol;
use crate::stream::{BufferedClientStream, ClientStream};
use crate::utils;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, AsyncWriteExt};
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
    // Shared with the HTTP/2 handler so multiplexed h2 streams are counted
    // against the same global cap (#41), not just the per-TCP-accept permit.
    let semaphore = state.global_conn_semaphore.clone();
    tracing::info!(
        "Proxy server listening on {} (max {} connections)",
        addr,
        semaphore.available_permits()
    );
    loop {
        tokio::select! {
            // Accept new connections
            Ok((mut client_stream, client_addr)) = listener.accept() => {
                let _ = client_stream.set_nodelay(true);
                utils::enable_tcp_keepalive(&client_stream);
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!("Global connection limit reached, rejecting {}", client_addr);
                        drop(client_stream);
                        continue;
                    }
                };

                // Parse PROXY protocol header only when enabled AND the immediate
                // socket peer is a trusted upstream. An untrusted peer must never
                // be able to forge its source IP (which drives IP/geo/rate
                // filters), so we leave the stream untouched and use the real
                // socket address in that case.
                let real_addr = {
                    let cfg = state.config.load();
                    let trust_header = cfg.server.proxy_protocol_enabled
                        && peer_is_trusted_proxy(
                            client_addr.ip(),
                            &cfg.server.proxy_protocol_trusted_cidrs,
                        );
                    drop(cfg);
                    if trust_header {
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
                    }
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
                    if let Err(e) = state.state.delete_connection(conn_id).await {
                        tracing::warn!(
                            "state backend: delete_connection({}) failed: {}",
                            conn_id, e
                        );
                        crate::metrics::STATE_BACKEND_ERRORS
                            .with_label_values(&["delete_connection"])
                            .inc();
                    }
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

/// True if `peer` falls within any of the configured trusted-proxy CIDRs.
/// Invalid CIDR entries are skipped (logged once at parse). Returns false on an
/// empty list, so an enabled-but-unconfigured PROXY protocol trusts nobody.
fn peer_is_trusted_proxy(peer: std::net::IpAddr, trusted_cidrs: &[String]) -> bool {
    trusted_cidrs.iter().any(|c| {
        match c.parse::<ipnet::IpNet>() {
            Ok(net) => net.contains(&peer),
            Err(_) => match c.parse::<std::net::IpAddr>() {
                // Bare IP (no prefix) — exact match.
                Ok(ip) => ip == peer,
                Err(_) => {
                    tracing::warn!("Invalid proxy_protocol_trusted_cidrs entry '{}'", c);
                    false
                }
            },
        }
    })
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
                b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 16\r\n\r\nQuota exceeded\r\n",
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
    use crate::middleware::Phase;
    let state: &AppState = &state_arc;
    let mut ctx = super::pipeline::ConnectionContext::new(client_addr, conn_id, state).await;
    // ── Phase 1: Pre-Connection (IP-based, no stream needed) ────────────
    // Note: cannot skip on is_admin here — auth hasn't happened yet.
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
    // Run PreAuth plugin middleware
    if let Verdict::Deny(reason) = state.middleware.run(Phase::PreAuth, &ctx, state).await {
        tracing::warn!("{} denied by middleware: {}", client_addr, reason);
        return;
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
            super::http2_handler::handle_h2_connection(client_stream, client_addr, state_arc).await;
        } else {
            tracing::warn!("{}: HTTP/2 detected but disabled in config", client_addr);
        }
        return;
    }
    // ── Processing: TLS upgrade (for HTTPS) ─────────────────────────────
    let stream: ClientStream = if protocol == ProxyProtocol::HTTPS {
        match &state.tls_acceptor {
            Some(tls_swap) => match tls_swap.load().accept(client_stream).await {
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
        // Bound the auth read so a slowloris client can't hold the connection
        // (and its global permit) open indefinitely.
        let auth = timeout(
            crate::constants::HANDSHAKE_TIMEOUT,
            protocol.authenticate(&mut buffered_stream, state),
        )
        .await;
        match auth {
            Ok(Ok((true, uid))) => {
                tracing::debug!("{} authenticated via {}", client_addr, protocol);
                uid
            }
            Ok(Ok((false, _))) => {
                tracing::error!("Auth required for {} via {}", client_addr, protocol);
                return;
            }
            Ok(Err(e)) => {
                tracing::error!("Auth failed for {} via {}: {}", client_addr, protocol, e);
                return;
            }
            Err(_) => {
                tracing::warn!("{}: handshake/auth timed out via {}", client_addr, protocol);
                return;
            }
        }
    } else {
        tracing::debug!("Skipping authentication (--no-creds)");
        None
    };
    // Update context with auth results
    ctx.user_id = user_id;
    ctx.protocol = Some(protocol);
    if let Some(uid) = ctx.effective_uid() {
        ctx.is_admin = state
            .cached_user_by_id(uid)
            .await
            .map(|u| u.role == "root_admin" || u.role == "admin")
            .unwrap_or(false);
    }
    // ── Phase 2: Post-Auth validators ───────────────────────────────────
    if !ctx.is_admin {
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
    }
    // Run PostAuth plugin middleware
    if let Verdict::Deny(reason) = state.middleware.run(Phase::PostAuth, &ctx, state).await {
        tracing::warn!("{} denied by middleware: {}", client_addr, reason);
        return;
    }
    // ── Processing: Parse target ────────────────────────────────────────
    let (target, mut stream) = if matches!(protocol, ProxyProtocol::HTTP | ProxyProtocol::HTTPS) {
        // Bound the CONNECT/target-header read (slowloris protection).
        match timeout(
            crate::constants::HANDSHAKE_TIMEOUT,
            protocol.parse_target_from_buffered(&mut buffered_stream),
        )
        .await
        {
            Ok(Ok(t)) => (t, buffered_stream.into_inner()),
            Ok(Err(e)) => {
                tracing::error!("Failed to parse target: {}", e);
                let _ = send_error_response(
                    &protocol,
                    &mut buffered_stream.into_inner(),
                    ErrorType::Handshake,
                )
                .await;
                return;
            }
            Err(_) => {
                tracing::warn!("{}: target-parse timed out via {}", client_addr, protocol);
                let _ = send_error_response(
                    &protocol,
                    &mut buffered_stream.into_inner(),
                    ErrorType::Timeout,
                )
                .await;
                return;
            }
        }
    } else {
        let mut stream = buffered_stream.into_inner();
        match timeout(
            crate::constants::HANDSHAKE_TIMEOUT,
            protocol.parse_target_from_stream(&mut stream),
        )
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "target parse timed out",
            ))
        }) {
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
    if !ctx.is_admin {
        for result in [
            validators::validate_target_domain(&ctx, state).await,
            validators::validate_access_schedule(&ctx, state).await,
        ] {
            if let Verdict::Deny(reason) = result {
                tracing::warn!("{} denied: {}", client_addr, reason);
                return;
            }
        }
    }
    // Run PostTarget plugin middleware
    if let Verdict::Deny(reason) = state.middleware.run(Phase::PostTarget, &ctx, state).await {
        tracing::warn!("{} denied by middleware: {}", client_addr, reason);
        return;
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
    if let Err(e) = state.state.set_connection(conn_id, conn_info).await {
        tracing::warn!(
            "state backend: set_connection({}) failed: {} — connection limit checks may be inaccurate for this conn",
            conn_id, e
        );
        crate::metrics::STATE_BACKEND_ERRORS
            .with_label_values(&["set_connection"])
            .inc();
    }
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
    if !ctx.is_admin {
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
    }
    // ── Relay + record usage ────────────────────────────────────────────
    let started_at = chrono::Utc::now().timestamp();
    let relay_start = std::time::Instant::now();
    let target_addr_str = format!("{}:{}", target.host, target.port);
    let mut protocol = ctx.protocol.take().unwrap();
    // Register a cancel handle so an admin can terminate this live connection
    // (DELETE /api/connections/:id). The relay races against it; on signal the
    // tunnel future is dropped, closing both halves.
    let cancel = std::sync::Arc::new(tokio::sync::Notify::new());
    state.conn_cancel.insert(conn_id, cancel.clone());
    let result = tokio::select! {
        biased;
        _ = cancel.notified() => {
            tracing::info!(target: "audit", %conn_id, %client_addr, "connection terminated by admin");
            Err((
                io::Error::new(io::ErrorKind::ConnectionAborted, "terminated by admin"),
                ErrorType::Connection,
            ))
        }
        r = async_handle_client_with_target(
            &mut stream,
            client_addr,
            &mut protocol,
            target,
            state,
            ctx.user_id,
            ctx.is_admin,
        ) => r,
    };
    state.conn_cancel.remove(&conn_id);

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
                state
                    .usage_writer
                    .submit(crate::usage_writer::UsageRecord {
                        user_id: uid,
                        connection_id: conn_id,
                        client_ip: client_ip_str.clone(),
                        target_host: target_addr_str.clone(),
                        protocol: proto_label.to_string(),
                        started_at,
                        ended_at,
                        bytes_sent: bytes_sent as i64,
                        bytes_received: bytes_received as i64,
                        status: crate::db::usage::ConnectionStatus::Success,
                    })
                    .await;
                // Persistence is the single source of truth for cumulative
                // usage (the live quota tracker handles in-flight enforcement).
                // The former Redis bandwidth counter was a write-only duplicate
                // and has been removed.
            }
            crate::metrics::REQUESTS_TOTAL
                .with_label_values(&[proto_label, "success"])
                .inc();

            // Structured access log
            tracing::info!(
                target: "access_log",
                client_ip = %client_addr.ip(),
                target = %target_addr_str,
                protocol = proto_label,
                user_id = ?ctx.effective_uid(),
                bytes_sent = bytes_sent,
                bytes_received = bytes_received,
                duration_ms = relay_start.elapsed().as_millis() as u64,
                status = "success",
                "connection completed"
            );
        }
        Err((e, error_type)) => {
            // Map the failure to the canonical ConnectionStatus (single source
            // of truth); the access-log label is derived from it so the two can
            // never drift.
            let status = match error_type {
                ErrorType::Handshake => crate::db::usage::ConnectionStatus::Handshake,
                ErrorType::Connection => crate::db::usage::ConnectionStatus::Connection,
                ErrorType::Response => crate::db::usage::ConnectionStatus::Response,
                ErrorType::Timeout => crate::db::usage::ConnectionStatus::Timeout,
                ErrorType::Tunnel => crate::db::usage::ConnectionStatus::Tunnel,
                ErrorType::QuotaExceeded => crate::db::usage::ConnectionStatus::QuotaExceeded,
            };
            let error_label = status.as_str();
            crate::metrics::REQUESTS_TOTAL
                .with_label_values(&[proto_label, "failed"])
                .inc();

            // Structured access log
            tracing::info!(
                target: "access_log",
                client_ip = %client_addr.ip(),
                target = %target_addr_str,
                protocol = proto_label,
                user_id = ?ctx.effective_uid(),
                duration_ms = relay_start.elapsed().as_millis() as u64,
                status = "failed",
                error_type = error_label,
                error = %e,
                "connection failed"
            );
            if let Some(uid) = ctx.effective_uid() {
                state
                    .usage_writer
                    .submit(crate::usage_writer::UsageRecord {
                        user_id: uid,
                        connection_id: conn_id,
                        client_ip: client_ip_str.clone(),
                        target_host: target_addr_str.clone(),
                        protocol: proto_label.to_string(),
                        started_at,
                        ended_at,
                        bytes_sent: 0,
                        bytes_received: 0,
                        status,
                    })
                    .await;
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
    user_id: Option<i64>,
    is_admin: bool,
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

    // SSRF egress guard: refuse internal/non-routable resolved targets unless
    // the operator has explicitly opted out. Runs on the resolved IP, so it
    // also defends against DNS rebinding past the name-based target filter.
    if state.config.load().filtering.block_private_targets
        && crate::self_loop::is_blocked_egress(resolved_addr.ip())
    {
        tracing::warn!(
            target: "audit",
            client_addr = %client_addr,
            target = %target_addr,
            resolved = %resolved_addr,
            rule = "ssrf_egress",
            "blocked connection to internal/non-routable target"
        );
        return Err((
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target resolves to a blocked internal address",
            ),
            ErrorType::Connection,
        ));
    }

    // Self-loop protection: refuse to connect back to our own listener.
    if let Some(ref guard) = state.self_loop_guard {
        if guard.is_self_loop(resolved_addr) {
            tracing::warn!(
                target: "audit",
                client_addr = %client_addr,
                target = %target_addr,
                resolved = %resolved_addr,
                rule = "self_loop",
                "blocked self-loop: target resolves to the proxy's own listener"
            );
            return Err((
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "self-loop blocked: target is the proxy's own listener",
                ),
                ErrorType::Connection,
            ));
        }
    }

    // Try the connection pool first so pool hits aren't counted in the
    // "new connect" histogram (R2-20). On a fresh connect failure we also
    // drop any other pooled idle sockets for this addr — the host is most
    // likely down (R2-15).
    let mut from_pool = false;
    let target_stream = if let Some(ref pool) = state.connection_pool {
        if let Some(s) = pool.try_get_pub(&target_addr).await {
            from_pool = true;
            s
        } else {
            pool.record_miss();
            match timeout(Duration::from_secs(10), TcpStream::connect(resolved_addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    s
                }
                Ok(Err(e)) => {
                    state.dns_cache.invalidate(&target.host, target.port);
                    pool.invalidate_addr(&target_addr);
                    return Err((e, ErrorType::Connection));
                }
                Err(_) => {
                    state.dns_cache.invalidate(&target.host, target.port);
                    pool.invalidate_addr(&target_addr);
                    return Err((
                        io::Error::new(io::ErrorKind::TimedOut, "Connection timeout"),
                        ErrorType::Timeout,
                    ));
                }
            }
        }
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
    if !from_pool {
        crate::metrics::UPSTREAM_CONNECT_DURATION
            .with_label_values(&[protocol.as_str()])
            .observe(upstream_start.elapsed().as_secs_f64());
    }
    let _ = target_stream.set_nodelay(true);
    utils::enable_tcp_keepalive(&target_stream);
    tracing::info!(
        "[{}]: Connection established to {} by {}",
        &protocol,
        target_addr,
        client_addr
    );

    // Send success response
    match *protocol {
        // HTTPS here is the outer-TLS proxy variant: the client issued an HTTP
        // CONNECT *inside* the terminated TLS session and expects the same "200"
        // acknowledgement as a plain-HTTP CONNECT before starting its
        // end-to-end TLS handshake to the target. The old `_ => Ok(())` sent
        // nothing for HTTPS, leaving such clients hanging.
        ProxyProtocol::HTTP | ProxyProtocol::HTTPS => {
            utils::send_http_connect_response(client_stream).await
        }
        ProxyProtocol::SOCKS4 => utils::send_socks4_response(client_stream, true).await,
        ProxyProtocol::SOCKS5 => utils::send_socks5_response(client_stream, true).await,
        _ => Ok(()),
    }
    .map_err(|e| (e, ErrorType::Response))?;

    let client_halves = io::split(client_stream);
    let target_halves = io::split(target_stream);

    // Tracing span carries the per-connection identity instead of two
    // per-connection format!() allocations. Direction labels are now static
    // string literals.
    let tunnel_span = tracing::debug_span!(
        "tunnel",
        protocol = protocol.as_str(),
        client = %client_addr,
        target = %target_addr,
    );
    let _tunnel_guard = tunnel_span.enter();

    // Resolve the live quota tracker for this user. The relay loop will
    // increment its atomic counter on every chunk and abort the tunnel
    // the moment the user crosses their configured limit. The tracker
    // also stashes the per-user bandwidth throttler so we don't pay for
    // a separate `bandwidth_throttlers.get_or_create` lookup per relay.
    let quota_tracker = if let Some(uid) = user_id {
        state
            .quota_trackers
            .get_or_seed(&state.db_pool, uid)
            .await
            .ok()
    } else {
        None
    };
    let throttler = match (user_id, quota_tracker.as_ref()) {
        (Some(uid), Some(tracker)) => {
            // Fast path: throttler already cached on the tracker.
            if let Some(t) = tracker.throttler_cached() {
                t
            } else {
                // Cold path: resolve once and stash on the tracker. Subsequent
                // connections in the same quota window hit the cached arm above.
                let resolved = if let Some(user) = state.cached_user_by_id(uid).await {
                    if user.bandwidth_rate_bps > 0 {
                        state
                            .bandwidth_throttlers
                            .get_or_create(uid, user.bandwidth_rate_bps as u64)
                    } else {
                        None
                    }
                } else {
                    None
                };
                tracker.throttler_or_init(|| resolved.clone())
            }
        }
        _ => None,
    };

    // Idle timeout reaps half-open tunnels whose peer vanished without FIN/RST.
    // 0 in config disables it.
    let idle_timeout = match state.config.load().server.idle_timeout_secs {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    };

    match crate::stream::create_throttled_tunnel(
        client_halves,
        target_halves,
        "c2t",
        "t2c",
        throttler,
        quota_tracker,
        !is_admin,
        idle_timeout,
    )
    .await
    {
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

#[cfg(test)]
mod tests {
    use super::peer_is_trusted_proxy;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_list_trusts_nobody() {
        assert!(!peer_is_trusted_proxy(ip("10.0.0.1"), &[]));
    }

    #[test]
    fn cidr_match() {
        let cidrs = vec!["10.0.0.0/8".to_string(), "192.168.1.5".to_string()];
        assert!(peer_is_trusted_proxy(ip("10.1.2.3"), &cidrs));
        assert!(peer_is_trusted_proxy(ip("192.168.1.5"), &cidrs)); // bare IP
        assert!(!peer_is_trusted_proxy(ip("192.168.1.6"), &cidrs));
        assert!(!peer_is_trusted_proxy(ip("8.8.8.8"), &cidrs));
    }

    #[test]
    fn invalid_entry_skipped() {
        let cidrs = vec!["not-a-cidr".to_string(), "172.16.0.0/12".to_string()];
        assert!(peer_is_trusted_proxy(ip("172.16.5.5"), &cidrs));
        assert!(!peer_is_trusted_proxy(ip("10.0.0.1"), &cidrs));
    }
}
