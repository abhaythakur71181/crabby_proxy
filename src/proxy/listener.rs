use super::protocol::ProxyTarget;
use crate::app_state::AppState;
use crate::proxy::protocol::ProxyProtocol;
use crate::stream::{
    create_bidirectional_tunnel, BufferedClientStream, ClientStream, TunnelStream,
};
use crate::utils;
use std::net::SocketAddr;
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

pub async fn run_proxy_server(state: AppState, addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            return;
        }
    };

    let mut shutdown_rx = state.shutdown_tx.subscribe();
    tracing::info!("Proxy server listening on {}", addr);
    loop {
        tokio::select! {
            // Accept new connections
            Ok((client_stream, client_addr)) = listener.accept() => {
                let state = state.clone();
                tokio::spawn(async move {
                    // Generate unique connection ID for tracking
                    let conn_id = uuid::Uuid::new_v4();
                    // Notify: New connection accepted
                    let _ = state.notify_tx.send(crate::app_state::ConnectionEvent::NewConnection(conn_id)).await;
                    // Handle the client connection
                    handle_client(client_stream, client_addr, state.clone(), conn_id).await;
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

async fn handle_client(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    state: AppState,
    conn_id: uuid::Uuid,
) {
    // Snapshot config values once to avoid multiple read locks per connection
    let (ip_filter_enabled, rate_limiting_enabled, auth_required, socks4_enabled) = {
        let config = state.config.read().await;
        (
            config.filtering.ip_filter_enabled,
            config.rate_limiting.enabled,
            config.authentication.enabled,
            config.protocols.enable_socks4,
        )
    };

    // Check IP filter first (before any processing)
    if ip_filter_enabled {
        let ip_filter = state.ip_filter.read().await;
        if !ip_filter.is_allowed(client_addr.ip()) {
            tracing::warn!("Connection from {} blocked by IP filter", client_addr.ip());
            crate::metrics::IP_FILTER_ACTIONS
                .with_label_values(&["blocked"])
                .inc();
            return; // Drop connection silently
        }
        crate::metrics::IP_FILTER_ACTIONS
            .with_label_values(&["allowed"])
            .inc();
    }

    // Check IP rate limiting
    if rate_limiting_enabled {
        if !state.ip_rate_limiter.check_ip(client_addr.ip()).await {
            tracing::warn!("Rate limit exceeded for {}", client_addr.ip());
            crate::metrics::RATE_LIMIT_EXCEEDED
                .with_label_values(&["ip"])
                .inc();
            return; // Drop connection
        }
    }

    let mut protocol;
    let protocol_detection_result = ProxyProtocol::detect_from_stream(&mut client_stream).await;
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
    let user_id = if auth_required {
        match protocol.authenticate(&mut buffered_stream, &state).await {
            Ok((true, uid)) => {
                tracing::debug!(
                    "{} authenticated successfully via {}",
                    &client_addr,
                    protocol
                );
                uid
            }
            Ok((false, _)) => {
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
        None // No auth required
    };

    // Check SOCKS4 protocol restrictions (config-based with admin bypass)
    if protocol == ProxyProtocol::SOCKS4 && !socks4_enabled {
        // Check if user is admin (admins bypass SOCKS4 restriction)
        let is_admin = if let Some(uid) = user_id {
            match crate::db::users::get_user_by_id(&state.db_pool, uid).await {
                Ok(Some(user)) => user.role == "root_admin" || user.role == "admin",
                _ => false,
            }
        } else {
            false
        };
        if is_admin {
            tracing::debug!("SOCKS4 allowed for admin user {:?}", user_id);
        } else {
            tracing::warn!(
                "SOCKS4 connection from {} rejected (protocol disabled for non-admin users)",
                client_addr
            );
            crate::metrics::AUTH_FAILURES
                .with_label_values(&["socks4_disabled"])
                .inc();
            return;
        }
    }

    // INFO: For HTTP/HTTPS, we need to parse the target from the buffered stream
    // to preserve any data read during authentication
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
    // INFO: for tracking
    let conn_info = crate::state::backend::ConnectionInfo {
        id: conn_id,
        client_addr,
        target_addr: format!("{:?}", target),
        protocol: protocol.clone(),
        state: crate::connection::ConnectionState::Active,
        user_id,
        bytes_sent: 0,
        bytes_received: 0,
        created_at: chrono::Utc::now().timestamp(),
    };
    let _ = state.state.set_connection(conn_id, conn_info).await;

    // Increment active connections metric
    crate::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&[&protocol.to_string()])
        .inc();
    crate::metrics::REQUESTS_TOTAL
        .with_label_values(&[&protocol.to_string(), "started"])
        .inc();

    // Check quota if user is authenticated (skip for config-based auth sentinel -1)
    if let Some(uid) = user_id {
        if uid > 0 {
            // Check cached quota result first (30s TTL avoids SUM() per connection)
            let quota_allowed = if let Some(entry) = state.quota_cache.get(&uid) {
                let (allowed, cached_at) = entry.value();
                if cached_at.elapsed() < std::time::Duration::from_secs(30) {
                    Some(*allowed)
                } else {
                    None // Cache expired
                }
            } else {
                None // Cache miss
            };

            let has_quota = match quota_allowed {
                Some(allowed) => allowed,
                None => {
                    // Cache miss or expired: query DB and cache result
                    match crate::db::quota::check_quota(&state.db_pool, uid).await {
                        Ok(allowed) => {
                            state
                                .quota_cache
                                .insert(uid, (allowed, std::time::Instant::now()));
                            allowed
                        }
                        Err(e) => {
                            tracing::error!("Error checking quota for user {}: {}", uid, e);
                            crate::metrics::ACTIVE_CONNECTIONS
                                .with_label_values(&[&protocol.to_string()])
                                .dec();
                            let _ =
                                send_error_response(&protocol, &mut stream, ErrorType::Connection)
                                    .await;
                            return; // Fail-closed: reject on DB error
                        }
                    }
                }
            };

            if !has_quota {
                tracing::warn!("Quota exceeded for user {}", uid);
                crate::metrics::ACTIVE_CONNECTIONS
                    .with_label_values(&[&protocol.to_string()])
                    .dec();
                let _ = send_error_response(&protocol, &mut stream, ErrorType::QuotaExceeded).await;
                return;
            }

            // Enforce per-user concurrent connection limit
            match state.state.count_user_connections(uid).await {
                Ok(active_count) => {
                    // Try cache first (populated by auth middleware, 60s TTL)
                    let max_connections = match state
                        .user_rate_limiter
                        .get_cached_max_connections(uid)
                        .await
                    {
                        Some(mc) => mc as usize,
                        None => {
                            // Cache miss: fetch from DB and cache for next time
                            match crate::db::users::get_user_by_id(&state.db_pool, uid).await {
                                Ok(Some(user)) => {
                                    state
                                        .user_rate_limiter
                                        .cache_config(
                                            uid,
                                            user.rate_limit_rps as u32,
                                            user.rate_limit_burst as u32,
                                            user.rate_limit_enabled,
                                            user.max_connections,
                                        )
                                        .await;
                                    user.max_connections as usize
                                }
                                _ => 5,
                            }
                        }
                    };
                    if active_count >= max_connections {
                        tracing::warn!(
                            "User {} has {} active connections (max {}), rejecting",
                            uid,
                            active_count,
                            max_connections
                        );
                        crate::metrics::ACTIVE_CONNECTIONS
                            .with_label_values(&[&protocol.to_string()])
                            .dec();
                        let _ =
                            send_error_response(&protocol, &mut stream, ErrorType::QuotaExceeded)
                                .await;
                        return;
                    }
                }
                Err(e) => {
                    tracing::error!("Error counting user connections for {}: {}", uid, e);
                    // Non-fatal: allow connection if counting fails
                }
            }
        }
    }

    let started_at = chrono::Utc::now().timestamp();
    let target_addr_str = format!("{}:{}", target.host, target.port);
    let result =
        async_handle_client_with_target(&mut stream, client_addr, &mut protocol, target).await;

    // Decrement active connections metric when done
    crate::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&[&protocol.to_string()])
        .dec();

    let ended_at = chrono::Utc::now().timestamp();
    match result {
        Ok((bytes_sent, bytes_received)) => {
            // Record bytes transferred metrics
            crate::metrics::BYTES_TRANSFERRED
                .with_label_values(&["sent"])
                .inc_by(bytes_sent);
            crate::metrics::BYTES_TRANSFERRED
                .with_label_values(&["received"])
                .inc_by(bytes_received);
            // Record usage in DB for authenticated users (skip config auth sentinel -1)
            if let Some(uid) = user_id {
                if uid > 0 {
                    let _ = crate::db::usage::record_usage(
                        &state.db_pool,
                        uid,
                        &conn_id.to_string(),
                        &client_addr.ip().to_string(),
                        &target_addr_str,
                        &protocol.to_string(),
                        started_at,
                        ended_at,
                        bytes_sent as i64,
                        bytes_received as i64,
                        "success",
                    )
                    .await;
                    // Invalidate quota cache so next connection gets fresh check
                    state.quota_cache.remove(&uid);
                }
            }
            // Record successful request
            crate::metrics::REQUESTS_TOTAL
                .with_label_values(&[&protocol.to_string(), "success"])
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
                .with_label_values(&[&protocol.to_string(), "failed"])
                .inc();
            // Record failed connection usage for authenticated users
            if let Some(uid) = user_id {
                if uid > 0 {
                    let _ = crate::db::usage::record_usage(
                        &state.db_pool,
                        uid,
                        &conn_id.to_string(),
                        &client_addr.ip().to_string(),
                        &target_addr_str,
                        &protocol.to_string(),
                        started_at,
                        ended_at,
                        0,
                        0,
                        error_label,
                    )
                    .await;
                    // Invalidate quota cache so next connection gets fresh check
                    state.quota_cache.remove(&uid);
                }
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
) -> Result<(u64, u64), (io::Error, ErrorType)> {
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
            Ok((c2t, t2c))
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
