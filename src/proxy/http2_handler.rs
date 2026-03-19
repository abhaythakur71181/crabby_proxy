//! HTTP/2 CONNECT proxy handler.
//!
//! Accepts an HTTP/2 connection from a client, processes CONNECT requests
//! (via `:method` = CONNECT, `:authority` = host:port), and bridges each
//! h2 stream to an upstream TCP connection.

use crate::app_state::AppState;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Handle a full HTTP/2 connection.
///
/// This function:
/// 1. Completes the h2 server handshake
/// 2. For each incoming request stream, extracts the CONNECT target
/// 3. Opens an upstream TCP connection
/// 4. Bridges data between the h2 stream and the upstream connection
pub async fn handle_h2_connection(stream: TcpStream, client_addr: SocketAddr, state: &AppState) {
    let mut h2 = match h2::server::handshake(stream).await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("[HTTP2] Handshake failed for {}: {}", client_addr, e);
            return;
        }
    };

    tracing::debug!("[HTTP2] Connection established from {}", client_addr);

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

        // Only support CONNECT for proxying
        if method != http::Method::CONNECT {
            tracing::warn!(
                "[HTTP2] Non-CONNECT method {} from {} (uri: {})",
                method,
                client_addr,
                uri
            );
            let response = http::Response::builder()
                .status(http::StatusCode::METHOD_NOT_ALLOWED)
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true);
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
                    .unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
        };

        let _state_ref = state;
        let addr = client_addr;

        // Spawn a task for each CONNECT stream (h2 is multiplexed)
        tokio::spawn(async move {
            handle_h2_connect(authority, addr, request, respond).await;
        });
    }

    tracing::debug!("[HTTP2] Connection closed from {}", client_addr);
}

/// Handle a single HTTP/2 CONNECT tunnel.
async fn handle_h2_connect(
    authority: String,
    client_addr: SocketAddr,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
) {
    // Connect to upstream
    let upstream = match timeout(Duration::from_secs(10), TcpStream::connect(&authority)).await {
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
                .unwrap();
            let _ = respond.send_response(response, true);
            return;
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
                .unwrap();
            let _ = respond.send_response(response, true);
            return;
        }
    };

    let _ = upstream.set_nodelay(true);

    // Send 200 OK to indicate the tunnel is established
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .unwrap();
    let mut send_stream = match respond.send_response(response, false) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("[HTTP2] Failed to send response for {}: {}", authority, e);
            return;
        }
    };

    let mut recv_stream = request.into_body();
    let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

    tracing::info!(
        "[HTTP2] Tunnel established: {} <-> {}",
        client_addr,
        authority
    );

    // Bridge: h2 recv_stream -> upstream writer
    let h2_to_upstream = async {
        loop {
            match recv_stream.data().await {
                Some(Ok(data)) => {
                    if data.is_empty() {
                        break;
                    }
                    // Release flow control capacity
                    let _ = recv_stream.flow_control().release_capacity(data.len());
                    if let Err(e) = upstream_writer.write_all(&data).await {
                        tracing::debug!("[HTTP2] upstream write error: {}", e);
                        break;
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
    let upstream_to_h2 = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match upstream_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                    if let Err(e) = send_stream.send_data(data, false) {
                        tracing::debug!("[HTTP2] h2 send error: {}", e);
                        break;
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

    tracing::info!("[HTTP2] Tunnel closed: {} <-> {}", client_addr, authority);
}
