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
}

pub async fn run_proxy_server(state: AppState, addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            return;
        }
    };

    tracing::info!("Proxy server listening on {}", addr);

    while let Ok((client_stream, client_addr)) = listener.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            handle_client(client_stream, client_addr, state).await;
        });
    }
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
        (ProxyProtocol::SOCKS4, _) => utils::send_socks4_response(stream, false).await,
        (ProxyProtocol::SOCKS5, _) => utils::send_socks5_response(stream, false).await,
        _ => Ok(()), // Unknown protocols don't send responses
    }
}

async fn handle_client(mut client_stream: TcpStream, client_addr: SocketAddr, state: AppState) {
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
    let auth_required = state.config.read().await.authentication.enabled;
    if auth_required {
        match protocol.authenticate(&mut buffered_stream, &state).await {
            Ok(true) => {
                tracing::debug!(
                    "{} authenticated successfully via {}",
                    &client_addr,
                    protocol
                );
            }
            Ok(false) => {
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

    let result =
        async_handle_client_with_target(&mut stream, client_addr, &mut protocol, target).await;

    if let Err((e, error_type)) = result {
        tracing::error!(
            "Error [{}] for {}: {}",
            match error_type {
                ErrorType::Handshake => "handshake",
                ErrorType::Connection => "connection",
                ErrorType::Response => "response",
                ErrorType::Timeout => "timeout",
                ErrorType::Tunnel => "tunnel",
            },
            client_addr,
            e
        );

        if error_type != ErrorType::Tunnel {
            let _ = send_error_response(&protocol, &mut stream, error_type).await;
        }
    }
}

async fn async_handle_client_with_target(
    client_stream: &mut ClientStream,
    client_addr: SocketAddr,
    protocol: &mut ProxyProtocol,
    target: ProxyTarget,
) -> Result<(), (io::Error, ErrorType)> {
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
            Ok(())
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
