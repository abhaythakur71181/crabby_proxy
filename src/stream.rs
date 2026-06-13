use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

pub enum ClientStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

/// A buffered wrapper for ClientStream that allows peeking on TLS streams
/// by buffering initial reads
pub struct BufferedClientStream {
    stream: ClientStream,
    buffer: Vec<u8>,
    buffer_pos: usize,
}

impl BufferedClientStream {
    pub fn new(stream: ClientStream) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
            buffer_pos: 0,
        }
    }

    /// Read data into the buffer (for TLS streams that don't support peek)
    pub async fn read_to_buffer(&mut self, size: usize) -> io::Result<usize> {
        let mut buf = vec![0u8; size];
        let n = match &mut self.stream {
            ClientStream::Plain(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Plain streams support peek, use peek() instead",
                ))
            }
            ClientStream::Tls(stream) => stream.read(&mut buf).await?,
        };
        self.buffer.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    /// Peek at data without consuming it
    pub async fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we have buffered data, return it
        if self.buffer_pos < self.buffer.len() {
            let available = (self.buffer.len() - self.buffer_pos).min(buf.len());
            buf[..available]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + available]);
            return Ok(available);
        }

        // For plain streams, use native peek
        match &mut self.stream {
            ClientStream::Plain(stream) => stream.peek(buf).await,
            ClientStream::Tls(_) => {
                // For TLS, we need to read into buffer first
                if self.buffer.is_empty() {
                    let n = self.read_to_buffer(buf.len()).await?;
                    if n > 0 {
                        buf[..n].copy_from_slice(&self.buffer[..n]);
                    }
                    Ok(n)
                } else {
                    Ok(0)
                }
            }
        }
    }

    /// Consume the buffered stream, returning the underlying stream
    pub fn into_inner(self) -> ClientStream {
        self.stream
    }
}

impl AsyncRead for BufferedClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, read from buffer if available
        if self.buffer_pos < self.buffer.len() {
            let available = self.buffer.len() - self.buffer_pos;
            let to_read = available.min(buf.remaining());
            buf.put_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_read]);
            self.buffer_pos += to_read;

            // Clean up buffer if fully consumed
            if self.buffer_pos >= self.buffer.len() {
                self.buffer.clear();
                self.buffer_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Then read from underlying stream
        match &mut self.stream {
            ClientStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            ClientStream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BufferedClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match &mut self.stream {
            ClientStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            ClientStream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match &mut self.stream {
            ClientStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            ClientStream::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut self.stream {
            ClientStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            ClientStream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl AsyncRead for ClientStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ClientStream::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            ClientStream::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            ClientStream::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            ClientStream::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match &mut *self {
            ClientStream::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            ClientStream::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match &mut *self {
            ClientStream::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            ClientStream::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub struct TunnelStream<R: AsyncRead, W: AsyncWrite> {
    read: R,
    write: W,
}

impl<R: AsyncRead, W: AsyncWrite> TunnelStream<R, W> {
    pub fn new(read: R, write: W) -> Self {
        Self { read, write }
    }

    /// Relay data from the read side to the write side
    pub async fn relay_with_logging(&mut self, label: &str) -> tokio::io::Result<u64>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let mut buf = [0u8; 65536];
        let mut total = 0u64;

        loop {
            let n = self.read.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            self.write.write_all(&buf[..n]).await?;
            total += n as u64;
        }

        tracing::debug!("{} - {} bytes transferred", label, total);
        self.write.shutdown().await?;
        Ok(total)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for TunnelStream<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for TunnelStream<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

pub async fn relay_with_tunnel_stream<R, W>(
    mut tunnel: TunnelStream<R, W>,
    label: &str,
) -> tokio::io::Result<u64>
where
    R: AsyncRead + AsyncReadExt + Unpin,
    W: AsyncWrite + AsyncWriteExt + Unpin,
{
    tunnel.relay_with_logging(label).await
}

/// Create a bidirectional tunnel with optional per-user bandwidth throttling
/// and optional in-flight quota enforcement.
///
/// If `throttler` is Some, both directions are rate-limited to the configured
/// bytes-per-second. The throttler is shared between directions so the total
/// bandwidth (upload + download) is capped.
///
/// If `quota` is Some, every chunk transferred (in either direction) is added
/// to the shared per-user atomic counter. The first direction whose chunk
/// causes the user to cross their limit returns `ErrorKind::QuotaExceeded` and
/// the `try_join!` tears down both halves.
pub async fn create_throttled_tunnel<R1, W1, R2, W2>(
    stream1: (R1, W1),
    stream2: (R2, W2),
    label1: &str,
    label2: &str,
    throttler: Option<crate::bandwidth::BandwidthThrottler>,
    quota: Option<std::sync::Arc<crate::quota_tracker::UserQuotaTracker>>,
    enforce_quota: bool,
) -> tokio::io::Result<(u64, u64)>
where
    R1: AsyncRead + AsyncReadExt + Unpin,
    W1: AsyncWrite + AsyncWriteExt + Unpin,
    R2: AsyncRead + AsyncReadExt + Unpin,
    W2: AsyncWrite + AsyncWriteExt + Unpin,
{
    let tunnel1 = TunnelStream::new(stream1.0, stream2.1);
    let tunnel2 = TunnelStream::new(stream2.0, stream1.1);

    // Shared abort flag — when one direction trips the quota limit it sets
    // this and the other side breaks on the next loop iteration. Both halves
    // still return Ok(bytes_so_far) so the caller can record the partial
    // transfer in the `usage` table (otherwise the DB SUM and the dashboard
    // would never see those bytes).
    let aborted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let t1 = throttler.clone();
    let t2 = throttler;
    let q1 = quota.clone();
    let q2 = quota;
    let a1 = aborted.clone();
    let a2 = aborted;
    let relay1 = relay_with_throttle(tunnel1, label1, t1, q1, enforce_quota, a1);
    let relay2 = relay_with_throttle(tunnel2, label2, t2, q2, enforce_quota, a2);

    // join! (not try_join!) so a partial count from one side is preserved
    // even if the other side errors.
    let (r1, r2) = tokio::join!(relay1, relay2);
    let bytes1 = r1.unwrap_or(0);
    let bytes2 = r2.unwrap_or(0);
    Ok((bytes1, bytes2))
}

/// Relay data with optional bandwidth throttling and optional quota enforcement.
///
/// Never returns `Err` for the quota-exceeded case — instead it sets the
/// shared `aborted` flag and returns `Ok(bytes_transferred_so_far)` so the
/// caller can persist the partial transfer.
async fn relay_with_throttle<R, W>(
    mut tunnel: TunnelStream<R, W>,
    label: &str,
    throttler: Option<crate::bandwidth::BandwidthThrottler>,
    quota: Option<std::sync::Arc<crate::quota_tracker::UserQuotaTracker>>,
    enforce_quota: bool,
    aborted: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> tokio::io::Result<u64>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    use std::sync::atomic::Ordering;

    let mut buf = [0u8; 65536];
    let mut total = 0u64;

    loop {
        // Check sibling-initiated abort before blocking on read.
        if aborted.load(Ordering::Relaxed) {
            break;
        }

        let n = tunnel.read.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        // Throttle if configured
        if let Some(ref t) = throttler {
            t.consume(n).await;
        }

        tunnel.write.write_all(&buf[..n]).await?;
        total += n as u64;

        // In-flight quota enforcement: increment the live per-user counter
        // and bail out the moment we cross the limit. This is the only path
        // that can stop a long-lived CONNECT tunnel — admission checks alone
        // are insufficient because usage rows are written at close.
        if let Some(ref q) = quota {
            let is_over = q.add_and_over(n as i64);
            if enforce_quota && is_over {
                tracing::warn!(
                    "{} - quota exceeded mid-stream after {} bytes (used={}, limit={}) — aborting tunnel",
                    label,
                    total,
                    q.used(),
                    q.limit()
                );
                aborted.store(true, Ordering::Relaxed);
                break;
            }
        }
    }

    tracing::debug!("{} - {} bytes transferred", label, total);
    let _ = tunnel.write.shutdown().await;
    Ok(total)
}

/// Create a bidirectional tunnel b/w two stream
pub async fn create_bidirectional_tunnel<R1, W1, R2, W2>(
    stream1: (R1, W1),
    stream2: (R2, W2),
    label1: &str,
    label2: &str,
) -> tokio::io::Result<(u64, u64)>
where
    R1: AsyncRead + AsyncReadExt + Unpin,
    W1: AsyncWrite + AsyncWriteExt + Unpin,
    R2: AsyncRead + AsyncReadExt + Unpin,
    W2: AsyncWrite + AsyncWriteExt + Unpin,
{
    let tunnel1 = TunnelStream::new(stream1.0, stream2.1);
    let tunnel2 = TunnelStream::new(stream2.0, stream1.1);

    let relay1 = relay_with_tunnel_stream(tunnel1, label1);
    let relay2 = relay_with_tunnel_stream(tunnel2, label2);

    tokio::try_join!(relay1, relay2)
}
