use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

/// Shared bidirectional idle clock for a single tunnel. Both relay directions
/// hold a clone; every transferred chunk stamps `last_activity`. A direction
/// that blocks on `read()` past the window checks this shared clock: if the
/// *sibling* direction moved data recently the tunnel is still live, so it
/// keeps waiting; only when neither direction has moved a byte for the whole
/// window is the tunnel declared dead and torn down.
///
/// This is what reaps half-open CONNECT tunnels (e.g. a mobile FCM client that
/// vanishes without sending TCP FIN/RST): otherwise both `read()` futures block
/// forever, the relay future never returns, and the connection record, tokio
/// task, semaphore permit, and socket FDs leak permanently.
#[derive(Clone)]
struct IdleClock {
    base: Instant,
    last_activity_ms: Arc<AtomicU64>,
    window: Duration,
}

impl IdleClock {
    fn new(window: Duration) -> Self {
        Self {
            base: Instant::now(),
            last_activity_ms: Arc::new(AtomicU64::new(0)),
            window,
        }
    }

    /// Stamp "bytes just flowed" — called by either direction on every chunk.
    fn touch(&self) {
        self.last_activity_ms
            .store(self.base.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// Time since either direction last moved a byte.
    fn idle_for(&self) -> Duration {
        let now = self.base.elapsed().as_millis() as u64;
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        Duration::from_millis(now.saturating_sub(last))
    }
}

// The Tls variant is large; boxing it (to shrink the enum copied per
// connection) is a tracked perf follow-up that touches the pin/poll impls.
#[allow(clippy::large_enum_variant)]
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

    /// Peek at data without consuming it.
    ///
    /// Plain TCP streams delegate to the kernel's `recv(MSG_PEEK)`. TLS streams
    /// cannot be peeked at the socket level (bytes are only readable after
    /// decryption), so the plaintext is read into an internal buffer and a copy
    /// is returned, leaving those bytes queued for the subsequent `AsyncRead`
    /// drain — so the read is still non-consuming from the caller's view.
    ///
    /// A single TLS record may not carry the whole HTTP header block (records
    /// can fragment across reads), so for TLS we keep reading until the
    /// end-of-headers marker (`\r\n\r\n`) is present or the caller's buffer is
    /// full. Reading only one record risked returning a request split *before*
    /// its `Proxy-Authorization` header, which made auth over an outer-TLS
    /// (`-x https://proxy`) connection intermittently fail.
    pub async fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we already buffered data (e.g. a prior peek), return a copy of it.
        if self.buffer_pos < self.buffer.len() {
            let available = (self.buffer.len() - self.buffer_pos).min(buf.len());
            buf[..available]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + available]);
            return Ok(available);
        }

        match &mut self.stream {
            ClientStream::Plain(stream) => stream.peek(buf).await,
            ClientStream::Tls(stream) => {
                let cap = buf.len();
                let mut chunk = vec![0u8; cap];
                while self.buffer.len() < cap {
                    let want = cap - self.buffer.len();
                    let n = stream.read(&mut chunk[..want]).await?;
                    if n == 0 {
                        break; // EOF before more data arrived
                    }
                    self.buffer.extend_from_slice(&chunk[..n]);
                    // Stop as soon as the full HTTP header block is buffered.
                    if self.buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let available = self.buffer.len().min(cap);
                buf[..available].copy_from_slice(&self.buffer[..available]);
                Ok(available)
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
///
/// If `idle_timeout` is `Some`, the tunnel is torn down once neither direction
/// has transferred a byte for that duration — the reaper for half-open peers
/// that never send FIN/RST. `None` disables the idle timeout (relay blocks
/// until EOF/error, the legacy behavior).
#[allow(clippy::too_many_arguments)]
pub async fn create_throttled_tunnel<R1, W1, R2, W2>(
    stream1: (R1, W1),
    stream2: (R2, W2),
    label1: &str,
    label2: &str,
    throttler: Option<crate::bandwidth::BandwidthThrottler>,
    quota: Option<std::sync::Arc<crate::quota_tracker::UserQuotaTracker>>,
    enforce_quota: bool,
    idle_timeout: Option<Duration>,
) -> tokio::io::Result<(u64, u64)>
where
    R1: AsyncRead + AsyncReadExt + Unpin,
    W1: AsyncWrite + AsyncWriteExt + Unpin,
    R2: AsyncRead + AsyncReadExt + Unpin,
    W2: AsyncWrite + AsyncWriteExt + Unpin,
{
    let tunnel1 = TunnelStream::new(stream1.0, stream2.1);
    let tunnel2 = TunnelStream::new(stream2.0, stream1.1);

    // Shared abort flag — when one direction trips the quota limit (or the idle
    // timeout) it sets this and the other side breaks on the next loop
    // iteration. Both halves still return Ok(bytes_so_far) so the caller can
    // record the partial transfer in the `usage` table (otherwise the DB SUM
    // and the dashboard would never see those bytes).
    let aborted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // One idle clock shared by both directions (None = idle timeout disabled).
    let idle = idle_timeout.map(IdleClock::new);

    let t1 = throttler.clone();
    let t2 = throttler;
    let q1 = quota.clone();
    let q2 = quota;
    let a1 = aborted.clone();
    let a2 = aborted;
    let i1 = idle.clone();
    let i2 = idle;
    let relay1 = relay_with_throttle(tunnel1, label1, t1, q1, enforce_quota, a1, i1);
    let relay2 = relay_with_throttle(tunnel2, label2, t2, q2, enforce_quota, a2, i2);

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
#[allow(clippy::too_many_arguments)]
async fn relay_with_throttle<R, W>(
    mut tunnel: TunnelStream<R, W>,
    label: &str,
    throttler: Option<crate::bandwidth::BandwidthThrottler>,
    quota: Option<std::sync::Arc<crate::quota_tracker::UserQuotaTracker>>,
    enforce_quota: bool,
    aborted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    idle: Option<IdleClock>,
) -> tokio::io::Result<u64>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    use std::sync::atomic::Ordering as AtomicOrdering;

    let mut buf = [0u8; 65536];
    let mut total = 0u64;

    loop {
        // Check sibling-initiated abort before blocking on read.
        if aborted.load(AtomicOrdering::Relaxed) {
            break;
        }

        // Read, optionally bounded by the idle window. On timeout we consult
        // the *shared* clock: if the sibling direction moved data recently the
        // tunnel is still live and we simply wait again; only a fully-idle
        // tunnel (neither direction active for the window) is torn down.
        let n = match idle {
            Some(ref clock) => {
                match tokio::time::timeout(clock.window, tunnel.read.read(&mut buf)).await {
                    Ok(res) => res?,
                    Err(_elapsed) => {
                        if clock.idle_for() >= clock.window {
                            tracing::info!(
                                "{} - tunnel idle for {:?}, closing (half-open peer reaped)",
                                label,
                                clock.window
                            );
                            aborted.store(true, AtomicOrdering::Relaxed);
                            break;
                        }
                        // Sibling still active — keep the tunnel open.
                        continue;
                    }
                }
            }
            None => tunnel.read.read(&mut buf).await?,
        };
        if n == 0 {
            break;
        }

        // Bytes flowed — stamp the shared idle clock for both directions.
        if let Some(ref clock) = idle {
            clock.touch();
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
                aborted.store(true, AtomicOrdering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

    // relay_with_logging copies every byte and reports the exact total.
    #[tokio::test]
    async fn relay_with_logging_copies_all_bytes() {
        let (mut src_client, src_proxy) = duplex(4096);
        let (dst_proxy, mut dst_client) = duplex(4096);

        let mut tunnel = TunnelStream::new(src_proxy, dst_proxy);
        let relay = tokio::spawn(async move { tunnel.relay_with_logging("test").await });

        src_client.write_all(b"hello world").await.unwrap();
        src_client.shutdown().await.unwrap();

        let mut got = Vec::new();
        dst_client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello world");
        assert_eq!(relay.await.unwrap().unwrap(), 11);
    }

    // create_throttled_tunnel with no throttle/quota relays both directions and
    // returns each direction's byte total.
    #[tokio::test]
    async fn throttled_tunnel_relays_both_directions() {
        let (mut client, client_proxy) = duplex(4096);
        let (mut upstream, upstream_proxy) = duplex(4096);
        let (cr, cw) = split(client_proxy);
        let (ur, uw) = split(upstream_proxy);

        let task = tokio::spawn(async move {
            create_throttled_tunnel((cr, cw), (ur, uw), "c2u", "u2c", None, None, false, None).await
        });

        client.write_all(b"ping").await.unwrap();
        client.shutdown().await.unwrap();
        upstream.write_all(b"pongpong").await.unwrap();
        upstream.shutdown().await.unwrap();

        let mut to_upstream = Vec::new();
        upstream.read_to_end(&mut to_upstream).await.unwrap();
        let mut to_client = Vec::new();
        client.read_to_end(&mut to_client).await.unwrap();
        assert_eq!(to_upstream, b"ping");
        assert_eq!(to_client, b"pongpong");

        let (a, b) = task.await.unwrap().unwrap();
        // One direction carried 4 bytes, the other 8 (order depends on mapping).
        let mut totals = [a, b];
        totals.sort_unstable();
        assert_eq!(totals, [4, 8]);
    }

    // With enforcement on and a tiny limit, a large transfer trips the quota
    // and the shared abort flag is set (connection torn down, not hung).
    #[tokio::test]
    async fn throttled_tunnel_enforces_quota() {
        let tracker =
            std::sync::Arc::new(crate::quota_tracker::UserQuotaTracker::new(0, Some(8), 0));
        let tracker_probe = tracker.clone();
        let (mut client, client_proxy) = duplex(64 * 1024);
        let (upstream, upstream_proxy) = duplex(64 * 1024);
        let (cr, cw) = split(client_proxy);
        let (ur, uw) = split(upstream_proxy);

        // Keep the upstream client end alive so reads don't error prematurely.
        let _upstream = upstream;

        let task = tokio::spawn(async move {
            create_throttled_tunnel(
                (cr, cw),
                (ur, uw),
                "c2u",
                "u2c",
                None,
                Some(tracker),
                true,
                None,
            )
            .await
        });

        // Send well beyond the 8-byte limit.
        let big = vec![0u8; 4096];
        let _ = client.write_all(&big).await;
        let _ = client.shutdown().await;

        // Must complete (not hang). Enforcement tripped: the tracker is over its
        // limit and the upstream->client direction carried nothing.
        let (_a, b) = task.await.unwrap().unwrap();
        assert!(tracker_probe.is_over(), "quota should have tripped");
        assert_eq!(b, 0);
    }

    // An idle tunnel (both peers alive but sending nothing — the half-open
    // FCM-client scenario) must be reaped within the idle window instead of
    // blocking forever. Without the idle timeout this hangs and the test's
    // outer timeout fires.
    #[tokio::test]
    async fn idle_tunnel_is_reaped_within_window() {
        let (_client, client_proxy) = duplex(4096);
        let (_upstream, upstream_proxy) = duplex(4096);
        let (cr, cw) = split(client_proxy);
        let (ur, uw) = split(upstream_proxy);

        // Keep both client ends alive and send NOTHING: reads block forever
        // unless the idle timeout tears the tunnel down.
        let window = std::time::Duration::from_millis(150);
        let task = tokio::spawn(async move {
            create_throttled_tunnel(
                (cr, cw),
                (ur, uw),
                "c2u",
                "u2c",
                None,
                None,
                false,
                Some(window),
            )
            .await
        });

        let res = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        let (a, b) = res
            .expect("idle tunnel must return, not hang")
            .unwrap()
            .unwrap();
        assert_eq!((a, b), (0, 0), "no bytes should have transferred");
    }

    // A tunnel that stays active in one direction only (e.g. a long download —
    // client sends nothing, server streams) must NOT be reaped: the shared
    // idle clock is kept fresh by the active direction.
    #[tokio::test]
    async fn one_way_active_tunnel_not_reaped() {
        let (mut client, client_proxy) = duplex(64 * 1024);
        let (mut upstream, upstream_proxy) = duplex(64 * 1024);
        let (cr, cw) = split(client_proxy);
        let (ur, uw) = split(upstream_proxy);

        let window = std::time::Duration::from_millis(120);
        let task = tokio::spawn(async move {
            create_throttled_tunnel(
                (cr, cw),
                (ur, uw),
                "c2u",
                "u2c",
                None,
                None,
                false,
                Some(window),
            )
            .await
        });

        // Upstream dribbles data for ~4 windows while the client stays silent.
        for _ in 0..4 {
            tokio::time::sleep(window / 2).await;
            upstream.write_all(b"chunk").await.unwrap();
        }
        // Now stop; the tunnel should reap shortly after (both idle).
        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();

        let (_a, b) = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("tunnel must return")
            .unwrap()
            .unwrap();
        assert!(
            b >= 20,
            "active direction bytes should have flowed, got {b}"
        );
    }

    #[test]
    fn quota_tracker_add_and_over_trips_at_limit() {
        let t = crate::quota_tracker::UserQuotaTracker::new(0, Some(10), 0);
        assert!(!t.add_and_over(5));
        assert!(t.add_and_over(5)); // reaches 10 >= limit
        assert!(t.used() >= 10);
    }
}
