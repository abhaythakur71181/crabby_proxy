//! `AsyncRead` / `AsyncWrite` adapters over h2 streams.
//!
//! These let an HTTP/2 stream plug into the same relay machinery the HTTP/1
//! and SOCKS paths use (`stream::create_throttled_tunnel`: shared idle clock,
//! per-user bandwidth throttle, in-flight quota, abort flag), instead of a
//! hand-rolled bridge (#40).
//!
//! Both adapters respect HTTP/2 flow control, so memory per stream is bounded
//! by the h2 windows rather than by how fast the faster peer can push (#42):
//!
//! * [`H2Reader`] releases receive capacity only for bytes the consumer has
//!   actually taken, so a slow upstream stalls the client's window.
//! * [`H2Writer`] reserves send capacity and waits for the peer's window
//!   before handing data to `SendStream::send_data`, so a slow-reading client
//!   stalls the upstream read instead of growing the h2 send buffer.

use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn h2_to_io(e: h2::Error) -> io::Error {
    if e.is_io() {
        // into_io is Some when is_io is true.
        e.into_io()
            .unwrap_or_else(|| io::Error::other("h2 io error"))
    } else {
        io::Error::new(io::ErrorKind::ConnectionReset, e)
    }
}

/// Reads the DATA frames of an h2 request/response body as a byte stream.
pub struct H2Reader {
    recv: RecvStream,
    pending: Bytes,
}

impl H2Reader {
    pub fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            pending: Bytes::new(),
        }
    }
}

impl AsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                // Hand window back only for what the consumer took.
                let _ = this.recv.flow_control().release_capacity(n);
                return Poll::Ready(Ok(()));
            }
            match ready!(this.recv.poll_data(cx)) {
                // Empty DATA frames are legal and are not end-of-stream.
                Some(Ok(data)) => this.pending = data,
                Some(Err(e)) => return Poll::Ready(Err(h2_to_io(e))),
                None => return Poll::Ready(Ok(())), // END_STREAM -> EOF
            }
        }
    }
}

/// Writes bytes into an h2 `SendStream`, honouring the peer's flow-control
/// window. `shutdown` sends END_STREAM.
pub struct H2Writer {
    send: SendStream<Bytes>,
    ended: bool,
}

impl H2Writer {
    pub fn new(send: SendStream<Bytes>) -> Self {
        Self { send, ended: false }
    }

    /// Abort the stream with RST_STREAM (e.g. the upstream body failed
    /// mid-way, so a clean END_STREAM would present a truncated body as
    /// complete).
    pub fn reset(&mut self, reason: h2::Reason) {
        self.ended = true;
        self.send.send_reset(reason);
    }
}

/// Error yielded by [`H2Body`] once the request body exceeds its cap.
#[derive(Debug)]
pub struct BodyTooLarge;

impl std::fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body exceeds the configured limit")
    }
}

impl std::error::Error for BodyTooLarge {}

/// Streams an h2 request body into an outbound HTTP request (via
/// `reqwest::Body::wrap`) without buffering it (#43). Receive window is
/// released only as the upstream client pulls frames, so a slow upstream
/// throttles the h2 client. Fails with [`BodyTooLarge`] past `max_bytes`;
/// the `too_large` flag lets the caller map that to a 413.
pub struct H2Body {
    recv: RecvStream,
    seen: u64,
    max_bytes: u64,
    exact_len: Option<u64>,
    too_large: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl H2Body {
    pub fn new(
        recv: RecvStream,
        max_bytes: u64,
        exact_len: Option<u64>,
        too_large: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            recv,
            seen: 0,
            max_bytes,
            exact_len,
            too_large,
        }
    }
}

impl http_body::Body for H2Body {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        match ready!(this.recv.poll_data(cx)) {
            Some(Ok(data)) => {
                let n = data.len();
                let _ = this.recv.flow_control().release_capacity(n);
                this.seen += n as u64;
                if this.seen > this.max_bytes {
                    this.too_large
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return Poll::Ready(Some(Err(Box::new(BodyTooLarge))));
                }
                Poll::Ready(Some(Ok(http_body::Frame::data(data))))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(Box::new(e)))),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.recv.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self.exact_len {
            Some(n) => http_body::SizeHint::with_exact(n),
            None => http_body::SizeHint::default(),
        }
    }
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        if this.ended {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        this.send.reserve_capacity(buf.len());
        loop {
            match ready!(this.send.poll_capacity(cx)) {
                // Capacity notifications can report 0 (e.g. all of it is still
                // buffered); poll again, which re-registers the waker.
                Some(Ok(0)) => continue,
                Some(Ok(cap)) => {
                    let n = cap.min(buf.len());
                    this.send
                        .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                        .map_err(h2_to_io)?;
                    return Poll::Ready(Ok(n));
                }
                Some(Err(e)) => return Poll::Ready(Err(h2_to_io(e))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Frames are flushed by the connection task.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.ended {
            this.ended = true;
            // Release any reservation we did not use, then end the stream.
            this.send.reserve_capacity(0);
            if let Err(e) = this.send.send_data(Bytes::new(), true) {
                return Poll::Ready(Err(h2_to_io(e)));
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Spin up an in-memory h2 client/server pair and return the client's
    /// request handle plus the server's accepted (request, respond) pair.
    pub(crate) async fn pair() -> (
        h2::client::SendRequest<Bytes>,
        h2::client::ResponseFuture,
        SendStream<Bytes>,
        http::Request<RecvStream>,
        h2::server::SendResponse<Bytes>,
    ) {
        let (c, s) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(s).await.unwrap();
            let (req, respond) = conn.accept().await.unwrap().unwrap();
            // Keep driving the connection in the background.
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            (req, respond)
        });
        let (mut client, conn) = h2::client::handshake(c).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = http::Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(())
            .unwrap();
        client = client.ready().await.unwrap();
        let (resp, send) = client.send_request(req, false).unwrap();
        let (req, respond) = server.await.unwrap();
        (client, resp, send, req, respond)
    }

    #[tokio::test]
    async fn reader_yields_client_data_then_eof() {
        let (_client, _resp, mut send, req, _respond) = pair().await;
        send.send_data(Bytes::from_static(b"hello "), false)
            .unwrap();
        send.send_data(Bytes::new(), false).unwrap(); // empty frame != EOF
        send.send_data(Bytes::from_static(b"world"), true).unwrap();

        let mut r = H2Reader::new(req.into_body());
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    /// #42: a client that never reads must stall the writer once the stream
    /// window is used up, instead of the proxy buffering without bound.
    #[tokio::test]
    async fn writer_applies_backpressure_to_slow_reader() {
        let (_client, resp, _send, _req, mut respond) = pair().await;
        let send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        // Client receives the 200 but never reads (or releases) the body.
        let _resp = resp.await.unwrap();

        let mut w = H2Writer::new(send);
        let chunk = vec![0u8; 16 * 1024];
        let mut written = 0usize;
        let res = tokio::time::timeout(Duration::from_millis(300), async {
            loop {
                w.write_all(&chunk).await.unwrap();
                written += chunk.len();
            }
        })
        .await;
        assert!(res.is_err(), "writer should block on flow control");
        // Default initial window is 65_535 bytes; allow one chunk of slack.
        assert!(
            written <= 65_535 + chunk.len(),
            "wrote {written} bytes past the peer's window"
        );
    }

    #[tokio::test]
    async fn body_streams_and_enforces_cap() {
        use http_body_util_lite::collect;

        let (_client, _resp, mut send, req, _respond) = pair().await;
        send.send_data(Bytes::from_static(b"abc"), false).unwrap();
        send.send_data(Bytes::from_static(b"def"), true).unwrap();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let body = H2Body::new(req.into_body(), 1024, None, flag.clone());
        assert_eq!(collect(body).await.unwrap(), b"abcdef");
        assert!(!flag.load(std::sync::atomic::Ordering::Relaxed));

        let (_client, _resp, mut send, req, _respond) = pair().await;
        send.send_data(Bytes::from_static(b"0123456789"), true)
            .unwrap();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let body = H2Body::new(req.into_body(), 4, None, flag.clone());
        assert!(collect(body).await.is_err());
        assert!(flag.load(std::sync::atomic::Ordering::Relaxed));
    }

    /// Minimal body collector (avoids a dev-dependency on http-body-util).
    mod http_body_util_lite {
        use http_body::Body;
        use std::pin::Pin;

        pub async fn collect<B>(mut body: B) -> Result<Vec<u8>, B::Error>
        where
            B: Body<Data = bytes::Bytes> + Unpin,
        {
            let mut out = Vec::new();
            while let Some(frame) =
                std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
            {
                if let Ok(data) = frame?.into_data() {
                    out.extend_from_slice(&data);
                }
            }
            Ok(out)
        }
    }

    #[tokio::test]
    async fn writer_shutdown_sends_end_stream() {
        let (_client, resp, _send, _req, mut respond) = pair().await;
        let send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        let mut w = H2Writer::new(send);
        w.write_all(b"payload").await.unwrap();
        w.shutdown().await.unwrap();

        let body = resp.await.unwrap().into_body();
        let mut r = H2Reader::new(body);
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"payload");
    }
}
