use std::{
    future::Future,
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use futures::FutureExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, UnixListener, UnixStream},
    sync::{watch, Semaphore},
    time::Instant,
};
use tracing::Instrument;

use super::{
    capture::{now, Admission, Capture, SessionStream},
    tee::{Tee, Unit},
    Sampled,
};
use crate::{
    internal_events::{SocketMode, SocketReceiveError, TcpSocketTlsConnectionError},
    proto::beam::{session_response, SessionResponse},
    shutdown::ShutdownSignal,
    tcp::TcpKeepaliveConfig,
    tls::{MaybeTlsIncomingStream, MaybeTlsListener},
};

const READ_BUF: usize = 64 * 1024;

/// A client or upstream byte stream.
pub(super) trait Conn: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Makes the coming close an RST rather than a FIN, where the transport has one.
    fn arm_reset(&self);
}

impl Conn for TcpStream {
    fn arm_reset(&self) {
        _ = self.set_linger(Some(Duration::ZERO));
    }
}

impl Conn for UnixStream {
    fn arm_reset(&self) {}
}

impl Conn for Box<dyn Conn> {
    fn arm_reset(&self) {
        self.as_ref().arm_reset();
    }
}

/// An accepted client connection, before and after its handshake.
pub(super) trait Client: Conn {
    fn peer(&self) -> String;

    fn handshake(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

pub(super) struct TcpClient {
    stream: MaybeTlsIncomingStream<TcpStream>,
    keepalive: Option<TcpKeepaliveConfig>,
    receive_buffer_bytes: Option<usize>,
    handshake_timeout: Duration,
}

impl AsyncRead for TcpClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Conn for TcpClient {
    fn arm_reset(&self) {
        if let Some(stream) = self.stream.get_ref() {
            stream.arm_reset();
        }
    }
}

impl Client for TcpClient {
    fn peer(&self) -> String {
        self.stream.peer_addr().to_string()
    }

    async fn handshake(&mut self) -> io::Result<()> {
        tokio::time::timeout(self.handshake_timeout, self.stream.handshake())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
            .map_err(|error| {
                let failed = io::Error::other(error.to_string());
                emit!(TcpSocketTlsConnectionError { error });
                failed
            })?;
        if let Some(keepalive) = self.keepalive {
            self.stream.set_keepalive(keepalive)?;
        }
        match self.receive_buffer_bytes {
            Some(bytes) => self.stream.set_receive_buffer_bytes(bytes),
            None => Ok(()),
        }
    }
}

pub(super) struct UnixClient(UnixStream);

impl AsyncRead for UnixClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for UnixClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Conn for UnixClient {
    fn arm_reset(&self) {}
}

impl Client for UnixClient {
    fn peer(&self) -> String {
        self.0
            .peer_addr()
            .ok()
            .and_then(|addr| addr.as_pathname().map(|path| path.display().to_string()))
            .unwrap_or_default()
    }

    async fn handshake(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A listener that yields clients.
pub(super) trait Acceptor: Send + 'static {
    type Client: Client;

    const MODE: SocketMode;

    fn accept(&mut self) -> impl Future<Output = io::Result<Self::Client>> + Send;
}

pub(super) struct TcpAcceptor {
    pub(super) listener: MaybeTlsListener,
    pub(super) keepalive: Option<TcpKeepaliveConfig>,
    pub(super) receive_buffer_bytes: Option<usize>,
    pub(super) handshake_timeout: Duration,
}

impl Acceptor for TcpAcceptor {
    type Client = TcpClient;

    const MODE: SocketMode = SocketMode::Tcp;

    async fn accept(&mut self) -> io::Result<TcpClient> {
        self.listener
            .accept()
            .await
            .map(|stream| TcpClient {
                stream,
                keepalive: self.keepalive,
                receive_buffer_bytes: self.receive_buffer_bytes,
                handshake_timeout: self.handshake_timeout,
            })
            .map_err(io::Error::other)
    }
}

pub(super) struct UnixAcceptor(pub(super) UnixListener);

impl Acceptor for UnixAcceptor {
    type Client = UnixClient;

    const MODE: SocketMode = SocketMode::Unix;

    async fn accept(&mut self) -> io::Result<UnixClient> {
        self.0.accept().await.map(|(stream, _)| UnixClient(stream))
    }
}

pub(super) enum DialTarget {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl DialTarget {
    async fn connect(&self) -> io::Result<Box<dyn Conn>> {
        match self {
            Self::Tcp(addr) => {
                let stream = TcpStream::connect(addr).await?;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream) as Box<dyn Conn>)
            }
            Self::Unix(path) => Ok(Box::new(UnixStream::connect(path).await?) as Box<dyn Conn>),
        }
    }
}

/// Update mode: where the relocated old source listens, and how its traffic is captured.
pub(super) struct Upstream {
    pub(super) target: DialTarget,
    pub(super) connect_timeout: Duration,
    pub(super) sampled: Sampled,
}

pub(super) struct StreamCtx {
    pub(super) capture: Arc<Capture>,
    pub(super) local_addr: String,
    pub(super) max_chunk_bytes: usize,
    /// `None` is new mode.
    pub(super) upstream: Option<Upstream>,
    pub(super) connection_limit: Option<u32>,
    pub(super) max_connection_duration: Option<Duration>,
    pub(super) shutdown_timeout: Duration,
}

impl StreamCtx {
    const fn unit(&self) -> Unit {
        Unit::Bytes {
            max_chunk: self.max_chunk_bytes,
        }
    }

    /// Accepts clients until shutdown or, in new mode, until control-agent stops the run.
    pub(super) async fn serve<A: Acceptor>(
        self: Arc<Self>,
        mut acceptor: A,
        shutdown: ShutdownSignal,
    ) {
        let limit = self
            .connection_limit
            .map(|limit| Arc::new(Semaphore::new(limit as usize)));
        let shutdown_timeout = self.shutdown_timeout;
        let tripwire = shutdown
            .clone()
            .then(move |_| tokio::time::sleep(shutdown_timeout))
            .shared();
        let stopped = {
            let capture = Arc::clone(&self.capture);
            let new_mode = self.upstream.is_none();
            async move {
                if new_mode {
                    capture.stopped().await;
                } else {
                    futures::future::pending::<()>().await;
                }
            }
        };
        tokio::pin!(shutdown, stopped);

        loop {
            let next = async {
                let permit = match &limit {
                    Some(limit) => Arc::clone(limit).acquire_owned().await.ok(),
                    None => None,
                };
                (acceptor.accept().await, permit)
            };
            let next = tokio::select! {
                biased;
                _ = &mut shutdown => None,
                () = &mut stopped => None,
                next = next => Some(next),
            };
            match next {
                None => break,
                Some((Err(error), _)) => {
                    emit!(SocketReceiveError {
                        mode: A::MODE,
                        error: &error
                    });
                }
                Some((Ok(client), permit)) => {
                    let ctx = Arc::clone(&self);
                    let tripwire = tripwire.clone();
                    // A duration too large to add means no deadline.
                    let deadline = self
                        .max_connection_duration
                        .and_then(|duration| Instant::now().checked_add(duration));
                    // Connections outlive `serve`, so shutdown never waits on them; the tripwire
                    // drops them.
                    tokio::spawn(
                        async move {
                            let _permit = permit;
                            tokio::select! {
                                () = ctx.connection(client, deadline) => {}
                                () = tripwire => {}
                            }
                        }
                        .in_current_span(),
                    );
                }
            }
        }
    }

    async fn connection<C: Client>(self: Arc<Self>, client: C, deadline: Option<Instant>) {
        // New mode refuses before the handshake, so a client isn't kept waiting on a session
        // that won't be captured.
        let admission = match &self.upstream {
            Some(_) => Ok(None),
            None => self.capture.admit().map(Some).ok_or(()),
        };
        match admission {
            Err(()) => self.capture.metrics.sessions_refused.increment(1),
            // In update mode the deadline ends only the capture (see `proxy`), never the
            // connection.
            Ok(admission) => {
                let session = self.handshaken(client, admission, deadline);
                match (&self.upstream, deadline) {
                    (None, Some(deadline)) => {
                        _ = tokio::time::timeout_at(deadline, session).await;
                    }
                    _ => session.await,
                }
            }
        }
    }

    async fn handshaken<C: Client>(
        &self,
        mut client: C,
        admission: Option<Admission>,
        deadline: Option<Instant>,
    ) {
        match (client.handshake().await, admission, &self.upstream) {
            (Err(error), _, _) => debug!(message = "Client handshake failed.", %error),
            (Ok(()), _, Some(upstream)) => self.update(upstream, client, deadline).await,
            (Ok(()), Some(admission), None) => self.new_mode(client, admission).await,
            (Ok(()), None, None) => {}
        }
    }

    async fn update<C: Client>(&self, upstream: &Upstream, client: C, deadline: Option<Instant>) {
        let connected = tokio::time::timeout(upstream.connect_timeout, upstream.target.connect())
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out connecting to upstream",
                ))
            });
        match connected {
            Ok(conn) => {
                let tee = upstream
                    .sampled
                    .pick()
                    .then(|| self.capture.admit())
                    .flatten()
                    .map(|admission| {
                        Tee::open(
                            &self.capture,
                            admission,
                            client.peer(),
                            self.local_addr.clone(),
                            upstream.sampled.buffer_bytes,
                            self.unit(),
                            0,
                        )
                    });
                let _active = self.capture.metrics.active(tee.is_some());
                self.proxy(client, conn, tee, deadline).await;
            }
            Err(error) => {
                warn!(message = "Failed to connect to upstream.", %error, internal_log_rate_limit = true);
                self.capture
                    .metrics
                    .sessions_upstream_connect_failed
                    .increment(1);
                client.arm_reset();
            }
        }
    }

    async fn proxy<C: Conn, U: Conn>(
        &self,
        client: C,
        upstream: U,
        mut tee: Option<Tee>,
        deadline: Option<Instant>,
    ) {
        let (mut client_rx, mut client_tx) = tokio::io::split(client);
        let (mut upstream_rx, mut upstream_tx) = tokio::io::split(upstream);
        let up = async {
            let mut buf = BytesMut::with_capacity(READ_BUF);
            loop {
                buf.reserve(READ_BUF);
                let expires = deadline.filter(|_| tee.is_some());
                let read = tokio::select! {
                    read = client_rx.read_buf(&mut buf) => Some(read?),
                    () = async {
                        match expires {
                            Some(expires) => tokio::time::sleep_until(expires).await,
                            None => futures::future::pending().await,
                        }
                    } => None,
                };
                match read {
                    None => {
                        if let Some(tee) = tee.take() {
                            tee.finish();
                        }
                    }
                    Some(0) => {
                        if let Some(tee) = tee.as_mut() {
                            tee.half_close();
                        }
                        break upstream_tx.shutdown().await;
                    }
                    Some(_) => {
                        let chunk = buf.split().freeze();
                        if let Some(tee) = tee.as_mut() {
                            tee.push(&chunk);
                        }
                        upstream_tx.write_all(&chunk).await?;
                    }
                }
            }
        };
        let down = async {
            tokio::io::copy(&mut upstream_rx, &mut client_tx).await?;
            client_tx.shutdown().await
        };
        let result = tokio::try_join!(up, down);

        match result {
            Ok(_) => {
                self.capture.metrics.sessions_closed.increment(1);
                if let Some(tee) = tee {
                    tee.finish();
                }
            }
            Err(error) => {
                debug!(message = "Session reset.", %error);
                self.capture.metrics.sessions_reset.increment(1);
                client_rx.unsplit(client_tx).arm_reset();
                upstream_rx.unsplit(upstream_tx).arm_reset();
                if let Some(tee) = tee {
                    tee.abort();
                }
            }
        }
    }

    async fn new_mode<C: Client>(&self, client: C, admission: Admission) {
        let session = self
            .capture
            .open(admission, client.peer(), self.local_addr.clone());
        let _active = self.capture.metrics.active(true);
        relay(&self.capture, client, session, self.unit()).await;
    }
}

/// How a new-mode session ends.
#[derive(Debug)]
pub(super) enum End {
    /// Close the client normally and end the RPC normally.
    Closed,
    /// Reset the client and cancel the RPC.
    Reset,
}

/// New mode: client bytes go to control-agent with backpressure; its replies go to the client.
async fn relay<C: Conn>(capture: &Capture, client: C, mut session: SessionStream, unit: Unit) {
    let (mut client_rx, mut client_tx) = tokio::io::split(client);
    let finish_timeout = session.finish_timeout();
    let (client_done, client_done_rx) = watch::channel(false);
    let end = {
        let tx = &session.tx;
        let rx = &mut session.rx;
        let max_session_bytes = capture.max_session_bytes();
        let up = async {
            let mut buf = BytesMut::with_capacity(READ_BUF);
            let mut offset = 0u64;
            loop {
                buf.reserve(READ_BUF);
                let read = client_rx.read_buf(&mut buf).await.map_err(|_| End::Reset)?;
                if read == 0 {
                    break tx.half_close().await.map_err(|()| End::Reset);
                }
                if offset + read as u64 > max_session_bytes {
                    break Err(End::Closed);
                }
                capture.rate(read).await;
                capture.charge(read);
                let received_at = now();
                for (offset, chunk) in unit.chunks(offset, buf.split().freeze()) {
                    tx.data(offset, received_at.clone(), chunk)
                        .await
                        .map_err(|()| End::Reset)?;
                }
                offset += read as u64;
            }
        };
        let down = async {
            loop {
                // Once the client has closed its side, a control-agent that sends nothing for
                // `finish_timeout` ends the session, so it can't hold a slot forever.
                let mut done = client_done_rx.clone();
                let quiet = async move {
                    _ = done.wait_for(|done| *done).await;
                    tokio::time::sleep(finish_timeout).await;
                };
                let response = tokio::select! {
                    response = rx.recv() => response,
                    () = quiet => {
                        debug!(message = "Control-agent went quiet after the client closed; ending the session.");
                        break End::Closed;
                    }
                };
                match response {
                    Some(Ok(SessionResponse {
                        msg: Some(session_response::Msg::Reply(reply)),
                    })) => {
                        if client_tx.write_all(&reply.payload).await.is_err() {
                            break End::Reset;
                        }
                    }
                    Some(Ok(SessionResponse {
                        msg: Some(session_response::Msg::HalfClose(_)),
                    })) => {
                        if client_tx.shutdown().await.is_err() {
                            break End::Reset;
                        }
                    }
                    Some(Ok(SessionResponse {
                        msg: Some(session_response::Msg::Stop(_)),
                    })) => break End::Closed,
                    Some(Ok(SessionResponse { msg: None })) => {}
                    Some(Err(status)) => {
                        debug!(message = "Capture session failed; resetting client.", %status);
                        break End::Reset;
                    }
                    None => break End::Closed,
                }
            }
        };
        tokio::pin!(up, down);
        let mut up_done = false;
        loop {
            tokio::select! {
                result = &mut up, if !up_done => match result {
                    Ok(()) => {
                        up_done = true;
                        client_done.send_replace(true);
                    }
                    Err(end) => break end,
                },
                end = &mut down => break end,
                () = capture.stopped() => break End::Closed,
            }
        }
    };

    match end {
        End::Closed => {
            capture.metrics.sessions_closed.increment(1);
            session.finish();
        }
        End::Reset => {
            capture.metrics.sessions_reset.increment(1);
            client_rx.unsplit(client_tx).arm_reset();
            drop(session);
        }
    }
}
