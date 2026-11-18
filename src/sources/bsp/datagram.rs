use std::{
    collections::BTreeMap,
    future::Future,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use ipnet::IpNet;
use tokio::{
    net::{UdpSocket, UnixDatagram},
    sync::mpsc,
    task::JoinHandle,
};

use super::{
    capture::{now, Capture, SessionGuard, SessionTx},
    metrics::ActiveSession,
    stream::End,
    tee::{Tee, Unit},
};
use crate::{
    internal_events::{IpAllowlistDeniedError, SocketMode, SocketReceiveError, SocketSendError},
    proto::beam::{session_response, SessionResponse},
    shutdown::ShutdownSignal,
};

/// A listening datagram socket.
pub(super) trait DgramSocket: Send + Sync + 'static {
    type Peer: Ord + Clone + Send + Sync + 'static;

    const MODE: SocketMode;

    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<(usize, Self::Peer)>> + Send;

    /// Whether `permit_origin` lets this peer in.
    fn permitted(&self, peer: &Self::Peer) -> bool;

    fn describe(peer: &Self::Peer) -> String;

    /// Sends one reply datagram to a client. Transports without replies drop it.
    fn reply(
        self: &Arc<Self>,
        payload: Bytes,
        peer: &Self::Peer,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Opens the per-session path to the upstream source.
    fn forwarder(
        self: &Arc<Self>,
        upstream: &DgramUpstream,
        peer: &Self::Peer,
    ) -> impl Future<Output = io::Result<Forwarder>> + Send;
}

pub(super) struct UdpListener {
    pub(super) socket: UdpSocket,
    pub(super) allowlist: Option<Vec<IpNet>>,
}

impl DgramSocket for UdpListener {
    type Peer = SocketAddr;

    const MODE: SocketMode = SocketMode::Udp;

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    fn permitted(&self, peer: &SocketAddr) -> bool {
        match &self.allowlist {
            Some(nets) => nets.iter().any(|net| net.contains(&peer.ip())),
            None => true,
        }
    }

    fn describe(peer: &SocketAddr) -> String {
        peer.to_string()
    }

    async fn reply(self: &Arc<Self>, payload: Bytes, peer: &SocketAddr) -> io::Result<()> {
        self.socket.send_to(&payload, peer).await.map(|_| ())
    }

    async fn forwarder(
        self: &Arc<Self>,
        upstream: &DgramUpstream,
        peer: &SocketAddr,
    ) -> io::Result<Forwarder> {
        match upstream {
            DgramUpstream::Udp(addr) => {
                let bind: SocketAddr = if addr.is_ipv4() {
                    ([0, 0, 0, 0], 0).into()
                } else {
                    ([0u16; 8], 0).into()
                };
                let socket = Arc::new(UdpSocket::bind(bind).await?);
                socket.connect(addr).await?;
                let replies =
                    tokio::spawn(udp_replies(Arc::clone(&socket), Arc::clone(self), *peer));
                Ok(Forwarder::Udp {
                    socket,
                    replies: Some(replies),
                })
            }
            DgramUpstream::Unix(_) => Err(io::Error::other("UDP input with a Unix upstream")),
        }
    }
}

/// Upstream replies to one client, sent back from the public socket.
async fn udp_replies(upstream: Arc<UdpSocket>, listener: Arc<UdpListener>, peer: SocketAddr) {
    let mut buf = vec![0u8; 65536];
    while let Ok(len) = upstream.recv(&mut buf).await {
        if let Err(error) = listener.socket.send_to(&buf[..len], peer).await {
            emit!(SocketSendError {
                mode: SocketMode::Udp,
                error
            });
        }
    }
}

pub(super) struct UnixDgramListener(pub(super) UnixDatagram);

impl DgramSocket for UnixDgramListener {
    /// The client's bound path; unbound clients share the anonymous session `""`.
    type Peer = String;

    const MODE: SocketMode = SocketMode::Unix;

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, String)> {
        self.0.recv_from(buf).await.map(|(len, addr)| {
            let peer = addr
                .as_pathname()
                .map(|path| path.display().to_string())
                .unwrap_or_default();
            (len, peer)
        })
    }

    fn permitted(&self, _peer: &String) -> bool {
        true
    }

    fn describe(peer: &String) -> String {
        peer.clone()
    }

    async fn reply(self: &Arc<Self>, _payload: Bytes, _peer: &String) -> io::Result<()> {
        Ok(())
    }

    async fn forwarder(
        self: &Arc<Self>,
        upstream: &DgramUpstream,
        _peer: &String,
    ) -> io::Result<Forwarder> {
        match upstream {
            DgramUpstream::Unix(path) => Ok(Forwarder::Unix {
                socket: Arc::new(UnixDatagram::unbound()?),
                path: path.clone(),
            }),
            DgramUpstream::Udp(_) => {
                Err(io::Error::other("Unix datagram input with a UDP upstream"))
            }
        }
    }
}

pub(super) enum DgramUpstream {
    Udp(SocketAddr),
    Unix(PathBuf),
}

pub(super) enum Forwarder {
    Udp {
        socket: Arc<UdpSocket>,
        replies: Option<JoinHandle<()>>,
    },
    Unix {
        socket: Arc<UnixDatagram>,
        path: PathBuf,
    },
}

impl Forwarder {
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Udp { socket, .. } => socket.send(payload).await.map(|_| ()),
            Self::Unix { socket, path } => socket.send_to(payload, path).await.map(|_| ()),
        }
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        if let Self::Udp {
            replies: Some(replies),
            ..
        } = self
        {
            replies.abort();
        }
    }
}

pub(super) struct DgramUpdate {
    pub(super) upstream: DgramUpstream,
    pub(super) sampling_rate: f64,
    pub(super) buffer_bytes: usize,
}

pub(super) struct DgramCtx {
    pub(super) capture: Arc<Capture>,
    pub(super) local_addr: String,
    pub(super) max_length: usize,
    pub(super) session_idle_timeout: Duration,
    /// `None` is new mode.
    pub(super) update: Option<DgramUpdate>,
}

enum Session {
    Update {
        forwarder: Forwarder,
        tee: Option<Tee>,
        index: u64,
        sampling_rate: f64,
        buffer_bytes: usize,
        _active: ActiveSession,
    },
    New {
        tx: SessionTx,
        guard: SessionGuard,
        replies: JoinHandle<()>,
        index: u64,
        bytes: u64,
        _active: ActiveSession,
    },
}

impl Session {
    fn close(self, end: End) {
        match self {
            Self::Update { tee, .. } => {
                if let Some(tee) = tee {
                    tee.finish();
                }
            }
            Self::New {
                tx, guard, replies, ..
            } => {
                replies.abort();
                drop(tx);
                match end {
                    End::Closed => guard.finish(),
                    End::Reset => drop(guard),
                }
            }
        }
    }
}

struct Entry {
    session: Session,
    last_seen: Instant,
}

impl DgramCtx {
    pub(super) async fn serve<L: DgramSocket>(self, listener: Arc<L>, shutdown: ShutdownSignal) {
        let mut sessions: BTreeMap<L::Peer, Entry> = BTreeMap::new();
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<(L::Peer, End)>();
        let mut buf = vec![0u8; self.max_length + 1];
        let mut expiry =
            tokio::time::interval((self.session_idle_timeout / 2).max(Duration::from_secs(1)));
        let new_mode = self.update.is_none();
        let stopped = {
            let capture = Arc::clone(&self.capture);
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
            tokio::select! {
                biased;
                _ = &mut shutdown => break,
                () = &mut stopped => break,
                Some((peer, end)) = ended_rx.recv() => {
                    if let Some(entry) = sessions.remove(&peer) {
                        self.count_end(&end);
                        entry.session.close(end);
                    }
                }
                _ = expiry.tick() => {
                    let idle: Vec<L::Peer> = sessions
                        .iter()
                        .filter(|(_, entry)| entry.last_seen.elapsed() >= self.session_idle_timeout)
                        .map(|(peer, _)| peer.clone())
                        .collect();
                    for peer in idle {
                        if let Some(entry) = sessions.remove(&peer) {
                            self.capture.metrics.sessions_closed.increment(1);
                            entry.session.close(End::Closed);
                        }
                    }
                }
                received = listener.recv(&mut buf) => match received {
                    Err(error) => emit!(SocketReceiveError {
                        mode: L::MODE,
                        error
                    }),
                    Ok((len, peer)) if listener.permitted(&peer) => {
                        let len = if len > self.max_length {
                            self.capture.metrics.datagrams_truncated.increment(1);
                            self.max_length
                        } else {
                            len
                        };
                        let payload = Bytes::copy_from_slice(&buf[..len]);
                        self.datagram(&listener, &mut sessions, &ended_tx, peer, payload)
                            .await;
                    }
                    Ok((_, peer)) => emit!(IpAllowlistDeniedError {
                        peer: &L::describe(&peer)
                    }),
                },
            }
        }

        for (_, entry) in std::mem::take(&mut sessions) {
            entry.session.close(End::Closed);
        }
    }

    fn count_end(&self, end: &End) {
        match end {
            End::Closed => self.capture.metrics.sessions_closed.increment(1),
            End::Reset => self.capture.metrics.sessions_reset.increment(1),
        }
    }

    async fn datagram<L: DgramSocket>(
        &self,
        listener: &Arc<L>,
        sessions: &mut BTreeMap<L::Peer, Entry>,
        ended: &mpsc::UnboundedSender<(L::Peer, End)>,
        peer: L::Peer,
        payload: Bytes,
    ) {
        let entry = match sessions.remove(&peer) {
            Some(entry) => Some(entry),
            None => self
                .open(listener, ended, &peer)
                .await
                .map(|session| Entry {
                    session,
                    last_seen: Instant::now(),
                }),
        };
        let kept = match entry {
            Some(mut entry) => {
                entry.last_seen = Instant::now();
                match self.deliver::<L>(&mut entry.session, &peer, payload).await {
                    Ok(()) => Some(entry),
                    Err(end) => {
                        self.count_end(&end);
                        entry.session.close(end);
                        None
                    }
                }
            }
            None => None,
        };
        if let Some(entry) = kept {
            sessions.insert(peer, entry);
        }
    }

    async fn open<L: DgramSocket>(
        &self,
        listener: &Arc<L>,
        ended: &mpsc::UnboundedSender<(L::Peer, End)>,
        peer: &L::Peer,
    ) -> Option<Session> {
        match &self.update {
            Some(update) => match listener.forwarder(&update.upstream, peer).await {
                Ok(forwarder) => Some(Session::Update {
                    forwarder,
                    tee: None,
                    index: 0,
                    sampling_rate: update.sampling_rate,
                    buffer_bytes: update.buffer_bytes,
                    _active: self.capture.metrics.active(false),
                }),
                Err(error) => {
                    warn!(message = "Failed to open upstream socket.", %error, internal_log_rate_limit = true);
                    self.capture
                        .metrics
                        .sessions_upstream_connect_failed
                        .increment(1);
                    None
                }
            },
            None => match self.capture.admit() {
                None => {
                    self.capture.metrics.sessions_refused.increment(1);
                    None
                }
                Some(admission) => {
                    let stream =
                        self.capture
                            .open(admission, L::describe(peer), self.local_addr.clone());
                    let replies = tokio::spawn(dgram_replies(
                        stream.rx,
                        Arc::clone(listener),
                        peer.clone(),
                        ended.clone(),
                        Arc::clone(&self.capture),
                    ));
                    Some(Session::New {
                        tx: stream.tx,
                        guard: stream.guard,
                        replies,
                        index: 0,
                        bytes: 0,
                        _active: self.capture.metrics.active(true),
                    })
                }
            },
        }
    }

    /// `Err` ends the session.
    async fn deliver<L: DgramSocket>(
        &self,
        session: &mut Session,
        peer: &L::Peer,
        payload: Bytes,
    ) -> Result<(), End> {
        match session {
            Session::Update {
                forwarder,
                tee,
                index,
                sampling_rate,
                buffer_bytes,
                ..
            } => {
                let sampled = rand::random::<f64>() < *sampling_rate;
                if sampled && tee.is_none() {
                    *tee = self.capture.admit().map(|admission| {
                        let stream = self.capture.open(
                            admission,
                            L::describe(peer),
                            self.local_addr.clone(),
                        );
                        Tee::spawn(
                            Arc::clone(&self.capture),
                            stream,
                            *buffer_bytes,
                            Unit::Datagrams,
                            *index,
                        )
                    });
                }
                match (tee.as_mut(), sampled) {
                    (Some(tee), true) => tee.push(payload.clone()),
                    (Some(tee), false) => tee.skip(),
                    (None, _) => {}
                }
                *index += 1;
                if let Err(error) = forwarder.send(&payload).await {
                    emit!(SocketSendError {
                        mode: L::MODE,
                        error
                    });
                }
                Ok(())
            }
            Session::New {
                tx, index, bytes, ..
            } => {
                let len = payload.len();
                if *bytes + len as u64 > self.capture.max_session_bytes() {
                    Err(End::Closed)
                } else {
                    self.capture.rate(len).await;
                    self.capture.charge(len);
                    *bytes += len as u64;
                    let sent = tx.data(*index, now(), payload).await;
                    *index += 1;
                    sent.map_err(|()| End::Reset)
                }
            }
        }
    }
}

/// New mode: control-agent's replies to one datagram client.
async fn dgram_replies<L: DgramSocket>(
    mut rx: mpsc::Receiver<Result<SessionResponse, tonic::Status>>,
    listener: Arc<L>,
    peer: L::Peer,
    ended: mpsc::UnboundedSender<(L::Peer, End)>,
    capture: Arc<Capture>,
) {
    let end = loop {
        match rx.recv().await {
            Some(Ok(SessionResponse {
                msg: Some(session_response::Msg::Reply(reply)),
            })) => {
                if let Err(error) = listener.reply(reply.payload, &peer).await {
                    emit!(SocketSendError {
                        mode: L::MODE,
                        error
                    });
                }
            }
            Some(Ok(SessionResponse {
                msg: Some(session_response::Msg::Stop(_)),
            })) => break End::Closed,
            Some(Ok(_)) => capture.metrics.ignored_responses.increment(1),
            Some(Err(status)) => {
                debug!(message = "Capture session failed; dropping datagram session.", %status);
                break End::Reset;
            }
            None => break End::Closed,
        }
    };
    _ = ended.send((peer, end));
}
