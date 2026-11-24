//! `bsp` (beam-splitter): listens where a push source would, proxies traffic to the relocated
//! old source (update mode) and streams a raw copy to control-agent over the `Beam` gRPC service.
//! Without an upstream (new mode) control-agent also supplies the replies. Design: OBE-13207.

mod capture;
pub mod config;
mod datagram;
mod metrics;
mod stream;
mod tee;
#[cfg(test)]
mod tests;

use std::{
    future::Future,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use futures::FutureExt;
use listenfd::ListenFd;
use tracing::Instrument;
use vector_lib::config::{DataType, LogNamespace};

pub use self::config::BspConfig;
use self::{
    capture::{Capture, Phase},
    config::{CaptureSampling, InputConfig, ReconnectBackoff, UpstreamCapture},
    datagram::{DgramCtx, DgramUpdate, DgramUpstream, UdpListener, UnixDgramListener},
    stream::{DialTarget, StreamCtx, TcpAcceptor, UnixAcceptor, Upstream},
};
use crate::{
    config::{GenerateConfig, Resource, SourceConfig, SourceContext, SourceOutput},
    internal_events::UnixSocketFileDeleteError,
    proto::beam::{Mode, Transport},
    schema::Definition,
    shutdown::ShutdownSignal,
    sources::{
        util::{
            change_socket_permissions,
            net::{try_bind_tcp_listener, try_bind_udp_socket},
        },
        Source,
    },
    tls::MaybeTlsSettings,
};

impl GenerateConfig for BspConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(
            r#"input.mode = "tcp"
            input.address = "0.0.0.0:9000"
            input.upstream.address = "127.0.0.1:65101"
            capture.endpoint = "https://control-agent:9443"
            capture.run_id = "00000000-0000-0000-0000-000000000000"
            capture.auth.token.type = "file"
            capture.auth.token.path = "/etc/observo/auth/site_token""#,
        )
        .unwrap()
    }
}

impl CaptureSampling {
    fn validated(&self) -> crate::Result<f64> {
        if self.rate > 0.0 && self.rate <= 1.0 {
            Ok(self.rate)
        } else {
            Err(format!(
                "upstream.capture.sampling.rate must be in (0, 1], got {}",
                self.rate
            )
            .into())
        }
    }
}

/// Update-mode capture settings, validated.
#[derive(Clone, Copy, Debug)]
pub(super) struct Sampled {
    rate: f64,
    pub(super) buffer_bytes: usize,
}

impl Sampled {
    /// Whether the next session (stream) or datagram is captured.
    pub(super) fn pick(&self) -> bool {
        rand::random::<f64>() < self.rate
    }
}

impl UpstreamCapture {
    fn validated(&self) -> crate::Result<Sampled> {
        self.sampling.validated().map(|rate| Sampled {
            rate,
            buffer_bytes: self.buffer_bytes,
        })
    }
}

impl ReconnectBackoff {
    fn validated(&self) -> crate::Result<()> {
        if self.initial.is_zero() || self.initial > self.max {
            Err(format!(
                "capture.reconnect_backoff.initial must be positive and at most max, got initial {:?}, max {:?}",
                self.initial, self.max
            )
            .into())
        } else {
            Ok(())
        }
    }
}

impl InputConfig {
    fn upstream_capture(&self) -> Option<&UpstreamCapture> {
        match self {
            Self::Tcp(input) => input.upstream.as_ref().map(|upstream| &upstream.capture),
            Self::Udp(input) => input.upstream.as_ref().map(|upstream| &upstream.capture),
            Self::UnixStream(input) => input.upstream.as_ref().map(|upstream| &upstream.capture),
            Self::UnixDatagram(input) => input.upstream.as_ref().map(|upstream| &upstream.capture),
        }
    }

    fn mode(&self) -> Mode {
        match self.upstream_capture() {
            Some(_) => Mode::Update,
            None => Mode::New,
        }
    }

    fn sampled(&self) -> crate::Result<Option<Sampled>> {
        self.upstream_capture()
            .map(UpstreamCapture::validated)
            .transpose()
    }

    fn validate(&self) -> crate::Result<()> {
        self.sampled()?;
        match self {
            Self::Tcp(input)
                if input
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.client_metadata_key.is_some()) =>
            {
                Err("input.tls.client_metadata_key is not supported: bsp emits no events".into())
            }
            Self::UnixStream(input) => SocketFile::stale(&input.path).map(|_| ()),
            Self::UnixDatagram(input) => SocketFile::stale(&input.path).map(|_| ()),
            Self::Tcp(_) | Self::Udp(_) => Ok(()),
        }
    }

    const fn transport(&self) -> Transport {
        match self {
            Self::Tcp(_) => Transport::Tcp,
            Self::Udp(_) => Transport::Udp,
            Self::UnixStream(_) => Transport::UnixStream,
            Self::UnixDatagram(_) => Transport::UnixDatagram,
        }
    }

    /// The listener future, given an armed capture client.
    async fn listen(self, capture: Arc<Capture>, shutdown: ShutdownSignal) -> crate::Result<()> {
        let sampled = self.sampled()?;
        match self {
            Self::Tcp(input) => {
                let tls = MaybeTlsSettings::from_config(
                    input.tls.as_ref().map(|tls| &tls.tls_config),
                    true,
                )?;
                let upstream = input
                    .upstream
                    .as_ref()
                    .zip(sampled)
                    .map(|(upstream, sampled)| Upstream {
                        target: DialTarget::Tcp(upstream.address),
                        connect_timeout: upstream.connect_timeout,
                        sampled,
                    });
                let allowlist = input.permit_origin.clone().map(Into::into);
                let listener =
                    try_bind_tcp_listener(input.address, ListenFd::from_env(), &tls, allowlist)
                        .await?;
                let local_addr = listener
                    .local_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_default();
                info!(message = "Listening.", addr = %local_addr, r#type = "tcp");
                let ctx = Arc::new(StreamCtx {
                    capture,
                    local_addr,
                    max_chunk_bytes: input.max_chunk_bytes.get(),
                    upstream,
                    connection_limit: input.connection_limit,
                    max_connection_duration: input.max_connection_duration,
                    shutdown_timeout: input.shutdown_timeout,
                });
                let acceptor = TcpAcceptor {
                    listener,
                    keepalive: input.keepalive,
                    receive_buffer_bytes: input.receive_buffer_bytes,
                    handshake_timeout: input.handshake_timeout,
                };
                ctx.serve(acceptor, shutdown).await;
                Ok(())
            }
            Self::UnixStream(input) => {
                let upstream = input
                    .upstream
                    .as_ref()
                    .zip(sampled)
                    .map(|(upstream, sampled)| Upstream {
                        target: DialTarget::Unix(upstream.path.clone()),
                        connect_timeout: upstream.connect_timeout,
                        sampled,
                    });
                SocketFile::claim(&input.path)?;
                let listener = tokio::net::UnixListener::bind(&input.path)?;
                let socket_file = SocketFile::bound(&input.path)?;
                change_socket_permissions(&input.path, input.socket_file_mode)?;
                info!(message = "Listening.", path = ?input.path, r#type = "unix_stream");
                let ctx = Arc::new(StreamCtx {
                    capture,
                    local_addr: input.path.display().to_string(),
                    max_chunk_bytes: input.max_chunk_bytes.get(),
                    upstream,
                    connection_limit: input.connection_limit,
                    max_connection_duration: None,
                    shutdown_timeout: input.shutdown_timeout,
                });
                ctx.serve(UnixAcceptor(listener), shutdown).await;
                drop(socket_file);
                Ok(())
            }
            Self::Udp(input) => {
                let update = input
                    .upstream
                    .as_ref()
                    .zip(sampled)
                    .map(|(upstream, sampled)| DgramUpdate {
                        upstream: DgramUpstream::Udp(upstream.address),
                        max_peers: upstream.max_peers.get(),
                        sampled,
                    });
                let socket = try_bind_udp_socket(input.address, ListenFd::from_env()).await?;
                if let Some(bytes) = input.receive_buffer_bytes {
                    if let Err(error) = crate::net::set_receive_buffer_size(&socket, bytes) {
                        warn!(message = "Failed configuring receive buffer size on UDP socket.", %error);
                    }
                }
                let local_addr = socket
                    .local_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_default();
                info!(message = "Listening.", addr = %local_addr, r#type = "udp");
                let listener = Arc::new(UdpListener {
                    socket,
                    allowlist: input.permit_origin.clone().map(Into::into),
                    max_length: input.max_length.get(),
                    truncated: capture.metrics.datagrams_truncated.clone(),
                });
                let ctx = DgramCtx {
                    capture,
                    local_addr,
                    max_length: input.max_length.get(),
                    session_idle_timeout: input.session_idle_timeout,
                    update,
                };
                ctx.serve(listener, shutdown).await;
                Ok(())
            }
            Self::UnixDatagram(input) => {
                let update = input
                    .upstream
                    .as_ref()
                    .zip(sampled)
                    .map(|(upstream, sampled)| DgramUpdate {
                        upstream: DgramUpstream::Unix(upstream.path.clone()),
                        max_peers: upstream.max_peers.get(),
                        sampled,
                    });
                SocketFile::claim(&input.path)?;
                let socket = tokio::net::UnixDatagram::bind(&input.path)?;
                let socket_file = SocketFile::bound(&input.path)?;
                change_socket_permissions(&input.path, input.socket_file_mode)?;
                info!(message = "Listening.", path = ?input.path, r#type = "unix_datagram");
                let ctx = DgramCtx {
                    capture,
                    local_addr: input.path.display().to_string(),
                    max_length: input.max_length.get(),
                    session_idle_timeout: input.session_idle_timeout,
                    update,
                };
                ctx.serve(Arc::new(UnixDgramListener(socket)), shutdown)
                    .await;
                drop(socket_file);
                Ok(())
            }
        }
    }
}

/// The file of a socket this instance bound. Removed on drop unless another socket has replaced
/// it since.
struct SocketFile {
    path: PathBuf,
    inode: u64,
}

impl SocketFile {
    /// Whether a stale socket is at `path`. Any other kind of file is an error: it is never
    /// removed to make room.
    fn stale(path: &Path) -> crate::Result<bool> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
            Ok(metadata) if metadata.file_type().is_socket() => Ok(true),
            Ok(_) => Err(format!("`{}` exists and is not a socket", path.display()).into()),
        }
    }

    /// Removes a stale socket at `path` so it can be bound.
    fn claim(path: &Path) -> crate::Result<()> {
        if Self::stale(path)? {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    fn bound(path: &Path) -> crate::Result<Self> {
        let inode = std::fs::symlink_metadata(path)?.ino();
        Ok(Self {
            path: path.to_owned(),
            inode,
        })
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        let ours = std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.ino() == self.inode);
        if ours {
            if let Err(error) = std::fs::remove_file(&self.path) {
                emit!(UnixSocketFileDeleteError {
                    path: &self.path,
                    error
                });
            }
        }
    }
}

/// Keeps the source alive until shutdown once its listener is gone, so a new-mode `Stop` doesn't
/// look like the source finishing.
async fn until_shutdown(
    listening: impl Future<Output = crate::Result<()>>,
    shutdown: ShutdownSignal,
) -> Result<(), ()> {
    match listening.await {
        Ok(()) => {
            shutdown.await;
            Ok(())
        }
        Err(error) => {
            error!(message = "BSP listener failed.", %error);
            Err(())
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "bsp")]
impl SourceConfig for BspConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<Source> {
        self.input.validate()?;
        self.capture.reconnect_backoff.validated()?;
        let input = self.input.clone();
        let mode = input.mode();
        let (capture, control) = Capture::new(
            &self.capture,
            mode,
            input.transport(),
            cx.key.id().to_owned(),
        )?;
        let shutdown = cx.shutdown;

        Ok(async move {
            let control = tokio::spawn(control.run().in_current_span());
            // New mode binds only once control-agent is ready to supply replies.
            let armed = match mode {
                Mode::New => {
                    tokio::select! {
                        phase = capture.settled() => phase == Phase::Ready,
                        _ = shutdown.clone() => false,
                    }
                }
                Mode::Update | Mode::Unspecified => true,
            };
            let result = if armed {
                until_shutdown(
                    input.listen(Arc::clone(&capture), shutdown.clone()),
                    shutdown,
                )
                .await
            } else {
                shutdown.await;
                Ok(())
            };
            control.abort();
            result
        }
        .boxed())
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        // BSP emits no events; the output only exists so the source can be wired to a sink.
        vec![SourceOutput::new_maybe_logs(
            DataType::Log,
            Definition::default_for_namespace(&[global_log_namespace].into()),
        )]
    }

    fn resources(&self) -> Vec<Resource> {
        match &self.input {
            InputConfig::Tcp(input) => vec![input.address.as_tcp_resource()],
            InputConfig::Udp(input) => vec![input.address.as_udp_resource()],
            InputConfig::UnixStream(_) | InputConfig::UnixDatagram(_) => vec![],
        }
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}
