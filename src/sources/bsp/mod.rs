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

use std::{future::Future, path::Path, sync::Arc};

use futures::FutureExt;
use listenfd::ListenFd;
use vector_lib::config::{DataType, LogNamespace};

pub use self::config::BspConfig;
use self::{
    capture::{Capture, Phase},
    config::{CaptureSampling, InputConfig},
    datagram::{DgramCtx, DgramUpdate, DgramUpstream, UdpListener, UnixDgramListener},
    stream::{DialTarget, StreamCtx, TcpAcceptor, UnixAcceptor, Upstream},
};
use crate::{
    config::{GenerateConfig, Resource, SourceConfig, SourceContext, SourceOutput},
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

impl InputConfig {
    const fn mode(&self) -> Mode {
        let update = match self {
            Self::Tcp(input) => input.upstream.is_some(),
            Self::Udp(input) => input.upstream.is_some(),
            Self::UnixStream(input) => input.upstream.is_some(),
            Self::UnixDatagram(input) => input.upstream.is_some(),
        };
        if update {
            Mode::Update
        } else {
            Mode::New
        }
    }

    fn sampling(&self) -> Option<&CaptureSampling> {
        match self {
            Self::Tcp(input) => input
                .upstream
                .as_ref()
                .map(|upstream| &upstream.capture.sampling),
            Self::Udp(input) => input
                .upstream
                .as_ref()
                .map(|upstream| &upstream.capture.sampling),
            Self::UnixStream(input) => input
                .upstream
                .as_ref()
                .map(|upstream| &upstream.capture.sampling),
            Self::UnixDatagram(input) => input
                .upstream
                .as_ref()
                .map(|upstream| &upstream.capture.sampling),
        }
    }

    fn validate(&self) -> crate::Result<()> {
        self.sampling()
            .map(CaptureSampling::validated)
            .transpose()?;
        match self {
            Self::Tcp(input)
                if input
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.client_metadata_key.is_some()) =>
            {
                Err("input.tls.client_metadata_key is not supported: bsp emits no events".into())
            }
            Self::Tcp(_) | Self::Udp(_) | Self::UnixStream(_) | Self::UnixDatagram(_) => Ok(()),
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
        match self {
            Self::Tcp(input) => {
                let tls = MaybeTlsSettings::from_config(
                    input.tls.as_ref().map(|tls| &tls.tls_config),
                    true,
                )?;
                let upstream = input
                    .upstream
                    .as_ref()
                    .map(|upstream| {
                        upstream.capture.sampling.validated().map(|rate| Upstream {
                            target: DialTarget::Tcp(upstream.address),
                            connect_timeout: upstream.connect_timeout,
                            sampling_rate: rate,
                            buffer_bytes: upstream.capture.buffer_bytes,
                        })
                    })
                    .transpose()?;
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
                    max_chunk_bytes: input.max_chunk_bytes,
                    upstream,
                    connection_limit: input.connection_limit,
                    max_connection_duration: input.max_connection_duration,
                    shutdown_timeout: input.shutdown_timeout,
                });
                let acceptor = TcpAcceptor {
                    listener,
                    keepalive: input.keepalive,
                    receive_buffer_bytes: input.receive_buffer_bytes,
                };
                ctx.serve(acceptor, shutdown).await;
                Ok(())
            }
            Self::UnixStream(input) => {
                let upstream = input
                    .upstream
                    .as_ref()
                    .map(|upstream| {
                        upstream.capture.sampling.validated().map(|rate| Upstream {
                            target: DialTarget::Unix(upstream.path.clone()),
                            connect_timeout: upstream.connect_timeout,
                            sampling_rate: rate,
                            buffer_bytes: upstream.capture.buffer_bytes,
                        })
                    })
                    .transpose()?;
                remove_stale_socket(&input.path)?;
                let listener = tokio::net::UnixListener::bind(&input.path)?;
                change_socket_permissions(&input.path, input.socket_file_mode)?;
                info!(message = "Listening.", path = ?input.path, r#type = "unix_stream");
                let ctx = Arc::new(StreamCtx {
                    capture,
                    local_addr: input.path.display().to_string(),
                    max_chunk_bytes: input.max_chunk_bytes,
                    upstream,
                    connection_limit: input.connection_limit,
                    max_connection_duration: None,
                    shutdown_timeout: input.shutdown_timeout,
                });
                ctx.serve(UnixAcceptor(listener), shutdown).await;
                Ok(())
            }
            Self::Udp(input) => {
                let update = input
                    .upstream
                    .as_ref()
                    .map(|upstream| {
                        upstream
                            .capture
                            .sampling
                            .validated()
                            .map(|rate| DgramUpdate {
                                upstream: DgramUpstream::Udp(upstream.address),
                                sampling_rate: rate,
                                buffer_bytes: upstream.capture.buffer_bytes,
                            })
                    })
                    .transpose()?;
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
                });
                let ctx = DgramCtx {
                    capture,
                    local_addr,
                    max_length: input.max_length,
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
                    .map(|upstream| {
                        upstream
                            .capture
                            .sampling
                            .validated()
                            .map(|rate| DgramUpdate {
                                upstream: DgramUpstream::Unix(upstream.path.clone()),
                                sampling_rate: rate,
                                buffer_bytes: upstream.capture.buffer_bytes,
                            })
                    })
                    .transpose()?;
                remove_stale_socket(&input.path)?;
                let socket = tokio::net::UnixDatagram::bind(&input.path)?;
                change_socket_permissions(&input.path, input.socket_file_mode)?;
                info!(message = "Listening.", path = ?input.path, r#type = "unix_datagram");
                let ctx = DgramCtx {
                    capture,
                    local_addr: input.path.display().to_string(),
                    max_length: input.max_length,
                    session_idle_timeout: input.session_idle_timeout,
                    update,
                };
                ctx.serve(Arc::new(UnixDgramListener(socket)), shutdown)
                    .await;
                Ok(())
            }
        }
    }
}

fn remove_stale_socket(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        Ok(()) | Err(_) => Ok(()),
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
            let control = tokio::spawn(control.run());
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
