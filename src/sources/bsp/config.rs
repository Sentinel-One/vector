use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

use serde_with::serde_as;
use vector_lib::{configurable::configurable_component, ipallowlist::IpAllowlistConfig};

use crate::{
    sinks::util::AuthTokenConfig,
    sources::util::net::SocketListenAddr,
    tcp::TcpKeepaliveConfig,
    tls::{TlsEnableableConfig, TlsSourceConfig},
};

const fn default_shutdown_timeout() -> Duration {
    Duration::from_secs(30)
}

const fn default_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

const fn default_session_idle_timeout() -> Duration {
    Duration::from_secs(60)
}

const fn default_handshake_timeout() -> Duration {
    Duration::from_secs(10)
}

const fn default_max_chunk_bytes() -> NonZeroUsize {
    NonZeroUsize::new(1024 * 1024).unwrap()
}

const fn default_max_length() -> NonZeroUsize {
    NonZeroUsize::new(65535).unwrap()
}

const fn default_max_peers() -> NonZeroUsize {
    NonZeroUsize::new(16384).unwrap()
}

/// Configuration for the `bsp` source.
#[configurable_component(source(
    "bsp",
    "Split push-source traffic to an upstream source and to control-agent."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct BspConfig {
    #[configurable(derived)]
    pub input: InputConfig,

    #[configurable(derived)]
    pub capture: CaptureConfig,
}

/// The listener BSP exposes to clients.
///
/// When `upstream` is set, BSP runs in update mode: traffic is proxied to the upstream source and
/// a copy is captured. Without it, BSP runs in new mode: traffic only goes to control-agent, which
/// also supplies the replies.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[configurable(metadata(docs::enum_tag_description = "The transport to listen on."))]
#[allow(clippy::large_enum_variant)]
pub enum InputConfig {
    /// Listen on TCP.
    Tcp(TcpInput),

    /// Listen on UDP.
    Udp(UdpInput),

    /// Listen on a Unix domain socket, in stream mode.
    UnixStream(UnixStreamInput),

    /// Listen on a Unix domain socket, in datagram mode.
    UnixDatagram(UnixDatagramInput),
}

/// TCP listener.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TcpInput {
    /// The public address to listen on.
    pub address: SocketListenAddr,

    #[configurable(derived)]
    pub keepalive: Option<TcpKeepaliveConfig>,

    /// TLS for client connections, copied verbatim from the client-facing source definition.
    ///
    /// `client_metadata_key` is rejected: BSP emits no events to attach it to.
    #[configurable(derived)]
    pub tls: Option<TlsSourceConfig>,

    /// Client allowlist, copied from the client-facing source definition.
    #[configurable(derived)]
    pub permit_origin: Option<IpAllowlistConfig>,

    /// The size of the receive buffer used for each connection.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub receive_buffer_bytes: Option<usize>,

    /// The maximum number of client connections allowed at any given time.
    #[configurable(metadata(docs::type_unit = "connections"))]
    pub connection_limit: Option<u32>,

    /// Maximum time to capture each client connection. In new mode the connection is closed
    /// when it is reached; in update mode only the capture ends and the client keeps talking to
    /// the upstream.
    #[serde_as(as = "Option<serde_with::DurationSecondsWithFrac<f64>>")]
    #[serde(alias = "max_connection_duration_secs")]
    pub max_connection_duration: Option<Duration>,

    /// How long open connections may drain on reload or shutdown before they are dropped.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(default = "default_shutdown_timeout", alias = "shutdown_timeout_secs")]
    pub shutdown_timeout: Duration,

    /// How long a client may take to complete its TLS handshake before it is dropped, so clients
    /// that never send a ClientHello can't hold a connection or capture slot.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(
        default = "default_handshake_timeout",
        alias = "handshake_timeout_secs"
    )]
    pub handshake_timeout: Duration,

    /// Maximum payload of one captured `Data` message.
    #[serde(default = "default_max_chunk_bytes")]
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub max_chunk_bytes: NonZeroUsize,

    /// The relocated old source. Present means update mode.
    #[configurable(derived)]
    pub upstream: Option<TcpUpstream>,
}

/// Upstream source for a TCP input.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TcpUpstream {
    /// Address the upstream source listens on.
    pub address: SocketAddr,

    /// How long to wait for the upstream to accept a connection.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(default = "default_connect_timeout", alias = "connect_timeout_secs")]
    pub connect_timeout: Duration,

    #[configurable(derived)]
    #[serde(default)]
    pub capture: UpstreamCapture,
}

/// UDP listener.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct UdpInput {
    /// The public address to listen on.
    pub address: SocketListenAddr,

    /// Maximum datagram size, in both directions: client datagrams and the replies sent back to
    /// clients. Longer datagrams are truncated.
    #[serde(default = "default_max_length")]
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub max_length: NonZeroUsize,

    /// The size of the socket receive buffer.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub receive_buffer_bytes: Option<usize>,

    /// Client allowlist, copied from the client-facing source definition.
    #[configurable(derived)]
    pub permit_origin: Option<IpAllowlistConfig>,

    /// A datagram session ends after this much idle time.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(
        default = "default_session_idle_timeout",
        alias = "session_idle_timeout_secs"
    )]
    pub session_idle_timeout: Duration,

    /// The relocated old source. Present means update mode.
    #[configurable(derived)]
    pub upstream: Option<UdpUpstream>,
}

/// Upstream source for a UDP input.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct UdpUpstream {
    /// Address the upstream source listens on.
    pub address: SocketAddr,

    /// Concurrent client sessions. Each one holds an upstream socket until it goes idle; datagrams
    /// from further clients are dropped.
    #[serde(default = "default_max_peers")]
    #[configurable(metadata(docs::type_unit = "sessions"))]
    pub max_peers: NonZeroUsize,

    #[configurable(derived)]
    #[serde(default)]
    pub capture: UpstreamCapture,
}

/// Unix stream listener.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct UnixStreamInput {
    /// The public socket path to listen on.
    pub path: PathBuf,

    /// Unix file mode bits applied to the socket file.
    pub socket_file_mode: Option<u32>,

    /// The maximum number of client connections allowed at any given time.
    #[configurable(metadata(docs::type_unit = "connections"))]
    pub connection_limit: Option<u32>,

    /// How long open connections may drain on reload or shutdown before they are dropped.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(default = "default_shutdown_timeout", alias = "shutdown_timeout_secs")]
    pub shutdown_timeout: Duration,

    /// Maximum payload of one captured `Data` message.
    #[serde(default = "default_max_chunk_bytes")]
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub max_chunk_bytes: NonZeroUsize,

    /// The relocated old source. Present means update mode.
    #[configurable(derived)]
    pub upstream: Option<UnixStreamUpstream>,
}

/// Upstream source for a Unix stream input.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct UnixStreamUpstream {
    /// Socket path the upstream source listens on.
    pub path: PathBuf,

    /// How long to wait for the upstream to accept a connection.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(default = "default_connect_timeout", alias = "connect_timeout_secs")]
    pub connect_timeout: Duration,

    #[configurable(derived)]
    #[serde(default)]
    pub capture: UpstreamCapture,
}

/// Unix datagram listener.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct UnixDatagramInput {
    /// The public socket path to listen on.
    pub path: PathBuf,

    /// Unix file mode bits applied to the socket file.
    pub socket_file_mode: Option<u32>,

    /// Maximum datagram size, in both directions: client datagrams and the replies sent back to
    /// clients. Longer datagrams are truncated.
    #[serde(default = "default_max_length")]
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub max_length: NonZeroUsize,

    /// A datagram session ends after this much idle time.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(
        default = "default_session_idle_timeout",
        alias = "session_idle_timeout_secs"
    )]
    pub session_idle_timeout: Duration,

    /// The relocated old source. Present means update mode.
    #[configurable(derived)]
    pub upstream: Option<UnixDatagramUpstream>,
}

/// Upstream source for a Unix datagram input.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct UnixDatagramUpstream {
    /// Socket path the upstream source listens on.
    pub path: PathBuf,

    /// Concurrent client sessions. Each one holds an upstream socket until it goes idle; datagrams
    /// from further clients are dropped.
    #[serde(default = "default_max_peers")]
    #[configurable(metadata(docs::type_unit = "sessions"))]
    pub max_peers: NonZeroUsize,

    #[configurable(derived)]
    #[serde(default)]
    pub capture: UpstreamCapture,
}

/// Capture settings that only exist in update mode.
///
/// New mode has no tee queue, and an unsampled session would have nowhere to go.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamCapture {
    #[configurable(derived)]
    pub sampling: CaptureSampling,

    /// Per-session tee queue. When it overflows the excess is dropped and a `Gap` is sent; the
    /// upstream is never slowed down.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub buffer_bytes: NonZeroUsize,
}

impl Default for UpstreamCapture {
    fn default() -> Self {
        Self {
            sampling: CaptureSampling::default(),
            buffer_bytes: NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
        }
    }
}

/// Which share of the traffic is captured.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct CaptureSampling {
    /// Fraction captured, in (0, 1]. Sampled per session for stream transports and per datagram
    /// for datagram transports. Unsampled traffic is still proxied to the upstream.
    pub rate: f64,
}

impl Default for CaptureSampling {
    fn default() -> Self {
        Self { rate: 1.0 }
    }
}

/// The capture branch: a gRPC `Beam` stream to control-agent.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    /// control-agent `Beam` endpoint, such as `https://control-agent:9443`.
    #[configurable(metadata(docs::examples = "https://control-agent:9443"))]
    pub endpoint: String,

    /// The source-test run this capture belongs to.
    pub run_id: String,

    #[configurable(derived)]
    pub auth: CaptureAuth,

    /// Client TLS for the gRPC channel.
    #[configurable(derived)]
    pub tls: Option<TlsEnableableConfig>,

    /// How long to wait for the TCP connection to control-agent.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(default = "default_connect_timeout", alias = "connect_timeout_secs")]
    pub connect_timeout: Duration,

    #[configurable(derived)]
    #[serde(default)]
    pub reconnect_backoff: ReconnectBackoff,

    #[configurable(derived)]
    #[serde(default)]
    pub limits: CaptureLimits,
}

/// Authentication towards control-agent.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CaptureAuth {
    /// Bearer token sent as `authorization` metadata on every RPC.
    pub token: AuthTokenConfig,
}

/// Backoff for re-establishing the control stream.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct ReconnectBackoff {
    /// First delay after a failure. Must be positive and at most `max`.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(alias = "initial_secs")]
    pub initial: Duration,

    /// Upper bound for the delay.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(alias = "max_secs")]
    pub max: Duration,
}

impl Default for ReconnectBackoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
        }
    }
}

/// Bounds on the cost of capture, per BSP instance.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct CaptureLimits {
    /// Concurrent captured sessions.
    pub max_sessions: NonZeroUsize,

    /// Capture budget for this instance. Once spent, no new sessions are captured, and BSP reports
    /// it to control-agent.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub max_bytes: NonZeroU64,

    /// Capture rate across all sessions.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub max_bytes_per_sec: NonZeroU64,

    /// Per-session capture cap. For datagram transports, a peer's next datagram after the cap
    /// starts a new session.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub max_session_bytes: NonZeroU64,

    /// How long a captured session may take, once its connection has ended, to deliver what is
    /// still queued and end its `Session` RPC. After that the RPC is cancelled and its slot
    /// freed. In new mode it also ends a session whose client has closed its side once
    /// control-agent has sent nothing for this long.
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    #[serde(alias = "finish_timeout_secs")]
    pub finish_timeout: Duration,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_sessions: NonZeroUsize::new(200).unwrap(),
            max_bytes: NonZeroU64::new(2 * 1024 * 1024 * 1024).unwrap(),
            max_bytes_per_sec: NonZeroU64::new(10 * 1024 * 1024).unwrap(),
            max_session_bytes: NonZeroU64::new(256 * 1024 * 1024).unwrap(),
            finish_timeout: Duration::from_secs(30),
        }
    }
}
