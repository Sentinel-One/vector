//! Operational limits shared across sources, transforms and sinks.
//!
//! Each group of limits (compression, framing, connection, ...) is carried in `GlobalOptions` and
//! resolved per-component against an optional override, so a deployment sets one ceiling and
//! individual pipelines may only tighten it, never loosen it, unless explicitly permitted. See
//! [`OperationalLimits::resolve`].

use std::{fmt, str::FromStr, sync::OnceLock};

use vector_config::configurable_component;

/// An `ops_limits` environment override that is set but is not a positive integer within range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidEnvOverride {
    /// The environment variable holding the value.
    pub variable: &'static str,
    /// The raw value it was set to.
    pub value: String,
}

impl fmt::Display for InvalidEnvOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid value {:?} for {}: expected a positive integer within range",
            self.value, self.variable
        )
    }
}

impl std::error::Error for InvalidEnvOverride {}

/// Why [`init_env_defaults`] refused to fix the `ops_limits` defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitEnvDefaultsError {
    /// One or more `VECTOR_OPS_LIMITS_*` variables are set but are not positive integers in range.
    InvalidOverrides(Vec<InvalidEnvOverride>),
    /// The defaults were already fixed by an earlier call.
    AlreadyInitialized,
}

impl fmt::Display for InitEnvDefaultsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOverrides(errors) => {
                let details: Vec<String> = errors.iter().map(ToString::to_string).collect();
                write!(f, "{}", details.join("; "))
            }
            Self::AlreadyInitialized => write!(f, "ops_limits defaults were already initialized"),
        }
    }
}

impl std::error::Error for InitEnvDefaultsError {}

/// Resolves a default from the raw value of environment variable `name`.
///
/// Unset uses `default`. A positive integer (surrounding whitespace allowed) uses that value.
/// Anything else is an error, so a mistyped override can never be silently replaced by `default`.
fn resolve_env_default<T>(
    name: &'static str,
    raw: Option<&str>,
    default: T,
) -> Result<T, InvalidEnvOverride>
where
    T: FromStr + Default + PartialEq,
{
    let Some(raw) = raw else {
        return Ok(default);
    };
    match raw.trim().parse::<T>() {
        Ok(value) if value != T::default() => Ok(value),
        _ => Err(InvalidEnvOverride {
            variable: name,
            value: raw.to_owned(),
        }),
    }
}

/// Overrides the built-in default for `compression.max_decompressed_size_bytes` when set to a
/// positive integer.
pub const MAX_DECOMPRESSED_SIZE_BYTES_ENV: &str = "VECTOR_OPS_LIMITS_MAX_DECOMPRESSED_SIZE_BYTES";

/// Overrides the built-in default for `framing.max_frame_length_bytes` when set to a positive
/// integer.
pub const MAX_FRAME_LENGTH_BYTES_ENV: &str = "VECTOR_OPS_LIMITS_MAX_FRAME_LENGTH_BYTES";

/// Overrides the built-in default for `connection.ack_write_timeout_secs` when set to a positive
/// integer.
pub const ACK_WRITE_TIMEOUT_SECS_ENV: &str = "VECTOR_OPS_LIMITS_ACK_WRITE_TIMEOUT_SECS";

/// The `ops_limits` defaults in effect for this process: each compiled constant, unless its
/// environment variable overrides it.
struct EnvDefaults {
    max_decompressed_size_bytes: usize,
    max_frame_length_bytes: usize,
    ack_write_timeout_secs: u64,
}

impl EnvDefaults {
    /// Resolves every override, reporting all invalid ones rather than stopping at the first.
    fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, Vec<InvalidEnvOverride>> {
        match (
            resolve_env_default(
                MAX_DECOMPRESSED_SIZE_BYTES_ENV,
                lookup(MAX_DECOMPRESSED_SIZE_BYTES_ENV).as_deref(),
                DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES,
            ),
            resolve_env_default(
                MAX_FRAME_LENGTH_BYTES_ENV,
                lookup(MAX_FRAME_LENGTH_BYTES_ENV).as_deref(),
                DEFAULT_MAX_FRAME_LENGTH_BYTES,
            ),
            resolve_env_default(
                ACK_WRITE_TIMEOUT_SECS_ENV,
                lookup(ACK_WRITE_TIMEOUT_SECS_ENV).as_deref(),
                DEFAULT_ACK_WRITE_TIMEOUT_SECS,
            ),
        ) {
            (
                Ok(max_decompressed_size_bytes),
                Ok(max_frame_length_bytes),
                Ok(ack_write_timeout_secs),
            ) => Ok(Self {
                max_decompressed_size_bytes,
                max_frame_length_bytes,
                ack_write_timeout_secs,
            }),
            (decompressed, frame, ack) => Err([decompressed.err(), frame.err(), ack.err()]
                .into_iter()
                .flatten()
                .collect()),
        }
    }
}

/// Set once at process bootstrap by [`init_env_defaults`].
static ENV_DEFAULTS: OnceLock<EnvDefaults> = OnceLock::new();

/// Used until [`init_env_defaults`] runs, and in processes that never call it (tests, benches,
/// library use).
static BUILT_IN_DEFAULTS: EnvDefaults = EnvDefaults {
    max_decompressed_size_bytes: DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES,
    max_frame_length_bytes: DEFAULT_MAX_FRAME_LENGTH_BYTES,
    ack_write_timeout_secs: DEFAULT_ACK_WRITE_TIMEOUT_SECS,
};

/// Reads the `VECTOR_OPS_LIMITS_*` environment overrides and fixes the `ops_limits` defaults for
/// the rest of the process.
///
/// Call exactly once at bootstrap, before any config is loaded.
///
/// # Errors
///
/// - [`InitEnvDefaultsError::InvalidOverrides`] lists every override that is set but is not a
///   positive integer within range. Nothing is stored, and the caller should refuse to start.
/// - [`InitEnvDefaultsError::AlreadyInitialized`] if the defaults were already fixed; they are left
///   unchanged.
pub fn init_env_defaults() -> Result<(), InitEnvDefaultsError> {
    let lookup =
        |name: &str| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
    let defaults =
        EnvDefaults::from_lookup(lookup).map_err(InitEnvDefaultsError::InvalidOverrides)?;
    ENV_DEFAULTS
        .set(defaults)
        .map_err(|_| InitEnvDefaultsError::AlreadyInitialized)?;

    let defaults = env_defaults();
    let source = |name: &str| {
        if lookup(name).is_some() {
            "env"
        } else {
            "built-in"
        }
    };
    tracing::info!(
        message =
            "Resolved ops_limits defaults. They apply to any ops_limits field not set in config.",
        max_decompressed_size_bytes = defaults.max_decompressed_size_bytes,
        max_decompressed_size_bytes_source = source(MAX_DECOMPRESSED_SIZE_BYTES_ENV),
        max_frame_length_bytes = defaults.max_frame_length_bytes,
        max_frame_length_bytes_source = source(MAX_FRAME_LENGTH_BYTES_ENV),
        ack_write_timeout_secs = defaults.ack_write_timeout_secs,
        ack_write_timeout_secs_source = source(ACK_WRITE_TIMEOUT_SECS_ENV),
    );
    Ok(())
}

fn env_defaults() -> &'static EnvDefaults {
    ENV_DEFAULTS.get().unwrap_or(&BUILT_IN_DEFAULTS)
}

/// Default cap on the size of any decompressed payload.
///
/// Prevents a compressed "bomb" from causing unbounded memory growth.
const DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES: usize = 1000 * 1024 * 1024;

/// RFC 9659 window ceiling for zstd under HTTP `Content-Encoding: zstd`: conformant senders use a
/// `Window_Size` of at most 8 MB (2^23) and decoders need only support up to that. Governs HTTP
/// content coding only; other transports (gRPC/OTLP, whose clients are not bound by RFC 9659 and
/// may legitimately use larger windows) are not clamped to it.
/// See <https://www.rfc-editor.org/info/rfc9659/>.
pub const HTTP_ZSTD_WINDOW_LOG_MAX: u32 = 23;

/// Limits applied wherever Vector decompresses data it did not produce.
///
/// Carried in `GlobalOptions`, so every component reaches it through its own context
/// (`SourceContext` / `SinkContext` / `TransformContext`) rather than reading process state. That
/// keeps the limit configurable per deployment and lets a test drive a decoder at any cap simply
/// by constructing this.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionLimits {
    /// Maximum number of bytes a single payload may occupy once decompressed.
    ///
    /// Sources that decompress incoming payloads (gzip, zlib, zstd) enforce this so a compressed
    /// "bomb" cannot exhaust memory. A payload exceeding it is rejected.
    ///
    /// When unset, defaults to the `VECTOR_OPS_LIMITS_MAX_DECOMPRESSED_SIZE_BYTES` environment variable if it is set, otherwise
    /// to the built-in default. Vector refuses to start if that variable is not a positive integer.
    #[serde(default = "default_max_decompressed_size_bytes")]
    pub max_decompressed_size_bytes: usize,
}

fn default_max_decompressed_size_bytes() -> usize {
    env_defaults().max_decompressed_size_bytes
}

impl Default for CompressionLimits {
    fn default() -> Self {
        Self {
            max_decompressed_size_bytes: default_max_decompressed_size_bytes(),
        }
    }
}

impl CompressionLimits {
    /// Builds limits with an explicit decompressed-size cap. Mostly useful in tests.
    #[must_use]
    pub const fn with_max_decompressed_size_bytes(max_decompressed_size_bytes: usize) -> Self {
        Self {
            max_decompressed_size_bytes,
        }
    }

    /// Largest compressed frame that could legitimately decompress within the cap, using zlib's
    /// worst-case expansion of 13.5% + 11 bytes.
    ///
    /// Lets a caller reject an oversized declared payload before buffering it, without rejecting a
    /// valid frame whose decompressed content stays within the cap.
    ///
    /// See <https://zlib.net/zlib_tech.html> ("the worst case ... can result in an expansion of at
    /// most 13.5%, plus eleven bytes").
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // derives from a usize; saturating math keeps it in range
    pub const fn max_zlib_compressed_frame_size_bytes(&self) -> usize {
        (self.max_decompressed_size_bytes as u64)
            .saturating_mul(1135)
            .saturating_div(1000)
            .saturating_add(11) as usize
    }

    /// Largest compressed frame that could legitimately decompress within the cap, using snappy's
    /// worst-case expansion of `32 + n + n/6`.
    ///
    /// Snappy's raw API decompresses a whole buffer in one allocation, so there is nothing to
    /// stream a cap against; the input has to be bounded before it is read. Mirrors
    /// [`Self::max_zlib_compressed_frame_size_bytes`].
    ///
    /// See <https://github.com/google/snappy/blob/main/snappy.cc> (`MaxCompressedLength`).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // derives from a usize; saturating math keeps it in range
    pub const fn max_snappy_compressed_frame_size_bytes(&self) -> usize {
        let max = self.max_decompressed_size_bytes as u64;
        max.saturating_add(max.saturating_div(6)).saturating_add(32) as usize
    }

    /// Smallest zstd `window_log_max` capable of representing the cap.
    ///
    /// A zstd frame declares a window the decoder must allocate *before* producing output, so an
    /// output-size cap alone cannot bound it. Protocol-neutral: transports with a tighter,
    /// spec-mandated window (HTTP, see [`Self::http_zstd_window_log`]) clamp further.
    #[must_use]
    #[allow(clippy::manual_clamp)] // `usize::clamp` is not const; the manual form keeps this const
    pub const fn zstd_window_log(&self) -> Option<u32> {
        const MIN_ZSTD_WINDOW_LOG: u32 = 10;
        const MAX_ZSTD_WINDOW_LOG: u32 = 31;

        match self.max_decompressed_size_bytes.checked_sub(1) {
            // A zero cap has no representable window; fall back to the smallest rather than
            // leaving the allocation guard unset.
            None => Some(MIN_ZSTD_WINDOW_LOG),
            Some(max_index) => {
                let window_log = usize::BITS - max_index.leading_zeros();
                let clamped = if window_log < MIN_ZSTD_WINDOW_LOG {
                    MIN_ZSTD_WINDOW_LOG
                } else if window_log > MAX_ZSTD_WINDOW_LOG {
                    MAX_ZSTD_WINDOW_LOG
                } else {
                    window_log
                };
                Some(clamped)
            }
        }
    }

    /// Like [`Self::zstd_window_log`] but clamped to the RFC 9659 HTTP ceiling
    /// ([`HTTP_ZSTD_WINDOW_LOG_MAX`]). Use for HTTP `Content-Encoding: zstd`.
    #[must_use]
    pub const fn http_zstd_window_log(&self) -> Option<u32> {
        match self.zstd_window_log() {
            Some(window) if window > HTTP_ZSTD_WINDOW_LOG_MAX => Some(HTTP_ZSTD_WINDOW_LOG_MAX),
            other => other,
        }
    }
}

/// Default cap on the length of a single delimited frame.
///
/// Sized well above ordinary line-oriented traffic so that unusually wide but legitimate records
/// decode without a pipeline author needing to raise it, while still bounding a peer that never
/// sends a delimiter. Deployments with larger single-line records can raise it via
/// `ops_limits.framing.max_frame_length_bytes`, `VECTOR_OPS_LIMITS_MAX_FRAME_LENGTH_BYTES`, or a
/// component's own `max_length`.
const DEFAULT_MAX_FRAME_LENGTH_BYTES: usize = 100 * 1024 * 1024;

/// Limits applied by delimited framers (`character_delimited`, `newline_delimited`,
/// `octet_counting`) while a frame is still incomplete.
///
/// Carried in `GlobalOptions`, so every component reaches it through its own context
/// (`SourceContext` / `SinkContext` / `TransformContext`) rather than reading process state.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramingLimits {
    /// Maximum length, in bytes, of a single delimited frame.
    ///
    /// Delimited framers buffer bytes until they see their delimiter, so a peer that never sends
    /// one would otherwise grow the per-connection buffer without bound. A frame that reaches this
    /// limit while still incomplete is a fatal decode error and the connection is reset.
    ///
    /// When unset, defaults to the `VECTOR_OPS_LIMITS_MAX_FRAME_LENGTH_BYTES` environment variable if it is set, otherwise
    /// to the built-in default. Vector refuses to start if that variable is not a positive integer.
    #[serde(default = "default_max_frame_length_bytes")]
    pub max_frame_length_bytes: usize,
}

fn default_max_frame_length_bytes() -> usize {
    env_defaults().max_frame_length_bytes
}

impl Default for FramingLimits {
    fn default() -> Self {
        Self {
            max_frame_length_bytes: default_max_frame_length_bytes(),
        }
    }
}

impl FramingLimits {
    /// Builds limits with an explicit frame-length cap. Mostly useful in tests.
    #[must_use]
    pub const fn with_max_frame_length_bytes(max_frame_length_bytes: usize) -> Self {
        Self {
            max_frame_length_bytes,
        }
    }
}

/// Default timeout for writing an acknowledgement back to a TCP peer, in seconds.
///
/// `write_all` progresses only as the peer's TCP receive window opens, so a peer that simply
/// stops calling `recv()` would otherwise park the write - and with it the task, socket and fd -
/// indefinitely. Generous enough that a merely slow client is never dropped.
const DEFAULT_ACK_WRITE_TIMEOUT_SECS: u64 = 300;

/// Limits applied to per-connection network operations, such as writing an acknowledgement back
/// to a peer.
///
/// Carried in `GlobalOptions`, so every component reaches it through its own context
/// (`SourceContext` / `SinkContext` / `TransformContext`) rather than reading process state.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// How long, in seconds, to wait for a peer to accept an acknowledgement before treating the
    /// connection as stalled and dropping it.
    ///
    /// When unset, defaults to the `VECTOR_OPS_LIMITS_ACK_WRITE_TIMEOUT_SECS` environment variable if it is set, otherwise
    /// to the built-in default. Vector refuses to start if that variable is not a positive integer.
    #[serde(default = "default_ack_write_timeout_secs")]
    pub ack_write_timeout_secs: u64,
}

fn default_ack_write_timeout_secs() -> u64 {
    env_defaults().ack_write_timeout_secs
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            ack_write_timeout_secs: default_ack_write_timeout_secs(),
        }
    }
}

/// Operational limits carried in `GlobalOptions`.
///
/// A single place to hang caps that components need but should not read from process state. Add
/// further groups here rather than introducing new globals.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationalLimits {
    /// Limits applied wherever Vector decompresses data it did not produce.
    #[configurable(derived)]
    #[serde(default)]
    pub compression: CompressionLimits,

    /// Limits applied by delimited framers while a frame is still incomplete.
    #[configurable(derived)]
    #[serde(default)]
    pub framing: FramingLimits,

    /// Limits applied to per-connection network operations.
    #[configurable(derived)]
    #[serde(default)]
    pub connection: ConnectionLimits,
}

/// Per-component override of [`CompressionLimits`].
///
/// Every field is optional so that "not set" stays distinct from "set to the default". Without
/// that distinction a component that says nothing would look like it were asking for the default
/// value, and could not be told apart from one that deliberately asked for it.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompressionLimitsOverride {
    /// Overrides [`CompressionLimits::max_decompressed_size_bytes`] for this component.
    ///
    /// A value below the global limit always applies. A value above it is clamped back to the
    /// global limit unless Vector is started with `--allow-component-limit-overrides`, so that a
    /// ceiling chosen by whoever runs the process cannot be lifted by editing pipeline config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_decompressed_size_bytes: Option<usize>,
}

/// Per-component override of [`FramingLimits`].
///
/// Every field is optional so that "not set" stays distinct from "set to the default". Without
/// that distinction a component that says nothing would look like it were asking for the default
/// value, and could not be told apart from one that deliberately asked for it.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FramingLimitsOverride {
    /// Overrides [`FramingLimits::max_frame_length_bytes`] for this component.
    ///
    /// A value below the global limit always applies. A value above it is clamped back to the
    /// global limit unless Vector is started with `--allow-component-limit-overrides`, so that a
    /// ceiling chosen by whoever runs the process cannot be lifted by editing pipeline config.
    /// Individual framing codecs also expose their own `max_length` option, which is unaffected by
    /// this override and always applies as given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_frame_length_bytes: Option<usize>,
}

/// Per-component override of [`ConnectionLimits`].
///
/// Every field is optional so that "not set" stays distinct from "set to the default". Without
/// that distinction a component that says nothing would look like it were asking for the default
/// value, and could not be told apart from one that deliberately asked for it.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionLimitsOverride {
    /// Overrides [`ConnectionLimits::ack_write_timeout_secs`] for this component.
    ///
    /// A value below the global limit always applies. A value above it is clamped back to the
    /// global limit unless Vector is started with `--allow-component-limit-overrides`, so that a
    /// ceiling chosen by whoever runs the process cannot be lifted by editing pipeline config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_write_timeout_secs: Option<u64>,
}

/// Per-component override of [`OperationalLimits`].
///
/// Attached to every source, transform and sink. Unset fields inherit the global value.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationalLimitsOverride {
    /// Overrides the global decompression limits for this component.
    #[configurable(derived)]
    #[serde(default)]
    pub compression: CompressionLimitsOverride,

    /// Overrides the global framing limits for this component.
    #[configurable(derived)]
    #[serde(default)]
    pub framing: FramingLimitsOverride,

    /// Overrides the global connection limits for this component.
    #[configurable(derived)]
    #[serde(default)]
    pub connection: ConnectionLimitsOverride,
}

impl OperationalLimitsOverride {
    /// Whether this component asked for anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A component asking for a limit lesser than the global one allows.
///
/// Reported so the same raise can be surfaced as a config warning (at startup, reload and
/// `vector validate`) and acted on when the topology is built, without the two disagreeing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitRaise {
    /// Config path of the limit, relative to the component, for use in messages.
    pub field: &'static str,
    /// What the component asked for.
    pub requested: u64,
    /// What the global limit permits.
    pub allowed: u64,
}

impl fmt::Display for LimitRaise {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} = {}, above the global limit of {}",
            self.field, self.requested, self.allowed
        )
    }
}

impl OperationalLimits {
    /// Logs these limits as the global values the process enforces: the config file's
    /// `ops_limits`, with unset fields filled from the defaults. Components may still lower them,
    /// or raise them with `--allow-component-limit-overrides`.
    pub fn log_effective(&self) {
        tracing::info!(
            message = "Effective global ops_limits.",
            max_decompressed_size_bytes = self.compression.max_decompressed_size_bytes,
            max_frame_length_bytes = self.framing.max_frame_length_bytes,
            ack_write_timeout_secs = self.connection.ack_write_timeout_secs,
        );
    }

    /// Applies a component's override to these global limits.
    ///
    /// Returns the limits the component should actually run under, together with every raise it
    /// asked for. A raise is granted only when `allow_raise` is set; otherwise it is clamped back
    /// to the global value. Lowering is always granted — a component may be stricter than the
    /// deployment, never looser than the operator permits.
    ///
    /// Raises are reported whether or not they were granted, so a caller can warn in both cases.
    #[must_use]
    pub fn resolve(
        &self,
        over: &OperationalLimitsOverride,
        allow_raise: bool,
    ) -> (Self, Vec<LimitRaise>) {
        let mut resolved = *self;
        let mut raises = Vec::new();

        if let Some(requested) = over.compression.max_decompressed_size_bytes {
            let allowed = self.compression.max_decompressed_size_bytes;
            if requested > allowed {
                raises.push(LimitRaise {
                    field: "ops_limits.compression.max_decompressed_size_bytes",
                    requested: requested as u64,
                    allowed: allowed as u64,
                });
            }
            resolved.compression.max_decompressed_size_bytes =
                if requested > allowed && !allow_raise {
                    allowed
                } else {
                    requested
                };
        }

        if let Some(requested) = over.framing.max_frame_length_bytes {
            let allowed = self.framing.max_frame_length_bytes;
            if requested > allowed {
                raises.push(LimitRaise {
                    field: "ops_limits.framing.max_frame_length_bytes",
                    requested: requested as u64,
                    allowed: allowed as u64,
                });
            }
            resolved.framing.max_frame_length_bytes = if requested > allowed && !allow_raise {
                allowed
            } else {
                requested
            };
        }

        if let Some(requested) = over.connection.ack_write_timeout_secs {
            let allowed = self.connection.ack_write_timeout_secs;
            if requested > allowed {
                raises.push(LimitRaise {
                    field: "ops_limits.connection.ack_write_timeout_secs",
                    requested,
                    allowed,
                });
            }
            resolved.connection.ack_write_timeout_secs = if requested > allowed && !allow_raise {
                allowed
            } else {
                requested
            };
        }

        (resolved, raises)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAR: &str = "VECTOR_OPS_LIMITS_TEST_ONLY";

    fn lookup_from(
        pairs: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn env_default_uses_compiled_value_when_unset() {
        assert_eq!(resolve_env_default(VAR, None, 42_usize), Ok(42));
    }

    #[test]
    fn env_default_uses_positive_integer_from_env() {
        assert_eq!(
            resolve_env_default(VAR, Some("1048576"), 42_usize),
            Ok(1_048_576)
        );
        assert_eq!(resolve_env_default(VAR, Some(" 300 "), 30_u64), Ok(300));
        assert_eq!(resolve_env_default(VAR, Some("1"), 30_u64), Ok(1));
    }

    #[test]
    fn env_default_rejects_values_that_are_not_positive_integers_in_range() {
        for raw in [
            "",
            "   ",
            "abc",
            "-5",
            "0",
            "1.5",
            "10MiB",
            "0x10",
            "99999999999999999999",
        ] {
            assert_eq!(
                resolve_env_default(VAR, Some(raw), 42_usize),
                Err(InvalidEnvOverride {
                    variable: VAR,
                    value: raw.to_owned(),
                }),
                "input {raw:?}"
            );
        }
    }

    #[test]
    fn env_default_rejects_u64_overflow_for_timeouts() {
        assert!(resolve_env_default(VAR, Some("18446744073709551616"), 30_u64).is_err());
        assert_eq!(
            resolve_env_default(VAR, Some("18446744073709551615"), 30_u64),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn invalid_env_override_message_names_variable_and_value() {
        let error = InvalidEnvOverride {
            variable: MAX_FRAME_LENGTH_BYTES_ENV,
            value: "abc".to_owned(),
        };
        let message = error.to_string();
        assert!(message.contains(MAX_FRAME_LENGTH_BYTES_ENV), "{message}");
        assert!(message.contains("\"abc\""), "{message}");
    }

    #[test]
    fn init_error_messages_describe_the_failure() {
        let invalid = InitEnvDefaultsError::InvalidOverrides(vec![
            InvalidEnvOverride {
                variable: MAX_FRAME_LENGTH_BYTES_ENV,
                value: "abc".to_owned(),
            },
            InvalidEnvOverride {
                variable: ACK_WRITE_TIMEOUT_SECS_ENV,
                value: "0".to_owned(),
            },
        ])
        .to_string();
        assert!(invalid.contains(MAX_FRAME_LENGTH_BYTES_ENV), "{invalid}");
        assert!(invalid.contains(ACK_WRITE_TIMEOUT_SECS_ENV), "{invalid}");
        let twice = InitEnvDefaultsError::AlreadyInitialized.to_string();
        assert!(twice.contains("already"), "{twice}");
    }

    #[test]
    fn env_defaults_read_each_field_from_its_own_variable() {
        let defaults = EnvDefaults::from_lookup(lookup_from(&[
            (MAX_DECOMPRESSED_SIZE_BYTES_ENV, "1000"),
            (MAX_FRAME_LENGTH_BYTES_ENV, "2000"),
            (ACK_WRITE_TIMEOUT_SECS_ENV, "3"),
        ]))
        .unwrap();
        assert_eq!(defaults.max_decompressed_size_bytes, 1000);
        assert_eq!(defaults.max_frame_length_bytes, 2000);
        assert_eq!(defaults.ack_write_timeout_secs, 3);
    }

    #[test]
    fn env_defaults_override_only_the_variables_that_are_set() {
        let defaults =
            EnvDefaults::from_lookup(lookup_from(&[(MAX_FRAME_LENGTH_BYTES_ENV, "2000")])).unwrap();
        assert_eq!(
            defaults.max_decompressed_size_bytes,
            DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES
        );
        assert_eq!(defaults.max_frame_length_bytes, 2000);
        assert_eq!(
            defaults.ack_write_timeout_secs,
            DEFAULT_ACK_WRITE_TIMEOUT_SECS
        );
    }

    #[test]
    fn env_defaults_fall_back_to_compiled_constants_when_unset() {
        let defaults = EnvDefaults::from_lookup(|_| None).unwrap();
        assert_eq!(
            defaults.max_decompressed_size_bytes,
            DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES
        );
        assert_eq!(
            defaults.max_frame_length_bytes,
            DEFAULT_MAX_FRAME_LENGTH_BYTES
        );
        assert_eq!(
            defaults.ack_write_timeout_secs,
            DEFAULT_ACK_WRITE_TIMEOUT_SECS
        );
    }

    #[test]
    fn env_defaults_report_the_invalid_variable() {
        let errors = EnvDefaults::from_lookup(lookup_from(&[
            (MAX_DECOMPRESSED_SIZE_BYTES_ENV, "1000"),
            (MAX_FRAME_LENGTH_BYTES_ENV, "abc"),
        ]))
        .err()
        .unwrap();
        assert_eq!(
            errors,
            vec![InvalidEnvOverride {
                variable: MAX_FRAME_LENGTH_BYTES_ENV,
                value: "abc".to_owned(),
            }]
        );
    }

    #[test]
    fn env_defaults_report_every_invalid_variable() {
        let errors = EnvDefaults::from_lookup(lookup_from(&[
            (MAX_DECOMPRESSED_SIZE_BYTES_ENV, "0"),
            (MAX_FRAME_LENGTH_BYTES_ENV, "abc"),
            (ACK_WRITE_TIMEOUT_SECS_ENV, "-1"),
        ]))
        .err()
        .unwrap();
        let variables: Vec<_> = errors.iter().map(|error| error.variable).collect();
        assert_eq!(
            variables,
            vec![
                MAX_DECOMPRESSED_SIZE_BYTES_ENV,
                MAX_FRAME_LENGTH_BYTES_ENV,
                ACK_WRITE_TIMEOUT_SECS_ENV
            ]
        );
    }

    #[test]
    fn defaults_are_built_in_until_bootstrap_reads_the_env() {
        assert_eq!(
            FramingLimits::default().max_frame_length_bytes,
            DEFAULT_MAX_FRAME_LENGTH_BYTES
        );
        assert_eq!(
            CompressionLimits::default().max_decompressed_size_bytes,
            DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES
        );
        assert_eq!(
            ConnectionLimits::default().ack_write_timeout_secs,
            DEFAULT_ACK_WRITE_TIMEOUT_SECS
        );
    }

    #[test]
    fn built_in_defaults() {
        assert_eq!(DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES, 1000 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_FRAME_LENGTH_BYTES, 100 * 1024 * 1024);
        assert_eq!(DEFAULT_ACK_WRITE_TIMEOUT_SECS, 300);
    }

    #[test]
    fn default_impls_match_serde_defaults_for_missing_fields() {
        let parsed: OperationalLimits = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, OperationalLimits::default());
    }

    #[test]
    fn config_value_wins_over_env_default() {
        let parsed: OperationalLimits =
            serde_json::from_str(r#"{"framing":{"max_frame_length_bytes":4096}}"#).unwrap();
        assert_eq!(parsed.framing.max_frame_length_bytes, 4096);
    }

    #[tracing_test::traced_test]
    #[test]
    fn log_effective_reports_the_values_in_use() {
        let limits: OperationalLimits = serde_json::from_str(
            r#"{"compression":{"max_decompressed_size_bytes":536870912},
                "framing":{"max_frame_length_bytes":10485760},
                "connection":{"ack_write_timeout_secs":30}}"#,
        )
        .unwrap();
        limits.log_effective();
        assert!(logs_contain("Effective global ops_limits."));
        assert!(logs_contain("max_decompressed_size_bytes=536870912"));
        assert!(logs_contain("max_frame_length_bytes=10485760"));
        assert!(logs_contain("ack_write_timeout_secs=30"));
    }

    #[test]
    fn zstd_window_log_tracks_the_cap() {
        // 100 MiB needs a 2^27 window; the HTTP variant is clamped to RFC 9659's 2^23.
        assert_eq!(
            CompressionLimits::with_max_decompressed_size_bytes(100 * 1024 * 1024)
                .zstd_window_log(),
            Some(27)
        );
        assert_eq!(
            CompressionLimits::with_max_decompressed_size_bytes(100 * 1024 * 1024)
                .http_zstd_window_log(),
            Some(HTTP_ZSTD_WINDOW_LOG_MAX)
        );
        // A zero cap clamps to the tightest window rather than disabling the guard.
        assert_eq!(
            CompressionLimits::with_max_decompressed_size_bytes(0).zstd_window_log(),
            Some(10)
        );
    }

    // ---- component limit overrides ------------------------------------------------------------

    fn global(max: usize) -> OperationalLimits {
        OperationalLimits {
            compression: CompressionLimits::with_max_decompressed_size_bytes(max),
            framing: FramingLimits::default(),
            connection: ConnectionLimits::default(),
        }
    }

    fn asking(max: usize) -> OperationalLimitsOverride {
        OperationalLimitsOverride {
            compression: CompressionLimitsOverride {
                max_decompressed_size_bytes: Some(max),
            },
            framing: FramingLimitsOverride::default(),
            connection: ConnectionLimitsOverride::default(),
        }
    }

    fn global_framing(max: usize) -> OperationalLimits {
        OperationalLimits {
            compression: CompressionLimits::default(),
            framing: FramingLimits::with_max_frame_length_bytes(max),
            connection: ConnectionLimits::default(),
        }
    }

    fn asking_framing(max: usize) -> OperationalLimitsOverride {
        OperationalLimitsOverride {
            compression: CompressionLimitsOverride::default(),
            framing: FramingLimitsOverride {
                max_frame_length_bytes: Some(max),
            },
            connection: ConnectionLimitsOverride::default(),
        }
    }

    fn global_connection(ack_write_timeout_secs: u64) -> OperationalLimits {
        OperationalLimits {
            compression: CompressionLimits::default(),
            framing: FramingLimits::default(),
            connection: ConnectionLimits {
                ack_write_timeout_secs,
            },
        }
    }

    fn asking_connection(ack_write_timeout_secs: u64) -> OperationalLimitsOverride {
        OperationalLimitsOverride {
            compression: CompressionLimitsOverride::default(),
            framing: FramingLimitsOverride::default(),
            connection: ConnectionLimitsOverride {
                ack_write_timeout_secs: Some(ack_write_timeout_secs),
            },
        }
    }

    /// The common case: the component says nothing, so it runs under the deployment's limits and
    /// there is nothing to warn about.
    #[test]
    fn an_empty_override_inherits_the_global_limits() {
        let (resolved, raises) = global(1024).resolve(&OperationalLimitsOverride::default(), false);

        assert_eq!(resolved, global(1024));
        assert!(raises.is_empty());
        assert!(OperationalLimitsOverride::default().is_empty());
    }

    /// A component may always be stricter than the deployment.
    #[test]
    fn lowering_is_always_granted() {
        for allow_raise in [false, true] {
            let (resolved, raises) = global(1024).resolve(&asking(512), allow_raise);

            assert_eq!(resolved.compression.max_decompressed_size_bytes, 512);
            assert!(raises.is_empty(), "lowering is not a raise");
        }
    }

    /// The whole point of the clamp: pipeline config cannot lift a ceiling the operator set.
    #[test]
    fn raising_is_clamped_by_default() {
        let (resolved, raises) = global(1024).resolve(&asking(4096), false);

        assert_eq!(
            resolved.compression.max_decompressed_size_bytes, 1024,
            "the global limit must survive a component asking for more"
        );
        assert_eq!(
            raises,
            vec![LimitRaise {
                field: "ops_limits.compression.max_decompressed_size_bytes",
                requested: 4096,
                allowed: 1024,
            }]
        );
    }

    /// The escape hatch, which only whoever starts the process can open.
    #[test]
    fn raising_is_granted_when_explicitly_allowed() {
        let (resolved, raises) = global(1024).resolve(&asking(4096), true);

        assert_eq!(resolved.compression.max_decompressed_size_bytes, 4096);
        assert_eq!(
            raises.len(),
            1,
            "a granted raise is still reported, so it can be warned about"
        );
    }

    /// Asking for exactly the global value is not a raise, so it must not warn.
    #[test]
    fn matching_the_global_limit_is_not_a_raise() {
        let (resolved, raises) = global(1024).resolve(&asking(1024), false);

        assert_eq!(resolved, global(1024));
        assert!(raises.is_empty());
    }

    /// A component that omits the field must not be treated as having asked for the default. With
    /// a global below the default, a naive merge would report a raise nobody requested.
    #[test]
    fn an_unset_field_is_not_read_as_a_request_for_the_default() {
        let strict = global(1024);
        assert!(
            strict.compression.max_decompressed_size_bytes < DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES
        );

        let (resolved, raises) = strict.resolve(&OperationalLimitsOverride::default(), false);

        assert_eq!(resolved, strict);
        assert!(raises.is_empty(), "silence is not a request");
    }

    /// An omitted override must deserialise to "unset", not to the default value.
    #[test]
    fn an_omitted_override_deserialises_as_unset() {
        let empty: OperationalLimitsOverride = serde_json::from_str("{}").unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.compression.max_decompressed_size_bytes, None);

        let set: OperationalLimitsOverride =
            serde_json::from_str(r#"{"compression":{"max_decompressed_size_bytes":512}}"#).unwrap();
        assert_eq!(set.compression.max_decompressed_size_bytes, Some(512));
    }

    // ---- framing limit overrides, mirroring the compression cases above ------------------------
    //
    // The resolution logic is shared (`resolve` applies both groups the same way), so these cases
    // exist to pin that `framing` is actually wired into it — a copy-paste that missed one branch
    // would leave this group inert while the compression tests above kept passing.

    /// A pipeline asking for a longer frame than the operator's ceiling — e.g.
    /// CloudTrail-via-`aws_s3` single-line records over 10 MB — is clamped by default.
    #[test]
    fn raising_the_frame_length_limit_is_clamped_by_default() {
        let (resolved, raises) = global_framing(1024).resolve(&asking_framing(4096), false);

        assert_eq!(
            resolved.framing.max_frame_length_bytes, 1024,
            "the global limit must survive a component asking for more"
        );
        assert_eq!(
            raises,
            vec![LimitRaise {
                field: "ops_limits.framing.max_frame_length_bytes",
                requested: 4096,
                allowed: 1024,
            }]
        );
    }

    /// The escape hatch applies to framing the same way it does to compression.
    #[test]
    fn raising_the_frame_length_limit_is_granted_when_explicitly_allowed() {
        let (resolved, raises) = global_framing(1024).resolve(&asking_framing(4096), true);

        assert_eq!(resolved.framing.max_frame_length_bytes, 4096);
        assert_eq!(raises.len(), 1);
    }

    /// A component may always ask for a stricter frame length than the deployment.
    #[test]
    fn lowering_the_frame_length_limit_is_always_granted() {
        for allow_raise in [false, true] {
            let (resolved, raises) =
                global_framing(4096).resolve(&asking_framing(1024), allow_raise);

            assert_eq!(resolved.framing.max_frame_length_bytes, 1024);
            assert!(raises.is_empty(), "lowering is not a raise");
        }
    }

    // ---- connection limit overrides, mirroring the compression/framing cases above --------------

    /// A component asking for a longer ack-write timeout than the operator's ceiling is clamped by
    /// default, the same as the byte-oriented limits.
    #[test]
    fn raising_the_ack_write_timeout_is_clamped_by_default() {
        let (resolved, raises) = global_connection(30).resolve(&asking_connection(120), false);

        assert_eq!(
            resolved.connection.ack_write_timeout_secs, 30,
            "the global limit must survive a component asking for more"
        );
        assert_eq!(
            raises,
            vec![LimitRaise {
                field: "ops_limits.connection.ack_write_timeout_secs",
                requested: 120,
                allowed: 30,
            }]
        );
    }

    /// The escape hatch applies to connection limits the same way it does to the others.
    #[test]
    fn raising_the_ack_write_timeout_is_granted_when_explicitly_allowed() {
        let (resolved, raises) = global_connection(30).resolve(&asking_connection(120), true);

        assert_eq!(resolved.connection.ack_write_timeout_secs, 120);
        assert_eq!(raises.len(), 1);
    }

    /// A component may always ask for a stricter (shorter) ack-write timeout than the deployment.
    #[test]
    fn lowering_the_ack_write_timeout_is_always_granted() {
        for allow_raise in [false, true] {
            let (resolved, raises) =
                global_connection(120).resolve(&asking_connection(30), allow_raise);

            assert_eq!(resolved.connection.ack_write_timeout_secs, 30);
            assert!(raises.is_empty(), "lowering is not a raise");
        }
    }
}
