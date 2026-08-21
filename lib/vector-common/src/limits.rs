//! Operational limits shared across sources, transforms and sinks.
//!
//! Each group of limits (compression, framing, connection, ...) is carried in `GlobalOptions` and
//! resolved per-component against an optional override, so a deployment sets one ceiling and
//! individual pipelines may only tighten it, never loosen it, unless explicitly permitted. See
//! [`OperationalLimits::resolve`].

use std::fmt;

use vector_config::configurable_component;

/// Default cap on the size of any decompressed payload.
///
/// Prevents a compressed "bomb" from causing unbounded memory growth.
pub const DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES: usize = 100 * 1024 * 1024;

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
    #[serde(default = "default_max_decompressed_size_bytes")]
    pub max_decompressed_size_bytes: usize,
}

const fn default_max_decompressed_size_bytes() -> usize {
    DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES
}

impl Default for CompressionLimits {
    fn default() -> Self {
        Self {
            max_decompressed_size_bytes: DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES,
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
/// sends a delimiter. Deployments with routinely larger single-line records (e.g.
/// CloudTrail-via-`aws_s3`, which can exceed 10 MB) still need to raise this via
/// `limits.framing.max_frame_length_bytes` or a component's own `max_length`.
pub const DEFAULT_MAX_FRAME_LENGTH_BYTES: usize = 1024 * 1024;

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
    #[serde(default = "default_max_frame_length_bytes")]
    pub max_frame_length_bytes: usize,
}

const fn default_max_frame_length_bytes() -> usize {
    DEFAULT_MAX_FRAME_LENGTH_BYTES
}

impl Default for FramingLimits {
    fn default() -> Self {
        Self {
            max_frame_length_bytes: DEFAULT_MAX_FRAME_LENGTH_BYTES,
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
pub const DEFAULT_ACK_WRITE_TIMEOUT_SECS: u64 = 30;

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
    #[serde(default = "default_ack_write_timeout_secs")]
    pub ack_write_timeout_secs: u64,
}

const fn default_ack_write_timeout_secs() -> u64 {
    DEFAULT_ACK_WRITE_TIMEOUT_SECS
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            ack_write_timeout_secs: DEFAULT_ACK_WRITE_TIMEOUT_SECS,
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
                    field: "limits.compression.max_decompressed_size_bytes",
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
                    field: "limits.framing.max_frame_length_bytes",
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
                    field: "limits.connection.ack_write_timeout_secs",
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

    #[test]
    fn default_cap_is_used_when_unset() {
        assert_eq!(
            CompressionLimits::default().max_decompressed_size_bytes,
            DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES
        );
        assert_eq!(
            FramingLimits::default().max_frame_length_bytes,
            DEFAULT_MAX_FRAME_LENGTH_BYTES
        );
        assert_eq!(
            ConnectionLimits::default().ack_write_timeout_secs,
            DEFAULT_ACK_WRITE_TIMEOUT_SECS
        );
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
                field: "limits.compression.max_decompressed_size_bytes",
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
                field: "limits.framing.max_frame_length_bytes",
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
                field: "limits.connection.ack_write_timeout_secs",
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
