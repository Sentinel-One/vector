//! Shared decompression limits used to prevent decompression-bomb (`DoS`) attacks.
//!
//! A length or compressed payload read from an untrusted peer must never drive an unbounded
//! in-memory allocation. This module owns the global decompressed-size cap and the helpers that
//! enforce it, so every source and codec that decompresses untrusted input shares a single,
//! consistently-configured limit.
//!
//! # Usage
//!
//! Wrap any decompression at an untrusted boundary with the appropriate [`CappedDecoder`]
//! constructor and call [`CappedDecoder::decompress`]:
//!
//! ```rust,ignore
//! let data = CappedDecoder::gzip(reader).decompress()?;
//! let data = CappedDecoder::zlib(reader).decompress()?;
//! let data = CappedDecoder::zstd(reader)?.decompress()?;
//! ```
//!
//! The constructors enforce the global decompressed-size cap so that a compression bomb cannot
//! drive unbounded allocation.

// Raw decoder types (flate2 / zstd) are only allowed in this module, which wraps them safely.
#![expect(
    clippy::disallowed_types,
    reason = "this module implements CappedDecoder, the safe wrapper around raw decoders; raw types may only appear here"
)]

use std::{
    fmt,
    io::{self, Read},
};

use vector_config::configurable_component;

use flate2::read::{MultiGzDecoder, ZlibDecoder};

/// Default cap on the size of any decompressed payload.
///
/// Prevents a compressed "bomb" from causing unbounded memory growth.
pub const DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES: usize = 100 * 1024 * 1024;

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
}

impl OperationalLimitsOverride {
    /// Whether this component asked for anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A component asking for a limit looser than the global one allows.
///
/// Reported so the same raise can be surfaced as a config warning (at startup, reload and
/// `vector validate`) and acted on when the topology is built, without the two disagreeing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitRaise {
    /// Config path of the limit, relative to the component, for use in messages.
    pub field: &'static str,
    /// What the component asked for.
    pub requested: usize,
    /// What the global limit permits.
    pub allowed: usize,
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
                    requested,
                    allowed,
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
                    requested,
                    allowed,
                });
            }
            resolved.framing.max_frame_length_bytes = if requested > allowed && !allow_raise {
                allowed
            } else {
                requested
            };
        }

        (resolved, raises)
    }
}

/// RFC 9659 window ceiling for zstd under HTTP `Content-Encoding: zstd`: conformant senders use a
/// `Window_Size` of at most 8 MB (2^23) and decoders need only support up to that. Governs HTTP
/// content coding only; other transports (gRPC/OTLP, whose clients are not bound by RFC 9659 and
/// may legitimately use larger windows) are not clamped to it.
/// See <https://www.rfc-editor.org/info/rfc9659/>.
pub const HTTP_ZSTD_WINDOW_LOG_MAX: u32 = 23;

/// Error raised when a decompressed payload would exceed the configured size cap.
///
/// Surfaced (wrapped in [`io::Error`]) by [`CappedDecoder::decompress`] and the [`CappedReader`]
/// returned by [`CappedDecoder::into_reader`]. Use [`DecompressedSizeLimitExceeded::is`] to detect
/// it and distinguish an oversized-input fault from an unrelated I/O error.
#[derive(Debug)]
pub struct DecompressedSizeLimitExceeded;

impl fmt::Display for DecompressedSizeLimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("decompressed size exceeds the configured limit")
    }
}

impl std::error::Error for DecompressedSizeLimitExceeded {}

impl DecompressedSizeLimitExceeded {
    /// Returns whether `error` was raised because decompression hit the size cap.
    #[must_use]
    pub fn is(error: &io::Error) -> bool {
        fn is_marker(source: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
            source.is::<DecompressedSizeLimitExceeded>()
        }

        error.get_ref().is_some_and(is_marker)
    }
}

/// A size-capped decompression reader.
///
/// Wraps any `R: Read` (typically a raw decoder like `MultiGzDecoder` or `ZlibDecoder`) and
/// enforces the configured decompressed-size cap so that a compression bomb cannot drive
/// unbounded memory allocation.
///
/// Construct via the typed class methods ([`CappedDecoder::gzip`], [`CappedDecoder::zlib`],
/// [`CappedDecoder::zstd`]) rather than by wrapping a raw decoder directly. Read the whole payload
/// into memory with [`CappedDecoder::decompress`], or stream it through [`CappedDecoder::into_reader`].
pub struct CappedDecoder<R: Read> {
    inner: io::Take<R>,
    limit: usize,
}

impl<R: Read> CappedDecoder<R> {
    fn with_limit(reader: R, limit: usize) -> Self {
        Self {
            inner: reader.take((limit as u64).saturating_add(1)),
            limit,
        }
    }

    /// Reads all decompressed bytes into a `Vec`, returning an error if the output exceeds the
    /// configured cap.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the underlying decoder fails, or
    /// [`DecompressedSizeLimitExceeded`] if the decompressed output exceeds the cap.
    pub fn decompress(self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.into_reader().read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Converts the decoder into a streaming [`CappedReader`] that enforces the cap as bytes are
    /// read, rather than buffering the whole payload up front.
    ///
    /// Prefer this over consuming a raw decoder directly: the returned reader errors out (instead
    /// of silently truncating) the moment the decompressed output would exceed the cap, so a
    /// streaming consumer such as [`io::copy`], `serde_json::from_reader`, or `BufReader` cannot
    /// process a truncated-but-valid-looking payload.
    pub fn into_reader(self) -> CappedReader<R> {
        CappedReader {
            inner: self.inner,
            limit: self.limit,
            consumed: 0,
        }
    }
}

/// A streaming, size-capped decompression reader returned by [`CappedDecoder::into_reader`].
///
/// Yields decompressed bytes incrementally and returns a [`DecompressedSizeLimitExceeded`] error
/// (wrapped in [`io::Error`]) as soon as the cumulative output would exceed the cap.
pub struct CappedReader<R: Read> {
    inner: io::Take<R>,
    limit: usize,
    consumed: usize,
}

/// The reader type produced by [`CappedDecoder::zstd`] and friends via
/// [`CappedDecoder::into_reader`].
///
/// Naming this type otherwise requires spelling the raw `zstd` decoder, which the
/// `disallowed-types` lint forbids outside this module. Store this alias instead of the raw type
/// when a struct needs to hold a capped zstd reader.
pub type CappedZstdReader<R> = CappedReader<zstd::stream::read::Decoder<'static, io::BufReader<R>>>;

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // The underlying reader is bounded one byte past the cap, so reading beyond `limit` is the
        // unambiguous signal that the payload is oversized.
        let n = self.inner.read(buf)?;
        self.consumed = self.consumed.saturating_add(n);
        if self.consumed > self.limit {
            return Err(io::Error::other(DecompressedSizeLimitExceeded));
        }
        Ok(n)
    }
}

impl<S: Read> CappedDecoder<MultiGzDecoder<S>> {
    /// Creates a capped gzip decoder.
    pub fn gzip(reader: S, limits: &CompressionLimits) -> Self {
        Self::with_limit(
            MultiGzDecoder::new(reader),
            limits.max_decompressed_size_bytes,
        )
    }
}

impl<S: Read> CappedDecoder<ZlibDecoder<S>> {
    /// Creates a capped zlib/deflate decoder.
    pub fn zlib(reader: S, limits: &CompressionLimits) -> Self {
        Self::with_limit(ZlibDecoder::new(reader), limits.max_decompressed_size_bytes)
    }
}

impl<S: Read> CappedDecoder<zstd::stream::read::Decoder<'static, io::BufReader<S>>> {
    /// Creates a capped zstd decoder.
    ///
    /// Also constrains the decoder's internal window allocation via `window_log_max` so a crafted
    /// frame cannot request a large window before the decompressed-size cap trips. The window is
    /// derived from the cap only ([`CompressionLimits::zstd_window_log`]); for HTTP
    /// `Content-Encoding: zstd` use [`zstd_http`](Self::zstd_http), which applies the tighter
    /// RFC 9659 ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error if the zstd decoder cannot be initialized (e.g. invalid header).
    pub fn zstd(reader: S, limits: &CompressionLimits) -> io::Result<Self> {
        Self::zstd_with_window_log(
            reader,
            limits.max_decompressed_size_bytes,
            limits.zstd_window_log(),
        )
    }

    /// Creates a capped zstd decoder for HTTP `Content-Encoding: zstd`, clamping the decoder
    /// window to the RFC 9659 8 MB ceiling ([`CompressionLimits::http_zstd_window_log`]).
    ///
    /// # Errors
    ///
    /// Returns an error if the zstd decoder cannot be initialized (e.g. invalid header).
    pub fn zstd_http(reader: S, limits: &CompressionLimits) -> io::Result<Self> {
        Self::zstd_with_window_log(
            reader,
            limits.max_decompressed_size_bytes,
            limits.http_zstd_window_log(),
        )
    }

    fn zstd_with_window_log(
        reader: S,
        limit: usize,
        window_log_max: Option<u32>,
    ) -> io::Result<Self> {
        let mut decoder = zstd::stream::read::Decoder::new(reader)?;
        if let Some(window_log_max) = window_log_max {
            decoder.window_log_max(window_log_max)?;
        }
        Ok(Self::with_limit(decoder, limit))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{write::GzEncoder, write::ZlibEncoder, Compression};

    use super::*;

    /// Compresses `len` zero bytes with gzip. Highly compressible, so the wire form is tiny
    /// relative to the output — the shape of a decompression bomb.
    fn gzip_bomb(len: usize) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&vec![0u8; len]).unwrap();
        encoder.finish().unwrap()
    }

    fn gzip_compress(payload: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib_compress(payload: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib_bomb(len: usize) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&vec![0u8; len]).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn gzip_within_limit_decompresses() {
        let payload = gzip_bomb(1024);
        let out = CappedDecoder::gzip(
            payload.as_slice(),
            &CompressionLimits::with_max_decompressed_size_bytes(1024),
        )
        .decompress()
        .expect("payload exactly at the limit must decompress");
        assert_eq!(out.len(), 1024);
    }

    #[test]
    fn gzip_over_limit_is_rejected() {
        let payload = gzip_bomb(64 * 1024);
        let error = CappedDecoder::gzip(
            payload.as_slice(),
            &CompressionLimits::with_max_decompressed_size_bytes(1024),
        )
        .decompress()
        .expect_err("payload over the limit must be rejected");
        assert!(
            DecompressedSizeLimitExceeded::is(&error),
            "expected the size-limit marker, got {error}"
        );
    }

    /// The load-bearing case for `MultiGzDecoder`: a single member's size does not bound the
    /// attack, because the decoder walks every concatenated member. The cap must apply to the
    /// summed output, not per member.
    #[test]
    fn gzip_concatenated_members_are_capped_in_aggregate() {
        let member = gzip_bomb(1024);
        let mut payload = Vec::new();
        for _ in 0..8 {
            payload.extend_from_slice(&member);
        }

        // Each member on its own is within the limit; together they are not.
        let error = CappedDecoder::gzip(
            payload.as_slice(),
            &CompressionLimits::with_max_decompressed_size_bytes(4096),
        )
        .decompress()
        .expect_err("concatenated members must be capped in aggregate");
        assert!(
            DecompressedSizeLimitExceeded::is(&error),
            "expected the size-limit marker, got {error}"
        );
    }

    #[test]
    fn zlib_over_limit_is_rejected() {
        let payload = zlib_bomb(64 * 1024);
        let error = CappedDecoder::zlib(
            payload.as_slice(),
            &CompressionLimits::with_max_decompressed_size_bytes(1024),
        )
        .decompress()
        .expect_err("payload over the limit must be rejected");
        assert!(DecompressedSizeLimitExceeded::is(&error));
    }

    /// A single frame declaring a window larger than the cap is refused by the `window_log_max`
    /// clamp, before any output buffer is allocated.
    #[test]
    fn zstd_oversized_window_is_rejected() {
        let payload = zstd::encode_all(vec![0u8; 64 * 1024].as_slice(), 19).unwrap();
        let result = CappedDecoder::zstd(
            payload.as_slice(),
            &CompressionLimits::with_max_decompressed_size_bytes(1024),
        )
        .expect("decoder init")
        .decompress();
        assert!(
            result.is_err(),
            "a frame whose window exceeds the cap must not decode"
        );
    }

    /// Concatenated frames each fit the window clamp, so the aggregate output is what the size cap
    /// has to catch.
    #[test]
    fn zstd_over_limit_is_rejected() {
        // Level 1 keeps each frame's declared window under the 1 MiB cap's 2^20 ceiling, so the
        // window clamp stays out of the way and the size cap is what rejects the payload.
        let frame = zstd::encode_all(vec![0u8; 256 * 1024].as_slice(), 1).unwrap();
        let mut payload = Vec::new();
        for _ in 0..8 {
            payload.extend_from_slice(&frame);
        }

        let error = CappedDecoder::zstd(
            payload.as_slice(),
            &CompressionLimits::with_max_decompressed_size_bytes(1024 * 1024),
        )
        .expect("decoder init")
        .decompress()
        .expect_err("payload over the limit must be rejected");
        assert!(
            DecompressedSizeLimitExceeded::is(&error),
            "expected the size-limit marker, got {error}"
        );
    }

    /// A streaming consumer must see an error rather than a truncated-but-plausible payload.
    #[test]
    fn streaming_reader_errors_instead_of_truncating() {
        let payload = gzip_bomb(64 * 1024);
        let mut reader = CappedDecoder::gzip(
            payload.as_slice(),
            &CompressionLimits::with_max_decompressed_size_bytes(1024),
        )
        .into_reader();

        let mut sink = Vec::new();
        let error = std::io::copy(&mut reader, &mut sink)
            .expect_err("streaming past the limit must error, not silently truncate");
        assert!(DecompressedSizeLimitExceeded::is(&error));
        assert!(
            sink.len() <= 1024,
            "must not hand more than the limit to the consumer, got {}",
            sink.len()
        );
    }

    /// An unrelated I/O failure must not be mistaken for the size cap.
    #[test]
    fn unrelated_io_error_is_not_a_limit_error() {
        let error = CappedDecoder::gzip(
            b"not gzip at all".as_slice(),
            &CompressionLimits::with_max_decompressed_size_bytes(1024),
        )
        .decompress()
        .expect_err("invalid gzip must fail");
        assert!(!DecompressedSizeLimitExceeded::is(&error));
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
    }

    /// Cross-check every capped decoder against the raw decoder it wraps.
    ///
    /// The rest of the suite exercises `CappedDecoder` against itself, and the codebase's other
    /// tests decode with the raw decoders — so nothing else would notice if a capped wrapper
    /// decoded *correctly-sized but wrong* output (a short read treated as EOF, an off-by-one in
    /// the `Take` bound, a dropped final block). Using the raw decoder as the reference is the
    /// point: if the two ever disagree, the wrapper is at fault.
    #[test]
    fn capped_decoders_agree_with_the_raw_decoders_they_wrap() {
        // Sizes chosen to straddle the internal buffer boundaries a short read would expose:
        // empty, sub-block, exactly 8 KiB, and a size that is not a multiple of any block.
        for size in [0usize, 1, 100, 8 * 1024, 8 * 1024 + 1, 70_000] {
            // Mixed content, not zeroes: a run of zeroes can hide a truncation that repeats.
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

            // gzip
            let compressed = gzip_compress(&payload);
            let mut expected = Vec::new();
            MultiGzDecoder::new(&compressed[..])
                .read_to_end(&mut expected)
                .expect("raw gzip decode");
            let actual = CappedDecoder::gzip(&compressed[..], &CompressionLimits::default())
                .decompress()
                .expect("capped gzip decode");
            assert_eq!(actual, expected, "gzip disagreed at {size} bytes");
            assert_eq!(actual, payload, "gzip round-trip lost data at {size} bytes");

            // zlib
            let compressed = zlib_compress(&payload);
            let mut expected = Vec::new();
            ZlibDecoder::new(&compressed[..])
                .read_to_end(&mut expected)
                .expect("raw zlib decode");
            let actual = CappedDecoder::zlib(&compressed[..], &CompressionLimits::default())
                .decompress()
                .expect("capped zlib decode");
            assert_eq!(actual, expected, "zlib disagreed at {size} bytes");
            assert_eq!(actual, payload, "zlib round-trip lost data at {size} bytes");

            // zstd
            let compressed = zstd::stream::encode_all(&payload[..], 3).expect("zstd encode");
            let mut expected = Vec::new();
            zstd::stream::read::Decoder::new(&compressed[..])
                .expect("raw zstd decoder")
                .read_to_end(&mut expected)
                .expect("raw zstd decode");
            let actual = CappedDecoder::zstd(&compressed[..], &CompressionLimits::default())
                .expect("capped zstd decoder")
                .decompress()
                .expect("capped zstd decode");
            assert_eq!(actual, expected, "zstd disagreed at {size} bytes");
            assert_eq!(actual, payload, "zstd round-trip lost data at {size} bytes");
        }
    }

    /// The streaming reader must agree with the buffered path, so a caller that streams through
    /// `into_reader` cannot silently receive different bytes than one calling `decompress`.
    #[test]
    fn streaming_reader_agrees_with_the_buffered_path() {
        let payload: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
        let compressed = gzip_compress(&payload);

        let buffered = CappedDecoder::gzip(&compressed[..], &CompressionLimits::default())
            .decompress()
            .expect("buffered decode");

        let mut streamed = Vec::new();
        CappedDecoder::gzip(&compressed[..], &CompressionLimits::default())
            .into_reader()
            .read_to_end(&mut streamed)
            .expect("streamed decode");

        assert_eq!(streamed, buffered);
        assert_eq!(streamed, payload);
    }

    // ---- component limit overrides ------------------------------------------------------------

    fn global(max: usize) -> OperationalLimits {
        OperationalLimits {
            compression: CompressionLimits::with_max_decompressed_size_bytes(max),
            framing: FramingLimits::default(),
        }
    }

    fn asking(max: usize) -> OperationalLimitsOverride {
        OperationalLimitsOverride {
            compression: CompressionLimitsOverride {
                max_decompressed_size_bytes: Some(max),
            },
            framing: FramingLimitsOverride::default(),
        }
    }

    fn global_framing(max: usize) -> OperationalLimits {
        OperationalLimits {
            compression: CompressionLimits::default(),
            framing: FramingLimits::with_max_frame_length_bytes(max),
        }
    }

    fn asking_framing(max: usize) -> OperationalLimitsOverride {
        OperationalLimitsOverride {
            compression: CompressionLimitsOverride::default(),
            framing: FramingLimitsOverride {
                max_frame_length_bytes: Some(max),
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
}
