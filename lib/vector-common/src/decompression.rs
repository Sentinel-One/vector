//! Size-capped decompression, to prevent decompression-bomb (`DoS`) attacks.
//!
//! A length or compressed payload read from an untrusted peer must never drive an unbounded
//! in-memory allocation. This module owns the decoders that enforce [`CompressionLimits`] (see
//! `crate::limits`) while decompressing.
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
//! The constructors enforce the configured decompressed-size cap so that a compression bomb
//! cannot drive unbounded allocation.

// Raw decoder types (flate2 / zstd) are only allowed in this module, which wraps them safely.
#![expect(
    clippy::disallowed_types,
    reason = "this module implements CappedDecoder, the safe wrapper around raw decoders; raw types may only appear here"
)]

use std::{
    fmt,
    io::{self, Read},
};

use flate2::read::{MultiGzDecoder, ZlibDecoder};

use crate::limits::CompressionLimits;

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
}
