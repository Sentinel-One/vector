use bytes::{Buf, Bytes, BytesMut};
use memchr::memchr;
use tokio_util::codec::Decoder;
use tracing::trace;
use vector_config::configurable_component;

use super::{BoxedFramingError, FramingError};
use crate::decoding::StreamDecodingError;
use vector_common::limits::{FramingLimits, DEFAULT_MAX_FRAME_LENGTH_BYTES};

/// A frame exceeded `max_length`.
///
/// Always fatal (`can_continue() == false`): the buffer is dropped and the transport resets the
/// connection. A peer that sends one illegal frame gives us no reason to trust the rest of its
/// stream, so the frame is not skipped over even when its delimiter is present and we could.
///
/// `terminated` records whether the delimiter had arrived, purely so the log says which of the two
/// situations occurred — it does not change the outcome.
#[derive(Debug)]
pub struct FrameTooLong {
    frame_length: usize,
    max_length: usize,
    terminated: bool,
}

impl std::fmt::Display for FrameTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.terminated {
            write!(
                f,
                "frame exceeds max_length: {} bytes, limit is {}; resetting the connection",
                self.frame_length, self.max_length
            )
        } else {
            write!(
                f,
                "frame exceeds max_length: buffered {} bytes with no delimiter, limit is {}; \
                 resetting the connection",
                self.frame_length, self.max_length
            )
        }
    }
}

impl std::error::Error for FrameTooLong {}

impl StreamDecodingError for FrameTooLong {
    fn can_continue(&self) -> bool {
        false
    }
}

impl FramingError for FrameTooLong {
    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}

/// Config used to build a `CharacterDelimitedDecoder`.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharacterDelimitedDecoderConfig {
    /// Options for the character delimited decoder.
    pub character_delimited: CharacterDelimitedDecoderOptions,
}

impl CharacterDelimitedDecoderConfig {
    /// Creates a `CharacterDelimitedDecoderConfig` with the specified delimiter and default max length.
    pub const fn new(delimiter: u8) -> Self {
        Self {
            character_delimited: CharacterDelimitedDecoderOptions::new(delimiter, None),
        }
    }
    /// Build the `CharacterDelimitedDecoder` from this configuration.
    ///
    /// Falls back to `limits.max_frame_length_bytes` (the deployment's configured cap) when this
    /// component has not set its own `max_length`.
    pub fn build(&self, limits: FramingLimits) -> CharacterDelimitedDecoder {
        let max_length = self
            .character_delimited
            .max_length
            .unwrap_or(limits.max_frame_length_bytes);
        CharacterDelimitedDecoder::new_with_max_length(
            self.character_delimited.delimiter,
            max_length,
        )
    }
}

/// Options for building a `CharacterDelimitedDecoder`.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CharacterDelimitedDecoderOptions {
    /// The character that delimits byte sequences.
    #[configurable(metadata(docs::type_override = "ascii_char"))]
    #[serde(with = "vector_core::serde::ascii_char")]
    pub delimiter: u8,

    /// The maximum length of the byte buffer.
    ///
    /// This length does *not* include the trailing delimiter.
    ///
    /// Defaults to the deployment's configured frame length cap
    /// (`limits.framing.max_frame_length_bytes`, 1 MiB unless overridden). Set this field to
    /// override the cap for this component alone; unlike `sources.<name>.limits.framing`, it is
    /// applied exactly as given, not clamped by `--allow-component-limit-overrides`.
    ///
    /// A frame longer than the limit is a fatal decode error and the connection is reset, whether
    /// or not its delimiter had arrived.
    #[serde(skip_serializing_if = "vector_core::serde::is_default")]
    pub max_length: Option<usize>,
}

impl CharacterDelimitedDecoderOptions {
    /// Create a `CharacterDelimitedDecoderOptions` with a delimiter and optional max_length.
    pub const fn new(delimiter: u8, max_length: Option<usize>) -> Self {
        Self {
            delimiter,
            max_length,
        }
    }
}

/// A decoder for handling bytes that are delimited by (a) chosen character(s).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CharacterDelimitedDecoder {
    /// The delimiter used to separate byte sequences.
    pub delimiter: u8,
    /// The maximum length of the byte buffer.
    pub max_length: usize,
}

impl CharacterDelimitedDecoder {
    /// Creates a `CharacterDelimitedDecoder` with the specified delimiter, using the documented
    /// default frame length cap.
    ///
    /// Callers that have access to a component's context (i.e. everything reached through
    /// [`CharacterDelimitedDecoderConfig::build`]) should prefer that instead, so the deployment's
    /// configured limit applies rather than this hardcoded default.
    pub const fn new(delimiter: u8) -> Self {
        Self::new_with_max_length(delimiter, DEFAULT_MAX_FRAME_LENGTH_BYTES)
    }

    /// Creates a `CharacterDelimitedDecoder` with a maximum frame length limit.
    ///
    /// A frame longer than `max_length` is a fatal decode error and the connection is reset — see
    /// [`FrameTooLong`].
    pub const fn new_with_max_length(delimiter: u8, max_length: usize) -> Self {
        CharacterDelimitedDecoder {
            delimiter,
            max_length,
        }
    }

    /// Returns the maximum frame length when decoding.
    pub const fn max_length(&self) -> usize {
        self.max_length
    }
}

impl Decoder for CharacterDelimitedDecoder {
    type Item = Bytes;
    type Error = BoxedFramingError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Bytes>, Self::Error> {
        // A frame longer than `max_length` fails the stream, whether or not its delimiter has
        // arrived. See `FrameTooLong`.
        match memchr(self.delimiter, buf) {
            None => {
                // `memchr` searched all of `buf` and found no delimiter, and any frame emitted or
                // rejected previously was removed from `buf` at that point. So whatever is here is
                // exactly one incomplete frame — `buf.len()` is that frame's length so far, not
                // the size of the last socket read. A read much larger than `max_length` is fine
                // as long as it contains delimiters: those frames are handled by the arm below.
                //
                // `>` and not `>=`: at exactly `max_length` bytes the next byte could still be the
                // delimiter, which would make it a legal frame of the maximum size.
                if buf.len() > self.max_length {
                    let frame_length = buf.len();
                    buf.clear();
                    return Err(FrameTooLong {
                        frame_length,
                        max_length: self.max_length,
                        terminated: false,
                    }
                    .into());
                }
                Ok(None)
            }
            Some(next_delimiter_idx) => {
                if next_delimiter_idx > self.max_length {
                    // We could resync here — the delimiter marks exactly where this frame ended —
                    // but an over-long frame fails the stream outright, so everything buffered
                    // goes with it.
                    buf.clear();
                    return Err(FrameTooLong {
                        frame_length: next_delimiter_idx,
                        max_length: self.max_length,
                        terminated: true,
                    }
                    .into());
                }
                let frame = buf.split_to(next_delimiter_idx).freeze();
                trace!(
                    message = "Decoding the frame.",
                    bytes_processed = frame.len()
                );
                buf.advance(1); // scoot past the delimiter
                Ok(Some(frame))
            }
        }
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Bytes>, Self::Error> {
        match self.decode(buf)? {
            Some(frame) => Ok(Some(frame)),
            None => {
                if buf.is_empty() {
                    Ok(None)
                } else {
                    // `decode` returned `Ok(None)`, so the remainder is within `max_length`;
                    // anything longer would already have errored above.
                    let bytes: Bytes = buf.split_to(buf.len()).freeze();
                    Ok(Some(bytes))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bytes::BufMut;
    use indoc::indoc;

    use super::*;

    #[test]
    fn decode() {
        let mut codec = CharacterDelimitedDecoder::new(b'\n');
        let buf = &mut BytesMut::new();
        buf.put_slice(b"abc\n");
        assert_eq!(Some("abc".into()), codec.decode(buf).unwrap());
    }

    /// A peer that never sends the delimiter must not be able to grow the buffer without bound.
    /// `max_length` previously only applied once a delimiter had been found, so this stream was
    /// unbounded even with the limit set explicitly.
    #[test]
    fn incomplete_frame_over_max_length_is_a_fatal_error() {
        const MAX_LENGTH: usize = 10;

        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();
        buf.put_slice(&[b'x'; 100]);

        let error = codec.decode(buf).unwrap_err();
        assert!(
            !error.can_continue(),
            "an over-long incomplete frame must be fatal so the stream closes",
        );
        assert!(
            error.to_string().contains("exceeds max_length"),
            "error should name the limit, got: {error}",
        );
        assert!(buf.is_empty(), "the pending bytes must be released");
    }

    /// The bound must not fire while the frame is still within the limit — that would reject
    /// ordinary streaming reads that simply have not seen their delimiter yet.
    #[test]
    fn incomplete_frame_within_max_length_waits_for_more_bytes() {
        const MAX_LENGTH: usize = 100;

        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();

        buf.put_slice(b"partial");
        assert_eq!(codec.decode(buf).unwrap(), None);
        assert_eq!(buf.len(), 7, "pending bytes must be kept for the next read");

        buf.put_slice(b" frame\n");
        assert_eq!(
            codec.decode(buf).unwrap(),
            Some(Bytes::from("partial frame"))
        );
    }

    /// A frame of exactly `max_length` is accepted; one byte more is not. Pins the boundary so a
    /// later refactor cannot silently turn `>` into `>=`.
    #[test]
    fn max_length_boundary_is_exact() {
        const MAX_LENGTH: usize = 10;

        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();
        buf.put_slice(&[b'x'; MAX_LENGTH]);
        buf.put_slice(b"\n");
        assert_eq!(
            codec.decode(buf).unwrap(),
            Some(Bytes::from(vec![b'x'; MAX_LENGTH])),
            "a frame of exactly max_length must be accepted",
        );

        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();
        buf.put_slice(&[b'x'; MAX_LENGTH + 1]);
        assert!(
            codec.decode(buf).is_err(),
            "one byte past max_length must be rejected",
        );
    }

    /// A single socket read is routinely far larger than `max_length`. That must be fine as long
    /// as it contains delimiters: the limit bounds one *frame*, not the read. This is the
    /// regression guard against measuring the wrong thing.
    #[test]
    fn read_much_larger_than_max_length_is_fine_when_it_contains_frames() {
        const MAX_LENGTH: usize = 10;

        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();

        // 8 KiB in one read, made of 1000 short valid frames — 800x the limit in total.
        for _ in 0..1_000 {
            buf.put_slice(b"abcdefg\n");
        }
        let total = buf.len();
        assert!(
            total > MAX_LENGTH * 100,
            "test should exceed the limit many times over"
        );

        for i in 0..1_000 {
            assert_eq!(
                codec.decode(buf).unwrap(),
                Some(Bytes::from("abcdefg")),
                "frame {i} of a large multi-frame read should decode",
            );
        }
        assert_eq!(codec.decode(buf).unwrap(), None);
        assert!(buf.is_empty());
    }

    /// The same, but the large read ends mid-frame: the complete frames decode and the short tail
    /// waits for more bytes rather than being judged against the total read size.
    #[test]
    fn large_read_with_trailing_partial_frame_waits_instead_of_erroring() {
        const MAX_LENGTH: usize = 10;

        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();
        for _ in 0..500 {
            buf.put_slice(b"abcdefg\n");
        }
        buf.put_slice(b"tail"); // 4 bytes, under the limit, no delimiter yet

        for _ in 0..500 {
            assert_eq!(codec.decode(buf).unwrap(), Some(Bytes::from("abcdefg")));
        }
        assert_eq!(
            codec.decode(buf).unwrap(),
            None,
            "a short trailing partial must wait, not error",
        );
        assert_eq!(buf.len(), 4, "the partial frame must be retained");
    }

    /// Exactly `max_length` bytes with no delimiter must wait: the very next byte could be the
    /// delimiter, making it a legal maximum-size frame. One byte more cannot be legal.
    #[test]
    fn exactly_max_length_without_delimiter_still_waits() {
        const MAX_LENGTH: usize = 10;

        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();
        buf.put_slice(&[b'x'; MAX_LENGTH]);
        assert_eq!(
            codec.decode(buf).unwrap(),
            None,
            "at exactly max_length the frame may still be completed by the next byte",
        );

        buf.put_slice(b"\n");
        assert_eq!(
            codec.decode(buf).unwrap(),
            Some(Bytes::from(vec![b'x'; MAX_LENGTH])),
        );
    }

    /// `new()` must pick up the documented default cap rather than the old unbounded default.
    #[test]
    fn new_uses_the_default_frame_length_cap() {
        let codec = CharacterDelimitedDecoder::new(b'\n');
        assert_eq!(codec.max_length(), DEFAULT_MAX_FRAME_LENGTH_BYTES);
        assert_ne!(codec.max_length(), usize::MAX);
    }

    /// `build()` must fall back to the deployment's configured cap, not the hardcoded default,
    /// when the component has not set its own `max_length`.
    #[test]
    fn build_falls_back_to_the_deployment_configured_cap() {
        let config = CharacterDelimitedDecoderConfig::new(b'\n');
        let codec = config.build(FramingLimits::with_max_frame_length_bytes(4096));
        assert_eq!(codec.max_length(), 4096);
    }

    /// An explicit `max_length` on the component always wins over the deployment's cap.
    #[test]
    fn build_prefers_an_explicit_max_length_over_the_deployment_cap() {
        let config = CharacterDelimitedDecoderConfig {
            character_delimited: CharacterDelimitedDecoderOptions::new(b'\n', Some(64)),
        };
        let codec = config.build(FramingLimits::with_max_frame_length_bytes(4096));
        assert_eq!(codec.max_length(), 64);
    }

    #[test]
    fn decode_max_length() {
        const MAX_LENGTH: usize = 6;

        // A terminated frame longer than the limit is fatal, exactly as an over-long incomplete
        // frame is. It used to be skipped so that following frames still decoded; that split
        // behaviour is gone, so nothing after the offending frame is read.
        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();
        buf.put_slice(b"1234567\n123456\n");
        let error = codec.decode(buf).unwrap_err();
        assert!(!error.can_continue());
        assert!(
            buf.is_empty(),
            "the stream is abandoned, not resynchronized"
        );

        // Frames within the limit are untouched, including one of exactly `max_length`.
        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();
        buf.put_slice(b"123456\n12345\n123");
        assert_eq!(codec.decode(buf).unwrap(), Some(Bytes::from("123456")));
        assert_eq!(codec.decode(buf).unwrap(), Some(Bytes::from("12345")));
        assert_eq!(codec.decode(buf).unwrap(), None);
        assert_eq!(codec.decode_eof(buf).unwrap(), Some(Bytes::from("123")));
        assert_eq!(codec.decode_eof(buf).unwrap(), None);
    }

    // Regression test for [infinite loop bug](https://github.com/vectordotdev/vector/issues/2564)
    // Derived from https://github.com/tokio-rs/tokio/issues/1483
    //
    // The guarantee this pins is "no spinning on the same bytes". It used to be met by returning
    // `Ok(None)` for an over-long incomplete frame, which meant the caller kept reading and the
    // buffer kept growing — bounded progress, but unbounded memory. It is now met by failing the
    // frame outright and releasing the buffer, so there is still no repeated work on the same
    // bytes and memory is bounded as well.
    #[test]
    fn decode_discard_repeat() {
        const MAX_LENGTH: usize = 1;

        let mut codec = CharacterDelimitedDecoder::new_with_max_length(b'\n', MAX_LENGTH);
        let buf = &mut BytesMut::new();

        buf.reserve(200);
        buf.put(&b"aa"[..]);
        assert!(codec.decode(buf).is_err());
        assert!(buf.is_empty(), "the rejected frame must be released");

        // No spin: the decoder makes progress rather than re-failing on the same bytes.
        buf.put(&b"a"[..]);
        assert!(codec.decode(buf).unwrap().is_none());
    }

    #[test]
    fn decode_json_escaped() {
        let mut input = HashMap::new();
        input.insert("key", "value");
        input.insert("new", "li\nne");

        let mut bytes = serde_json::to_vec(&input).unwrap();
        bytes.push(b'\n');

        let mut codec = CharacterDelimitedDecoder::new(b'\n');
        let buf = &mut BytesMut::new();

        buf.reserve(bytes.len());
        buf.extend(bytes);

        let result = codec.decode(buf).unwrap();

        assert!(result.is_some());
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_json_multiline() {
        let events = indoc! {r#"
            {"log":"\u0009at org.springframework.security.web.context.SecurityContextPersistenceFilter.doFilter(SecurityContextPersistenceFilter.java:105)\n","stream":"stdout","time":"2019-01-18T07:49:27.374616758Z"}
            {"log":"\u0009at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:334)\n","stream":"stdout","time":"2019-01-18T07:49:27.374640288Z"}
            {"log":"\u0009at org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter.doFilterInternal(WebAsyncManagerIntegrationFilter.java:56)\n","stream":"stdout","time":"2019-01-18T07:49:27.374655505Z"}
            {"log":"\u0009at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)\n","stream":"stdout","time":"2019-01-18T07:49:27.374671955Z"}
            {"log":"\u0009at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:334)\n","stream":"stdout","time":"2019-01-18T07:49:27.374690312Z"}
            {"log":"\u0009at org.springframework.security.web.FilterChainProxy.doFilterInternal(FilterChainProxy.java:215)\n","stream":"stdout","time":"2019-01-18T07:49:27.374704522Z"}
            {"log":"\u0009at org.springframework.security.web.FilterChainProxy.doFilter(FilterChainProxy.java:178)\n","stream":"stdout","time":"2019-01-18T07:49:27.374718459Z"}
            {"log":"\u0009at org.springframework.web.filter.DelegatingFilterProxy.invokeDelegate(DelegatingFilterProxy.java:357)\n","stream":"stdout","time":"2019-01-18T07:49:27.374732919Z"}
            {"log":"\u0009at org.springframework.web.filter.DelegatingFilterProxy.doFilter(DelegatingFilterProxy.java:270)\n","stream":"stdout","time":"2019-01-18T07:49:27.374750799Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)\n","stream":"stdout","time":"2019-01-18T07:49:27.374764819Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)\n","stream":"stdout","time":"2019-01-18T07:49:27.374778682Z"}
            {"log":"\u0009at org.springframework.web.filter.RequestContextFilter.doFilterInternal(RequestContextFilter.java:99)\n","stream":"stdout","time":"2019-01-18T07:49:27.374792429Z"}
            {"log":"\u0009at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)\n","stream":"stdout","time":"2019-01-18T07:49:27.374805985Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)\n","stream":"stdout","time":"2019-01-18T07:49:27.374819625Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)\n","stream":"stdout","time":"2019-01-18T07:49:27.374833335Z"}
            {"log":"\u0009at org.springframework.web.filter.HttpPutFormContentFilter.doFilterInternal(HttpPutFormContentFilter.java:109)\n","stream":"stdout","time":"2019-01-18T07:49:27.374847845Z"}
            {"log":"\u0009at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)\n","stream":"stdout","time":"2019-01-18T07:49:27.374861925Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)\n","stream":"stdout","time":"2019-01-18T07:49:27.37487589Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)\n","stream":"stdout","time":"2019-01-18T07:49:27.374890043Z"}
            {"log":"\u0009at org.springframework.web.filter.HiddenHttpMethodFilter.doFilterInternal(HiddenHttpMethodFilter.java:93)\n","stream":"stdout","time":"2019-01-18T07:49:27.374903813Z"}
            {"log":"\u0009at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)\n","stream":"stdout","time":"2019-01-18T07:49:27.374917793Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)\n","stream":"stdout","time":"2019-01-18T07:49:27.374931586Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)\n","stream":"stdout","time":"2019-01-18T07:49:27.374946006Z"}
            {"log":"\u0009at org.springframework.boot.actuate.metrics.web.servlet.WebMvcMetricsFilter.filterAndRecordMetrics(WebMvcMetricsFilter.java:117)\n","stream":"stdout","time":"2019-01-18T07:49:27.37496104Z"}
            {"log":"\u0009at org.springframework.boot.actuate.metrics.web.servlet.WebMvcMetricsFilter.doFilterInternal(WebMvcMetricsFilter.java:106)\n","stream":"stdout","time":"2019-01-18T07:49:27.37498773Z"}
            {"log":"\u0009at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)\n","stream":"stdout","time":"2019-01-18T07:49:27.375003113Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)\n","stream":"stdout","time":"2019-01-18T07:49:27.375017063Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)\n","stream":"stdout","time":"2019-01-18T07:49:27.37503086Z"}
            {"log":"\u0009at org.springframework.web.filter.CharacterEncodingFilter.doFilterInternal(CharacterEncodingFilter.java:200)\n","stream":"stdout","time":"2019-01-18T07:49:27.3750454Z"}
            {"log":"\u0009at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)\n","stream":"stdout","time":"2019-01-18T07:49:27.37505928Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)\n","stream":"stdout","time":"2019-01-18T07:49:27.37507306Z"}
            {"log":"\u0009at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)\n","stream":"stdout","time":"2019-01-18T07:49:27.375086726Z"}
            {"log":"\u0009at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:198)\n","stream":"stdout","time":"2019-01-18T07:49:27.375100817Z"}
            {"log":"\u0009at org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:96)\n","stream":"stdout","time":"2019-01-18T07:49:27.375115354Z"}
            {"log":"\u0009at org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:493)\n","stream":"stdout","time":"2019-01-18T07:49:27.375129454Z"}
            {"log":"\u0009at org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:140)\n","stream":"stdout","time":"2019-01-18T07:49:27.375144001Z"}
            {"log":"\u0009at org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:81)\n","stream":"stdout","time":"2019-01-18T07:49:27.375157464Z"}
            {"log":"\u0009at org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:87)\n","stream":"stdout","time":"2019-01-18T07:49:27.375170981Z"}
            {"log":"\u0009at org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:342)\n","stream":"stdout","time":"2019-01-18T07:49:27.375184417Z"}
            {"log":"\u0009at org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:800)\n","stream":"stdout","time":"2019-01-18T07:49:27.375198024Z"}
            {"log":"\u0009at org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:66)\n","stream":"stdout","time":"2019-01-18T07:49:27.375211594Z"}
            {"log":"\u0009at org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:806)\n","stream":"stdout","time":"2019-01-18T07:49:27.375225237Z"}
            {"log":"\u0009at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1498)\n","stream":"stdout","time":"2019-01-18T07:49:27.375239487Z"}
            {"log":"\u0009at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:49)\n","stream":"stdout","time":"2019-01-18T07:49:27.375253464Z"}
            {"log":"\u0009at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\n","stream":"stdout","time":"2019-01-18T07:49:27.375323255Z"}
            {"log":"\u0009at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\n","stream":"stdout","time":"2019-01-18T07:49:27.375345642Z"}
            {"log":"\u0009at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\n","stream":"stdout","time":"2019-01-18T07:49:27.375363208Z"}
            {"log":"\u0009at java.lang.Thread.run(Thread.java:748)\n","stream":"stdout","time":"2019-01-18T07:49:27.375377695Z"}
            {"log":"\n","stream":"stdout","time":"2019-01-18T07:49:27.375391335Z"}
            {"log":"\n","stream":"stdout","time":"2019-01-18T07:49:27.375416915Z"}
            {"log":"2019-01-18 07:53:06.419 [               ]  INFO 1 --- [vent-bus.prod-1] c.t.listener.CommonListener              : warehousing Dailywarehousing.daily\n","stream":"stdout","time":"2019-01-18T07:53:06.420527437Z"}
        "#};

        let mut codec = CharacterDelimitedDecoder::new(b'\n');
        let buf = &mut BytesMut::new();

        buf.extend(events.to_string().as_bytes());

        let mut i = 0;
        while codec.decode(buf).unwrap().is_some() {
            i += 1;
        }

        assert_eq!(i, 51);
    }
}
