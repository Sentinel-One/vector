use bytes::{Bytes, BytesMut};
use derivative::Derivative;
use tokio_util::codec::Decoder;
use vector_config::configurable_component;

use super::{BoxedFramingError, CharacterDelimitedDecoder};

/// Config used to build a `NewlineDelimitedDecoder`.
#[configurable_component]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewlineDelimitedDecoderConfig {
    /// Options for the newline delimited decoder.
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub newline_delimited: NewlineDelimitedDecoderOptions,
}

/// Options for building a `NewlineDelimitedDecoder`.
#[configurable_component]
#[derive(Clone, Debug, Derivative, PartialEq, Eq)]
#[derivative(Default)]
pub struct NewlineDelimitedDecoderOptions {
    /// The maximum length of the byte buffer.
    ///
    /// This length does *not* include the trailing delimiter.
    ///
    /// Defaults to 1 MiB. Lines longer than this are discarded, which bounds the memory a
    /// malformed or adversarial stream can force the decoder to buffer.
    ///
    /// Raise this if your source legitimately emits lines larger than 1 MiB — oversized lines are
    /// dropped, not truncated, so an undersized limit is silent data loss.
    #[serde(skip_serializing_if = "vector_core::serde::is_default")]
    pub max_length: Option<usize>,
}

impl NewlineDelimitedDecoderOptions {
    /// Creates a `NewlineDelimitedDecoderOptions` with a maximum frame length limit.
    pub const fn new_with_max_length(max_length: usize) -> Self {
        Self {
            max_length: Some(max_length),
        }
    }
}

impl NewlineDelimitedDecoderConfig {
    /// Creates a new `NewlineDelimitedDecoderConfig`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a `NewlineDelimitedDecoder` with a maximum frame length limit.
    pub const fn new_with_max_length(max_length: usize) -> Self {
        Self {
            newline_delimited: { NewlineDelimitedDecoderOptions::new_with_max_length(max_length) },
        }
    }

    /// Build the `NewlineDelimitedDecoder` from this configuration.
    ///
    /// When no explicit `max_length` is configured, [`NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH`] is applied. The bound
    /// lives here rather than in [`NewlineDelimitedDecoder::new`] so that callers constructing the
    /// decoder directly keep full control over their own limit.
    pub const fn build(&self) -> NewlineDelimitedDecoder {
        if let Some(max_length) = self.newline_delimited.max_length {
            NewlineDelimitedDecoder::new_with_max_length(max_length)
        } else {
            NewlineDelimitedDecoder::new_with_max_length(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH)
        }
    }
}

/// Default maximum line length (1 MiB) applied by [`NewlineDelimitedDecoderConfig::build`] when no
/// explicit limit is configured. Guards against unbounded `BytesMut` growth from malformed or
/// adversarial streams.
pub const NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH: usize = 1024 * 1024;

/// A codec for handling bytes that are delimited by (a) newline(s).
#[derive(Debug, Clone)]
pub struct NewlineDelimitedDecoder(CharacterDelimitedDecoder);

impl NewlineDelimitedDecoder {
    /// Creates a new `NewlineDelimitedDecoder` with no maximum line length.
    ///
    /// Prefer [`NewlineDelimitedDecoder::new_with_max_length`] when the input comes from an
    /// untrusted sender; an unbounded decoder will buffer a line of arbitrary size. Configuration
    /// built through [`NewlineDelimitedDecoderConfig::build`] applies [`NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH`]
    /// automatically.
    pub const fn new() -> Self {
        Self(CharacterDelimitedDecoder::new(b'\n'))
    }

    /// Creates a `NewlineDelimitedDecoder` with a maximum frame length limit.
    ///
    /// Any frames longer than `max_length` bytes will be discarded entirely.
    pub const fn new_with_max_length(max_length: usize) -> Self {
        Self(CharacterDelimitedDecoder::new_with_max_length(
            b'\n', max_length,
        ))
    }
}

impl Default for NewlineDelimitedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for NewlineDelimitedDecoder {
    type Item = Bytes;
    type Error = BoxedFramingError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.0.decode(src)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.0.decode_eof(src)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_bytes_with_newlines() {
        let mut input = BytesMut::from("foo\nbar\nbaz");
        let mut decoder = NewlineDelimitedDecoder::new();

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "foo");
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "bar");
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
    }

    #[test]
    fn decode_bytes_with_newlines_trailing() {
        let mut input = BytesMut::from("foo\nbar\nbaz\n");
        let mut decoder = NewlineDelimitedDecoder::new();

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "foo");
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "bar");
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "baz");
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
    }

    #[test]
    fn decode_bytes_with_newlines_and_max_length() {
        let mut input = BytesMut::from("foo\nbarbara\nbaz\n");
        let mut decoder = NewlineDelimitedDecoder::new_with_max_length(3);

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "foo");
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "baz");
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
    }

    #[test]
    fn decode_eof_bytes_with_newlines() {
        let mut input = BytesMut::from("foo\nbar\nbaz");
        let mut decoder = NewlineDelimitedDecoder::new();

        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "foo");
        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "bar");
        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "baz");
    }

    #[test]
    fn decode_eof_bytes_with_newlines_trailing() {
        let mut input = BytesMut::from("foo\nbar\nbaz\n");
        let mut decoder = NewlineDelimitedDecoder::new();

        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "foo");
        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "bar");
        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "baz");
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), None);
    }

    #[test]
    fn decode_eof_bytes_with_newlines_and_max_length() {
        let mut input = BytesMut::from("foo\nbarbara\nbaz\n");
        let mut decoder = NewlineDelimitedDecoder::new_with_max_length(3);

        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "foo");
        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "baz");
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), None);
    }

    /// `new()` must stay unbounded: callers that construct the decoder directly (and the `Default`
    /// impl) are expected to opt into a limit themselves. Bounding `new()` silently overrode every
    /// caller that had deliberately chosen no limit, including `aws_s3`'s default framing.
    #[test]
    fn new_is_unbounded() {
        assert_eq!(NewlineDelimitedDecoder::new().0.max_length(), usize::MAX);
        assert_eq!(
            NewlineDelimitedDecoder::default().0.max_length(),
            usize::MAX
        );
    }

    #[test]
    fn new_decodes_line_far_over_the_config_default() {
        // A line 4x the config-layer default must survive an explicitly unbounded decoder.
        let huge = "a".repeat(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH * 4);
        let mut input = BytesMut::from(format!("{huge}\n").as_str());
        let mut decoder = NewlineDelimitedDecoder::new();

        assert_eq!(
            decoder.decode(&mut input).unwrap().unwrap().len(),
            NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH * 4
        );
    }

    /// The bound belongs at the config layer, so a config with no explicit `max_length` still gets
    /// a finite limit. This is what protects socket/exec/gcs/aws_s3 from unbounded buffering.
    #[test]
    fn config_build_applies_default_max_length_when_unset() {
        let decoder = NewlineDelimitedDecoderConfig::new().build();
        assert_eq!(
            decoder.0.max_length(),
            NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH
        );
    }

    #[test]
    fn config_build_honors_explicit_max_length() {
        let decoder = NewlineDelimitedDecoderConfig::new_with_max_length(42).build();
        assert_eq!(decoder.0.max_length(), 42);
    }

    #[test]
    fn config_build_explicit_max_length_may_exceed_default() {
        // Raising the limit above the default must be possible for sources with large records.
        let raised = NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH * 8;
        let decoder = NewlineDelimitedDecoderConfig::new_with_max_length(raised).build();
        assert_eq!(decoder.0.max_length(), raised);
    }

    #[test]
    fn config_default_max_length_is_one_mib() {
        // Pinned deliberately: this value is user-visible in docs and changing it is a breaking
        // change for anyone whose lines sit between the old and new limits.
        assert_eq!(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH, 1024 * 1024);
    }

    #[test]
    fn config_default_boundary_at_limit_passes_over_limit_discarded() {
        let at_limit = "a".repeat(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH);
        let over_limit = "b".repeat(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH + 1);
        let mut input = BytesMut::from(format!("{at_limit}\n{over_limit}\nok\n").as_str());
        let mut decoder = NewlineDelimitedDecoderConfig::new().build();

        assert_eq!(
            decoder.decode(&mut input).unwrap().unwrap().len(),
            NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH,
            "a line exactly at the limit must pass"
        );
        assert_eq!(
            decoder.decode(&mut input).unwrap().unwrap(),
            "ok",
            "the oversized line is dropped and decoding resumes at the next line"
        );
    }

    #[test]
    fn config_default_recovers_after_consecutive_oversized_lines() {
        // Two oversized lines back to back must not desynchronize the framer.
        let over = "x".repeat(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH + 1);
        let mut input = BytesMut::from(format!("first\n{over}\n{over}\nlast\n").as_str());
        let mut decoder = NewlineDelimitedDecoderConfig::new().build();

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "first");
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "last");
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
    }

    #[test]
    fn config_default_oversized_line_dropped_at_eof() {
        let over = "x".repeat(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH + 1);
        let mut input = BytesMut::from(over.as_str());
        let mut decoder = NewlineDelimitedDecoderConfig::new().build();

        // No trailing delimiter: decode_eof must drop it rather than emit an oversized frame.
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), None);
    }
}
