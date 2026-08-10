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
    /// Defaults to 10 MiB. Lines longer than this are discarded, which bounds the memory a
    /// malformed or adversarial stream can force the decoder to buffer.
    ///
    /// Raise this if your source legitimately emits lines larger than 10 MiB — oversized lines are
    /// dropped, not truncated, so an undersized limit is silent data loss.
    #[serde(default = "default_max_length")]
    #[derivative(Default(value = "default_max_length()"))]
    pub max_length: Option<usize>,
}

const fn default_max_length() -> Option<usize> {
    Some(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH)
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
    /// `None` means unbounded and is preserved as such. The default lives on
    /// [`NewlineDelimitedDecoderOptions::max_length`] as a serde default, so a user who omits the
    /// key gets [`NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH`] while a component that constructs `None`
    /// in Rust — such as `aws_s3`, whose objects may be one newline-free JSON document — keeps the
    /// unbounded behavior it asked for.
    pub const fn build(&self) -> NewlineDelimitedDecoder {
        if let Some(max_length) = self.newline_delimited.max_length {
            NewlineDelimitedDecoder::new_with_max_length(max_length)
        } else {
            NewlineDelimitedDecoder::new()
        }
    }
}

/// Default maximum line length (10 MiB) applied by [`NewlineDelimitedDecoderConfig::build`] when no
/// explicit limit is configured. Guards against unbounded `BytesMut` growth from malformed or
/// adversarial streams, while sitting far above any realistic single log line.
pub const NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH: usize = 10 * 1024 * 1024;

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

    /// A config that omits `max_length` gets the default via serde. This is what protects
    /// socket/exec/stdin from unbounded buffering.
    #[test]
    fn config_omitting_max_length_gets_the_default() {
        let config: NewlineDelimitedDecoderConfig =
            serde_json::from_str(r#"{"newline_delimited":{}}"#).unwrap();
        assert_eq!(
            config.build().0.max_length(),
            NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH
        );
    }

    /// Regression: a component that constructs `max_length: None` in Rust means unbounded and must
    /// keep it. `aws_s3` does exactly this, and its objects can be one newline-free JSON document
    /// (CloudTrail `{"Records":[...]}`), which a per-line cap would drop wholesale.
    #[test]
    fn explicit_none_stays_unbounded() {
        let config = NewlineDelimitedDecoderConfig {
            newline_delimited: NewlineDelimitedDecoderOptions { max_length: None },
        };
        assert_eq!(config.build().0.max_length(), usize::MAX);
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
    fn config_default_max_length_is_ten_mib() {
        // Pinned deliberately: this value is user-visible in docs and changing it is a breaking
        // change for anyone whose lines sit between the old and new limits.
        assert_eq!(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH, 10 * 1024 * 1024);
    }

    #[test]
    fn config_default_boundary_at_limit_passes_over_limit_discarded() {
        let at_limit = "a".repeat(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH);
        let over_limit = "b".repeat(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH + 1);
        let mut input = BytesMut::from(format!("{at_limit}\n{over_limit}\nok\n").as_str());
        let mut decoder =
            NewlineDelimitedDecoder::new_with_max_length(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH);

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
        let mut decoder =
            NewlineDelimitedDecoder::new_with_max_length(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH);

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "first");
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "last");
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
    }

    #[test]
    fn config_default_oversized_line_dropped_at_eof() {
        let over = "x".repeat(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH + 1);
        let mut input = BytesMut::from(over.as_str());
        let mut decoder =
            NewlineDelimitedDecoder::new_with_max_length(NEWLINE_DELIMITED_DEFAULT_MAX_LENGTH);

        // No trailing delimiter: decode_eof must drop it rather than emit an oversized frame.
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), None);
    }
}
