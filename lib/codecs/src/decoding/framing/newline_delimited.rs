use bytes::{Bytes, BytesMut};
use derivative::Derivative;
use tokio_util::codec::Decoder;
use vector_common::limits::FramingLimits;
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
    /// Falls back to `limits.max_frame_length_bytes` (the deployment's configured cap) when this
    /// component has not set its own `max_length`.
    pub fn build(&self, limits: FramingLimits) -> NewlineDelimitedDecoder {
        let max_length = self
            .newline_delimited
            .max_length
            .unwrap_or(limits.max_frame_length_bytes);
        NewlineDelimitedDecoder::new_with_max_length(max_length)
    }
}

/// A codec for handling bytes that are delimited by (a) newline(s).
#[derive(Debug, Clone)]
pub struct NewlineDelimitedDecoder(CharacterDelimitedDecoder);

impl NewlineDelimitedDecoder {
    /// Creates a new `NewlineDelimitedDecoder`, using the documented default frame length cap.
    ///
    /// Callers that have access to a component's context should prefer
    /// [`NewlineDelimitedDecoderConfig::build`] instead, so the deployment's configured limit
    /// applies rather than this hardcoded default.
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
        // An over-long line is now fatal rather than skipped, so "baz" behind it is never read.
        let mut input = BytesMut::from("foo\nbarbara\nbaz\n");
        let mut decoder = NewlineDelimitedDecoder::new_with_max_length(3);

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "foo");
        assert!(decoder.decode(&mut input).is_err());
        assert!(
            input.is_empty(),
            "the stream is abandoned, not resynchronized"
        );
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
        assert!(decoder.decode_eof(&mut input).is_err());
        assert!(input.is_empty());
    }

    /// Lines within the limit are unaffected by the cap, including at EOF without a trailing
    /// delimiter — the accept half of the pair above.
    #[test]
    fn decode_bytes_within_max_length_are_unaffected() {
        let mut input = BytesMut::from("foo\nbar\nbaz");
        let mut decoder = NewlineDelimitedDecoder::new_with_max_length(3);

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "foo");
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "bar");
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "baz");
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), None);
    }

    /// `build()` must fall back to the deployment's configured cap, not the hardcoded default,
    /// when the component has not set its own `max_length`.
    #[test]
    fn build_falls_back_to_the_deployment_configured_cap() {
        let config = NewlineDelimitedDecoderConfig::new();
        let decoder = config.build(FramingLimits::with_max_frame_length_bytes(4096));
        assert_eq!(decoder.0.max_length(), 4096);
    }

    /// An explicit `max_length` on the component always wins over the deployment's cap.
    #[test]
    fn build_prefers_an_explicit_max_length_over_the_deployment_cap() {
        let config = NewlineDelimitedDecoderConfig::new_with_max_length(64);
        let decoder = config.build(FramingLimits::with_max_frame_length_bytes(4096));
        assert_eq!(decoder.0.max_length(), 64);
    }
}
