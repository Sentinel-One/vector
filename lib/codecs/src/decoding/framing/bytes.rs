use bytes::{Bytes, BytesMut};
use tokio_util::codec::Decoder;
use vector_config::configurable_component;

use super::BoxedFramingError;

/// Config used to build a `BytesDecoderConfig`.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytesDecoderConfig {
    /// Emit buffered bytes as soon as at least this many have accumulated.
    ///
    /// The whole buffer is emitted as a single frame (it is not split into pieces of this size).
    /// Fewer buffered bytes are held until more arrive or the stream ends, at which point whatever
    /// remains is emitted. The default (`i64::MAX`) effectively holds everything until the end of
    /// the stream/message.
    #[serde(default = "default_min_chunk_bytes")]
    pub min_chunk_bytes: u64,
}

const fn default_min_chunk_bytes() -> u64 {
    i64::MAX as u64
}

impl Default for BytesDecoderConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl BytesDecoderConfig {
    /// Creates a new `BytesDecoderConfig`.
    pub const fn new() -> Self {
        Self {
            min_chunk_bytes: default_min_chunk_bytes(),
        }
    }

    /// Build the `ByteDecoder` from this configuration.
    pub const fn build(&self) -> BytesDecoder {
        BytesDecoder::with_min_chunk_bytes(self.min_chunk_bytes)
    }
}

/// A decoder for passing through bytes as-is.
///
/// This is basically a no-op and is used to convert from `BytesMut` to `Bytes`.
#[derive(Debug, Clone)]
pub struct BytesDecoder {
    /// Whether the empty buffer has been flushed. This is important to
    /// propagate empty frames in message based transports.
    flushed: bool,
    min_chunk_bytes: u64,
}

impl BytesDecoder {
    /// Creates a new `BytesDecoder`.
    pub const fn new() -> Self {
        Self::with_min_chunk_bytes(default_min_chunk_bytes())
    }

    /// Creates a `BytesDecoder` that emits early once `min_chunk_bytes` have been buffered.
    pub const fn with_min_chunk_bytes(min_chunk_bytes: u64) -> Self {
        Self {
            flushed: false,
            min_chunk_bytes,
        }
    }
}

impl Default for BytesDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for BytesDecoder {
    type Item = Bytes;
    type Error = BoxedFramingError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.flushed = false;
        let ready = !src.is_empty() && src.len() as u64 >= self.min_chunk_bytes;
        Ok(ready.then(|| src.split().freeze()))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.flushed && src.is_empty() {
            Ok(None)
        } else {
            self.flushed = true;
            let frame = src.split();
            Ok(Some(frame.freeze()))
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tokio_util::codec::FramedRead;

    use super::*;

    #[test]
    fn decode_frame() {
        let mut input = BytesMut::from("some bytes");
        let mut decoder = BytesDecoder::new();

        assert_eq!(decoder.decode(&mut input).unwrap(), None);
        assert_eq!(
            decoder.decode_eof(&mut input).unwrap().unwrap(),
            "some bytes"
        );
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
    }

    #[test]
    fn decode_emits_whole_buffer_when_min_chunk_bytes_reached() {
        let mut input = BytesMut::from("0123456789");
        let mut decoder = BytesDecoder::with_min_chunk_bytes(4);

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "0123456789");
        assert!(input.is_empty());
    }

    #[test]
    fn decode_holds_bytes_below_min_chunk_bytes_until_eof() {
        let mut input = BytesMut::from("abc");
        let mut decoder = BytesDecoder::with_min_chunk_bytes(4);

        assert_eq!(decoder.decode(&mut input).unwrap(), None);
        input.extend_from_slice(b"de");
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "abcde");
        input.extend_from_slice(b"fg");
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "fg");
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), None);
    }

    #[test]
    fn decode_with_min_chunk_bytes_default_never_emits_before_eof() {
        let mut input = BytesMut::from("a lot of bytes");
        let mut decoder = BytesDecoderConfig::new().build();

        assert_eq!(decoder.decode(&mut input).unwrap(), None);
    }

    #[tokio::test]
    async fn decode_frame_reader_with_min_chunk_bytes_emits_big_then_remainder() {
        let input: &[u8] = b"hello world";
        let decoder = BytesDecoder::with_min_chunk_bytes(100);
        let mut reader = FramedRead::new(input, decoder);

        assert_eq!(reader.next().await.unwrap().unwrap(), "hello world");
        assert!(reader.next().await.is_none());
    }

    #[test]
    fn config_deserializes_min_chunk_bytes() {
        let config: BytesDecoderConfig = serde_json::from_str(r#"{"min_chunk_bytes": 8}"#).unwrap();
        assert_eq!(config.min_chunk_bytes, 8);
        let config: BytesDecoderConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.min_chunk_bytes, i64::MAX as u64);
    }

    #[tokio::test]
    async fn decode_frame_reader() {
        let input: &[u8] = b"foo";
        let decoder = BytesDecoder::new();

        let mut reader = FramedRead::new(input, decoder);

        assert_eq!(reader.next().await.unwrap().unwrap(), "foo");
        assert!(reader.next().await.is_none());
    }

    #[tokio::test]
    async fn decode_frame_reader_empty() {
        let input: &[u8] = b"";
        let decoder = BytesDecoder::new();

        let mut reader = FramedRead::new(input, decoder);

        assert_eq!(reader.next().await.unwrap().unwrap(), "");
        assert!(reader.next().await.is_none());
    }
}
