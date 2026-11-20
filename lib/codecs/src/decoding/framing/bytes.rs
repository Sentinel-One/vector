use bytes::{Bytes, BytesMut};
use tokio_util::codec::Decoder;
use vector_config::configurable_component;

use super::BoxedFramingError;

/// Config used to build a `BytesDecoder`.
#[configurable_component]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BytesDecoderConfig {
    /// Options for the bytes decoder.
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub bytes: BytesDecoderOptions,
}

/// Options for building a `BytesDecoder`.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BytesDecoderOptions {
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

impl BytesDecoderOptions {
    /// Whether `min_chunk_bytes` is set, so frames are cut wherever enough bytes have arrived.
    pub const fn emits_partial_frames(&self) -> bool {
        self.min_chunk_bytes != default_min_chunk_bytes()
    }
}

impl Default for BytesDecoderOptions {
    fn default() -> Self {
        Self {
            min_chunk_bytes: default_min_chunk_bytes(),
        }
    }
}

impl BytesDecoderConfig {
    /// Creates a new `BytesDecoderConfig`.
    pub const fn new() -> Self {
        Self {
            bytes: BytesDecoderOptions {
                min_chunk_bytes: default_min_chunk_bytes(),
            },
        }
    }

    /// Creates a `BytesDecoderConfig` that emits early once `min_chunk_bytes` have been buffered.
    pub const fn new_with_min_chunk_bytes(min_chunk_bytes: u64) -> Self {
        Self {
            bytes: BytesDecoderOptions { min_chunk_bytes },
        }
    }

    /// Build the `ByteDecoder` from this configuration.
    pub const fn build(&self) -> BytesDecoder {
        BytesDecoder::with_min_chunk_bytes(self.bytes.min_chunk_bytes)
    }
}

/// A decoder for passing through bytes as-is.
///
/// This is basically a no-op and is used to convert from `BytesMut` to `Bytes`.
#[derive(Debug, Clone)]
pub struct BytesDecoder {
    emitted: bool,
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
            emitted: false,
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
        let ready = !src.is_empty() && src.len() as u64 >= self.min_chunk_bytes;
        self.emitted |= ready;
        Ok(ready.then(|| src.split().freeze()))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let emit = !src.is_empty() || !self.emitted;
        self.emitted |= emit;
        Ok(emit.then(|| src.split().freeze()))
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
    fn only_a_set_min_chunk_bytes_emits_partial_frames() {
        assert!(!BytesDecoderOptions::default().emits_partial_frames());
        assert!(BytesDecoderConfig::new_with_min_chunk_bytes(4096)
            .bytes
            .emits_partial_frames());
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
    fn decode_eof_after_frames_emitted_by_decode_yields_no_empty_frame() {
        let mut input = BytesMut::from("abcd");
        let mut decoder = BytesDecoder::with_min_chunk_bytes(4);

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "abcd");
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), None);
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), None);
    }

    #[test]
    fn decode_eof_after_the_remainder_yields_nothing_however_often_it_is_called() {
        let mut input = BytesMut::from("abcde");
        let mut decoder = BytesDecoder::with_min_chunk_bytes(4);

        assert_eq!(decoder.decode(&mut input).unwrap().unwrap(), "abcde");
        input.extend_from_slice(b"fg");
        assert_eq!(decoder.decode(&mut input).unwrap(), None);
        assert_eq!(decoder.decode_eof(&mut input).unwrap().unwrap(), "fg");
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), None);
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

    async fn frames(reads: &[&[u8]], min_chunk_bytes: u64) -> Vec<Bytes> {
        let reads = reads
            .iter()
            .map(|read| Ok::<_, std::io::Error>(Bytes::copy_from_slice(read)))
            .collect::<Vec<_>>();
        FramedRead::new(
            tokio_util::io::StreamReader::new(futures::stream::iter(reads)),
            BytesDecoder::with_min_chunk_bytes(min_chunk_bytes),
        )
        .map(Result::unwrap)
        .collect()
        .await
    }

    #[tokio::test]
    async fn decode_frame_reader_with_min_chunk_bytes_emits_the_whole_input_without_an_empty_frame()
    {
        assert_eq!(frames(&[b"hello world"], 1).await, ["hello world"]);
    }

    #[tokio::test]
    async fn decode_frame_reader_trickled_one_byte_at_a_time_emits_no_empty_frame() {
        let reads: Vec<&[u8]> = b"hello".chunks(1).collect();
        assert_eq!(frames(&reads, 1).await, ["h", "e", "l", "l", "o"]);
        assert_eq!(frames(&reads, 2).await, ["he", "ll", "o"]);
        assert_eq!(frames(&reads, 5).await, ["hello"]);
    }

    #[tokio::test]
    async fn decode_frame_reader_empty_with_min_chunk_bytes_emits_one_empty_frame() {
        assert_eq!(frames(&[], 1).await, [""]);
        assert_eq!(frames(&[b""], 4).await, [""]);
    }

    #[test]
    fn config_omits_default_options_when_serialized() {
        assert_eq!(
            serde_json::to_string(&BytesDecoderConfig::new()).unwrap(),
            "{}"
        );
        assert_eq!(
            serde_json::to_string(&BytesDecoderConfig::new_with_min_chunk_bytes(8)).unwrap(),
            r#"{"bytes":{"min_chunk_bytes":8}}"#
        );
    }

    #[test]
    fn config_deserializes_min_chunk_bytes_from_bytes_options() {
        let config: BytesDecoderConfig =
            serde_json::from_str(r#"{"bytes": {"min_chunk_bytes": 8}}"#).unwrap();
        assert_eq!(config.bytes.min_chunk_bytes, 8);
        let config: BytesDecoderConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.bytes.min_chunk_bytes, i64::MAX as u64);
    }

    #[test]
    fn framing_config_parses_method_bytes_with_nested_bytes_options() {
        let config: crate::decoding::FramingConfig =
            serde_json::from_str(r#"{"method": "bytes", "bytes": {"min_chunk_bytes": 8}}"#)
                .unwrap();
        assert_eq!(
            config,
            crate::decoding::FramingConfig::Bytes(BytesDecoderConfig::new_with_min_chunk_bytes(8))
        );
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
