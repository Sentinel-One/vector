use crate::decoding::{BoxedFramingError, Deserializer, Error, Framer};
use crate::internal_events::codecs::DecoderFramingError;
use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;
use vector_core::config::LogNamespace;
use vector_core::emit;
use vector_core::event::Event;

/// A decoder that can decode structured events from a byte stream / byte
/// messages.
pub struct Decoder {
    /// The framer being used.
    pub framer: Framer,
    /// The deserializer being used.
    pub deserializer: Deserializer,
    /// The `log_namespace` being used.
    pub log_namespace: LogNamespace,
}

// A decoder owns the mutable state of exactly one unit of input (a connection, a message, a
// datagram) and is driven through `&mut self`.
// - Not `Clone`: a clone would have to decide whether that state is copied, reset or shared, and
//   that decision used to hide in each codec's `Clone` impl. It now lives in one place,
//   `DecoderFactory`: build a new decoder per unit, and hold anything meant to be shared across
//   units in the factory.
// - Not `Sync`: nothing should read a decoder from two threads at once, and requiring `Sync` is what
//   pushed stateful codecs into `Arc<Mutex<..>>` interior mutability. The `Boxed` variants hold
//   trait objects without a `Sync` bound, which is what keeps `Framer` and `Deserializer` `!Sync`.
// - `Send`: a decoder moves into the tokio task that owns its unit.
static_assertions::assert_impl_all!(Decoder: Send);
static_assertions::assert_not_impl_any!(Decoder: Clone, Sync);
static_assertions::assert_impl_all!(Framer: Send);
static_assertions::assert_not_impl_any!(Framer: Clone, Sync);
static_assertions::assert_impl_all!(Deserializer: Send);
static_assertions::assert_not_impl_any!(Deserializer: Clone, Sync);

impl Decoder {
    /// Creates a new `Decoder` with the specified `Framer` to produce byte
    /// frames from the byte stream / byte messages and `Deserializer` to parse
    /// structured events from a byte frame.
    pub const fn new(framer: Framer, deserializer: Deserializer) -> Self {
        Self {
            framer,
            deserializer,
            log_namespace: LogNamespace::Legacy,
        }
    }

    /// Sets the log namespace that will be used when decoding.
    pub const fn with_log_namespace(mut self, log_namespace: LogNamespace) -> Self {
        self.log_namespace = log_namespace;
        self
    }

    /// Handles the framing result and parses it into a structured event, if
    /// possible.
    ///
    /// Emits logs if either framing or parsing failed.
    fn handle_framing_result(
        &mut self,
        frame: Result<Option<Bytes>, BoxedFramingError>,
    ) -> Result<Option<(SmallVec<[Event; 1]>, usize)>, Error> {
        let frame = frame.map_err(|error| {
            emit!(DecoderFramingError { error: &error });
            Error::FramingError(error)
        })?;

        frame
            .map(|frame| self.deserializer_parse(frame))
            .transpose()
    }

    /// Parses a frame using the included deserializer, and handles any errors by logging.
    pub fn deserializer_parse(
        &mut self,
        frame: Bytes,
    ) -> Result<(SmallVec<[Event; 1]>, usize), Error> {
        self.deserializer.parse_frame(frame, self.log_namespace)
    }
}

impl tokio_util::codec::Decoder for Decoder {
    type Item = (SmallVec<[Event; 1]>, usize);
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let frame = self.framer.decode(buf);
        self.handle_framing_result(frame)
    }

    /// Flushes the deserializer once the framer has no frames left, so state carried across a
    /// unit's frames ends with the unit (for a datagram source, each datagram). Whatever the flush
    /// returns is one last item, of zero framed bytes.
    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.framer.decode_eof(buf) {
            Ok(None) => self
                .deserializer
                .flush_unit(self.log_namespace)
                .map(|events| (!events.is_empty()).then_some((events, 0))),
            frame => self.handle_framing_result(frame),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Decoder;
    use crate::{
        decoding::{
            format::{PathOperation, PathOperationConfig},
            Deserializer, Framer, JsonPathDeserializer, JsonPathDeserializerOptions,
        },
        JsonDeserializer, NewlineDelimitedDecoder, StreamDecodingError,
    };
    use vector_common::limits::FramingLimits;
    use bytes::{Bytes, BytesMut};
    use futures::{stream, StreamExt};
    use tokio_util::{
        codec::{Decoder as _, FramedRead},
        io::StreamReader,
    };
    use vrl::{owned_value_path, value::Value};

    #[tokio::test]
    async fn framed_read_recover_from_error() {
        let iter = stream::iter(
            ["{ \"foo\": 1 }\n", "invalid\n", "{ \"bar\": 2 }\n"]
                .into_iter()
                .map(Bytes::from),
        );
        let stream = iter.map(Ok::<_, std::io::Error>);
        let reader = StreamReader::new(stream);
        let decoder = Decoder::new(
            Framer::NewlineDelimited(NewlineDelimitedDecoder::new(FramingLimits::default().max_frame_length_bytes)),
            Deserializer::Json(JsonDeserializer::default()),
        );
        let mut stream = FramedRead::new(reader, decoder);

        let next = stream.next().await.unwrap();
        let event = next.unwrap().0.pop().unwrap().into_log();
        assert_eq!(event.get("foo").unwrap(), &Value::from(1));

        let next = stream.next().await.unwrap();
        let error = next.unwrap_err();
        assert!(error.can_continue());

        let next = stream.next().await.unwrap();
        let event = next.unwrap().0.pop().unwrap().into_log();
        assert_eq!(event.get("bar").unwrap(), &Value::from(2));
    }

    fn json_paths_decoder() -> Decoder {
        let config = PathOperationConfig::new(owned_value_path!(), PathOperation::Identity.into());
        Decoder::new(
            Framer::NewlineDelimited(NewlineDelimitedDecoder::new(
                FramingLimits::default().max_frame_length_bytes,
            )),
            Deserializer::JsonPaths(JsonPathDeserializer::new(
                &config,
                &JsonPathDeserializerOptions::default(),
            )),
        )
    }

    #[test]
    fn json_paths_decoder_completes_a_document_split_across_its_own_frames() {
        let mut decoder = json_paths_decoder();

        let mut buf = BytesMut::from("{\"b\":\n");
        assert_eq!(decoder.decode(&mut buf).unwrap().unwrap().0.len(), 0);

        let mut buf = BytesMut::from("2}\n");
        let (events, _) = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_log().get("data.b"), Some(&Value::from(2)));
    }
}
