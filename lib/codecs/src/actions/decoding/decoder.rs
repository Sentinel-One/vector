use crate::decoding::{
    format::Deserializer as _, BoxedFramingError, BytesDeserializer, Deserializer, Error, Framer,
    NewlineDelimitedDecoder,
};
use crate::internal_events::codecs::{DecoderDeserializeError, DecoderFramingError};
use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;
use std::net::IpAddr;
use vector_core::config::LogNamespace;
use vector_core::emit;
use vector_core::event::Event;

/// A decoder that can decode structured events from a byte stream / byte
/// messages.
#[derive(Clone)]
pub struct Decoder {
    /// The framer being used.
    pub framer: Framer,
    /// The deserializer being used.
    pub deserializer: Deserializer,
    /// The `log_namespace` being used.
    pub log_namespace: LogNamespace,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            framer: Framer::NewlineDelimited(NewlineDelimitedDecoder::new()),
            deserializer: Deserializer::Bytes(BytesDeserializer),
            log_namespace: LogNamespace::Legacy,
        }
    }
}

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

    /// Clones this decoder for a newly accepted connection.
    ///
    /// If the configured framer is [`Framer::Netflow`], gives the clone a fresh template scope so
    /// it does not share a template cache with any other connection built from the same configured
    /// decoder — see `NetflowDecoder::set_new_connection_scope`. A no-op for every other framer.
    ///
    /// Call this (not a plain `.clone()`) once per accepted stream connection, whether TCP or Unix
    /// domain.
    #[must_use]
    pub fn clone_for_connection(&self) -> Self {
        let mut decoder = self.clone();
        if let Framer::Netflow(netflow) = &mut decoder.framer {
            netflow.set_new_connection_scope();
        }
        decoder
    }

    /// Clones this decoder for a single datagram received from `peer`.
    ///
    /// If the configured framer is [`Framer::Netflow`], scopes the clone's template cache to that
    /// peer so one exporter cannot redefine the template ids another exporter's records decode
    /// against — see `NetflowDecoder::set_datagram_peer`. A no-op for every other framer.
    ///
    /// Call this (not a plain `.clone()`) once per received UDP datagram.
    #[must_use]
    pub fn clone_for_datagram_peer(&self, peer: IpAddr) -> Self {
        let mut decoder = self.clone();
        if let Framer::Netflow(netflow) = &mut decoder.framer {
            netflow.set_datagram_peer(peer);
        }
        decoder
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
    pub fn deserializer_parse(&self, frame: Bytes) -> Result<(SmallVec<[Event; 1]>, usize), Error> {
        let byte_size = frame.len();

        // Parse structured events from the byte frame.
        self.deserializer
            .parse(frame, self.log_namespace)
            .map(|events| (events, byte_size))
            .map_err(|error| {
                emit!(DecoderDeserializeError { error: &error });
                Error::ParsingError(error)
            })
    }
}

impl tokio_util::codec::Decoder for Decoder {
    type Item = (SmallVec<[Event; 1]>, usize);
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let frame = self.framer.decode(buf);
        self.handle_framing_result(frame)
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let frame = self.framer.decode_eof(buf);
        self.handle_framing_result(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::Decoder;
    use crate::{
        decoding::{Deserializer, Framer},
        JsonDeserializer, NewlineDelimitedDecoder, StreamDecodingError,
    };
    use bytes::Bytes;
    use futures::{stream, StreamExt};
    use tokio_util::{codec::FramedRead, io::StreamReader};
    use vrl::value::Value;

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
            Framer::NewlineDelimited(NewlineDelimitedDecoder::new()),
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
}
