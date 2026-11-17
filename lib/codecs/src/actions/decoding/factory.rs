use std::marker::PhantomData;
use std::net::IpAddr;

use vector_core::config::LogNamespace;

use super::Decoder;
use crate::decoding::{DeserializerFactory, FramerFactory};

/// The kind of unit a [`DecoderFactory`] builds decoders for: [`Stream`] or [`Datagram`].
pub trait Scope: sealed::Sealed {}

mod sealed {
    pub trait Sealed {}
}

/// Scope of a [`DecoderFactory`] whose units have no peer identity to share state under: a stream
/// connection, a message, a request, an object.
#[derive(Clone, Copy, Debug)]
pub struct Stream;

/// Scope of a [`DecoderFactory`] whose units are datagrams from an identifiable peer.
#[derive(Clone, Copy, Debug)]
pub struct Datagram;

impl sealed::Sealed for Stream {}
impl Scope for Stream {}
impl sealed::Sealed for Datagram {}
impl Scope for Datagram {}

/// Builds a fresh [`Decoder`] for each unit of input a source receives.
///
/// Decoders are never cloned. A decoder owns the mutable state of exactly one unit (a streaming
/// parser's half-read document, a framer's partial frame), and when decoders were cloned per unit,
/// whether that state was copied, reset or shared was decided implicitly by each codec's `Clone`
/// impl. The factory makes that decision explicit and puts it in one place: everything a decoder
/// needs per unit is created by `build`, and everything meant to be shared across units (a
/// compiled VRL program, netflow's template cache, chunked GELF's partially received messages) is
/// held by the factory and handed to each decoder it builds.
///
/// `S` fixes the kind of unit at the type level, so a source cannot build a datagram decoder
/// without naming the peer, or name a peer for a stream.
#[derive(Clone, Debug)]
pub struct DecoderFactory<S: Scope> {
    framer: FramerFactory,
    deserializer: DeserializerFactory,
    log_namespace: LogNamespace,
    scope: PhantomData<S>,
}

impl<S: Scope> DecoderFactory<S> {
    pub(super) const fn new(
        framer: FramerFactory,
        deserializer: DeserializerFactory,
        log_namespace: LogNamespace,
    ) -> Self {
        Self {
            framer,
            deserializer,
            log_namespace,
            scope: PhantomData,
        }
    }

    /// Sets the log namespace that decoders built by this factory use.
    pub const fn with_log_namespace(mut self, log_namespace: LogNamespace) -> Self {
        self.log_namespace = log_namespace;
        self
    }

    fn build_for(&self, peer: Option<IpAddr>) -> Decoder {
        Decoder::new(self.framer.build(peer), self.deserializer.build())
            .with_log_namespace(self.log_namespace)
    }
}

static_assertions::assert_impl_all!(DecoderFactory<Stream>: Clone, Send, Sync);
static_assertions::assert_impl_all!(DecoderFactory<Datagram>: Clone, Send, Sync);

impl DecoderFactory<Stream> {
    /// Builds a decoder for one stream connection, message, request or object.
    pub fn build(&self) -> Decoder {
        self.build_for(None)
    }
}

impl DecoderFactory<Datagram> {
    /// Builds a decoder for one datagram received from `peer`.
    pub fn build(&self, peer: IpAddr) -> Decoder {
        self.build_for(Some(peer))
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use tokio_util::codec::Decoder as _;
    use vector_common::limits::OperationalLimits;
    use vector_core::config::LogNamespace;
    use vrl::{owned_value_path, value::Value};

    use super::{Datagram, DecoderFactory, Scope, Stream};
    use crate::actions::DecodingConfig;
    use crate::decoding::{
        format::{PathOperation, PathOperationConfig},
        FramingConfig, JsonPathDeserializerConfig, JsonPathDeserializerOptions,
        NewlineDelimitedDecoderConfig,
    };

    fn json_paths_factory<S: Scope>() -> DecoderFactory<S> {
        DecodingConfig::new(
            FramingConfig::NewlineDelimited(NewlineDelimitedDecoderConfig::new()),
            JsonPathDeserializerConfig::new(
                PathOperationConfig::new(owned_value_path!(), PathOperation::Identity.into()),
                JsonPathDeserializerOptions::default(),
            )
            .into(),
            LogNamespace::Legacy,
            OperationalLimits::default(),
        )
        .build()
        .unwrap()
    }

    fn decode(decoder: &mut crate::actions::Decoder, input: &str) -> Vec<Option<Value>> {
        let mut buf = BytesMut::from(input);
        decoder
            .decode(&mut buf)
            .unwrap()
            .map_or_else(Vec::new, |(events, _)| {
                events
                    .iter()
                    .map(|event| event.as_log().get("data.b").cloned())
                    .collect()
            })
    }

    #[test]
    fn stream_decoders_built_from_one_factory_do_not_share_json_paths_state() {
        let factory = json_paths_factory::<Stream>();

        assert_eq!(
            decode(&mut factory.build(), "{\"a\":\n"),
            Vec::<Option<Value>>::new()
        );
        assert_eq!(
            decode(&mut factory.build(), "{\"b\":2}\n"),
            vec![Some(Value::from(2))]
        );
    }

    #[test]
    fn datagram_decoders_for_one_peer_do_not_share_json_paths_state() {
        let factory = json_paths_factory::<Datagram>();
        let peer = "10.0.0.1".parse().unwrap();

        assert_eq!(
            decode(&mut factory.build(peer), "{\"a\":\n"),
            Vec::<Option<Value>>::new()
        );
        assert_eq!(
            decode(&mut factory.build(peer), "{\"b\":2}\n"),
            vec![Some(Value::from(2))]
        );
    }

    #[test]
    fn stream_decoder_completes_json_paths_document_split_across_its_own_frames() {
        let mut decoder = json_paths_factory::<Stream>().build();

        assert_eq!(
            decode(&mut decoder, "{\"b\":\n"),
            Vec::<Option<Value>>::new()
        );
        assert_eq!(decode(&mut decoder, "2}\n"), vec![Some(Value::from(2))]);
    }
}
