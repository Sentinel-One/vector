use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use vector_lib::event::{EventFinalizers, Finalizable};
use vector_lib::request_metadata::RequestMetadata;

use super::{
    encoder::HecLogsEncoder,
    sink::{HecProcessedEvent, Partitioned},
};
use crate::sinks::{
    splunk_hec::common::request::HecRequest,
    util::{
        metadata::RequestMetadataBuilder, request_builder::EncodeResult, Compression, Compressor,
        RequestBuilder,
    },
};

pub struct HecLogsRequestBuilder {
    pub encoder: HecLogsEncoder,
    pub compression: Compression,
}

/// Encoded batch body, carrying the batch's effective bytes through to its `HecRequest`.
pub struct HecLogsPayload {
    body: Bytes,
    effective_bytes: Option<u64>,
}

impl From<Bytes> for HecLogsPayload {
    fn from(body: Bytes) -> Self {
        Self {
            body,
            effective_bytes: None,
        }
    }
}

impl AsRef<[u8]> for HecLogsPayload {
    fn as_ref(&self) -> &[u8] {
        &self.body
    }
}

#[derive(Debug, Clone)]
pub struct HecRequestMetadata {
    finalizers: EventFinalizers,
    partition: Option<Arc<str>>,
    source: Option<String>,
    sourcetype: Option<String>,
    index: Option<String>,
    host: Option<String>,
    headers: Vec<(HeaderName, Option<HeaderValue>)>,
}

impl RequestBuilder<(Option<Partitioned>, Vec<HecProcessedEvent>)> for HecLogsRequestBuilder {
    type Metadata = HecRequestMetadata;
    type Events = Vec<HecProcessedEvent>;
    type Encoder = HecLogsEncoder;
    type Payload = HecLogsPayload;
    type Request = HecRequest;
    type Error = std::io::Error;

    fn compression(&self) -> Compression {
        self.compression
    }

    fn encoder(&self) -> &Self::Encoder {
        &self.encoder
    }

    fn split_input(
        &self,
        input: (Option<Partitioned>, Vec<HecProcessedEvent>),
    ) -> (Self::Metadata, RequestMetadataBuilder, Self::Events) {
        let (mut partition, mut events) = input;

        let finalizers = events.take_finalizers();

        let builder = RequestMetadataBuilder::from_events(&events);

        (
            HecRequestMetadata {
                finalizers,
                partition: partition.as_ref().and_then(|p| p.token.clone()),
                source: partition.as_mut().and_then(|p| p.source.take()),
                sourcetype: partition.as_mut().and_then(|p| p.sourcetype.take()),
                index: partition.as_mut().and_then(|p| p.index.take()),
                host: partition.as_mut().and_then(|p| p.host.take()),
                headers: partition
                    .as_mut()
                    .map(|p| std::mem::take(&mut p.headers))
                    .unwrap_or_default(),
            },
            builder,
            events,
        )
    }

    /// Same as the default `encode_events`, except the payload also carries the effective bytes.
    fn encode_events(
        &self,
        events: Self::Events,
    ) -> Result<EncodeResult<Self::Payload>, Self::Error> {
        let mut compressor = Compressor::from(self.compression);
        let is_compressed = compressor.is_compressed();
        let (_, json_size, effective_bytes) = self.encoder.encode_batch(events, &mut compressor)?;

        let payload = HecLogsPayload {
            body: compressor.into_inner().freeze(),
            effective_bytes,
        };
        let result = if is_compressed {
            let compressed_byte_size = payload.body.len();
            EncodeResult::compressed(payload, compressed_byte_size, json_size)
        } else {
            EncodeResult::uncompressed(payload, json_size)
        };

        Ok(result)
    }

    fn build_request(
        &self,
        hec_metadata: Self::Metadata,
        metadata: RequestMetadata,
        payload: EncodeResult<Self::Payload>,
    ) -> Self::Request {
        let headers = hec_metadata
            .headers
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect();

        let payload = payload.into_payload();
        HecRequest {
            body: payload.body,
            effective_bytes: payload.effective_bytes,
            finalizers: hec_metadata.finalizers,
            passthrough_token: hec_metadata.partition,
            source: hec_metadata.source,
            sourcetype: hec_metadata.sourcetype,
            index: hec_metadata.index,
            host: hec_metadata.host,
            headers,
            metadata,
        }
    }
}
