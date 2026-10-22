use std::borrow::Cow;

use bytes::BytesMut;
use serde::Serialize;
use tokio_util::codec::Encoder as _;
use vector_lib::request_metadata::GroupedCountByteSize;
use vector_lib::{config::telemetry, EstimatedJsonEncodedSizeOf};

use super::sink::HecProcessedEvent;
use crate::{
    codecs::Transformer,
    event::{Event, LogEvent},
    internal_events::SplunkEventEncodeError,
    sinks::{
        splunk_hec::common::{EffectiveBytesAlgorithm, EndpointTarget, SentEvent, SentMetadata},
        util::encoding::Encoder,
    },
};

#[derive(Serialize, Debug)]
pub enum HecEvent<'a> {
    #[serde(rename = "event")]
    Json(serde_json::Value),
    #[serde(rename = "event")]
    Text(Cow<'a, str>),
}

#[derive(Serialize, Debug)]
pub struct HecData<'a> {
    #[serde(flatten)]
    pub event: HecEvent<'a>,
    pub fields: LogEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sourcetype: Option<String>,
}

impl<'a> HecData<'a> {
    pub const fn new(event: HecEvent<'a>, fields: LogEvent, time: Option<f64>) -> Self {
        Self {
            event,
            fields,
            time,
            host: None,
            index: None,
            source: None,
            sourcetype: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HecLogsEncoder {
    pub transformer: Transformer,
    pub encoder: crate::codecs::Encoder<()>,
    pub auto_extract_timestamp: bool,
    pub effective_bytes_algorithm: EffectiveBytesAlgorithm,
}

impl HecLogsEncoder {
    /// Encodes the batch like [`Encoder::encode_input`], also returning the batch's effective bytes
    /// (`0` when the algorithm is `none`).
    pub fn encode_batch(
        &self,
        input: Vec<HecProcessedEvent>,
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<(usize, GroupedCountByteSize, u64)> {
        let mut encoder = self.encoder.clone();
        let mut byte_size = telemetry().create_request_count_byte_size();
        let algorithm = self.effective_bytes_algorithm;
        let sends_json = encoder.serializer().supports_json();
        let mut effective_bytes: u64 = 0;
        let mut encoded_input: Vec<u8> = Vec::new();
        input
            .into_iter()
            .filter_map(|processed_event| {
                let mut event = Event::from(processed_event.event);
                let metadata = processed_event.metadata;
                self.transformer.transform(&mut event);

                byte_size.add_event(&event, event.estimated_json_encoded_size_of());

                let mut bytes = BytesMut::new();

                match metadata.endpoint_target {
                    EndpointTarget::Raw => {
                        let host = metadata.host.as_ref().map(|host| host.to_string_lossy());
                        // Sent once per request as query parameters, but counted once per event so
                        // both endpoints measure the same data the same way.
                        let sent_metadata = SentMetadata {
                            host: host.as_deref(),
                            source: metadata.source.as_deref(),
                            sourcetype: metadata.sourcetype.as_deref(),
                            index: metadata.index.as_deref(),
                            ..SentMetadata::default()
                        };
                        // A JSON codec is measured from the event before `encode` consumes it,
                        // any other codec from the encoded text it sends.
                        let json_bytes = sends_json.then(|| {
                            algorithm
                                .measure(SentEvent::Value(event.as_log().value()), &sent_metadata)
                        });
                        encoder.encode(event, &mut bytes).ok()?;
                        let measured = json_bytes.unwrap_or_else(|| {
                            algorithm.measure(SentEvent::Text(&bytes), &sent_metadata)
                        });
                        Some((bytes.to_vec(), measured))
                    }
                    EndpointTarget::Event => {
                        let serializer = encoder.serializer();
                        let hec_event = if sends_json {
                            HecEvent::Json(
                                serializer
                                    .to_json_value(event)
                                    .map_err(|error| emit!(SplunkEventEncodeError { error }))
                                    .ok()?,
                            )
                        } else {
                            encoder.encode(event, &mut bytes).ok()?;
                            HecEvent::Text(String::from_utf8_lossy(&bytes))
                        };

                        let mut hec_data = HecData::new(
                            hec_event,
                            metadata.fields,
                            // If auto_extract_timestamp is set we don't want to pass the timestamp in the
                            // event since we want Splunk to extract it from the message.
                            if self.auto_extract_timestamp {
                                None
                            } else {
                                metadata.timestamp
                            },
                        );
                        hec_data.host = metadata
                            .host
                            .map(|host| host.to_string_lossy().into_owned());
                        hec_data.index = metadata.index;
                        hec_data.source = metadata.source;
                        hec_data.sourcetype = metadata.sourcetype;
                        let measured = measure_hec_data(algorithm, &hec_data);

                        match serde_json::to_vec(&hec_data) {
                            Ok(value) => Some((value, measured)),
                            Err(error) => {
                                emit!(SplunkEventEncodeError {
                                    error: error.into()
                                });
                                None
                            }
                        }
                    }
                }
            })
            .for_each(|(encoded, measured)| {
                encoded_input.extend_from_slice(&encoded);
                effective_bytes += measured;
            });

        let encoded_size = encoded_input.len();
        writer.write_all(encoded_input.as_slice())?;
        Ok((encoded_size, byte_size, effective_bytes))
    }
}

/// Effective bytes of one event-endpoint record, measured from exactly what is serialized.
fn measure_hec_data(algorithm: EffectiveBytesAlgorithm, hec_data: &HecData<'_>) -> u64 {
    let event = match &hec_data.event {
        HecEvent::Json(json) => SentEvent::Json(json),
        HecEvent::Text(text) => SentEvent::Text(text.as_bytes()),
    };
    let metadata = SentMetadata {
        host: hec_data.host.as_deref(),
        source: hec_data.source.as_deref(),
        sourcetype: hec_data.sourcetype.as_deref(),
        index: hec_data.index.as_deref(),
        fields: Some(hec_data.fields.value()),
        time: hec_data.time,
    };
    algorithm.measure(event, &metadata)
}

impl Encoder<Vec<HecProcessedEvent>> for HecLogsEncoder {
    fn encode_input(
        &self,
        input: Vec<HecProcessedEvent>,
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<(usize, GroupedCountByteSize)> {
        let (encoded_size, byte_size, _) = self.encode_batch(input, writer)?;
        Ok((encoded_size, byte_size))
    }
}
