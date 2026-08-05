use base64::prelude::{Engine as _, BASE64_STANDARD};
use bytes::Bytes;
use chrono::Utc;
use futures::StreamExt;
use snafu::{ResultExt, Snafu};
use tokio_util::codec::FramedRead;
use vector_common::constants::GZIP_MAGIC;
use vector_lib::codecs::StreamDecodingError;
use vector_lib::lookup::{metadata_path, path, PathPrefix};
use vector_lib::{
    config::{LegacyKey, LogNamespace},
    event::BatchNotifier,
    EstimatedJsonEncodedSizeOf,
};
use vector_lib::{
    finalization::AddBatchNotifier,
    internal_event::{
        ByteSize, BytesReceived, CountByteSize, InternalEventHandle as _, Registered,
    },
};
use vrl::compiler::SecretTarget;
use warp::reject;

use super::{
    errors::{ParseRecordsSnafu, RequestError},
    models::{EncodedFirehoseRecord, FirehoseRequest, FirehoseResponse},
    Compression,
};
use crate::{
    codecs::Decoder,
    config::log_schema,
    event::{BatchStatus, Event},
    internal_events::{
        AwsKinesisFirehoseAutomaticRecordDecodeError, EventsReceived, StreamClosedError,
    },
    sources::{
        aws_kinesis_firehose::AwsKinesisFirehoseConfig,
        util::decompression::{is_decompressed_size_limit_error, CappedDecoder},
    },
    SourceSender,
};

#[derive(Clone)]
pub(super) struct Context {
    pub(super) compression: Compression,
    pub(super) store_access_key: bool,
    pub(super) decoder: Decoder,
    pub(super) acknowledgements: bool,
    pub(super) bytes_received: Registered<BytesReceived>,
    pub(super) out: SourceSender,
    pub(super) log_namespace: LogNamespace,
}

/// Publishes decoded events from the FirehoseRequest to the pipeline
pub(super) async fn firehose(
    request_id: String,
    source_arn: String,
    request: FirehoseRequest,
    mut context: Context,
) -> Result<impl warp::Reply, reject::Rejection> {
    let log_namespace = context.log_namespace;
    let events_received = register!(EventsReceived);

    for record in request.records {
        let bytes = decode_record(&record, context.compression)
            .with_context(|_| ParseRecordsSnafu {
                request_id: request_id.clone(),
            })
            .map_err(reject::custom)?;
        context.bytes_received.emit(ByteSize(bytes.len()));

        let mut stream = FramedRead::new(bytes.as_ref(), context.decoder.clone());
        loop {
            match stream.next().await {
                Some(Ok((mut events, _byte_size))) => {
                    events_received.emit(CountByteSize(
                        events.len(),
                        events.estimated_json_encoded_size_of(),
                    ));

                    let (batch, receiver) = context
                        .acknowledgements
                        .then(|| {
                            let (batch, receiver) = BatchNotifier::new_with_receiver();
                            (Some(batch), Some(receiver))
                        })
                        .unwrap_or((None, None));

                    let now = Utc::now();
                    for event in &mut events {
                        if let Some(batch) = &batch {
                            event.add_batch_notifier(batch.clone());
                        }
                        if let Event::Log(ref mut log) = event {
                            log_namespace.insert_vector_metadata(
                                log,
                                log_schema().source_type_key(),
                                path!("source_type"),
                                Bytes::from_static(AwsKinesisFirehoseConfig::NAME.as_bytes()),
                            );
                            // This handles the transition from the original timestamp logic. Originally the
                            // `timestamp_key` was always populated by the `request.timestamp` time.
                            match log_namespace {
                                LogNamespace::Vector => {
                                    log.insert(metadata_path!("vector", "ingest_timestamp"), now);
                                    log.insert(
                                        metadata_path!(AwsKinesisFirehoseConfig::NAME, "timestamp"),
                                        request.timestamp,
                                    );
                                }
                                LogNamespace::Legacy => {
                                    if let Some(timestamp_key) = log_schema().timestamp_key() {
                                        log.try_insert(
                                            (PathPrefix::Event, timestamp_key),
                                            request.timestamp,
                                        );
                                    }
                                }
                            };

                            log_namespace.insert_source_metadata(
                                AwsKinesisFirehoseConfig::NAME,
                                log,
                                Some(LegacyKey::InsertIfEmpty(path!("request_id"))),
                                path!("request_id"),
                                request_id.to_owned(),
                            );
                            log_namespace.insert_source_metadata(
                                AwsKinesisFirehoseConfig::NAME,
                                log,
                                Some(LegacyKey::InsertIfEmpty(path!("source_arn"))),
                                path!("source_arn"),
                                source_arn.to_owned(),
                            );

                            if context.store_access_key {
                                if let Some(access_key) = &request.access_key {
                                    log.metadata_mut().secrets_mut().insert_secret(
                                        "aws_kinesis_firehose_access_key",
                                        access_key,
                                    );
                                }
                            }
                        }
                    }

                    let count = events.len();
                    if let Err(error) = context.out.send_batch(events).await {
                        emit!(StreamClosedError { count });
                        let error = RequestError::ShuttingDown {
                            request_id: request_id.clone(),
                            source: error,
                        };
                        warp::reject::custom(error);
                    }

                    drop(batch);
                    if let Some(receiver) = receiver {
                        match receiver.await {
                            BatchStatus::Delivered => Ok(()),
                            BatchStatus::Rejected => {
                                Err(warp::reject::custom(RequestError::DeliveryFailed {
                                    request_id: request_id.clone(),
                                }))
                            }
                            BatchStatus::Errored => {
                                Err(warp::reject::custom(RequestError::DeliveryErrored {
                                    request_id: request_id.clone(),
                                }))
                            }
                        }?;
                    }
                }
                Some(Err(error)) => {
                    // Error is logged by `crate::codecs::Decoder`, no further
                    // handling is needed here.
                    if !error.can_continue() {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    Ok(warp::reply::json(&FirehoseResponse {
        request_id: request_id.clone(),
        timestamp: Utc::now(),
        error_message: None,
    }))
}

#[derive(Debug, Snafu)]
pub enum RecordDecodeError {
    #[snafu(display("Could not base64 decode request data: {}", source))]
    Base64 { source: base64::DecodeError },
    #[snafu(display("Could not decompress request data as {}: {}", compression, source))]
    Decompression {
        source: std::io::Error,
        compression: Compression,
    },
}

/// Decodes a Firehose record.
fn decode_record(
    record: &EncodedFirehoseRecord,
    compression: Compression,
) -> Result<Bytes, RecordDecodeError> {
    let buf = BASE64_STANDARD
        .decode(record.data.as_bytes())
        .context(Base64Snafu {})?;

    if buf.is_empty() {
        return Ok(Bytes::default());
    }

    match compression {
        Compression::None => Ok(Bytes::from(buf)),
        Compression::Gzip => decode_gzip(&buf[..]).with_context(|_| DecompressionSnafu {
            compression: compression.to_owned(),
        }),
        Compression::Auto => {
            if is_gzip(&buf) {
                decode_gzip(&buf[..]).or_else(|error| {
                    // An exceeded size cap means the magic bytes really were gzip and the payload
                    // is oversized, so reject it. Only fall back to forwarding the raw bytes when
                    // auto-detection guessed wrong (valid-looking magic, but not actually gzip).
                    if is_decompressed_size_limit_error(&error) {
                        return Err(error).with_context(|_| DecompressionSnafu {
                            compression: Compression::Gzip,
                        });
                    }
                    emit!(AwsKinesisFirehoseAutomaticRecordDecodeError {
                        compression: Compression::Gzip,
                        error
                    });
                    Ok(Bytes::from(buf))
                })
            } else {
                // only support gzip for now
                Ok(Bytes::from(buf))
            }
        }
    }
}

fn is_gzip(data: &[u8]) -> bool {
    // The header length of a GZIP file is 10 bytes. The first two bytes of the constant comes from
    // the GZIP file format specification, which is the fixed member header identification bytes.
    // The third byte is the compression method, of which only one is defined which is 8 for the
    // deflate algorithm.
    //
    // Reference: https://datatracker.ietf.org/doc/html/rfc1952 Section 2.3
    data.starts_with(GZIP_MAGIC)
}

fn decode_gzip(data: &[u8]) -> std::io::Result<Bytes> {
    // Cap the decompressed output so a gzip-bomb record cannot drive unbounded allocation.
    CappedDecoder::gzip(data).decompress().map(Bytes::from)
}

#[cfg(test)]
mod tests {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write as _;

    use super::*;

    const CONTENT: &[u8] = b"Example";

    #[test]
    fn correctly_detects_gzipped_content() {
        assert!(!is_gzip(CONTENT));
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(CONTENT).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(is_gzip(&compressed));
    }

    /// One cheap gzip member repeated past the cap. `MultiGzDecoder` walks every concatenated
    /// member, so no single oversized member is required.
    fn gzip_bomb() -> Vec<u8> {
        use crate::sources::util::decompression::DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&vec![0u8; 1024 * 1024]).unwrap();
        let member = encoder.finish().unwrap();

        let mut bomb = Vec::new();
        for _ in 0..(DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES / (1024 * 1024) + 1) {
            bomb.extend_from_slice(&member);
        }
        assert!(
            bomb.len() < 1024 * 1024,
            "the bomb must stay small on the wire to be a meaningful test, got {} bytes",
            bomb.len()
        );
        bomb
    }

    fn record(data: &[u8]) -> EncodedFirehoseRecord {
        EncodedFirehoseRecord {
            data: BASE64_STANDARD.encode(data),
        }
    }

    /// A gzip-bomb record must be refused rather than inflated.
    #[test]
    fn explicit_gzip_record_over_the_cap_is_rejected() {
        let error = decode_record(&record(&gzip_bomb()), super::Compression::Gzip)
            .expect_err("a record inflating past the cap must be rejected");

        assert!(matches!(
            error,
            RecordDecodeError::Decompression { .. }
        ));
    }

    /// Under `Auto`, an oversized payload whose magic bytes really are gzip must be rejected, not
    /// silently forwarded as raw bytes. The raw-bytes fallback exists only for a mis-detection.
    #[test]
    fn auto_detected_gzip_record_over_the_cap_is_rejected_not_forwarded() {
        let error = decode_record(&record(&gzip_bomb()), super::Compression::Auto)
            .expect_err("an oversized auto-detected gzip record must not fall back to raw bytes");

        assert!(matches!(
            error,
            RecordDecodeError::Decompression { .. }
        ));
    }

    /// The cap must not disturb ordinary records, on either the explicit or the auto path.
    #[test]
    fn records_under_the_cap_are_unaffected() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(CONTENT).unwrap();
        let compressed = encoder.finish().unwrap();

        for compression in [super::Compression::Gzip, super::Compression::Auto] {
            let decoded = decode_record(&record(&compressed), compression)
                .expect("a record within the cap must decode");
            assert_eq!(decoded, Bytes::from_static(CONTENT));
        }

        let plain = decode_record(&record(CONTENT), super::Compression::None)
            .expect("an uncompressed record must decode");
        assert_eq!(plain, Bytes::from_static(CONTENT));
    }

    /// Auto-detection guessing wrong (gzip magic, not actually gzip) must still fall back to
    /// forwarding the raw bytes -- the size cap must not turn that into a hard failure.
    #[test]
    fn auto_detection_mistake_still_falls_back_to_raw_bytes() {
        let mut not_gzip = vector_common::constants::GZIP_MAGIC.to_vec();
        not_gzip.extend_from_slice(b"definitely not a gzip stream");

        let decoded = decode_record(&record(&not_gzip), super::Compression::Auto)
            .expect("a mis-detected record must fall back to raw bytes");

        assert_eq!(decoded, Bytes::from(not_gzip));
    }
}
