use std::{
    cmp,
    io::{self, Write},
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use flate2::write::GzDecoder;
use futures_util::FutureExt;
use http::{Request, Response};
use hyper::{
    body::{HttpBody, Sender},
    Body,
};
use std::future::Future;
use tokio::{pin, select};
use tonic::{body::BoxBody, metadata::AsciiMetadataValue, Status};
use tower::{Layer, Service};
use vector_lib::internal_event::{
    ByteSize, BytesReceived, InternalEventHandle as _, Protocol, Registered,
};

use crate::internal_events::{GrpcError, GrpcInvalidCompressionSchemeError};
use crate::sources::util::decompression::{
    max_decompressed_size_bytes,
    max_zlib_compressed_frame_size_bytes, DecompressedSizeLimitExceeded,
};

// Every gRPC message has a five byte header:
// - a compressed flag (u8, 0/1 for compressed/decompressed)
// - a length prefix, indicating the number of remaining bytes to read (u32)
const GRPC_MESSAGE_HEADER_LEN: usize = mem::size_of::<u8>() + mem::size_of::<u32>();
// Fixed container framing a valid frame adds on top of zlib's worst-case expansion. Added to the
// compressed-frame pre-filter so a small cap does not reject a typical gzip frame whose
// decompressed size is within the cap.
//
// gzip's mandatory framing is 18 bytes (10 header + 8 trailer), but its optional FNAME, FCOMMENT
// and FEXTRA fields are unbounded (RFC 1952 section 2.3.1): a gzip frame carrying more than this
// slack in those optional fields could still be rejected here. Encoders don't emit them in
// practice, so 22 covers the realistic case; the prefilter is only a cheap wire-size guard and the
// authoritative per-output cap is still enforced during decompression.
const GRPC_COMPRESSED_FRAME_OVERHEAD_SLACK: usize = 22;
const GRPC_ENCODING_HEADER: &str = "grpc-encoding";
const GRPC_ACCEPT_ENCODING_HEADER: &str = "grpc-accept-encoding";

enum CompressionScheme {
    Gzip,
}

impl CompressionScheme {
    fn from_encoding_header(req: &Request<Body>) -> Result<Option<Self>, Status> {
        req.headers()
            .get(GRPC_ENCODING_HEADER)
            .map(|s| {
                s.to_str().map(|s| s.to_string()).map_err(|_| {
                    Status::unimplemented(format!(
                        "`{}` contains non-visible characters and is not a valid encoding",
                        GRPC_ENCODING_HEADER
                    ))
                })
            })
            .transpose()
            .and_then(|value| match value {
                None => Ok(None),
                Some(scheme) => match scheme.as_str() {
                    "gzip" => Ok(Some(CompressionScheme::Gzip)),
                    other => Err(Status::unimplemented(format!(
                        "compression scheme `{}` is not supported",
                        other
                    ))),
                },
            })
            .map_err(|mut status| {
                status.metadata_mut().insert(
                    GRPC_ACCEPT_ENCODING_HEADER,
                    AsciiMetadataValue::from_static("gzip,identity"),
                );
                status
            })
    }
}

enum State {
    WaitingForHeader,
    Forward { overall_len: usize },
    Decompress { remaining: usize },
}

impl Default for State {
    fn default() -> Self {
        Self::WaitingForHeader
    }
}

/// Maps a decompressor `io::Error` to a gRPC [`Status`]: an oversized payload becomes
/// `out_of_range` (a client fault, matching the existing >4GB handling) while anything else falls
/// back to `internal` with `internal_msg`.
fn decompressor_error_to_status(error: &io::Error, internal_msg: &'static str) -> Status {
    if DecompressedSizeLimitExceeded::is(error) {
        Status::out_of_range("decompressed message exceeds the maximum allowed size")
    } else {
        Status::internal(internal_msg)
    }
}

/// A `Write` sink that appends into a `Vec` but refuses to grow past `max_len`, so a streaming
/// decompressor errors out *during* decompression rather than first materializing an oversized
/// output and only then having its size checked.
struct LimitedWriter {
    buf: Vec<u8>,
    max_len: usize,
}

impl LimitedWriter {
    const fn new(buf: Vec<u8>, max_len: usize) -> Self {
        Self { buf, max_len }
    }

    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > self.max_len {
            return Err(io::Error::other(DecompressedSizeLimitExceeded));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn new_decompressor() -> GzDecoder<LimitedWriter> {
    // Create the backing buffer for the decompressor and set the compression flag to false (0) and pre-allocate
    // the space for the length prefix, which we'll fill out once we've finalized the decompressor.
    let buf = vec![0; GRPC_MESSAGE_HEADER_LEN];

    // Cap the decompressed output so a compression bomb on this unauthenticated gRPC listener
    // cannot drive unbounded allocation. The buffer already holds the 5-byte header, so the sink
    // may grow to the header plus the decompressed cap; anything larger errors mid-decompression.
    GzDecoder::new(LimitedWriter::new(
        buf,
        GRPC_MESSAGE_HEADER_LEN.saturating_add(max_decompressed_size_bytes()),
    ))
}

async fn drive_body_decompression(
    mut source: Body,
    mut destination: Sender,
) -> Result<usize, Status> {
    let mut state = State::default();
    let mut buf = BytesMut::new();
    let mut decompressor = None;
    let mut bytes_received = 0;

    // Drain all message chunks from the body first.
    while let Some(result) = source.data().await {
        let chunk = result.map_err(|_| Status::internal("failed to read from underlying body"))?;
        buf.put(chunk);

        let maybe_message = loop {
            match state {
                State::WaitingForHeader => {
                    // If we don't have enough data yet to even read the gRPC message header, we can't do anything yet.
                    if buf.len() < GRPC_MESSAGE_HEADER_LEN {
                        break None;
                    }

                    // Extract the compressed flag and length prefix.
                    let (is_compressed, message_len) = {
                        let header = &buf[..GRPC_MESSAGE_HEADER_LEN];

                        let message_len_raw: u32 = header[1..]
                            .try_into()
                            .map(u32::from_be_bytes)
                            .expect("there must be four bytes remaining in the header slice");
                        let message_len = message_len_raw
                            .try_into()
                            .expect("Vector does not support 16-bit platforms");

                        (header[0] == 1, message_len)
                    };

                    // Now, if the message is not compressed, then put ourselves into forward mode, where we'll wait for
                    // the rest of the message to come in -- decoding isn't streaming so there's no benefit there --
                    // before we emit it.
                    //
                    // If the message _is_ compressed, we do roughly the same thing but we shove it into the
                    // decompressor incrementally because there's no good reason to make both the internal buffer and
                    // the decompressor buffer expand if we don't have to.
                    if is_compressed {
                        // Reject a compressed payload whose declared wire size could not
                        // legitimately decompress within the cap, before we buffer any of it. The
                        // bound (decompressed cap plus zlib's worst-case expansion, shared with the
                        // logstash source) keeps a peer from advertising a huge length and
                        // slow-streaming bytes to grow the decompressor's input buffer unbounded.
                        let compressed_frame_limit = max_zlib_compressed_frame_size_bytes()
                            .saturating_add(GRPC_COMPRESSED_FRAME_OVERHEAD_SLACK);
                        if message_len > compressed_frame_limit {
                            return Err(Status::out_of_range(
                                "compressed message length exceeds the maximum allowed size",
                            ));
                        }

                        // We skip the header in the buffer because it doesn't matter to the decompressor and we
                        // recreate it anyways.
                        buf.advance(GRPC_MESSAGE_HEADER_LEN);

                        state = State::Decompress {
                            remaining: message_len,
                        };
                    } else {
                        // Reject an identity (uncompressed) message larger than the cap before
                        // buffering it to `overall_len`, so a large declared length cannot drive
                        // unbounded buffering here ahead of tonic's own decode-size limit.
                        if message_len > max_decompressed_size_bytes() {
                            return Err(Status::out_of_range(
                                "message length exceeds the maximum allowed size",
                            ));
                        }

                        let overall_len = GRPC_MESSAGE_HEADER_LEN + message_len;
                        state = State::Forward { overall_len };
                    }
                }
                State::Forward { overall_len } => {
                    // All we're doing at this point is waiting until we have all the bytes for the current gRPC message
                    // before we emit them to the caller.
                    if buf.len() < overall_len {
                        break None;
                    }

                    // Now that we have all the bytes we need, slice them out of our internal buffer, reset our state,
                    // and hand the message back to the caller.
                    let message = buf.split_to(overall_len).freeze();
                    state = State::WaitingForHeader;

                    bytes_received += overall_len;

                    break Some(message);
                }
                State::Decompress { ref mut remaining } => {
                    if *remaining > 0 {
                        // We're waiting for `remaining` more bytes to feed to the decompressor before we finalize it and
                        // generate our new chunk of data. We might have data in our internal buffer, so try and drain that
                        // first before polling the underlying body for more.
                        let available = buf.len();
                        if available > 0 {
                            // Write the lesser of what the buffer has, or what is remaining for the current message, into
                            // the decompressor. This is _technically_ synchronous but there's really no way to do it
                            // asynchronously since we already have the data, and that's the only asynchronous part.
                            let to_take = cmp::min(available, *remaining);
                            let decompressor = decompressor.get_or_insert_with(new_decompressor);
                            if let Err(error) = decompressor.write_all(&buf[..to_take]) {
                                return Err(decompressor_error_to_status(
                                    &error,
                                    "failed to write to decompressor",
                                ));
                            }

                            *remaining -= to_take;
                            buf.advance(to_take);
                        } else {
                            break None;
                        }
                    } else {
                        // We don't need any more data, so consume the decompressor, finalize it by updating the length
                        // prefix, and then pass it back to the caller.
                        let result = decompressor
                            .take()
                            .expect("consumed decompressor when no decompressor was present")
                            .finish()
                            .map(LimitedWriter::into_inner);

                        // Decompression can fail here either because the payload exceeded the size
                        // cap (an oversized-request client fault) or, for malformed input, during
                        // finalization; map the former to `out_of_range` and treat anything else as
                        // an internal error.
                        let mut buf = result.map_err(|error| {
                            decompressor_error_to_status(
                                &error,
                                "reached impossible error during decompressor finalization",
                            )
                        })?;
                        bytes_received += buf.len();

                        // Write the length of our decompressed message in the pre-allocated slot for the message's length prefix.
                        let message_len_actual = buf.len() - GRPC_MESSAGE_HEADER_LEN;
                        let message_len = u32::try_from(message_len_actual).map_err(|_| {
                            Status::out_of_range("messages greater than 4GB are not supported")
                        })?;

                        let message_len_bytes = message_len.to_be_bytes();
                        let message_len_slot = &mut buf[1..GRPC_MESSAGE_HEADER_LEN];
                        message_len_slot.copy_from_slice(&message_len_bytes[..]);

                        // Reset our state before returning the decompressed message.
                        state = State::WaitingForHeader;

                        break Some(buf.into());
                    }
                }
            }
        };

        if let Some(message) = maybe_message {
            // We got a decompressed (or passthrough) message chunk, so just forward it to the destination.
            if destination.send_data(message).await.is_err() {
                return Err(Status::internal("destination body abnormally closed"));
            }
        }
    }

    // When we've exhausted all the message chunks, we try sending any trailers that came in on the underlying body.
    let result = source.trailers().await;
    let maybe_trailers =
        result.map_err(|_| Status::internal("error reading trailers from underlying body"))?;
    if let Some(trailers) = maybe_trailers {
        if destination.send_trailers(trailers).await.is_err() {
            return Err(Status::internal("destination body abnormally closed"));
        }
    }

    Ok(bytes_received)
}

async fn drive_request<F, E>(
    source: Body,
    destination: Sender,
    inner: F,
    bytes_received: Registered<BytesReceived>,
) -> Result<Response<BoxBody>, E>
where
    F: Future<Output = Result<Response<BoxBody>, E>>,
    E: std::fmt::Display,
{
    let body_decompression = drive_body_decompression(source, destination);

    pin!(inner);
    pin!(body_decompression);

    let mut body_eof = false;
    let mut body_bytes_received = 0;

    let result = loop {
        select! {
            biased;

            // Drive the inner future, as this will be consuming the message chunks we give it.
            result = &mut inner => break result,

            // Drive the core decompression loop, reading chunks from the underlying body, decompressing them if needed,
            // and eventually handling trailers at the end, if they're present.
            result = &mut body_decompression, if !body_eof => match result {
                Err(e) => break Ok(e.to_http()),
                Ok(bytes_received) => {
                    body_bytes_received = bytes_received;
                    body_eof = true;
                },
            }
        }
    };

    // If the response indicates success, then emit the necessary metrics
    // otherwise emit the error.
    match &result {
        Ok(res) if res.status().is_success() => {
            bytes_received.emit(ByteSize(body_bytes_received));
        }
        Ok(res) => {
            emit!(GrpcError {
                error: format!("Received {}", res.status())
            });
        }
        Err(error) => {
            emit!(GrpcError { error: &error });
        }
    };

    result
}

#[derive(Clone)]
pub struct DecompressionAndMetrics<S> {
    inner: S,
    bytes_received: Registered<BytesReceived>,
}

impl<S> Service<Request<Body>> for DecompressionAndMetrics<S>
where
    S: Service<Request<Body>, Response = Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        match CompressionScheme::from_encoding_header(&req) {
            // There was a header for the encoding, but it was either invalid data or a scheme we don't support.
            Err(status) => {
                emit!(GrpcInvalidCompressionSchemeError { status: &status });
                Box::pin(async move { Ok(status.to_http()) })
            }

            // The request either isn't using compression, or it has indicated compression may be used and we know we
            // can support decompression based on the indicated compression scheme... so wrap the body to decompress, if
            // need be, and then track the bytes that flowed through.
            //
            // TODO: Actually use the scheme given back to us to support other compression schemes.
            Ok(_) => {
                let (destination, decompressed_body) = Body::channel();
                let (req_parts, req_body) = req.into_parts();
                let mapped_req = Request::from_parts(req_parts, decompressed_body);

                let inner = self.inner.call(mapped_req);

                drive_request(req_body, destination, inner, self.bytes_received.clone()).boxed()
            }
        }
    }
}

/// A layer for decompressing Tonic request payloads and emitting telemetry for the payload sizes.
///
/// In some cases, we configure `tonic` to use compression on requests to save CPU and throughput when sending those
/// large requests. In the case of Vector-to-Vector communication, this means the Vector v2 source may deal with
/// compressed requests. The code already transparently handles decompression, but as part of our component
/// specification, we have specific goals around what event representations we pay attention to.
///
/// In the case of tracking bytes sent/received, we always want to track the number of bytes received _after_
/// decompression to faithfully represent the amount of data being processed by Vector. This poses a problem with the
/// out-of-the-box `tonic` codegen as there is no hook whatsoever to inspect the raw request payload (after
/// decompression, if it was compressed at all) prior to the payload being decoded as a Protocol Buffers payload.
///
/// This layer wraps the incoming body in our own body type, which allows us to do two things: decompress the payload
/// before it enters the decoding phase, and emit metrics based on the decompressed payload.
///
/// Since we can see the decompressed bytes, and also know if the underlying service responded successfully -- i.e. the
/// request was valid, and was processed -- we can now report the number of bytes (after decompression) that were
/// received _and_ processed correctly.
///
/// The only supported compression scheme is gzip, which is also the only supported compression scheme in `tonic` itself.
#[derive(Clone, Default)]
pub struct DecompressionAndMetricsLayer;

impl<S> Layer<S> for DecompressionAndMetricsLayer {
    type Service = DecompressionAndMetrics<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DecompressionAndMetrics {
            inner,
            bytes_received: register!(BytesReceived::from(Protocol::from("grpc"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::util::decompression::DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES;

    fn gzip(payload: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn limited_writer_accepts_within_limit() {
        let mut writer = LimitedWriter::new(Vec::new(), 8);
        writer
            .write_all(b"12345678")
            .expect("exactly at the limit must be accepted");
        assert_eq!(writer.into_inner(), b"12345678");
    }

    #[test]
    fn limited_writer_rejects_past_limit() {
        let mut writer = LimitedWriter::new(Vec::new(), 8);
        let error = writer
            .write_all(b"123456789")
            .expect_err("one byte past the limit must be rejected");

        assert!(
            DecompressedSizeLimitExceeded::is(&error),
            "expected the size-limit marker, got {error}"
        );
    }

    /// The cap must fire *during* decompression rather than after materialising the whole output,
    /// which is the entire point of the `LimitedWriter` sink.
    #[test]
    fn gzip_decompressor_rejects_bomb_mid_stream() {
        let bomb = gzip(&vec![0u8; 1024 * 1024]);
        let mut decoder = GzDecoder::new(LimitedWriter::new(Vec::new(), 4096));

        let error = decoder
            .write_all(&bomb)
            .expect_err("a payload inflating past the cap must be rejected");

        assert!(DecompressedSizeLimitExceeded::is(&error));
    }

    #[test]
    fn gzip_decompressor_passes_ordinary_payload() {
        let payload = b"hello grpc";
        let mut decoder = GzDecoder::new(LimitedWriter::new(Vec::new(), 4096));
        decoder.write_all(&gzip(payload)).expect("must decompress");
        let out = decoder.finish().map(LimitedWriter::into_inner).unwrap();

        assert_eq!(out, payload);
    }

    /// An oversized payload is a client fault, so it must surface as `out_of_range` rather than
    /// being reported as an internal server error.
    #[test]
    fn size_limit_maps_to_out_of_range_other_errors_to_internal() {
        let limit_error = io::Error::other(DecompressedSizeLimitExceeded);
        assert_eq!(
            decompressor_error_to_status(&limit_error, "internal").code(),
            tonic::Code::OutOfRange
        );

        let other = io::Error::other("some unrelated failure");
        assert_eq!(
            decompressor_error_to_status(&other, "internal").code(),
            tonic::Code::Internal
        );
    }

    fn grpc_frame(compressed: bool, declared_len: u32) -> Body {
        let mut frame = vec![u8::from(compressed)];
        frame.extend_from_slice(&declared_len.to_be_bytes());
        Body::from(frame)
    }

    async fn drive(frame: Body) -> Result<usize, Status> {
        let (sender, _receiver) = Body::channel();
        drive_body_decompression(frame, sender).await
    }

    /// A compressed frame declaring more bytes than could legitimately decompress within the cap
    /// must be refused from its header alone, before any of the payload is buffered.
    #[tokio::test]
    async fn oversized_compressed_frame_length_is_rejected_from_the_header() {
        let declared = u32::MAX;
        assert!(
            declared as usize
                > max_zlib_compressed_frame_size_bytes()
                    .saturating_add(GRPC_COMPRESSED_FRAME_OVERHEAD_SLACK),
            "the declared length must exceed the prefilter for this test to mean anything"
        );

        let status = drive(grpc_frame(true, declared))
            .await
            .expect_err("an oversized declared length must be rejected");

        assert_eq!(status.code(), tonic::Code::OutOfRange);
    }

    /// The same guard is needed on the identity path: an uncompressed message declaring a huge
    /// length would otherwise be buffered to `overall_len` before tonic's own limit applied.
    #[tokio::test]
    async fn oversized_identity_frame_length_is_rejected_from_the_header() {
        let declared = u32::MAX;
        assert!(declared as usize > max_decompressed_size_bytes());

        let status = drive(grpc_frame(false, declared))
            .await
            .expect_err("an oversized identity length must be rejected");

        assert_eq!(status.code(), tonic::Code::OutOfRange);
    }

    /// A legitimate declared length must not be refused by either guard — the frame simply waits
    /// for its payload.
    #[tokio::test]
    async fn ordinary_frame_length_is_accepted() {
        for compressed in [true, false] {
            let result = drive(grpc_frame(compressed, 64)).await;
            assert!(
                result.is_ok(),
                "a small declared length must pass the guards (compressed={compressed}), got {:?}",
                result.err()
            );
        }
    }

    /// The new decompressor must carry the global cap, not an unbounded sink.
    #[test]
    fn new_decompressor_is_capped_at_the_global_limit() {
        let decoder = new_decompressor();
        assert_eq!(
            decoder.get_ref().max_len,
            GRPC_MESSAGE_HEADER_LEN + DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES
        );
    }
}
