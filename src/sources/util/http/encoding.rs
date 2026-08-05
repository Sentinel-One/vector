use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::StreamExt;
use snap::raw::Decoder as SnappyDecoder;
use warp::http::StatusCode;
use warp::{filters::BoxedFilter, Filter};

use super::error::ErrorMessage;
use crate::internal_events::HttpDecompressError;
use vector_common::decompression::{
    is_decompressed_size_limit_error, max_decompressed_size_bytes, CappedDecoder,
};

/// Collects a request body into [`Bytes`] while enforcing an in-memory size cap.
///
/// The cap is the global decompressed-size limit ([`max_decompressed_size_bytes`]): it bounds the
/// raw (still-compressed) body a source buffers before decompression, so a large upload cannot
/// drive unbounded allocation independently of the decompressed-size cap.
pub(crate) fn capped_body() -> BoxedFilter<(Bytes,)> {
    let max_body_size = max_decompressed_size_bytes();
    let max_body_size_header = u64::try_from(max_body_size).unwrap_or(u64::MAX);

    warp::header::optional::<u64>("content-length")
        .and_then(move |declared: Option<u64>| async move {
            if declared.is_some_and(|len| len > max_body_size_header) {
                Err(warp::reject::custom(request_body_too_large_error(
                    max_body_size,
                )))
            } else {
                Ok(())
            }
        })
        .untuple_one()
        .and(warp::body::stream())
        .and_then(move |body| async move {
            collect_body_with_limit(body, max_body_size)
                .await
                .map_err(warp::reject::custom)
        })
        .boxed()
}

/// Decompresses the body based on the Content-Encoding header.
///
/// Supports gzip, deflate, snappy, zstd, and identity (no compression).
///
/// Caps the decompressed output at the global limit to mitigate decompression-bomb DoS attacks.
pub fn decode(header: Option<&str>, body: Bytes) -> Result<Bytes, ErrorMessage> {
    decode_with_limit(header, body, max_decompressed_size_bytes())
}

/// Like [`decode`], but allows the caller to control the decompressed size cap.
fn decode_with_limit(
    header: Option<&str>,
    mut body: Bytes,
    max_decompressed_size: usize,
) -> Result<Bytes, ErrorMessage> {
    if let Some(encodings) = header {
        // Each round is capped, which also bounds a stacked `Content-Encoding: gzip,gzip,...`
        // chain, since every round's output is the next round's input.
        for encoding in encodings.rsplit(',').map(str::trim) {
            body = match encoding {
                "identity" => body,
                "gzip" => CappedDecoder::gzip_with_limit(body.reader(), max_decompressed_size)
                    .decompress()
                    .map(Bytes::from)
                    .map_err(|error| {
                        emit_decompress_error(encoding, error, max_decompressed_size)
                    })?,
                "deflate" => CappedDecoder::zlib_with_limit(body.reader(), max_decompressed_size)
                    .decompress()
                    .map(Bytes::from)
                    .map_err(|error| {
                        emit_decompress_error(encoding, error, max_decompressed_size)
                    })?,
                "snappy" => decompress_snappy(&body, max_decompressed_size)?,
                "zstd" => CappedDecoder::zstd_http_with_limit(body.reader(), max_decompressed_size)
                    .map_err(|error| emit_decompress_error(encoding, error, max_decompressed_size))?
                    .decompress()
                    .map(Bytes::from)
                    .map_err(|error| {
                        emit_decompress_error(encoding, error, max_decompressed_size)
                    })?,
                encoding => {
                    return Err(ErrorMessage::new(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        format!("Unsupported encoding {}", encoding),
                    ))
                }
            }
        }
    }

    ensure_body_within_limit(&body, "identity", max_decompressed_size)?;
    Ok(body)
}

fn decompress_snappy(body: &Bytes, max_decompressed_size: usize) -> Result<Bytes, ErrorMessage> {
    // Snappy stores the decompressed length in the frame header, so reject oversized
    // payloads before allocating the output buffer.
    let len = snap::raw::decompress_len(body).map_err(|error| {
        emit_decompress_error(
            "snappy",
            std::io::Error::other(error),
            max_decompressed_size,
        )
    })?;
    if len > max_decompressed_size {
        return Err(decompressed_too_large_error(
            "snappy",
            max_decompressed_size,
        ));
    }
    let decoded = SnappyDecoder::new().decompress_vec(body).map_err(|error| {
        emit_decompress_error(
            "snappy",
            std::io::Error::other(error),
            max_decompressed_size,
        )
    })?;
    Ok(decoded.into())
}

/// Spare capacity added to the initial buffer so a third or later chunk can be appended without
/// reallocating right away.
const ADDITIONAL_CAPACITY_FOR_CHUNKS_BEYOND_FIRST_TWO: usize = 16 * 1024;

/// Collects the body into [`Bytes`] under `max_body_size`, mirroring the fast paths of hyper's
/// `to_bytes`. Single-chunk bodies avoid the `BytesMut` allocation; a buffer sized for both chunks
/// plus an arbitrary 16 KiB (to try to avoid having to reallocate multiple times once other chunks
/// arrive) is only allocated once a second chunk arrives.
async fn collect_body_with_limit<S, B>(body: S, max_body_size: usize) -> Result<Bytes, ErrorMessage>
where
    S: futures_util::Stream<Item = Result<B, warp::Error>>,
    B: Buf,
{
    futures_util::pin_mut!(body);

    let mut total_body_size: usize = 0;
    let mut admit_chunk_within_limit = |chunk: Result<B, warp::Error>| -> Result<B, ErrorMessage> {
        let chunk = chunk.map_err(|error| {
            ErrorMessage::new(
                StatusCode::BAD_REQUEST,
                format!("Failed reading request body: {}", error),
            )
        })?;

        total_body_size = total_body_size.saturating_add(chunk.remaining());
        if total_body_size > max_body_size {
            return Err(request_body_too_large_error(max_body_size));
        }

        Ok(chunk)
    };

    let Some(chunk) = body.next().await else {
        return Ok(Bytes::new());
    };
    let mut first = admit_chunk_within_limit(chunk)?;

    let Some(chunk) = body.next().await else {
        return Ok(first.copy_to_bytes(first.remaining()));
    };
    let second = admit_chunk_within_limit(chunk)?;

    let mut bytes = BytesMut::with_capacity(
        first.remaining() + second.remaining() + ADDITIONAL_CAPACITY_FOR_CHUNKS_BEYOND_FIRST_TWO,
    );
    bytes.put(first);
    bytes.put(second);

    while let Some(chunk) = body.next().await {
        bytes.put(admit_chunk_within_limit(chunk)?);
    }

    Ok(bytes.freeze())
}

fn ensure_body_within_limit(
    body: &Bytes,
    encoding: &str,
    max_decompressed_size: usize,
) -> Result<(), ErrorMessage> {
    if body.len() > max_decompressed_size {
        return Err(decompressed_too_large_error(
            encoding,
            max_decompressed_size,
        ));
    }
    Ok(())
}

fn request_body_too_large_error(max: usize) -> ErrorMessage {
    ErrorMessage::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        format!("Request body exceeds limit of {} bytes.", max),
    )
}

fn decompressed_too_large_error(encoding: &str, max: usize) -> ErrorMessage {
    ErrorMessage::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        format!(
            "Decompressed {} body exceeds limit of {} bytes.",
            encoding, max
        ),
    )
}

/// Maps a decompression failure to a response. If `error` is a `DecompressedSizeLimitExceeded`
/// (the decompressed output exceeded the configured size cap), it becomes a `413 Payload Too
/// Large` reporting the cap that was actually enforced, matching the request-body and snappy size
/// errors. Any other decode failure emits an `HttpDecompressError` event and becomes a
/// `422 Unprocessable Entity`.
///
/// Callers whose error is not already an [`std::io::Error`] (e.g. snappy) wrap it via
/// [`std::io::Error::other`].
fn emit_decompress_error(
    encoding: &str,
    error: std::io::Error,
    max_decompressed_size: usize,
) -> ErrorMessage {
    if is_decompressed_size_limit_error(&error) {
        return decompressed_too_large_error(encoding, max_decompressed_size);
    }
    emit!(HttpDecompressError {
        encoding,
        error: &error
    });
    ErrorMessage::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        format!("Failed decompressing payload with {} decoder.", encoding),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{write::GzEncoder, write::ZlibEncoder, Compression};
    use futures_util::stream;

    use super::*;

    const LIMIT: usize = 64 * 1024;

    /// Asserts the rejection came from the guard that stops the allocation *before* it happens
    /// (the per-encoding streaming cap, or snappy's declared-length pre-check), rather than from
    /// the `ensure_body_within_limit` backstop, which reports "identity" and only fires once the
    /// whole payload has already been materialised in memory.
    fn assert_rejected_by_streaming_cap(error: &ErrorMessage, encoding: &str) {
        let rendered = error.to_string();
        assert!(
            rendered.contains(&format!("Decompressed {encoding} body")),
            "expected rejection by the {encoding} cap before allocating, got: {rendered}"
        );
    }

    fn gzip(plaintext: &[u8]) -> Bytes {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(plaintext).unwrap();
        Bytes::from(encoder.finish().unwrap())
    }

    fn deflate(plaintext: &[u8]) -> Bytes {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(plaintext).unwrap();
        Bytes::from(encoder.finish().unwrap())
    }

    // ---- positive cases: ordinary traffic must be unaffected ----

    #[test]
    fn gzip_within_limit_is_decoded() {
        let decoded = decode_with_limit(Some("gzip"), gzip(b"hello"), LIMIT).expect("must decode");
        assert_eq!(decoded, Bytes::from_static(b"hello"));
    }

    #[test]
    fn deflate_within_limit_is_decoded() {
        let decoded =
            decode_with_limit(Some("deflate"), deflate(b"hello"), LIMIT).expect("must decode");
        assert_eq!(decoded, Bytes::from_static(b"hello"));
    }

    #[test]
    fn snappy_within_limit_is_decoded() {
        let body = Bytes::from(snap::raw::Encoder::new().compress_vec(b"hello").unwrap());
        let decoded = decode_with_limit(Some("snappy"), body, LIMIT).expect("must decode");
        assert_eq!(decoded, Bytes::from_static(b"hello"));
    }

    /// zstd is exercised at a production-scale limit on purpose. `zstd_http` derives the decoder
    /// window from the limit (clamped to RFC 9659's 8 MiB), so at a small limit the window clamp
    /// binds tighter than the size cap and would refuse even a legitimate frame. At the real
    /// 100 MiB default the clamp sits at 8 MiB, which is what this models.
    const ZSTD_LIMIT: usize = 8 * 1024 * 1024;

    #[test]
    fn zstd_within_limit_is_decoded() {
        let body = Bytes::from(zstd::encode_all(&b"hello"[..], 1).unwrap());
        let decoded = decode_with_limit(Some("zstd"), body, ZSTD_LIMIT).expect("must decode");
        assert_eq!(decoded, Bytes::from_static(b"hello"));
    }

    #[test]
    fn identity_within_limit_passes_through() {
        let decoded =
            decode_with_limit(Some("identity"), Bytes::from_static(b"hello"), LIMIT).unwrap();
        assert_eq!(decoded, Bytes::from_static(b"hello"));
    }

    // ---- negative cases: oversized payloads must be rejected, not buffered ----

    #[test]
    fn gzip_exceeding_limit_returns_413() {
        let body = gzip(&vec![0u8; LIMIT + 1]);
        let error = decode_with_limit(Some("gzip"), body, LIMIT).expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_rejected_by_streaming_cap(&error, "gzip");
    }

    #[test]
    fn deflate_exceeding_limit_returns_413() {
        let body = deflate(&vec![0u8; LIMIT + 1]);
        let error = decode_with_limit(Some("deflate"), body, LIMIT).expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_rejected_by_streaming_cap(&error, "deflate");
    }

    /// Snappy declares its output length in the frame header, so this must be rejected without
    /// ever allocating the output buffer.
    #[test]
    fn snappy_exceeding_limit_returns_413_before_allocating() {
        let body = Bytes::from(
            snap::raw::Encoder::new()
                .compress_vec(&vec![0u8; LIMIT + 1])
                .unwrap(),
        );
        let error = decode_with_limit(Some("snappy"), body, LIMIT).expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_rejected_by_streaming_cap(&error, "snappy");
    }

    /// Concatenated level-1 frames each fit the 8 MiB window clamp, so the aggregate output is
    /// what the size cap has to catch — not the window guard.
    #[test]
    fn zstd_exceeding_limit_returns_413() {
        let frame = zstd::encode_all(vec![0u8; 1024 * 1024].as_slice(), 1).unwrap();
        let mut bomb = Vec::new();
        for _ in 0..(ZSTD_LIMIT / (1024 * 1024) + 1) {
            bomb.extend_from_slice(&frame);
        }

        let error = decode_with_limit(Some("zstd"), Bytes::from(bomb), ZSTD_LIMIT)
            .expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_rejected_by_streaming_cap(&error, "zstd");
    }

    /// An uncompressed body over the cap must be rejected too, otherwise `identity` would be a
    /// trivial bypass of the whole mechanism.
    #[test]
    fn identity_exceeding_limit_returns_413() {
        let body = Bytes::from(vec![0u8; LIMIT + 1]);
        let error = decode_with_limit(Some("identity"), body, LIMIT).expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn missing_content_encoding_exceeding_limit_returns_413() {
        let body = Bytes::from(vec![0u8; LIMIT + 1]);
        let error = decode_with_limit(None, body, LIMIT).expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Stacking encodings must not multiply the amplification: every round is capped.
    #[test]
    fn stacked_encodings_are_capped_at_every_round() {
        let outer = gzip(&gzip(&vec![0u8; LIMIT + 1]));
        let error =
            decode_with_limit(Some("gzip,gzip"), outer, LIMIT).expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_rejected_by_streaming_cap(&error, "gzip");
    }

    /// A malformed payload must stay a 422, distinct from the 413 the cap raises — otherwise the
    /// size tests above could be passing for the wrong reason.
    #[test]
    fn malformed_payload_is_422_not_413() {
        let error = decode_with_limit(Some("gzip"), Bytes::from_static(b"not gzip"), LIMIT)
            .expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn unsupported_encoding_is_415() {
        let error = decode_with_limit(Some("br"), Bytes::from_static(b"x"), LIMIT)
            .expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // ---- body collection ----

    #[tokio::test]
    async fn collect_body_within_limit_succeeds() {
        let chunks: Vec<Result<Bytes, warp::Error>> = vec![
            Ok(Bytes::from_static(b"foo")),
            Ok(Bytes::from_static(b"bar")),
        ];
        let collected = collect_body_with_limit(stream::iter(chunks), LIMIT)
            .await
            .expect("must collect");
        assert_eq!(collected, Bytes::from_static(b"foobar"));
    }

    /// The running total must trip mid-stream, so no single chunk needs to exceed the cap.
    #[tokio::test]
    async fn collect_body_rejects_oversized_stream() {
        let chunk = Bytes::from(vec![0u8; LIMIT / 2]);
        let chunks: Vec<Result<Bytes, warp::Error>> =
            vec![Ok(chunk.clone()), Ok(chunk.clone()), Ok(chunk)];
        let error = collect_body_with_limit(stream::iter(chunks), LIMIT)
            .await
            .expect_err("must be rejected");
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
