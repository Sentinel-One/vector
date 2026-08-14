//! Re-export of the shared decompression limits.
//!
//! The implementation lives in [`vector_common::decompression`] so that both this crate and
//! `lib/codecs` enforce the same limits. Components take a [`CompressionLimits`] from their own
//! context (`cx.globals.limits.compression`) rather than reading process state.
pub use vector_common::decompression::{
    CappedDecoder, CappedReader, CompressionLimits, DecompressedSizeLimitExceeded,
    OperationalLimits, DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES, HTTP_ZSTD_WINDOW_LOG_MAX,
};
