//! An encoder for [Snappy] compression.
//! Whilst there does exist a [Writer] implementation for Snappy, this compresses
//! using the [Snappy frame format][frame], which is not quite what we want. So
//! instead this encoder buffers the data in a [`Vec`] until the end. The `raw`
//! compressor is then used to compress the data and writes it to the provided
//! writer.
//!
//! [Snappy]: https://github.com/google/snappy/blob/main/docs/README.md
//! [Writer]: https://docs.rs/snap/latest/snap/write/struct.FrameEncoder.html
//! [frame]: https://github.com/google/snappy/blob/master/framing_format.txt

use std::io;

use snap::raw::{decompress_len, Decoder, Encoder};
use vector_common::decompression::DecompressedSizeLimitExceeded;
use vector_common::limits::CompressionLimits;

pub struct SnappyEncoder<W: io::Write> {
    writer: W,
    buffer: Vec<u8>,
}

impl<W: io::Write> SnappyEncoder<W> {
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            buffer: Vec::new(),
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        let mut encoder = Encoder::new();
        let compressed = encoder.compress_vec(&self.buffer)?;

        self.writer.write_all(&compressed)?;

        Ok(self.writer)
    }

    pub const fn get_ref(&self) -> &W {
        &self.writer
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl<W: io::Write> io::Write for SnappyEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W: io::Write + std::fmt::Debug> std::fmt::Debug for SnappyEncoder<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnappyEncoder")
            .field("inner", &self.get_ref())
            .finish()
    }
}

pub struct SnappyDecoder<R: io::Read> {
    reader: R,
    limits: CompressionLimits,
    buffer: Vec<u8>,
    decoded: bool,
}

impl<R: io::Read> SnappyDecoder<R> {
    /// Decodes snappy under `limits`.
    ///
    /// The limits are a constructor parameter rather than something a caller may forget, because
    /// this is a `Read` impl in name only: the first `read` materialises the entire input and the
    /// entire output. There is no streaming point at which a cap could be applied afterwards.
    pub const fn new(reader: R, limits: CompressionLimits) -> Self {
        Self {
            reader,
            limits,
            buffer: Vec::new(),
            decoded: false,
        }
    }
}

impl<R: io::Read> io::Read for SnappyDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.decoded {
            // Bound the input first: `read_to_end` on an untrusted reader is itself unbounded, and
            // it runs before anything can be learned about the declared output size. Reading one
            // byte past the ceiling is what makes an over-long input detectable.
            let max_compressed = self.limits.max_snappy_compressed_frame_size_bytes();
            let mut compressed = Vec::new();
            io::Read::take(&mut self.reader, max_compressed as u64 + 1)
                .read_to_end(&mut compressed)?;
            if compressed.len() > max_compressed {
                return Err(io::Error::other(DecompressedSizeLimitExceeded));
            }

            // Snappy's header declares the decompressed length, so the allocation can be refused
            // before it happens rather than capped while it grows.
            let declared = decompress_len(&compressed)?;
            if declared > self.limits.max_decompressed_size_bytes {
                return Err(io::Error::other(DecompressedSizeLimitExceeded));
            }

            let mut decoder = Decoder::new();
            self.buffer = decoder.decompress_vec(&compressed)?;
            self.decoded = true;
        }

        if self.buffer.is_empty() {
            return Ok(0);
        }
        let len = std::cmp::min(buf.len(), self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);

        Ok(len)
    }
}

impl<R: io::Read + std::fmt::Debug> std::fmt::Debug for SnappyDecoder<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnappyDecoder")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use bytes::{BufMut, BytesMut};

    use super::*;

    fn limits(max: usize) -> CompressionLimits {
        CompressionLimits::with_max_decompressed_size_bytes(max)
    }

    fn snappy(payload: &[u8]) -> Vec<u8> {
        Encoder::new().compress_vec(payload).expect("compress")
    }

    fn decode(compressed: &[u8], max: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        SnappyDecoder::new(io::Cursor::new(compressed.to_vec()), limits(max))
            .read_to_end(&mut out)?;
        Ok(out)
    }

    /// Positive: a payload within the cap round-trips byte for byte. The cap must not change what
    /// a legitimate decode produces.
    #[test]
    fn a_payload_within_the_limit_round_trips() {
        let payload = vec![b'x'; 4096];
        let decoded = decode(&snappy(&payload), 8192).expect("should decode");

        assert_eq!(decoded, payload);
    }

    /// Negative: a frame small enough to pass the input bound, whose header still declares more
    /// than the cap. Snappy manages roughly 21:1 on repetitive data, so 128 KiB of one byte
    /// compresses to about 6 KiB — under the ~9.6 KiB compressed ceiling for an 8 KiB cap, but
    /// declaring 128 KiB of output. This is the case the header check exists for.
    #[test]
    fn a_payload_over_the_limit_is_rejected() {
        let max = 8192;
        let payload = vec![b'x'; 128 * 1024];
        let compressed = snappy(&payload);
        assert!(
            compressed.len() <= limits(max).max_snappy_compressed_frame_size_bytes(),
            "the frame must pass the input bound so the header check is what rejects it, got {} bytes",
            compressed.len()
        );

        let error = decode(&compressed, max).expect_err("an over-large payload must be refused");

        assert!(
            DecompressedSizeLimitExceeded::is(&error),
            "should be the shared limit error, got: {error}"
        );
    }

    /// The refusal must happen before the output is allocated, not after — that is the whole point
    /// of reading the declared length from the header.
    #[test]
    fn an_over_large_payload_is_refused_before_it_is_allocated() {
        // 512 MiB declared, far more than a test should ever allocate. Compressing this directly
        // would defeat the purpose, so build the frame from its varint header instead: snappy
        // stores the decompressed length first, which is all the check reads.
        let mut frame = Vec::new();
        let mut declared = 512u64 * 1024 * 1024;
        while declared >= 0x80 {
            frame.push((declared as u8) | 0x80);
            declared >>= 7;
        }
        frame.push(declared as u8);
        frame.extend_from_slice(&snappy(b"trailing garbage")[1..]);

        let error = decode(&frame, 4096).expect_err("a huge declared length must be refused");

        assert!(
            DecompressedSizeLimitExceeded::is(&error),
            "should be refused on the declared length, got: {error}"
        );
    }

    /// The input read is bounded too. A well-formed frame can never breach the compressed
    /// ceiling while declaring an output within the cap, so the bound exists for a hostile
    /// *reader*: without it, `read_to_end` on an endless stream runs until memory is gone, long
    /// before the header can be inspected.
    #[test]
    fn an_endless_stream_is_cut_off_instead_of_being_buffered() {
        let mut out = Vec::new();
        let error = SnappyDecoder::new(io::repeat(0u8), limits(1024))
            .read_to_end(&mut out)
            .expect_err("an endless stream must be cut off");

        assert!(
            DecompressedSizeLimitExceeded::is(&error),
            "should stop on the compressed-size ceiling, got: {error}"
        );
    }

    /// Boundary: a payload landing exactly on the cap is legitimate and must still decode, so the
    /// check cannot drift into rejecting valid traffic.
    #[test]
    fn a_payload_exactly_at_the_limit_is_accepted() {
        let payload = vec![b'y'; 4096];
        let decoded = decode(&snappy(&payload), 4096).expect("exactly at the limit must decode");

        assert_eq!(decoded.len(), 4096);
    }

    #[test]
    fn is_empty() {
        let writer = BytesMut::with_capacity(64).writer();
        let mut encoder = SnappyEncoder::new(writer);

        encoder.write_all(b"I am a potato").unwrap();

        // Because we are buffering the results until the end, the writer will be
        // empty, but our buffer won't be. The `is_empty` function is provided to
        // allow us to determine if data has been written to the encoder without having
        // to check the writer.
        assert!(encoder.get_ref().get_ref().is_empty());
        assert!(!encoder.is_empty());
    }
}
