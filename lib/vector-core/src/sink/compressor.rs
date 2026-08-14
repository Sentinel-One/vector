#![allow(warnings)]
#![allow(unreachable_pub)]
use std::{io, io::Read, io::BufWriter};

use bytes::{BufMut, BytesMut, Bytes, Buf};
use flate2::write::{GzEncoder, ZlibEncoder};
use vector_common::decompression::{CappedDecoder, CompressionLimits};
use crate::sink::compression::Compression;
use super::{
    snappy::SnappyEncoder, snappy::SnappyDecoder,
    zstd::ZstdEncoder, zstd::ZstdDecoder,
    };

const GZIP_INPUT_BUFFER_CAPACITY: usize = 4_096;
const ZLIB_INPUT_BUFFER_CAPACITY: usize = 4_096;

const OUTPUT_BUFFER_CAPACITY: usize = 1_024;

enum Writer {
    Plain(bytes::buf::Writer<BytesMut>),
    Gzip(BufWriter<GzEncoder<bytes::buf::Writer<BytesMut>>>),
    Zlib(BufWriter<ZlibEncoder<bytes::buf::Writer<BytesMut>>>),
    Zstd(ZstdEncoder<bytes::buf::Writer<BytesMut>>),
    Snappy(SnappyEncoder<bytes::buf::Writer<BytesMut>>),
}

impl Writer {
    pub fn get_ref(&self) -> &BytesMut {
        match self {
            Writer::Plain(inner) => inner.get_ref(),
            Writer::Gzip(inner) => inner.get_ref().get_ref().get_ref(),
            Writer::Zlib(inner) => inner.get_ref().get_ref().get_ref(),
            Writer::Zstd(inner) => inner.get_ref().get_ref(),
            Writer::Snappy(inner) => inner.get_ref().get_ref(),
        }
    }

    pub fn into_inner(self) -> BytesMut {
        match self {
            Writer::Plain(writer) => writer,
            Writer::Gzip(writer) => writer
                .into_inner()
                .expect("BufWriter writer should not fail to finish")
                .finish()
                .expect("gzip writer should not fail to finish"),
            Writer::Zlib(writer) => writer
                .into_inner()
                .expect("BufWriter writer should not fail to finish")
                .finish()
                .expect("zlib writer should not fail to finish"),
            Writer::Zstd(writer) => writer
                .finish()
                .expect("zstd writer should not fail to finish"),
            Writer::Snappy(writer) => writer
                .finish()
                .expect("snappy writer should not fail to finish"),
        }
            .into_inner()
    }

    pub fn finish(self) -> io::Result<BytesMut> {
        let buf = match self {
            Writer::Plain(writer) => writer,
            Writer::Gzip(writer) => writer.into_inner()?.finish()?,
            Writer::Zlib(writer) => writer.into_inner()?.finish()?,
            Writer::Zstd(writer) => writer.finish()?,
            Writer::Snappy(writer) => writer.finish()?,
        }
            .into_inner();

        Ok(buf)
    }
}

impl From<Compression> for Writer {
    fn from(compression: Compression) -> Self {
        let writer = BytesMut::with_capacity(OUTPUT_BUFFER_CAPACITY).writer();
        match compression {
            Compression::None => Writer::Plain(writer),
            // Buffering writes to the underlying Encoder writer
            // to avoid Vec-trashing and expensive memset syscalls.
            // https://github.com/rust-lang/flate2-rs/issues/395#issuecomment-1975088152
            Compression::Gzip(level) => Writer::Gzip(BufWriter::with_capacity(
                GZIP_INPUT_BUFFER_CAPACITY,
                GzEncoder::new(writer, level.as_flate2()),
            )),
            // Buffering writes to the underlying Encoder writer
            // to avoid Vec-trashing and expensive memset syscalls.
            // https://github.com/rust-lang/flate2-rs/issues/395#issuecomment-1975088152
            Compression::Zlib(level) => Writer::Zlib(BufWriter::with_capacity(
                ZLIB_INPUT_BUFFER_CAPACITY,
                ZlibEncoder::new(writer, level.as_flate2()),
            )),
            Compression::Zstd(level) => {
                let encoder = ZstdEncoder::new(writer, level.into())
                    .expect("Zstd encoder should not fail on init.");
                Writer::Zstd(encoder)
            }
            Compression::Snappy => Writer::Snappy(SnappyEncoder::new(writer)),
        }
    }
}

impl io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[allow(clippy::disallowed_methods)] // Caller handles the result of `write`.
        match self {
            Writer::Plain(inner_buf) => inner_buf.write(buf),
            Writer::Gzip(writer) => writer.write(buf),
            Writer::Zlib(writer) => writer.write(buf),
            Writer::Zstd(writer) => writer.write(buf),
            Writer::Snappy(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Writer::Plain(writer) => writer.flush(),
            Writer::Gzip(writer) => writer.flush(),
            Writer::Zlib(writer) => writer.flush(),
            Writer::Zstd(writer) => writer.flush(),
            Writer::Snappy(writer) => writer.flush(),
        }
    }
}

/// Simple compressor implementation based on [`Compression`].
///
/// Users can acquire a `Compressor` via [`Compressor::from`] based on the desired compression scheme.
pub struct Compressor {
    compression: Compression,
    inner: Writer,
}

impl Compressor {
    /// Gets a mutable reference to the underlying buffer.
    pub fn get_ref(&self) -> &BytesMut {
        self.inner.get_ref()
    }

    /// Gets whether or not this compressor will actually compress the input.
    ///
    /// While it may be counterintuitive for "compression" to not compress, this is simply a
    /// consequence of designing a single type that may or may not compress so that we can avoid
    /// having to box writers at a higher-level.
    ///
    /// Some callers can benefit from knowing whether or not compression is actually taking place,
    /// as different size limitations may come into play.
    pub const fn is_compressed(&self) -> bool {
        self.compression.is_compressed()
    }

    /// Consumes the compressor, returning the internal buffer used by the compressor.
    ///
    /// # Errors
    ///
    /// If the compressor encounters an I/O error while finalizing the payload, an error
    /// variant will be returned.
    pub fn finish(self) -> io::Result<BytesMut> {
        self.inner.finish()
    }

    /// Consumes the compressor, returning the internal buffer used by the compressor.
    ///
    /// # Panics
    ///
    /// Panics if finalizing the compressor encounters an I/O error.  This should generally only be
    /// possible when the system is out of memory and allocations cannot be performed to write any
    /// footer/checksum data.
    ///
    /// Consider using `finish` if catching these scenarios is important.
    pub fn into_inner(self) -> BytesMut {
        self.inner.into_inner()
    }
}

impl io::Write for Compressor {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[allow(clippy::disallowed_methods)] // Caller handles the result of `write`.
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl From<Compression> for Compressor {
    fn from(compression: Compression) -> Self {
        Compressor {
            compression,
            inner: compression.into(),
        }
    }
}

pub enum Decompressor {
    Plain,
    Gzip(CompressionLimits),
    Zlib(CompressionLimits),
    Zstd(CompressionLimits),
    Snappy(CompressionLimits),
}

impl Decompressor {
    pub fn decompress(&self, bytes: Bytes) -> io::Result<Bytes> {
        match self {
            Decompressor::Plain => Ok(bytes),
            Decompressor::Gzip(limits) => Ok(CappedDecoder::gzip(io::Cursor::new(bytes), limits)
                .decompress()?
                .into()),
            Decompressor::Zlib(limits) => Ok(CappedDecoder::zlib(bytes.reader(), limits)
                .decompress()?
                .into()),
            Decompressor::Zstd(limits) => {
                let mut decoder = ZstdDecoder::new(bytes.reader(), limits)?;
                let mut buff: Vec<u8> = Vec::with_capacity(OUTPUT_BUFFER_CAPACITY);
                Read::read_to_end(&mut decoder, &mut buff)?;
                Ok(buff.into())
            },
            Decompressor::Snappy(limits) => {
                let mut decoder = SnappyDecoder::new(bytes.reader(), *limits);
                let mut buff: Vec<u8> = Vec::with_capacity(OUTPUT_BUFFER_CAPACITY);
                Read::read_to_end(&mut decoder, &mut buff)?;
                Ok(buff.into())
            },
        }
    }
}

/// Built from the compression scheme plus the limits to decode under.
///
/// `CompressionLimits` is `Copy`, so this needs neither a lifetime nor an `Arc`: callers hand over
/// a copy of the one in `GlobalOptions`.
impl From<(Compression, CompressionLimits)> for Decompressor {
    fn from((compression, limits): (Compression, CompressionLimits)) -> Self {
        match compression {
            Compression::None => Decompressor::Plain,
            Compression::Gzip(_) => Decompressor::Gzip(limits),
            Compression::Zlib(_) => Decompressor::Zlib(limits),
            Compression::Zstd(_) => Decompressor::Zstd(limits),
            Compression::Snappy => Decompressor::Snappy(limits),
        }
    }
}

#[cfg(test)]
mod tests {
    use vector_common::decompression::CompressionLimits;
    use std::io::Write;

    use crate::sink::compression::CompressionLevel;

    use super::{Compression, Compressor, Decompressor};

    fn big_str() -> Vec<u8> {
        let mut data = Vec::new();
        for i in 0..20 {
            data.extend_from_slice(format!("Hello, world! {}", i).as_bytes());
        }
        data
    }

    fn run_test(c: Compression, eq: bool) {
        let data = big_str();
        let mut writer = Compressor::from(c);
        writer.write_all(&data).unwrap();
        writer.flush().unwrap();
        let compressed_data = writer.into_inner().freeze();
        if eq {
            assert_eq!(compressed_data.len(), data.len());
        } else {
            assert!(compressed_data.len() < data.len());
            assert_ne!(data, &compressed_data[..]);
        }
        let decompressor = Decompressor::from((c, CompressionLimits::default()));
        let decompressed_data = decompressor.decompress(compressed_data).unwrap();
        assert_eq!(data, &decompressed_data[..]);
    }

    #[test]
    fn test_plain_compress_and_decompress() {
        run_test(Compression::None, true);
    }

    #[test]
    fn test_gz_compress_and_decompress() {
        run_test(Compression::Gzip(CompressionLevel::Default), false);
    }

    #[test]
    fn test_zlib_compress_and_decompress() {
        run_test(Compression::Zlib(CompressionLevel::Default), false);
    }

    #[test]
    fn test_zstd_compress_and_decompress() {
        run_test(Compression::Zstd(CompressionLevel::Default), false);
    }

    #[test]
    fn test_snappy_compress_and_decompress() {
        run_test(Compression::Snappy, false);
    }
}
