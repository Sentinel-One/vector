//! Structural pre-scan of an untrusted MessagePack frame.
//!
//! `rmp_serde` deserialises nested MessagePack by recursing, and the `fluent` source hands it
//! attacker-controlled bytes. Nesting costs one byte per level on the wire (`0x91` for a
//! one-element array), so a small frame can drive hundreds of thousands of stack frames and
//! overflow the stack — a byte-size cap such as
//! [`FluentDecoder::max_frame_size`](super::FluentDecoder) cannot defend against it.
//!
//! Recursion is reachable through more than one path: `FluentRecord` values are `rmpv::Value`,
//! the `Heartbeat` variant is a bare `rmpv::Value`, `#[serde(untagged)]` buffers input into
//! serde's own recursive `Content` type before any variant is chosen, and converting the result
//! into a VRL `Value` (and later dropping it) recurses again. Bounding depth here, at admission,
//! bounds all of them at once.
//!
//! The scan is deliberately **iterative**: a recursive scanner would reintroduce the very bug it
//! exists to prevent.

use super::DecodeError;

/// Default maximum MessagePack nesting depth accepted from a peer.
///
/// Fluent records are shallow in practice — a tag, a timestamp and a flat map of fields. This
/// leaves generous headroom for nested objects while keeping recursion far below any stack limit.
/// Configurable per source via `max_msgpack_depth`.
pub(super) const DEFAULT_MAX_MSGPACK_DEPTH: usize = 128;

/// Walks the MessagePack structure in `buf` without recursing, rejecting frames that are nested
/// too deeply or that declare a length no legitimate frame could satisfy.
///
/// A truncated buffer is **not** an error: the caller is a streaming decoder, so an incomplete
/// prefix simply means more bytes are needed and the scan stops early. Only structural violations
/// are reported.
///
/// `max_len` bounds any single declared length (string, binary, ext) and any declared element
/// count. A container needs at least one byte per element, so a count beyond `max_len` can never
/// be satisfied within a frame that size — rejecting it up front also keeps this scan cheap.
pub(super) fn scan_msgpack_frame(
    buf: &[u8],
    max_depth: usize,
    max_len: usize,
) -> Result<(), DecodeError> {
    // Remaining element count at each open container level; the initial entry is the single
    // top-level value.
    let mut stack: Vec<usize> = vec![1];
    let mut pos: usize = 0;

    // Reads `n` bytes as a big-endian length, or signals truncation.
    fn read_len(buf: &[u8], pos: usize, n: usize) -> Option<usize> {
        let bytes = buf.get(pos..pos + n)?;
        let mut value: u64 = 0;
        for byte in bytes {
            value = (value << 8) | u64::from(*byte);
        }
        usize::try_from(value).ok()
    }

    let too_large = |len: usize| DecodeError::DeclaredLengthTooLarge { len, max: max_len };

    while let Some(remaining) = stack.last_mut() {
        if *remaining == 0 {
            stack.pop();
            continue;
        }
        *remaining -= 1;

        let Some(&marker) = buf.get(pos) else {
            // Truncated: the caller needs more bytes.
            return Ok(());
        };
        pos += 1;

        // `payload` is a byte count to skip; `children` is a count of nested values to expect.
        let (payload, children) = match marker {
            // fixint (positive and negative), nil, false, true
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => (0, 0),
            // never used
            0xc1 => return Err(DecodeError::InvalidMarker { marker }),
            0x80..=0x8f => (0, 2 * usize::from(marker & 0x0f)), // fixmap
            0x90..=0x9f => (0, usize::from(marker & 0x0f)),     // fixarray
            0xa0..=0xbf => (usize::from(marker & 0x1f), 0),     // fixstr
            0xcc | 0xd0 => (1, 0),
            0xcd | 0xd1 => (2, 0),
            0xca | 0xce | 0xd2 => (4, 0),
            0xcb | 0xcf | 0xd3 => (8, 0),
            0xd4 => (2, 0),  // fixext1  (type + 1)
            0xd5 => (3, 0),  // fixext2
            0xd6 => (5, 0),  // fixext4
            0xd7 => (9, 0),  // fixext8
            0xd8 => (17, 0), // fixext16
            // bin / str with an explicit length
            0xc4 | 0xd9 | 0xc5 | 0xda | 0xc6 | 0xdb => {
                let width = match marker {
                    0xc4 | 0xd9 => 1,
                    0xc5 | 0xda => 2,
                    _ => 4,
                };
                let Some(len) = read_len(buf, pos, width) else {
                    return Ok(());
                };
                if len > max_len {
                    return Err(too_large(len));
                }
                pos += width;
                (len, 0)
            }
            // ext with an explicit length (payload carries a one-byte type tag)
            0xc7 | 0xc8 | 0xc9 => {
                let width = match marker {
                    0xc7 => 1,
                    0xc8 => 2,
                    _ => 4,
                };
                let Some(len) = read_len(buf, pos, width) else {
                    return Ok(());
                };
                if len > max_len {
                    return Err(too_large(len));
                }
                pos += width;
                (len.saturating_add(1), 0)
            }
            // array / map with an explicit element count
            0xdc | 0xdd | 0xde | 0xdf => {
                let width = if matches!(marker, 0xdc | 0xde) { 2 } else { 4 };
                let Some(count) = read_len(buf, pos, width) else {
                    return Ok(());
                };
                if count > max_len {
                    return Err(too_large(count));
                }
                pos += width;
                let children = if matches!(marker, 0xde | 0xdf) {
                    count.saturating_mul(2)
                } else {
                    count
                };
                (0, children)
            }
        };

        if payload > 0 {
            match pos.checked_add(payload) {
                Some(next) if next <= buf.len() => pos = next,
                // Truncated, or a length that overflows the buffer: need more bytes.
                _ => return Ok(()),
            }
        }

        if children > 0 {
            if stack.len() >= max_depth {
                return Err(DecodeError::FrameTooDeep {
                    depth: stack.len() + 1,
                    max: max_depth,
                });
            }
            stack.push(children);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use vector_lib::codecs::StreamDecodingError;

    use super::*;

    const MAX_LEN: usize = 1024 * 1024;

    fn scan(buf: &[u8]) -> Result<(), DecodeError> {
        scan_msgpack_frame(buf, DEFAULT_MAX_MSGPACK_DEPTH, MAX_LEN)
    }

    /// `0x91` is a one-element array, so each byte adds a nesting level.
    fn nested(levels: usize) -> Vec<u8> {
        let mut buf = vec![0x91; levels];
        buf.push(0xc0); // nil at the centre
        buf
    }

    // ---- accept: ordinary frames must be unaffected ----

    #[test]
    fn accepts_a_typical_fluent_frame() {
        // ["tag", 1441588984, {"message": "foo"}]
        let frame = rmp_serde::to_vec(&(
            "tag.name",
            1_441_588_984u32,
            std::collections::BTreeMap::from([("message", "foo")]),
        ))
        .unwrap();

        scan(&frame).expect("an ordinary fluent frame must be accepted");
    }

    #[test]
    fn accepts_nesting_just_below_the_limit() {
        scan(&nested(DEFAULT_MAX_MSGPACK_DEPTH - 1))
            .expect("nesting within the limit must be accepted");
    }

    #[test]
    fn accepts_every_scalar_marker() {
        for frame in [
            vec![0xc0],                         // nil
            vec![0xc2],                         // false
            vec![0xc3],                         // true
            vec![0x7f],                         // positive fixint
            vec![0xff],                         // negative fixint
            vec![0xcc, 0x01],                   // uint8
            vec![0xcd, 0x00, 0x01],             // uint16
            vec![0xce, 0, 0, 0, 1],             // uint32
            vec![0xcf, 0, 0, 0, 0, 0, 0, 0, 1], // uint64
            vec![0xcb, 0, 0, 0, 0, 0, 0, 0, 0], // float64
            vec![0xa3, b'f', b'o', b'o'],       // fixstr
            vec![0xc4, 0x02, 0xaa, 0xbb],       // bin8
            vec![0xd4, 0x00, 0x01],             // fixext1
            vec![0xc7, 0x01, 0x00, 0xaa],       // ext8
        ] {
            scan(&frame).unwrap_or_else(|e| panic!("marker {:#04x} rejected: {e}", frame[0]));
        }
    }

    /// A streaming decoder feeds partial frames constantly; truncation must never be an error.
    #[test]
    fn truncation_is_not_an_error() {
        let frame = rmp_serde::to_vec(&("tag.name", 1u32, "payload")).unwrap();
        for cut in 0..frame.len() {
            scan(&frame[..cut])
                .unwrap_or_else(|e| panic!("truncation at {cut} must not error, got {e}"));
        }
    }

    /// A declared length larger than the buffer is truncation, not a violation, so long as it
    /// stays within the cap — the rest of the frame may still be in flight.
    #[test]
    fn declared_length_within_the_cap_but_not_yet_arrived_is_truncation() {
        // bin32 declaring 4096 bytes, none of which have arrived.
        let frame = vec![0xc6, 0x00, 0x00, 0x10, 0x00];
        scan(&frame).expect("a legitimate declared length awaiting bytes must not error");
    }

    // ---- reject: the two vectors this scan exists for ----

    /// OBE-10708: one byte per nesting level, so a byte-size cap cannot bound recursion depth.
    #[test]
    fn rejects_nesting_past_the_limit() {
        let error = scan(&nested(DEFAULT_MAX_MSGPACK_DEPTH + 1))
            .expect_err("nesting past the limit must be rejected");

        assert!(
            matches!(error, DecodeError::FrameTooDeep { max, .. } if max == DEFAULT_MAX_MSGPACK_DEPTH),
            "unexpected error: {error:?}"
        );
        assert!(
            !error.can_continue(),
            "an over-deep frame must drop the connection"
        );
    }

    /// The depth guard must hold for maps as well as arrays.
    #[test]
    fn rejects_deep_map_nesting() {
        // 0x81 is a one-pair fixmap: key, then a nested map as the value.
        let mut frame = Vec::new();
        for _ in 0..=DEFAULT_MAX_MSGPACK_DEPTH {
            frame.push(0x81);
            frame.push(0xc0); // nil key
        }
        frame.push(0xc0);

        let error = scan(&frame).expect_err("deep map nesting must be rejected");
        assert!(matches!(error, DecodeError::FrameTooDeep { .. }));
    }

    /// OBE-11233: a declared length no frame could satisfy is refused up front, so the claim
    /// cannot resurface if a dependency bump changes how `rmp_serde` pre-allocates.
    #[test]
    fn rejects_declared_length_beyond_the_cap() {
        // bin32 declaring ~4 GiB.
        let frame = vec![0xc6, 0xff, 0xff, 0xff, 0xff];

        let error = scan(&frame).expect_err("an impossible declared length must be rejected");
        assert!(
            matches!(error, DecodeError::DeclaredLengthTooLarge { max, .. } if max == MAX_LEN),
            "unexpected error: {error:?}"
        );
        assert!(!error.can_continue());
    }

    #[test]
    fn rejects_declared_element_count_beyond_the_cap() {
        // array32 declaring ~4 billion elements.
        let frame = vec![0xdd, 0xff, 0xff, 0xff, 0xff];

        let error = scan(&frame).expect_err("an impossible element count must be rejected");
        assert!(matches!(error, DecodeError::DeclaredLengthTooLarge { .. }));
    }

    #[test]
    fn rejects_str32_and_map32_beyond_the_cap() {
        for frame in [
            vec![0xdb, 0xff, 0xff, 0xff, 0xff], // str32
            vec![0xdf, 0xff, 0xff, 0xff, 0xff], // map32
        ] {
            let error = scan(&frame).expect_err("an impossible declared length must be rejected");
            assert!(matches!(error, DecodeError::DeclaredLengthTooLarge { .. }));
        }
    }

    #[test]
    fn rejects_the_never_used_marker() {
        let error = scan(&[0xc1]).expect_err("0xc1 is never valid msgpack");
        assert!(matches!(error, DecodeError::InvalidMarker { marker: 0xc1 }));
    }

    /// The scan must not itself recurse, or it reintroduces the bug it prevents. A frame far
    /// deeper than any stack could handle must return an error rather than crash the process.
    #[test]
    fn scanning_is_iterative_and_survives_pathological_depth() {
        let error = scan(&nested(5_000_000)).expect_err("must be rejected, not overflow the stack");
        assert!(matches!(error, DecodeError::FrameTooDeep { .. }));
    }
}
