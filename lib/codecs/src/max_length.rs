//! Global cap on the length of a single delimited frame.
//!
//! A delimited framer accumulates bytes until it sees its delimiter. A peer that never sends one
//! would otherwise grow the per-connection buffer with everything it sends, so the framers consult
//! this cap while a frame is still incomplete and reject anything past it.
//!
//! The cap is process-wide and set once at startup from `--max-frame-length-bytes` (or
//! `VECTOR_MAX_FRAME_LENGTH_BYTES`). Individual framers may still override it per component via
//! their own `max_length` option; this only supplies the default.

use std::sync::OnceLock;

/// Default cap on the length of a single delimited frame.
///
/// Matches the limit the `file`, `syslog`, `stdin`, `file_descriptor` and `socket` mode `udp`
/// sources have always applied, so a frame length that is acceptable to one of those is acceptable
/// to every delimited framer.
pub const DEFAULT_MAX_FRAME_LENGTH_BYTES: usize = 100 * 1024;

static MAX_FRAME_LENGTH_BYTES: OnceLock<usize> = OnceLock::new();

/// Override the global frame length cap. Must be called before any sources start.
///
/// # Panics
///
/// Panics if called more than once, as the global cap may only be initialized a single time.
pub fn set_max_frame_length_bytes(size: usize) {
    MAX_FRAME_LENGTH_BYTES
        .set(size)
        .expect("max_frame_length_bytes already set");
}

/// Returns the currently configured frame length cap.
#[must_use]
pub fn max_frame_length_bytes() -> usize {
    *MAX_FRAME_LENGTH_BYTES
        .get()
        .unwrap_or(&DEFAULT_MAX_FRAME_LENGTH_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without an explicit override the getter must report the documented default, since that is
    /// what every framer built by `new()` will enforce.
    #[test]
    fn defaults_to_the_documented_limit() {
        assert_eq!(DEFAULT_MAX_FRAME_LENGTH_BYTES, 102_400);
        // `set_*` is process-global and may have been called by another test in this binary, so
        // only assert the default when it has not been overridden.
        if MAX_FRAME_LENGTH_BYTES.get().is_none() {
            assert_eq!(max_frame_length_bytes(), DEFAULT_MAX_FRAME_LENGTH_BYTES);
        }
    }
}
