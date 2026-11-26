use metrics::{counter, Counter};
use tracing::trace;

use super::ByteSize;

// `component_sent_bytes_total` carries no `protocol` tag: the component tags (`component_id`,
// `component_kind`, `component_type`) are added from the active span. Every sink counts its sent
// bytes into this one series, whatever the transport.
crate::registered_event!(
    BytesSent => {
        bytes_sent: Counter = counter!("component_sent_bytes_total"),
    }

    fn emit(&self, byte_size: ByteSize) {
        trace!(message = "Bytes sent.", byte_size = %byte_size.0);
        self.bytes_sent.increment(byte_size.0 as u64);
    }
);

// The handle is held by sink services, which derive `Debug`. Registered handles do not implement
// it, and the counter has nothing useful to print.
impl std::fmt::Debug for BytesSentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytesSentHandle").finish_non_exhaustive()
    }
}
