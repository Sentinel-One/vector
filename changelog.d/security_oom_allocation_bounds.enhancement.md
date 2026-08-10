Added default upper bounds to previously-unbounded allocation paths in several sources, so a
malicious or malformed peer can no longer exhaust the heap. Every default is set above documented
producer maxima, so legitimate traffic is unaffected; each is overridable.

- `logstash`: new `max_decompressed_bytes` (256 MiB) caps compressed-frame inflation; nested
  compressed frames are rejected.
- `gcp_gcs`: new `max_decompressed_bytes` (4 GiB); truncation is logged and counted by
  `gcs_object_truncated_total`.
- `stcp`: new `max_frame_bytes` (4x `max_event_size`, 64 MiB) and `max_lines_per_event` (1e6).
- `wef`: `max_content_length` is now enforced on the inbound HTTP body, defaulting to 4x the
  advertised `max_envelope_size` and never dropping below it.
- GELF chunked framing: `pending_messages_limit` 10000, `max_length` 8 MiB — both above the
  protocol's own ceiling of 128 chunks per message.

The `tcp` source now releases its `RequestLimiter` permit before writing the acknowledgement and
bounds that write with a 30-second timeout, so a peer that stops reading cannot starve others.
