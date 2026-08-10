Added default upper bounds to previously-unbounded allocation paths in several sources, so a
malicious or malformed peer can no longer exhaust the heap. Every default is set above documented
producer maxima, so legitimate traffic is unaffected; each is overridable.

- Newline framing: 10 MiB default line length when `framing.newline_delimited.max_length` is unset.
- `logstash`: new `max_decompressed_bytes` (256 MiB) caps compressed-frame inflation; nested
  compressed frames are rejected.
- `gcp_gcs`: new `max_decompressed_bytes` (4 GiB); truncation is logged and counted by
  `gcs_object_truncated_total`.
- `stcp`: new `max_frame_bytes` (tracks `max_event_size`, 16 MiB) and `max_lines_per_event` (1e6).
- `wef`: the existing `max_content_length` is now enforced on the inbound HTTP body.
- GELF chunked framing: `pending_messages_limit` 10000, `max_length` 8 MiB — both above the
  protocol's own ceiling of 128 chunks per message.

The `tcp` source now releases its `RequestLimiter` permit before writing the acknowledgement and
bounds that write with a 30-second timeout, so a peer that stops reading cannot starve others.
