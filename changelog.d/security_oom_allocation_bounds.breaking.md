Several sources now enforce default upper bounds on how much memory a remote sender can cause
Vector to allocate. Previously these paths were unbounded, so a single malicious or malformed
peer could exhaust the heap.

The new defaults are deliberately generous, but any input that exceeds them is **dropped or
truncated** rather than buffered. If you ingest unusually large records, raise the relevant
setting explicitly.

- **Newline framing** — when `framing.method = "newline_delimited"` is used without an explicit
  `framing.newline_delimited.max_length`, a 1 MiB per-line limit now applies. This affects every
  stream-based source that frames on newlines (`socket`, `exec`, `file_descriptors`, `aws_s3`,
  `gcp_gcs`, and any source configured with the `json` or `syslog` codec). Lines longer than the
  limit are discarded and logged. Set `max_length` explicitly to raise it.
- **`logstash` source** — new `max_decompressed_bytes` option, defaulting to 32 MiB, caps how far
  a compressed frame may inflate. Nested compressed (`C`) frames are now rejected outright.
- **`gcp_gcs` source** — new `max_decompressed_bytes` option, defaulting to 32 MiB, caps
  decompressed object size. Objects exceeding it are truncated; truncation is logged and counted
  by `gcs_object_truncated_total`.
- **`stcp` source** — new `max_frame_bytes` (defaults to `max_event_size`, 16 MiB) bounds the
  per-connection receive buffer, and new `max_lines_per_event` (default 10 000) bounds the events
  produced from one RAW field.
- **`wef` source** — the existing `max_content_length` (default 512 000) is now enforced on the
  inbound HTTP body; oversized requests receive `413 Payload Too Large`. SLDC decompression output
  is capped at 100x `max_content_length`.
- **GELF chunked framing** — `pending_messages_limit` now defaults to 1000 (was unlimited) and
  `max_length` to 5 MiB (was unlimited).

The `tcp` source now releases its `RequestLimiter` permit before writing the acknowledgement, and
bounds that write with a 30-second timeout, so a peer that stops reading can no longer starve
other connections.
