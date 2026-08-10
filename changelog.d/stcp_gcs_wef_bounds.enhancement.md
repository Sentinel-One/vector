Bounded previously-unbounded allocation paths in three sources:

- `stcp`: new `max_frame_bytes` (4x `max_event_size`, 64 MiB) bounds the per-connection receive
  buffer, and `max_lines_per_event` (1e6) bounds the events produced from one RAW field.
- `gcp_gcs`: new `max_decompressed_bytes` (4 GiB) caps decompressed object size; truncation is
  logged and counted by `gcs_object_truncated_total`.
- `wef`: `max_content_length` is now enforced on the inbound HTTP body, defaulting to 4x the
  advertised `max_envelope_size` and never dropping below it.
