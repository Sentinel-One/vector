# OOM / Unbounded Allocation Bounds — Implementation Plan

Spec: docs/specs/2026-08-07-security-oom-allocation-bounds.md
Workspace: worktree: ~/vector-oom-bounds, branch: security-oom-bounds
Jira: OBE-10709, OBE-10712, OBE-10718, OBE-11232, OBE-11234, OBE-11235, OBE-11236, OBE-11238, OBE-11555, OBE-11556

## Progress

- [ ] Task 1: GCS decompression cap + framing max_length (OBE-10709)
- [x] Task 2: Logstash decompression + nested-C recursion guard (OBE-10712) — `b034a7fd7`
- [ ] Task 3: WEF body limit + SLDC decompress cap (OBE-10718, OBE-11236)
- [x] Task 4: Newline framer max_length default + socket/statsd exposure (OBE-11232) — `15c3bc3ad`
- [x] Task 5: GELF finite defaults — pending_messages_limit and max_length (OBE-11235 part 1) — `0153d5aa6`
- [ ] Task 6: GELF DelayQueue reaper — O(N) task → O(1) (OBE-11235 part 2)
- [ ] Task 7: STCP frame buffer cap — max_frame_bytes in decode() (OBE-11238)
- [ ] Task 8: STCP RegisterChannel header-count cap + LEB128 error propagation (OBE-11234)
- [ ] Task 9: STCP parse_lines clone → Arc shared metadata + max_lines cap (OBE-11556)
- [x] Task 10: TCP ack permit release before write_all (OBE-11555) — `e99054335`

## Tasks

---

### Task 1: GCS decompression cap + framing max_length (OBE-10709)

**What**: Two fixes in the GCS source:

1. Wrap the async decompressor in `vector/lib/observo/private/gcs/gcs.rs:676-721` with
   `tokio::io::AsyncReadExt::take(max_decompressed_bytes)` before it is boxed and fed to
   `FramedRead`. This limits how many bytes the decompressor can emit into the framer
   regardless of how large or dense the GCS object is.
   Add `max_decompressed_bytes: u64` to `GcsConfig` (default `256 * 1024 * 1024`).
   Thread it from `GcsSource::parse_message` through to each decompressor arm.

2. Change `default_framing()` in `vector/lib/observo/private/gcs/config.rs:126-130` to set
   `max_length: Some(bytesize::mib(1u64) as usize)` instead of `None`. This caps the per-line
   buffer inside `FramedRead` to 1 MiB, matching the DEVELOPING.md guidance for untrusted input.

Add a unit test covering: a `GzipDecoder` input that would decompress to > 256 MiB is cut at
the `take` boundary without allocating the full payload. Use a repeating-byte in-memory reader
to avoid filesystem I/O.

**Files**:
- `vector/lib/observo/private/gcs/gcs.rs` — add `.take(max_decompressed_bytes)` on the decoder,
  add config field plumbing
- `vector/lib/observo/private/gcs/config.rs` — update `default_framing()`, add
  `max_decompressed_bytes` field

**Depends on**: none
**Verify**: `cargo test -p observo-gcs` (or equivalent crate name for the private GCS crate)
passes. The new RED test fails without the `.take()` change and passes after.
**Parallelizable**: yes — does not share files with Tasks 2, 3, 4, 5, 6, 7, 8, 9, 10

---

### Task 2: Logstash decompression + nested-C recursion guard (OBE-10712)

**What**: Two fixes in `vector/src/sources/logstash.rs:666-685` (`decode_compressed_frame`):

1. Wrap the `flate2::read::ZlibDecoder` with `.take(max_decompressed_bytes)` before the
   `.read_to_end(&mut buf)` call. Return `DecompressionFailed` if `buf.len() as u64 >=
   max_decompressed_bytes` (bomb detected). Add `max_decompressed_bytes: u64` to `LogstashConfig`
   (default 256 MiB). Also eliminate the redundant `Vec → BytesMut::from(&buf[..])` copy by
   building `BytesMut` directly via `BytesMut::from(buf.as_slice())` or by draining.

2. Add a `depth: u8` parameter to `decode_compressed_frame`. Construct the inner `LogstashDecoder`
   with `depth + 1` and return `DecodeError::UnknownFrameType` if `depth >= 1`. The Lumberjack
   spec never legitimately nests a `C` frame inside another `C` frame; this kills the recursion
   at depth 1.

Add two RED tests: (a) a zlib payload that decompresses to > 256 MiB is rejected before OOM;
(b) a two-level nested `C` frame is rejected with `UnknownFrameType`.

**Files**:
- `vector/src/sources/logstash.rs` — add `.take()`, eliminate copy, add `depth` parameter

**Depends on**: none
**Verify**: `cargo test -p vector --lib sources::logstash` passes. Both RED tests fail before the
fix and pass after.
**Parallelizable**: yes — does not share files with Tasks 1, 3, 4, 5, 6, 7, 8, 9, 10

---

### Task 3: WEF body limit + SLDC decompress cap (OBE-10718, OBE-11236)

**What**: Two fixes in the WEF handler:

1. **WEF body size limit** (`vector/lib/observo/private/wef/server.rs:184`): Thread
   `config.max_content_length` from `WefSourceConfig` through `run()` into `WefHandler`. Wrap the
   incoming body before collecting:
   ```rust
   let limited = http_body_util::Limited::new(req.into_body(), self.max_content_length as usize);
   let body_bytes = match limited.collect().await { ... };
   ```
   This activates the dead `max_content_length` field (default 512 000 in `config.rs:164`).
   Verify that `source.rs::run()` signature is updated to accept and forward the limit.

2. **SLDC decompress output cap** (`vector/lib/observo/private/wef/sldc.rs:91-147`): Add
   `max_out: usize` parameter to `decompress()`. After each `emit()` call — centrally inside
   `emit()` or inside the Scheme-1 copy loop (`process_scheme1`, lines 163-174) — check
   `output.len() >= max_out` and bail with an error. Pass
   `config.max_content_length as usize * 4` (or a separate `max_decompressed_bytes` config field)
   at both call sites in `server.rs` (TLS path at :216, Kerberos path at :596). Optionally also
   cap `decode_utf16le` by checking `bytes.len()` against the limit before allocating.

Add RED tests: (a) POST body exceeding `max_content_length` is rejected before body allocation
completes; (b) an SLDC payload that would expand beyond `max_out` is rejected mid-loop.

**Files**:
- `vector/lib/observo/private/wef/server.rs` — thread `max_content_length`, wrap body with
  `Limited`, update both `sldc::decompress` call sites to pass `max_out`
- `vector/lib/observo/private/wef/sldc.rs` — add `max_out` param to `decompress()`, add limit
  check inside `process_scheme1` / `emit()`
- `vector/lib/observo/private/wef/config.rs` — verify field is present (it is); consider adding
  `max_decompressed_bytes` if a separate cap is desired

**Depends on**: none
**Verify**: `cargo test -p observo-wef` (or the crate name that contains the WEF handler) passes.
Both RED tests fail before and pass after.
**Parallelizable**: yes — does not share files with Tasks 1, 2, 4, 5, 6, 7, 8, 9, 10

---

### Task 4: Newline framer max_length default + socket/statsd exposure (OBE-11232)

**What**: Three changes to fix `max_length: usize::MAX` on the newline framer:

1. Change `NewlineDelimitedDecoder::new()` in
   `vector/lib/codecs/src/decoding/framing/newline_delimited.rs` to call
   `new_with_max_length(default_max_length())` instead of wrapping
   `CharacterDelimitedDecoder::new(b'\n')` directly. `default_max_length()` returns 100 KiB
   (already defined in `vector/lib/codecs/src/serde.rs`).

2. Add `max_length: Option<usize>` to `socket::tcp::TcpConfig`
   (`vector/src/sources/socket/tcp.rs`), defaulting to `Some(default_max_length())`. Thread
   the value into the decoder call:
   `NewlineDelimitedDecoder::new_with_max_length(self.max_length.unwrap_or_else(default_max_length))`.

3. Add the same `max_length` field to the statsd TCP config
   (`vector/src/sources/statsd/mod.rs`). Change `StatsdTcpSource::decoder()` from
   `NewlineDelimitedDecoder::new()` to
   `NewlineDelimitedDecoder::new_with_max_length(self.max_length.unwrap_or_else(default_max_length))`.

Verify `CharacterDelimitedDecoder::decode` already discards oversized frames via the
`buf.len() > self.max_length` branch (line 150) — no logic change needed there.

Add a RED test for each: stream bytes with no newline character far beyond 100 KiB to a
`NewlineDelimitedDecoder` instance and assert the `BytesMut` does not grow beyond `max_length`.

**Files**:
- `vector/lib/codecs/src/decoding/framing/newline_delimited.rs` — change `new()` body
- `vector/src/sources/socket/tcp.rs` — add `max_length` field, thread to decoder
- `vector/src/sources/statsd/mod.rs` — add `max_length` to TCP sub-config, update `decoder()`

**Depends on**: none
**Verify**: `cargo test -p codecs --lib decoding::framing::newline_delimited` and
`cargo test -p vector --lib sources::statsd` pass. RED tests fail before and pass after.
**Parallelizable**: yes — does not share files with Tasks 1, 2, 3, 5, 6, 7, 8, 9, 10

---

### Task 5: GELF finite defaults — pending_messages_limit and max_length (OBE-11235 part 1)

**What**: In `vector/lib/codecs/src/decoding/framing/chunked_gelf.rs`, change the defaults in
`ChunkedGelfDecoderOptions`:
- `pending_messages_limit: Option<usize>` → default `Some(5_000)` (instead of `None`)
- `max_length: Option<usize>` → default `Some(1_048_576)` (1 MiB, instead of `None`)

Reorder the limit checks:
- Apply the `max_length` check on the chunk payload **before** inserting into `MessageState`, so
  oversized chunks are rejected without allocating storage.
- Apply the `pending_messages_limit` check only when the `message_id` is **not** already in the
  map, so in-flight reassembly for tracked messages is not disrupted when the limit is reached.

Update the doc-comment on `pending_messages_limit` to note the Observo default is bounded.

Add a RED test: spray 6 000 unique `message_id` datagrams and assert the `HashMap` does not
grow beyond 5 000 entries.

**Files**:
- `vector/lib/codecs/src/decoding/framing/chunked_gelf.rs` — update defaults, reorder checks

**Depends on**: none
**Verify**: `cargo test -p codecs --lib decoding::framing::chunked_gelf` passes. RED test for
HashMap bound fails before and passes after.
**Parallelizable**: yes — does not share files with Tasks 1, 2, 3, 4, 7, 8, 9, 10

---

### Task 6: GELF DelayQueue reaper — O(N) task → O(1) (OBE-11235 part 2)

**What**: Replace the per-message-id `tokio::spawn(sleep(timeout))` in `decode_chunk` with a
single `tokio_util::time::DelayQueue`-based reaper per decoder instance:

1. Add `reaper_queue: Arc<Mutex<tokio_util::time::DelayQueue<u64>>>` to the decoder struct.
2. On decoder creation, spawn one background reaper task that loops on `DelayQueue` expirations
   and removes stale entries from the shared `HashMap<u64, MessageState>`.
3. When a new `message_id` entry is inserted into `state`, push the id into the `DelayQueue`
   with the configured timeout instead of calling `tokio::spawn(sleep(...))`.
4. Remove the `JoinHandle` field from `MessageState` (it no longer exists per-message).

Confirm `tokio_util` is already a workspace dependency (it is — used by `tokio_util::codec::FramedRead`).

Add a task-count assertion test: create a decoder with N pending messages and assert that the
number of active tokio tasks does not increase linearly with N (stays at O(1) reaper tasks).

**Files**:
- `vector/lib/codecs/src/decoding/framing/chunked_gelf.rs` — replace spawn with DelayQueue,
  update `MessageState`, update decoder struct

**Depends on**: Task 5
**Verify**: `cargo test -p codecs --lib decoding::framing::chunked_gelf` passes. Task-count
assertion test confirms O(1) background tasks.

---

### Task 7: STCP frame buffer cap — max_frame_bytes in decode() (OBE-11238)

**What**: Two changes to bound the `FramedRead` internal `BytesMut` growth for the STCP source:

1. Add `max_frame_bytes: usize` to `STcpConfig`
   (`vector/lib/observo/private/stcp/config.rs:14-44`) with a default of `1_048_576` (1 MiB —
   Splunk S2S frames are ≤ 64 KiB by spec; 1 MiB is generous). Expose it as a serde-default
   field.

2. At the top of `STcpDecoder::decode()` in
   `vector/lib/observo/private/stcp/stcp_decoder.rs:33`, add:
   ```rust
   if buf.len() > self.max_frame_bytes {
       return Err(STcpDecoderError::BufferOverflow);
   }
   ```
   Verify that `BufferOverflow`'s `can_continue()` returns `false` (or update it to return
   `false`) so `FramedRead` terminates the stream rather than retrying. The variant already
   exists at line 2017-2018 but is never constructed — this activates it.

   Also stop swallowing non-`InSufficientData` errors as `Ok(None)` at lines 39-42. Map
   `InSufficientData` to `Ok(None)` and all other variants to `Err(e)` so `FramedRead`
   terminates the connection on unexpected errors.

Thread `max_frame_bytes` from `STcpConfig` into `STcpDecoder::new()` (via `make_decoder()` in
`vector/src/sources/stcp/mod.rs`).

Add a RED test: stream garbage bytes exceeding `max_frame_bytes` and assert the connection
is terminated, not buffered indefinitely.

**Files**:
- `vector/lib/observo/private/stcp/config.rs` — add `max_frame_bytes` field with 1 MiB default
- `vector/lib/observo/private/stcp/stcp_decoder.rs` — add buffer-size guard, fix error mapping
- `vector/src/sources/stcp/mod.rs` — thread `max_frame_bytes` to decoder constructor

**Depends on**: none
**Verify**: `cargo test -p vector --lib sources::stcp` passes. RED test for buffer overflow
fails before and passes after.
**Parallelizable**: yes — does not share files with Tasks 1, 2, 3, 4, 5, 6, 10

---

### Task 8: STCP RegisterChannel header-count cap + LEB128 error propagation (OBE-11234)

**What**: Two fixes in `vector/lib/observo/private/stcp/stcp_decoder.rs`:

1. In `build_channel_data` (lines 1043-1056): after reading `n` from `read_leb128_i32`, reject
   if `n > 256` (matching the indexing use at line 474) and return
   `STcpDecoderError::InvalidDataEncoding`. This prevents the 2-billion-iteration hot loop from
   a 5-byte wire payload.

2. Fix `read_leb128_i32` (lines 753-759) and `read_leb128_i64` to return
   `Result<i32, STcpDecoderError::InSufficientData>` instead of silently returning a
   truncated/zero value when they reach end-of-buffer. Update all call sites to propagate the
   `Result`. This prevents the attacker from driving the loop with bogus zero-length headers
   by exhausting the buffer early.

   Apply the same `n > limit` check to the analogous loop in `parse_event` (lines 365/371,
   `num_fields` → cap at `max_fields_per_event`) and `read_legacy_event` (lines 1260/1273,
   cap `i` at 65535).

Add RED tests: (a) a `RegisterChannel` frame claiming `n = i32::MAX` headers is rejected
before any `Vec::push`; (b) a `parse_event` with `num_fields = u32::MAX` is rejected.

**Files**:
- `vector/lib/observo/private/stcp/stcp_decoder.rs` — cap `n` in `build_channel_data`,
  fix `read_leb128_i32`/`read_leb128_i64`, cap analogous loops in `parse_event` /
  `read_legacy_event`

**Depends on**: Task 7
**Verify**: `cargo test -p vector --lib sources::stcp` passes. Both RED tests fail before and
pass after. The test suite from Task 7 continues to pass.

---

### Task 9: STCP parse_lines clone → Arc shared metadata + max_lines cap (OBE-11556)

**What**: In `vector/lib/observo/private/stcp/stcp_decoder.rs:756-776` (`parse_lines`):

Replace the per-line `s2sevent.clone()` with a design that shares immutable metadata across
lines:
1. Wrap the immutable parts of `S2SEventFrame` (specifically `fields`, `control_fields`,
   `breaker_fields`, `flags`, and any other attacker-filled maps) in `Arc<...>` so each
   per-line struct holds a reference, not a deep copy. Only `raw` (the line-specific content)
   and `event_id` need to be per-line.
2. Add `max_lines_per_event: usize` to `STcpConfig` (default 10 000, matching
   `max_fields_per_event`). In `parse_lines` (or in `post_process_event` at line 745 where
   `data.lines()` is called), reject events whose line count exceeds the cap.
3. Enforce `max_event_size` against the cumulative size of RAW + field values during
   `parse_event` (lines 499-511 and 632-654 — currently `max_event_size` is defined but not
   applied to these). This closes the size amplification path independently of line count.

Add a RED test: a ReadEvent frame with 1 MiB of field state and 1 MiB of `\n`-only RAW should
be processed without materializing a 2 TiB heap demand. Assert peak allocation does not exceed
`max_event_size * 2` (rather than `field_bytes * line_count`).

**Files**:
- `vector/lib/observo/private/stcp/stcp_decoder.rs` — refactor `parse_lines` to `Arc`-share
  metadata, add `max_lines_per_event` cap, apply `max_event_size` in `parse_event`
- `vector/lib/observo/private/stcp/config.rs` — add `max_lines_per_event` field with 10 000
  default

**Depends on**: Task 8
**Verify**: `cargo test -p vector --lib sources::stcp` passes (Tasks 7 and 8 tests still pass).
RED test for parse_lines amplification fails before and passes after.

---

### Task 10: TCP ack permit release before write_all (OBE-11555)

**What**: In `vector/src/sources/util/net/tcp/mod.rs`, the `RequestLimiterPermit` acquired
at line 297 is dropped only at line 411, after the ack write `stream.write_all(&ack_bytes).await`
at line 381. A peer that never reads its socket parks the write forever with the permit held,
starving all other connections of that source.

Fix: drop the permit explicitly after `receiver.await` (line 370) completes and before the ack
write begins:
```rust
// After: let ack = receiver.await...
drop(permit);
// Then: if let Some(ack_bytes) = acker.build_ack(ack) { stream.write_all(...).await?; }
```

The permit's purpose — bounding in-flight decoded events — ends once `send_batch` and
`receiver.await` complete. Dropping it before the write does not change correctness for the
permit's intended use.

Additionally: wrap the `stream.write_all(&ack_bytes).await` at line 381 with
`tokio::time::timeout(Duration::from_secs(30), ...)` as a defense-in-depth backstop. On
timeout, log a warning and return an error to close the connection.

Add a RED test: create a mock `TcpStream` writer that never consumes data (zero-window
simulation), perform a logstash/fluent ack write, and assert the permit is released before
the write completes (i.e. the permit drops are counted and a waiting acquirer unblocks).

**Files**:
- `vector/src/sources/util/net/tcp/mod.rs` — drop permit before `write_all`, add write timeout

**Depends on**: none
**Verify**: `cargo test -p vector --lib sources::util::net::tcp` passes. RED test for permit
starvation (zero-window peer) fails before the drop-before-write change and passes after.
**Parallelizable**: yes — does not share files with Tasks 1, 2, 3, 4, 5, 6, 7, 8, 9
