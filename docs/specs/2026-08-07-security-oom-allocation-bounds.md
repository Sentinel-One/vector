# Security: OOM / Unbounded Allocation Bounds

Jira: OBE-11232, OBE-11234, OBE-11235, OBE-11236, OBE-11238, OBE-11555, OBE-11556, OBE-10709, OBE-10712, OBE-10718
Date: 2026-08-07
Status: Draft
Last reviewed: 2026-08-07

## Problem

Ten confirmed high-severity findings across the vector codebase allow unauthenticated network
attackers to exhaust process memory and OOM-kill the Vector daemon, halting every configured
pipeline. The root pattern is the same across all findings: allocations driven by untrusted network
input with no configurable upper bound.

The findings cluster into four independent sub-problems:

| Family | Tickets | Location | Attack vector |
|--------|---------|----------|---------------|
| A: Decompression output | OBE-10709, OBE-10712, OBE-10718, OBE-11236 | `util/http/encoding.rs`, logstash framer, SLDC decoder | `read_to_end` into unbounded `Vec<u8>` |
| B: Framer buffer | OBE-11232 | `character_delimited.rs`, `socket/tcp.rs`, `statsd/mod.rs` | `max_length: usize::MAX` on newline framer |
| C: GELF chunk-reassembly | OBE-11235 | `chunked_gelf.rs` | Unbounded `HashMap` + O(N) `tokio::spawn` |
| D: STCP bounds | OBE-11234, OBE-11238, OBE-11555, OBE-11556 | `lib/observo/stcp/` | Frame buffer, header loop, ack write, per-line clone |

**Out of scope for this PR:**
- OBE-10715 (file-sink path traversal) — different fix category, separate PR
- OBE-11558 (array-root condition panic) — different fix class, separate PR
- OBE-10717 — stale: scanner already resolved as duplicate; Jira transition to close required

## Approach

Each family is an independent code change. All changes:
- Enforce a configurable upper bound on allocations driven by network input
- Default to a safe value that is generous enough for real traffic
- Return an error (not panic, not silently discard) when the limit is exceeded
- Are covered by a RED test that feeds the exploit input and asserts the unsafe outcome cannot occur

No existing behavior is broken for well-formed traffic within the default limits.

## Design

### Family A — Decompression output limit

**Files:** `vector/src/sources/util/http/encoding.rs`, `vector/src/sources/logstash.rs`,
and the SLDC decoder used by the WEF handler.

**Root cause:** `read_to_end` is called into a bare `Vec<u8>` with no `.take(limit)` guard.
The encoding loop in `util/http/encoding.rs` also iterates over comma-stacked `Content-Encoding`
tokens, multiplying the expansion ratio per stage.

**Fix:**

1. Add `max_decompressed_bytes: u64` parameter to `util/http/encoding.rs::decode()`.
   Default: **256 MiB** (exposed as `max_decompressed_bytes` config field on each source that
   calls it; wired via the source's existing `HttpConfig` or equivalent).

2. Wrap every `read_to_end` call with `.take(max_decompressed_bytes)`:
   ```rust
   MultiGzDecoder::new(body.reader())
       .take(max_decompressed_bytes)
       .read_to_end(&mut decoded)?;
   if decoded.len() as u64 >= max_decompressed_bytes {
       return Err(ErrorMessage::new(StatusCode::PAYLOAD_TOO_LARGE, "..."));
   }
   ```
   For `zstd`, replace `decode_all`/`copy_decode` with `zstd::Decoder::new(body.reader())?.take(limit).read_to_end(...)`.

3. Track cumulative decoded size across encoding layers. After each decode step, add
   `decoded.len()` to a running total and reject if it exceeds the limit. This prevents
   an attacker from stacking `gzip,gzip,...` to multiply past any per-stage cap.

4. Apply the same `.take(limit)` pattern in the logstash compressed frame handler
   (`vector/src/sources/logstash.rs`) and the SLDC decoder.

5. Add `max_decompressed_bytes` to the relevant source config structs
   (`DatadogAgentConfig`, `HttpConfig`, `LogstashConfig`, `WefHandlerConfig`) with the
   256 MiB default.

### Family B — Framer buffer bound

**Files:** `vector/lib/codecs/src/decoding/framing/newline_delimited.rs`,
`vector/src/sources/socket/tcp.rs`, `vector/src/sources/statsd/mod.rs`.

**Root cause:** `NewlineDelimitedDecoder::new()` wraps `CharacterDelimitedDecoder::new(b'\n')`
which defaults `max_length: usize::MAX`. Neither `socket::tcp::TcpConfig` nor
`statsd::TcpConfig` exposes a `max_length` knob, so operators cannot harden the default.

**Fix:**

1. Change `NewlineDelimitedDecoder::new()` to call `new_with_max_length(default_max_length())`
   (100 KiB, matching UDP and syslog source defaults).

2. Add `max_length: Option<usize>` to `socket::tcp::TcpConfig` and `statsd::TcpConfig`,
   defaulting to `Some(default_max_length())`. Thread it into the decoder via
   `NewlineDelimitedDecoder::new_with_max_length(...)`.

3. Verify that `CharacterDelimitedDecoder::decode` already discards oversized frames (it
   does — the `buf.len() > self.max_length` branch at line 150). No logic change needed there.

### Family C — GELF chunk-reassembly

**File:** `vector/lib/codecs/src/decoding/framing/chunked_gelf.rs`.

**Root cause:** Two independent issues:
- `pending_messages_limit` and `max_length` both default to `None`, so the per-decoder
  `HashMap<u64,MessageState>` is unbounded.
- One `tokio::spawn(sleep(5s))` is issued per new `message_id`, making task count
  O(pending messages) instead of O(1).

**Fix:**

1. Change `ChunkedGelfDecoderOptions` defaults:
   - `pending_messages_limit: Option<usize>` → default `Some(5_000)`
   - `max_length: Option<usize>` → default `Some(1_048_576)` (1 MiB)

2. Replace per-id `tokio::spawn(sleep(timeout))` with a single
   `tokio_util::time::DelayQueue`-based reaper task per decoder instance. The reaper
   owns a `DelayQueue<u64>` (keyed by `message_id`) and processes expirations in a
   single background loop, removing stale entries from the shared `HashMap`. The
   per-id `JoinHandle` field on `MessageState` is removed.

3. Apply the `max_length` check on the chunk payload **before** inserting into `MessageState`
   so oversized chunks are rejected without allocating storage.

4. Move the `pending_messages_limit` check to after `state_lock.contains_key(&message_id)`
   so in-flight reassemblies for already-tracked messages are not rejected when the limit
   is reached.

### Family D — STCP bounds

**Files:** `vector/lib/observo/stcp/src/stcp/stcp_decoder.rs`,
`vector/lib/observo/stcp/src/stcp/stcp.rs`.

The stcp crate already has `max_channel_headers`, `max_fields_per_event`, and `max_event_size`
parameters. The issues are:

- **OBE-11234 (RegisterChannel header loop):** Verify the `max_channel_headers` bound is
  enforced before allocating the per-header `Vec` entry, not after parsing it. If the check
  is post-parse, move it to pre-allocation.

- **OBE-11238 (STCP frame buffer):** Verify `max_event_size` is applied to the full frame
  buffer, not only to individual event fields. If the frame accumulation buffer is unbounded,
  add a size check after each `BytesMut` append.

- **OBE-11555 (ack write stall):** The ack write to a slow/non-reading peer blocks
  indefinitely while holding a shared request-limiter permit. Add a write deadline:
  wrap the ack write with `tokio::time::timeout(Duration::from_secs(30), ack.write_all(...))`.
  On timeout, drop the connection rather than blocking the permit.

- **OBE-11556 (per-line clone):** Eliminate the unnecessary per-line deep-clone of the
  full event frame in the decoder. Use `Arc` sharing or a reference where the clone serves
  no functional purpose.

## Acceptance Criteria

Each criterion must be covered by a RED test that feeds the exact exploit input and asserts
the memory-unsafe outcome cannot occur (not just "no error").

1. **When** a TCP `socket` or `statsd` source receives a stream of bytes with no newline,
   **the system shall** disconnect the client and discard the frame once the buffer exceeds
   `max_length` (default 100 KiB), and not grow the `BytesMut` beyond that bound.

2. **When** an HTTP POST to a `datadog_agent` or `opentelemetry` source contains a
   `Content-Encoding: gzip` body whose decompressed size exceeds `max_decompressed_bytes`
   (default 256 MiB), **the system shall** return HTTP 413 and not allocate the full
   decompressed payload.

3. **When** the same request contains stacked encodings (`Content-Encoding: gzip, gzip`)
   and the cumulative decompressed size exceeds `max_decompressed_bytes`, **the system shall**
   return HTTP 413 after the first stage that crosses the cumulative limit.

4. **When** a GELF UDP source receives datagrams with unique `message_id`s beyond
   `pending_messages_limit` (default 5,000), **the system shall** reject the excess datagrams
   with a logged error and not grow the reassembly `HashMap` beyond the limit.

5. **When** the GELF reassembly timeout elapses for a partial message, **the system shall**
   clean it up using the single reaper task, not a per-message tokio task. (Assert task
   count stays O(1) relative to pending message count.)

6. **While** an STCP peer is not reading ack responses, **the system shall** terminate the
   write attempt after the ack timeout (30 s) and drop the connection without holding the
   shared request-limiter permit indefinitely.

7. **If** an STCP `RegisterChannel` message contains more headers than `max_channel_headers`,
   **the system shall** reject the frame before allocating storage for the excess headers.

8. **If** an STCP frame buffer grows beyond `max_event_size`, **the system shall** reject
   the frame at the point of accumulation, not only after full parse.

9. **When** a logstash source receives a compressed frame whose decompressed output exceeds
   the configured limit, **the system shall** close the connection with an error and not
   allocate the full decompressed payload.

10. **The system shall** not regress any existing passing tests for `socket`, `statsd`,
    `gelf`, `logstash`, `datadog_agent`, `opentelemetry`, or `stcp` sources under normal
    (within-limit) traffic.

## Out of Scope

- OBE-10715: file-sink path traversal (separate PR)
- OBE-11558: array-root condition panic (separate PR)
- OBE-10717: stale/duplicate ticket; Jira close only, no code change required beyond what
  the decompression family fix already covers
- Other sinks/sources using `Template::render` for path/key generation (noted for audit,
  not in scope here)
- OS-level firewall rules or admission controls (deployment concern, not code)

## Risks & Open Questions

- **STCP crate scope:** OBE-11234, OBE-11238, OBE-11555, OBE-11556 are in `lib/observo/stcp`.
  The exact allocation sites need confirmation by reading the full stcp decoder before
  coding. If `max_channel_headers` is already enforced pre-allocation, OBE-11234 may be a
  false positive — needs spike. Status: **Needs spike**.

- **256 MiB decompression default:** May be too high if Vector is deployed with limited
  memory. Recommend documenting it prominently in the config schema. Status: **Deferred** —
  operator can override.

- **GELF reaper task ordering:** Moving from per-id spawn to DelayQueue changes the
  timeout precision from per-id to a shared wheel resolution. Impact on legitimate
  reassembly timing should be verified with an integration test. Status: **Deferred**.

- **Breaking change for socket/statsd:** Operators who intentionally receive frames larger
  than 100 KiB on TCP socket/statsd sources will need to set `max_length` explicitly.
  This is a behavior change (previously silently accepted; now discards with a log).
  Status: **Accepted** — the prior behavior was unsafe; the new default is documented.

## Testing

- Unit tests: one RED test per acceptance criterion, placed alongside the changed module
- Integration: existing source integration tests must continue to pass (criterion 10)
- Manual: run the PoC from each ticket against a local Vector build with the fix applied
  and confirm the exploit no longer succeeds; confirm normal traffic is unaffected
