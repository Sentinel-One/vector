# OOM / Unbounded Allocation Bounds — Architecture Decision Record

Spec: docs/specs/2026-08-07-security-oom-allocation-bounds.md
Branch: security-oom-bounds

---

## D1 — [2026-08-07] — Task 5/6: GELF defaults change from None to bounded

**Status**: Accepted
**Decision**: Changed `pending_messages_limit` default from `None` (unbounded) to `Some(1000)` and `max_length` default from `None` to `Some(5_242_880)` (5 MiB).
**Reason**: The original `None` defaults match Graylog Server behavior but are unsafe for untrusted senders. A default of 1 000 concurrent in-flight messages (each up to 5 MiB) caps the worst-case held memory at ~5 GiB — still generous, but finite and bounded by config. The existing serde field kept `None` serialization for backward compat; we changed `skip_serializing_if` to a hard default so new deployments are safe without any config change.
**Alternatives considered**: Keeping `None` default and requiring operators to set the limit — rejected because security-critical defaults should be secure out of the box; operators who need higher limits can explicitly set them.

---

## D2 — [2026-08-07] — Task 6: GELF reaper uses unbounded channel + DelayQueue, not Arc<Mutex<DelayQueue>>

**Status**: Accepted
**Decision**: The reaper task receives new message IDs via `tokio::sync::mpsc::unbounded_channel` rather than sharing a `Arc<Mutex<DelayQueue>>` directly with `decode_chunk`.
**Reason**: `DelayQueue::insert` is not `Send + Sync` in a way that's safe to share across tasks without additional complexity. The channel design is simpler: the decode path only ever sends a `u64`, the reaper task exclusively owns the `DelayQueue`. An unbounded channel is safe here because the queue itself is bounded by `pending_messages_limit` — at most 1 000 entries will ever be queued.
**Alternatives considered**: `Arc<Mutex<DelayQueue>>` — rejected because `DelayQueue::next()` requires pinning and mut access, making shared access awkward; the channel pattern is idiomatic tokio.

---

## D3 — [2026-08-07] — Task 8: LEB128 EOF returns InSufficientData, not Ok(partial)

**Status**: Accepted
**Decision**: When `read_leb128_i64` exhausts the buffer mid-read, it now returns `Err(STcpDecoderError::InSufficientData)` instead of `Ok(result_so_far)` (which was effectively `Ok(0)` on first byte exhaustion).
**Reason**: The old behavior was a silent truncation: a continuation byte at end-of-buffer would cause the caller to proceed with a zero count, bypassing loop guards (e.g. `n > max_channel_headers`). Returning `InSufficientData` signals `FramedRead` to buffer more bytes and retry from the frame start — the standard "need more data" contract for streaming decoders. The `InSufficientData` path was already special-cased in `decode()` to return `Ok(None)`, so existing behavior for genuine partial frames is preserved.
**Alternatives considered**: Returning `Ok(0)` (the previous behavior) — rejected because it silently breaks loop-count guards and enables the attack described in OBE-11234.

---

## D4 — [2026-08-07] — Task 9: max_lines_per_event cap only; Arc-sharing deferred

**Status**: Accepted
**Decision**: Task 9 implemented `max_lines_per_event = 10 000` truncation only. The Arc-sharing optimization (wrapping `fields`, `control_fields`, `breaker_fields` in `Arc<...>` to avoid per-line deep clones) was not implemented.
**Reason**: The cap is the primary security control — it bounds the total number of `S2SEventFrame` clones to 10 000, eliminating the unbounded O(N×M) allocation. The Arc-sharing would reduce per-clone cost by sharing read-only HashMaps, but with the cap in place, the worst case is 10 000 × `sizeof(S2SEventFrame)` — bounded, not exponential. The Arc-sharing requires changing 11+ write sites across the struct's lifetime (`fields.insert`, `control_fields.get_mut`, etc.) to use `Arc::make_mut`, which is a larger refactor and carries more risk than the security value at this point.
**Alternatives considered**: Full Arc-sharing — deferred; suitable as a follow-up optimization ticket once the security bound is confirmed in production.

---

## D5 — [2026-08-07] — Task 2: Bomb detection uses >= not >

**Status**: Accepted
**Decision**: In `decode_compressed_frame` (Logstash), the bomb check is `buf.len() as u64 >= max_decompressed_bytes` (not `>`).
**Reason**: After `.take(max_decompressed_bytes)`, if the decompressor fills the buffer to exactly `max_decompressed_bytes`, the output was truncated — the actual payload could be larger. Using `>=` catches both the "exactly at limit" (truncated) and "over limit" cases. Using `>` would accept exactly-at-limit output as a complete decompression, which is wrong if the real payload is `max_decompressed_bytes + 1`.
**Alternatives considered**: `>` — rejected because it accepts a potentially-truncated decompression silently.

---

## D6 — [2026-08-07] — Task 3: SLDC max_out = max_content_length × 100

**Status**: Accepted
**Decision**: The SLDC decompressor output cap is `max_content_length as usize * 100`, not a separate config field.
**Reason**: SLDC is a lossless compressor used for WEF XML payloads. Real compression ratios for XML are typically 5–15×. A 100× cap is generous enough to never trigger on legitimate data while still bounding the worst-case output at 512 KB × 100 = 51.2 MB (with the default 512 KB `max_content_length`). A separate `max_decompressed_bytes` field was considered but adds surface without significant benefit given the 100× ratio is already conservative.
**Alternatives considered**: Separate `max_sldc_decompressed_bytes` config field — deferred; can be added if operators need finer control.

---

## D7 — [2026-08-07] — Task 10: TCP permit drop uses Option::take, not explicit drop

**Status**: Accepted
**Decision**: `permit.take()` is called to release the permit before `write_all`, where `permit: Option<RequestLimiterPermit>`. The original `drop(permit)` at the end of the loop body is preserved as a no-op fallback for non-ack paths.
**Reason**: The permit is held in an `Option<RequestLimiterPermit>` due to the existing code structure. `take()` sets it to `None` and drops the value, cleanly expressing "I am done with this permit now." The existing `drop(permit)` at the end of the loop still compiles and handles error paths where `take()` was not called.
**Alternatives considered**: Moving the permit into a local and adding an explicit `drop(permit_local)` — equivalent but more verbose. The `take()` approach is idiomatic for `Option`-wrapped guards.
