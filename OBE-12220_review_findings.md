# OBE-12220 Review Findings

## Context

This change makes GCP OAuth token fetching lazy — previously tokens were fetched eagerly at
`build()` time, causing crash loops when credentials were expired at restart. Tokens are now
fetched by a background `token_regenerator` task that fires immediately on startup and retries
on failure.

Reviewed with Opus. AWS auth patterns studied for comparison.

---

## Issues

### HIGH — Health checks race the background token fetch (sinks)

Every GCP sink constructs the healthcheck future and then spawns the token regenerator:

```rust
// same pattern in gcp/pubsub.rs, stackdriver/logs, stackdriver/metrics,
// gcs cloud_storage, gcp_chronicle
let healthcheck = healthcheck(client, uri, sink.auth.clone()).boxed();
sink.auth.spawn_regenerate_token(&APP_INFO);   // token not yet fetched
```

The healthcheck calls `auth.apply()` → `make_token()` → `None` (no token yet) → no
`Authorization` header → GCP returns 401 → healthcheck fails. With healthchecks enabled
(the default), the crash loop becomes a healthcheck failure at startup instead of being
fully resolved.

The `gcp_pubsub` **source** is handled correctly — the watch channel + stream restart
covers the race. **Sinks are the weak spot.**

Fix options:
- **Option A**: Await the first watch signal (with timeout) inside the healthcheck before
  sending the request, treating a missing token as "pending" rather than fatal.
- **Option B**: Gate sink readiness on the first `watch::Receiver::changed()` signal.
- **Option C** (lowest touch): Treat 401 as a retryable/non-fatal response in the
  healthcheck instead of a hard failure.

### MEDIUM — First real sink request sends no auth header

For HTTP sinks, `apply()` silently omits the `Authorization` header when `make_token()`
returns `None`. Recovery depends on each sink's retry logic classifying 401 as retryable.
That is not uniform across the affected sinks — needs verification:

- `GcsRetryLogic` (`src/sinks/gcs_common/`)
- Stackdriver logs/metrics retry logic
- Chronicle retry logic

If any classify 401 as non-retryable, the first batch of events is dropped on startup.

### MEDIUM — `map_or` guard is dead code masking an invariant

```rust
// gcp.rs — after Ok(()) from regenerate_token:
let expires_in = inner.token.read().unwrap()
    .as_ref()
    .map_or(METADATA_TOKEN_ERROR_RETRY_SECS, |t| t.expires_in() as u64);
```

`regenerate_token` unconditionally writes `Some(token)` before returning `Ok`, so the
`None` fallback arm is unreachable under the current design. If a future change broke this
invariant, the fallback (retry every 2s) would silently hammer the token endpoint rather
than surfacing the bug.

Prefer:
```rust
let expires_in = inner.token.read().unwrap()
    .as_ref()
    .expect("token present after successful regenerate")
    .expires_in() as u64;
```

### LOW — No exponential backoff on repeated fetch failures

With invalid static credentials (e.g. bad service account JSON), the loop retries every
`METADATA_TOKEN_ERROR_RETRY_SECS` (2s) forever against `oauth2.googleapis.com`. The old
code failed fast at build time. Consider exponential backoff with a cap for persistent
auth failures.

### LOW — `from_file` and `new_implicit` are needlessly `async`

Both constructors do zero async work after the token fetch was removed. Drop `async` for
accuracy. `GcpAuthConfig::build` will also no longer need to be `async` unless another
reason requires it.

### Formatting regression (unrelated)

`src/sources/gcp_pubsub.rs` — the `#[snafu(display(...))]` attribute on the `Endpoint`
variant lost its indentation:

```rust
// broken
#[snafu(display("Could not create endpoint: {}", source))]
```

Fix with `make fmt` before merge.

---

## Test Coverage Gaps

1. **No test that the background task delivers a token and fires the watch signal.**
   The core async behavior (token transitions `None → Some`, watch receiver observes
   `changed()`) is completely untested.

2. **No test for the sink healthcheck race.** The HIGH finding above has no regression
   test.

3. **Invalid credentials path is untested.** `fails_missing_creds` was the only test
   covering this. Its deletion leaves the error path for bad/expired credentials with
   zero test coverage.

---

## AWS Comparison

AWS uses `IdentityCache::lazy()` across all auth variants (`src/aws/auth.rs:205-225`).
Credentials are never fetched at build time — only on the first request. There is no
background refresh task; the AWS SDK refreshes inline via `provide_credentials()` on
every signing call, with expiry managed inside the identity cache.

The key difference: AWS delegates "no token yet" to the SDK, which blocks the first
request for up to `load_timeout` (default 5s) waiting for credentials. The first request
does not go out unauthenticated. GCP's new approach sends immediately with no header,
which is what creates the sink healthcheck and first-request 401 problems.

The GCP source path (gcp_pubsub) converges on the same safety property via a different
mechanism — the stream fails, `changed()` fires when the token arrives, and the stream
restarts authenticated. The sink path lacks an equivalent gate.

---

## Summary

| Finding | Severity | Affects |
|---------|----------|---------|
| Healthcheck races token fetch | HIGH | All GCP sinks |
| First request sends no auth header | MEDIUM | All GCP HTTP sinks |
| `map_or` dead fallback masks invariant | MEDIUM | `token_regenerator` |
| No backoff on auth failures | LOW | `token_regenerator` |
| Needless `async` on constructors | LOW | `from_file`, `new_implicit` |
| Formatting regression | LOW | `gcp_pubsub.rs` |
| Missing async-token test | Gap | `gcp.rs` tests |
| Missing healthcheck race test | Gap | sink integration tests |
| Invalid creds path untested | Gap | `gcp.rs` tests |