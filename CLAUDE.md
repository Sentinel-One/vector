@AGENTS.md

# CLAUDE.md — Observo Vector Overlay

This is the **Observo fork of Vector**. The line above pulls in upstream's `AGENTS.md`, which covers generic Vector dev: `make fmt`, `make check-clippy`, `cargo vdev`, integration tests, PR conventions, project layout, YAML config defaults, license checks. **Don't duplicate those here.**

This file is the **Observo-specific overlay**: how the fork diverges, the proprietary components in `lib/observo/`, and the non-obvious architectural details that aren't in AGENTS.md.

## Architecture (Beyond AGENTS.md)

AGENTS.md describes sources/transforms/sinks at a high level. The performance- and correctness-critical details below are unique to this file.

### Data Flow & Channels

```
Sources -> async channels -> Transforms -> async channels -> Sinks
```

Connected via a **Topology** (`src/topology/`) that supports hot-reload. Channels carry **`EventArray`** batches (an enum: `Logs(Vec<LogEvent>)` / `Metrics(Vec<Metric>)` / `Traces(Vec<TraceEvent>)`), not individual `Event`s. This is the central perf decision — homogeneous `Vec` layout, one tag check per batch, bulk-serializable. **Don't introduce per-event channels in hot paths.**

### Core Types (from `vector-lib` / `vector-core`)

- **`Event`** — enum wrapping `LogEvent`, `Metric`, `TraceEvent`
- **`EventArray`** — the channeled type; one variant per `Event` variant
- **`SourceConfig` / `SinkConfig` / `TransformConfig`** — traits every component config implements (returned `Source` / `VectorSink` / `Transform` are runtime values)
- **`Source`** — type alias for `BoxFuture<'static, Result<(), ()>>`; sources are one-shot futures, not long-lived trait objects
- **`Transform`** — enum: `Function` / `Synchronous` / `Task` (each wraps a different trait object; not unified under one trait)
- **`VectorSink`** — enum: `Sink(Box<dyn Sink<EventArray>>)` / `Stream(Box<dyn StreamSink<EventArray>>)`
- **`Fanout`** — custom 1→N broadcast at `lib/vector-core/src/fanout.rs` with `Add`/`Remove`/`Pause`/`Replace` control messages for hot-reload (not `tokio::sync::broadcast`)
- **`TopologyController`** — top-level lifecycle: start, reload, stop

### Key Files

- `src/topology/builder.rs` — builds component tasks from config (`build_sources`, `build_transforms`, `build_sinks`; the transform `Runner` and `run_inline` / `run_concurrently` modes). Also home of Observo's `CHECKPT_STORE` global.
- `src/topology/running.rs` — `RunningTopology`, `spawn_*` functions, reload state machine
- `src/topology/task.rs` — `Task` wrapper (`BoxFuture` + `ComponentKey` + `typetag`)
- `lib/vector-core/src/fanout.rs` — the trickiest concurrency primitive
- `lib/vector-core/src/event/mod.rs` + `event/array.rs` — event model
- `lib/vector-buffers/src/topology/channel/sender.rs` — pluggable buffer backends

### Component Registration

All components use `#[configurable_component]` + `#[typetag::serde]` + `inventory` for compile-time self-registration:

```rust
#[configurable_component(source("my_source", "Description"))]
#[derive(Clone, Debug)]
pub struct MySourceConfig { /* fields */ }

#[async_trait]
#[typetag::serde(name = "my_source")]
impl SourceConfig for MySourceConfig {
    async fn build(&self, cx: SourceContext) -> Result<Source> { /* ... */ }
    fn outputs(&self, _: LogNamespace) -> Vec<SourceOutput> { /* ... */ }
}
```

Each component lives behind a feature flag: `sources-{name}`, `sinks-{name}`, `transforms-{name}`.

### Transform Variants

- `FunctionTransform` — simple event-by-event; cloned per worker when concurrent
- `SyncTransform` — broader; can write to multiple named outputs
- `TaskTransform<EventArray>` — stateful, stream-to-stream; coordination barrier (cannot be parallelized)

### Sink Variants

- Stream-based (`StreamSink`) or `futures::Sink<EventArray>`, typically composed with Tower middleware in `src/sinks/util/` for batching, retries, rate-limiting.

### Backpressure

Structural — every channel is bounded. Per-sink `WhenFull` policy (`lib/vector-buffers/src/lib.rs`):

- `Block` (default) — backpressure all the way up to the source
- `DropNewest` — shed load (intentionally breaks backpressure)
- `Overflow` — multi-stage buffers (memory → disk)

### Concurrency Model

- One tokio runtime, multi-threaded (worker count = CPU count by default)
- Per source: 2 tasks (the source future + a "pump" task draining `SourceSender` into `Fanout`)
- Per transform / sink: 1 task each
- Synchronous transforms can opt into `run_concurrently` (clones the transform, spawns sub-tasks via `FuturesOrdered`); task transforms cannot
- Use `tokio::select! { biased; ... }` when shutdown must trump other branches
- Bounded channels for data (`BufferSender`, `LimitedSender`); unbounded `mpsc` only for control plane (e.g., fanout `ControlMessage`, `abort_tx`)

## Observo-Specific Development

### Private Submodule Architecture

Observo proprietary code lives in `lib/observo/private/` — a git submodule (URL in `.gitmodules`). Public wrapper crates under `lib/observo/{name}/` re-export from the private tree; build manifests (`Cargo.toml`) stay in the public tree.

After cloning, initialize the submodule: `git submodule update --init`

For IDE / rust-analyzer setup, see the private submodule's own tooling.

Observo crates do not register components with `inventory` themselves. They expose engine primitives; the integration glue lives in `src/sources/`, `src/sinks/`, `src/transforms/` gated behind feature flags (e.g., `#[cfg(feature = "sources-scol")] pub mod scol;`).

### Observo Feature Flags

- `observo` — aggregates all Observo features (lext, scol, lv3, chkpts, stcp, wef, vrl, gcs, azs, ssa)
- `observo-test` — enables test-scenario features for scol, lv3, ssa
- `observo-lext`, `observo-lv3`, `observo-chkpts`, `observo-ssa` — individual feature flags

**Makefile behavior**: By default, Observo crates are excluded from builds via `EXCLUDE_WORKSPACES`. Setting `FEATURES=observo` automatically clears this exclusion.

**Build awareness**: Default `cargo check` / `cargo build` / `make test` do *not* build Observo crates and do *not* mirror what CI tests. Before pushing changes that touch component-config glue, `mod.rs` files under `src/sources/` / `src/sinks/` / `src/transforms/`, or anything used by Observo crates, run:

```bash
FEATURES=observo cargo check              # catch breakages early
FEATURES=observo make test                # Observo unit tests
FEATURES=observo,observo-test make test   # + Observo test scenarios
```

Adding `use crate::sources::scol` (or any Observo-touching path) without a `#[cfg(feature = "...")]` gate will break the default build.

### Observo Crates

| Crate   | Purpose |
|---------|---------|
| azs     | Azure Storage sink |
| chkpts  | Checkpointing / state |
| gcs     | GCS source/sink |
| lext    | Lua extensions |
| lv3     | Lua v3 transform |
| obvrl   | Custom VRL functions |
| sauth   | Auth framework |
| scol    | Streaming collection/transform |
| ssa     | Streaming aggregation |
| stcp    | TCP source |
| wef     | WEF format handler |

### VRL Fork

This repo depends on `Observo-Inc/vrl.git` (custom fork), not upstream VRL. The rev is pinned in root `Cargo.toml`. For local VRL iteration, see vdev README for git server setup (`git://172.17.0.1/vrl`). Observo VRL extensions (MessagePack, XML, etc.) live in `lib/observo/obvrl` and are wired in via the `observo-vrl` feature on `vector-vrl-functions`.

### Process-wide CheckpointStore

Observo introduces one deliberate global singleton in `src/topology/builder.rs` that exposes a checkpoint store to sources via `SourceContext`. It survives topology reloads (in-place `reload()` rather than rebuild). This is a deliberate exception to Vector's "no shared state" stance — sources need persistent checkpoints across reloads. **Don't add hot-path locking; checkpoint access should be per-batch, not per-event.**

## Code Style

- **Logging**: Use `tracing` with key-value style: `warn!(message = "Failed.", %error);` — not `warn!("Failed: {}", err);`
- **Error variable naming**: Always spell out `error`, never `e` or `err`
- **Display over Debug**: Prefer `%error` over `?error` in tracing macros
- **Error handling**: Use `snafu` crate for structured errors. Never panic in regular code paths.
- **Rust version**: Toolchain 1.83, MSRV 1.81
- **Metrics on hot paths**: For any metric type (counter, gauge, histogram) on hot paths (per-event transforms, stream processing), pre-fetch the handle once at component construction — add a `metrics::Counter` / `metrics::Gauge` / `metrics::Histogram` field to the struct, initialize it with `counter!("name")` / `gauge!("name")` / `histogram!("name")` in `new()`, and call the operation (`.increment(1)`, `.set(v)`, `.record(v)`) directly on the stored handle. The macros do a registry lookup (~30–70 ns) on every call; a stored handle is just an atomic operation (~3–7 ns). Use the macro-per-call / `emit!` pattern only for cold paths (error branches, flush callbacks, low-frequency events). Reference: `src/transforms/hist_summ.rs` (stored handle) vs `src/internal_events/aggregate.rs` (per-call macro). Metric names need no component-type prefix because `TracingContextLayer` + `VectorLabelFilter` inject `component_type` automatically from the tracing span — verify that `build()` runs within the component span (it does for all topology-managed components via `builder.rs:515`).

## Testing Notes (Observo-specific)

- Default `cargo test` and `make test` skip Observo crates (excluded via `EXCLUDE_WORKSPACES`). Run `FEATURES=observo make test` to include them.
- `cargo-nextest` retries 3× before reporting failure (config in `.config/nextest.toml`, 30s slow-test threshold, no fail-fast) — flaky tests slip through. Watch the test summary for "flaky retries."
- `#[tokio::test]` defaults to single-threaded; use `#[tokio::test(flavor = "multi_thread")]` when concurrency is required for the test logic.
- Config generation test: `crate::test_util::test_generate_config::<MyConfig>()`
- Test utilities in `src/test_util/`: `start_topology()`, `random_events_with_stream()`, compliance assertions
- For transform-only tests, fake source/sink helpers exist as `UnitTestStreamSourceConfig` / `UnitTestStreamSinkConfig` (`src/config/unit_test/`)

## CI (Observo Fork)

- `.github/workflows/observo.test.yml` — triggers test workflow in external `dataplane-build` repo on PRs and master pushes
- `.github/workflows/observo.release.yml` — triggers publish workflow on `test.*` or `release.*` tags
- Actual build/test execution happens in the separate `Observo-Inc/dataplane-build` repo (not in this repo's GitHub Actions)

## Syncing AGENTS.md from Upstream

`AGENTS.md` at the repo root is a verbatim copy of `vectordotdev/vector`'s file. To refresh it:

```bash
# One-time: register upstream (already done locally; check `git remote -v`)
git remote add upstream https://github.com/vectordotdev/vector.git

# Resync
git fetch upstream master
git checkout upstream/master -- AGENTS.md
git diff --staged AGENTS.md   # review before committing
```

If upstream's AGENTS.md introduces commands or conventions that conflict with our fork (e.g., new linting requirements, removed `make` targets), update this file's overlay accordingly rather than diverging AGENTS.md.
