# Testing

This is the Observo fork of Vector (Rust workspace). Pick the workflow by what you changed:

- Upstream code or shared libs (`src/`, `lib/vector-*`): `make test`.
- Anything touching Observo crates (`lib/observo/*`), their glue in `src/sources|sinks|transforms/`, or shared code they use: `FEATURES=observo make test`, then `FEATURES=observo,observo-test make test`. The default run **does not compile or run Observo crates**.
- A transform's TOML behavior: `make test-behavior`. A service-backed component: `make test-integration-{NAME}`.

Upstream policy: [AGENTS.md](AGENTS.md), [docs/DEVELOPING.md](docs/DEVELOPING.md#testing), [CONTRIBUTING.md](CONTRIBUTING.md#testing). Observo overlay: [CLAUDE.md](CLAUDE.md#testing-notes-observo-specific).

## Writing tests

| Scope | Test location and discovery | Authoring guidance | Examples / sources |
| --- | --- | --- | --- |
| `src components` | Inline `#[cfg(test)] mod tests` in the same file as the component; run by nextest. | Use helpers in `src/test_util/` (`components::assert_source_compliance` / `assert_transform_compliance`, `metrics`, `start_topology`). Every component config needs a `crate::test_util::test_generate_config::<Config>()` test. Use `#[tokio::test(flavor = "multi_thread")]` when the test needs real concurrency (default is single-threaded). | [src/transforms/hist_summ.rs](src/transforms/hist_summ.rs) (transform with helpers + compliance), [src/sources/scol/mod.rs](src/sources/scol/mod.rs) (source using `scol::test_scenarios`) |
| `behavior tests` | `tests/behavior/{transforms,formats,config}/*.toml`; each file defines transforms plus `[[tests]]` blocks, run by `vector test`. | Declare the transforms under test, then `[[tests.inputs]]` with `insert_at` and `[[tests.outputs]]` assertions. `make test-behavior` picks up every file in the category directory. | [tests/behavior/transforms/filter.toml](tests/behavior/transforms/filter.toml) |
| `lib crates` | Inline `#[cfg(test)]` modules; run with `--workspace` by `make test`. | Same conventions as components. | [lib/vector-core/src/fanout.rs](lib/vector-core/src/fanout.rs) |
| `lib/observo crates` | Inline tests in the crate and in the glue under `src/`. Sources live in `lib/observo/private/` (git submodule) and are exposed through `lib/observo/{name}/src/{name}` symlinks. | Reusable scenarios sit behind each crate's `test-scenarios` feature (scol, lv3, ssa, stcp); `observo-test` enables them all. Do **not** `cfg`-gate a test on `test-scenarios` in glue code: it must fail loudly instead of silently skipping (see the NOTE in `src/sources/scol/mod.rs`). Gate any `use` of an Observo path with `#[cfg(feature = "…")]`, or the default build breaks. | [src/sources/scol/mod.rs](src/sources/scol/mod.rs), [lib/observo/private/ssa/tests.rs](lib/observo/private/ssa/tests.rs), [lib/observo/scol/Cargo.toml](lib/observo/scol/Cargo.toml) |
| `Service integration` | Cargo features `*-integration-tests` in `Cargo.toml`; test bodies in `src/` modules; Docker environment and `test_filter` per integration in `scripts/integration/{NAME}/{test.yaml,compose.yaml}`. | Tests must run against a Docker Compose service on an env-configured port. Add a `test.yaml` (features, `test_filter`, `env`, `matrix`, trigger `paths`). Driven by `cargo vdev`. | [scripts/integration/kafka/test.yaml](scripts/integration/kafka/test.yaml) |
| `cli tests` | `tests/integration/lib.rs` (Cargo `[[test]] integration`, feature `cli-tests`). | Shell out to the built binary; `shutdown.rs` covers signal/shutdown behavior. | [tests/integration/cli.rs](tests/integration/cli.rs) |
| `Component validation` | `src/components/validation/` tests, feature `component-validation-tests`; fixtures under `tests/validation/`. | Validates components against the component spec. | [src/components/validation/mod.rs](src/components/validation/mod.rs) |

## Commands

Commands run from the repository-relative directory shown. Keep required flags unchanged. Substitute `{UPPER_SNAKE}` values only when using the corresponding selector.

| Scope | Purpose | Run from | Command | Arguments | Source |
| --- | --- | --- | --- | --- | --- |
| `Default unit tests` | Workspace unit tests with default features; Observo crates excluded. Fast path for upstream-area changes. | `.` | `make test` | Append `SCOPE="{NEXTEST_ARGS}"` (e.g. `-E 'test(hist_summ)'`, or `-p {CRATE}`) to narrow; it is placed after `--features`. | [Makefile](Makefile) |
| `Unit tests incl. Observo` | Same, with every Observo crate compiled and tested (clears `EXCLUDE_WORKSPACES`). Run before pushing glue changes. | `.` | `FEATURES=observo make test` | Same `SCOPE` syntax. | [Makefile](Makefile) |
| `Unit tests incl. Observo scenarios` | Also enables `scol`/`lv3`/`ssa`/`stcp` `test-scenarios`. Matches what the private CI is meant to exercise. | `.` | `FEATURES=observo,observo-test make test` | Same `SCOPE` syntax. | [Makefile](Makefile), [Cargo.toml](Cargo.toml) |
| `Single component (fast loop)` | Only one component's unit tests, minimal features. | `.` | `cargo test --lib --no-default-features --features={COMPONENT_TYPE}-{COMPONENT_ID} {COMPONENT_TYPE}::{COMPONENT_ID}` | `{COMPONENT_TYPE}` is `sources`/`transforms`/`sinks`; `{COMPONENT_ID}` the module name. Uses `cargo test`, not nextest (no retries). | [docs/DEVELOPING.md](docs/DEVELOPING.md) |
| `Doc tests` | Rust doctests (nextest does not run them). | `.` | `make test-docs` | Same `SCOPE` and `FEATURES` handling as `make test`. | [Makefile](Makefile) |
| `Behavior (TOML)` | Runs `vector test` over `tests/behavior/**`. | `.` | `make test-behavior` | Single category: `make test-behavior-{CATEGORY}` (`transforms`, `formats`, `config`). | [Makefile](Makefile), [scripts/test-behavior.sh](scripts/test-behavior.sh) |
| `CLI` | CLI integration tests, 4 threads. | `.` | `make test-cli` | — | [Makefile](Makefile) |
| `Component validation` | Component spec validation tests. | `.` | `make test-component-validation` | — | [Makefile](Makefile) |
| `Service integration` | One integration's Docker environment and tests via vdev. | `.` | `make test-integration-{NAME}` | `{NAME}` is a directory in `scripts/integration/`. Add `AUTODESPAWN=true` to tear the environment down afterwards; `make test-integration-{NAME}-cleanup` stops it. | [Makefile](Makefile), [scripts/integration/kafka/compose.yaml](scripts/integration/kafka/compose.yaml) (example) |
| `Lint / format gate` | Required after each Rust change per AGENTS.md; not a test but part of the loop. | `.` | `make check-clippy` | `make clippy-fix` auto-fixes; `make fmt` / `make check-fmt` for formatting. | [AGENTS.md](AGENTS.md) |
| `Everything upstream-style` | Unit + docs + behavior + integration + validation. Needs Docker and is long-running. | `.` | `make test-all` | — | [Makefile](Makefile) |

## References

- [Makefile](Makefile): `test*` targets, `FEATURES` / `EXCLUDE_WORKSPACES` / `SCOPE` handling
- [Cargo.toml](Cargo.toml): workspace members, `observo`, `observo-test`, `*-integration-tests` features, `[[test]]` targets
- [.config/nextest.toml](.config/nextest.toml): nextest profile
- [rust-toolchain.toml](rust-toolchain.toml): pinned toolchain
- [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md), [docs/DEVELOPING.md](docs/DEVELOPING.md), [CONTRIBUTING.md](CONTRIBUTING.md): maintained guidance
- [src/test_util/mod.rs](src/test_util/mod.rs), [src/config/unit_test/mod.rs](src/config/unit_test/mod.rs): shared test helpers
- [scripts/integration/kafka/test.yaml](scripts/integration/kafka/test.yaml), [scripts/test-behavior.sh](scripts/test-behavior.sh): integration and behavior wiring
- [.github/workflows/integration_windows.yml](.github/workflows/integration_windows.yml): the only workflow present in this repo

## Prerequisites

- Rust toolchain pinned in [rust-toolchain.toml](rust-toolchain.toml) and [cargo-nextest](https://nexte.st) (used by `make test`).
- Observo builds need the private submodule: `git submodule update --init` ([CLAUDE.md](CLAUDE.md)). Without it, `FEATURES=observo` builds fail.
- Service integration tests and `make test-all` need Docker (or Podman); see [docs/DEVELOPING.md](docs/DEVELOPING.md).
- Cloud integrations (e.g. `aws`, `gcp`, `azure`) may consult ambient credential providers or reach services; check the integration's `test.yaml` and `compose.yaml` before treating them as offline.

## Caveats

- **Flaky-test masking:** nextest retries each failing test 3 times and does not fail fast ([.config/nextest.toml](.config/nextest.toml)). A pass can hide flakiness; look for "flaky" in the summary. Tests are flagged slow at 30s and terminated after four periods (2 min).
- **Observo coverage:** `make test` and plain `cargo test` skip Observo crates. `cargo test -F observo` without `observo-test` is expected to be incomplete or fail for scenario-dependent tests ([src/sources/scol/mod.rs](src/sources/scol/mod.rs)); use `observo-test`.
- **CI not in this repo:** per [CLAUDE.md](CLAUDE.md), PR/master tests run in the external `Observo-Inc/dataplane-build` repo via `observo.test.yml`, which is not present in `.github/workflows/` here. What CI runs could not be verified from this checkout. [docs/DEVELOPING.md](docs/DEVELOPING.md) also references an `integration-test.yml` that does not exist here.
- **Windows:** Windows uses `FEATURES=default-msvc` and does not apply the Observo exclusion list ([Makefile](Makefile)). The Windows Event Log integration test (`make test-integration-windows-event-log`) runs only on Windows.
- **Toolchain docs disagree:** [CLAUDE.md](CLAUDE.md) says toolchain 1.83; [rust-toolchain.toml](rust-toolchain.toml) pins 1.88. Trust the latter.

## Maintenance

Update this guide when test entry points, argument handling, locations,
authoring conventions, or prerequisites change. Check the linked
configuration and guidance before relying on a conflicting instruction.
