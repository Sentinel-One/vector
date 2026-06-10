#![allow(missing_docs)]
//! Topology contains all topology based types.
//!
//! # Adding a new Observo metadata field
//!
//! 1. Add the constant and struct field to `lib/vector-core/src/config/observo_metadata.rs`
//!    (constant, `ObservoMetadata`, `SpanValues`, `SpanValuesOwned`, `OBSERVO_LABEL_KEYS`,
//!    both conversion methods, and tests).
//! 2. Re-export the new constant from `lib/vector-core/src/config/mod.rs` and
//!    `lib/vector-lib/src/lib.rs` (two one-line additions).
//! 3. Add the new field to the `component_span!` macro below — one line.
//!
//! No other files need to change.
//!
//! Topology is broken up into two main sections. The first
//! section contains all the main topology types include `Topology`
//! and the ability to start, stop and reload a config. The second
//! part contains config related items including config traits for
//! each type of component.

pub(super) use vector_lib::fanout;

/// Creates a tracing `error_span!` for a component with all standard and Observo fields.
///
/// Arguments: span_name, component_kind, component_id expr, component_type expr,
/// observo (&SpanValuesOwned).
macro_rules! component_span {
    ($span_name:literal, $kind:literal, $id:expr, $type:expr, $obs:expr) => {
        error_span!(
            $span_name,
            component_kind = $kind,
            component_id = %$id,
            component_type = %$type,
            observo_component_name = $obs.component_name.as_str(),
            observo_component_version = $obs.component_version.as_str(),
            observo_integration_name = $obs.integration_name.as_str(),
            observo_source_version = $obs.source_version.as_str(),
            observo_last_update_tm = $obs.last_update_tm.as_str(),
        )
    };
}
pub mod schema;

pub mod builder;
mod controller;
mod ready_arrays;
mod running;
mod task;

#[cfg(test)]
mod test;

use std::{
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
};

use futures::{Future, FutureExt};
use tokio::sync::mpsc;
use vector_lib::buffers::topology::channel::{BufferReceiverStream, BufferSender};

pub use self::builder::TopologyPieces;
pub use self::controller::{ReloadOutcome, SharedTopologyController, TopologyController};
pub use self::running::{RunningTopology, ShutdownErrorReceiver};

use self::task::{Task, TaskError, TaskResult};
use crate::{
    config::{ComponentKey, Config, ConfigDiff},
    event::EventArray,
    signal::ShutdownError,
};

type TaskHandle = tokio::task::JoinHandle<TaskResult>;

type BuiltBuffer = (
    BufferSender<EventArray>,
    Arc<Mutex<Option<BufferReceiverStream<EventArray>>>>,
);

pub(super) fn take_healthchecks(
    diff: &ConfigDiff,
    pieces: &mut TopologyPieces,
) -> Vec<(ComponentKey, Task)> {
    (&diff.sinks.to_change | &diff.sinks.to_add)
        .into_iter()
        .filter_map(|id| pieces.healthchecks.remove(&id).map(move |task| (id, task)))
        .collect()
}

async fn handle_errors(
    task: impl Future<Output = TaskResult>,
    abort_tx: mpsc::UnboundedSender<ShutdownError>,
    error: impl FnOnce(String) -> ShutdownError,
) -> TaskResult {
    AssertUnwindSafe(task)
        .catch_unwind()
        .await
        .map_err(|_| TaskError::Panicked)
        .and_then(|res| res)
        .map_err(|e| {
            error!("An error occurred that Vector couldn't handle: {}.", e);
            _ = abort_tx.send(error(e.to_string()));
            e
        })
}

/// If the closure returns false, then the element is removed
fn retain<T>(vec: &mut Vec<T>, mut retain_filter: impl FnMut(&mut T) -> bool) {
    let mut i = 0;
    while let Some(data) = vec.get_mut(i) {
        if retain_filter(data) {
            i += 1;
        } else {
            _ = vec.remove(i);
        }
    }
}
