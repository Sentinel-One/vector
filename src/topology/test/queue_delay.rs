//! End-to-end test that `topology_queue_delay_seconds` is emitted with the consumer's
//! `component_id` for every buffered arrow, going through the TOML config -> builder ->
//! running-topology path (`demo_logs` -> `remap` -> `remap` -> `blackhole`).

use std::{collections::HashMap, time::Duration};

use tokio::time::sleep;
use vector_lib::metrics::Controller;

use crate::{
    config::ConfigBuilder,
    event::MetricValue,
    test_util::{start_topology, trace_init},
};

const QUEUE_DELAY_METRIC: &str = "topology_queue_delay_seconds";

const CONFIG: &str = r#"
[sources.in]
type = "demo_logs"
format = "shuffle"
lines = ["queue-delay-test-line"]
count = 5
interval = 0.0

[transforms.t1]
type = "remap"
inputs = ["in"]
source = "."

[transforms.t2]
type = "remap"
inputs = ["t1"]
source = "."

[sinks.out]
type = "blackhole"
inputs = ["t2"]
"#;

#[tokio::test(flavor = "current_thread")]
async fn histograms_emitted_for_every_buffered_arrow() {
    trace_init();

    let config = ConfigBuilder::from_toml(CONFIG)
        .build()
        .expect("build config");
    let (topology, _shutdown) = start_topology(config, false).await;

    // demo_logs emits 5 events with interval=0 then closes. A short real-time sleep is enough
    // for the events to drain through three buffers on the current-thread runtime.
    sleep(Duration::from_millis(200)).await;

    let mut sample_counts: HashMap<String, u64> = HashMap::new();
    for metric in Controller::get().unwrap().capture_metrics() {
        if metric.name() != QUEUE_DELAY_METRIC {
            continue;
        }
        let Some(tags) = metric.tags() else { continue };
        let Some(cid) = tags.get("component_id") else {
            continue;
        };
        if let MetricValue::AggregatedHistogram { count, .. } = metric.value() {
            *sample_counts.entry(cid.to_string()).or_default() += count;
        }
    }

    for cid in &["t1", "t2", "out"] {
        let count = sample_counts.get(*cid).copied().unwrap_or(0);
        assert!(
            count > 0,
            "expected at least one histogram sample for component_id={cid}, got {count}. \
             Captured counts: {sample_counts:?}"
        );
    }

    topology.stop().await;
}
