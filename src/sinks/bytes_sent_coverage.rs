//! Checks that every registered sink gets the `component_sent_bytes_total` handle, so that no sink,
//! including one added later, can be missing from that metric.
//!
//! Every sink is built from its own generated example config. A sink that builds must keep the handle
//! it gets from its `SinkContext`, which is what stops the series expiring while the sink is idle. A sink
//! that cannot be built here, or that registers the handle itself when it starts running, has to be
//! listed below with the reason. Each list is checked in both directions, so it cannot go stale and a
//! new sink cannot be skipped silently.
use std::time::Duration;

use vector_lib::configurable::component::SinkDescription;
use vector_lib::metrics::Controller;

use crate::{
    config::{SinkConfig, SinkContext},
    test_util::components::init_test,
};

/// Sinks that cannot be built here because building connects to a backend.
///
/// The topology builder still gives them the series (see
/// `topology::test::sink_has_the_sent_bytes_series_from_startup`), and their services have their own
/// counting tests.
const NEEDS_BACKEND: &[(&str, &str)] = &[
    ("amqp", "connects to the broker while it is built"),
    ("nats", "connects to the server while it is built"),
    ("pulsar", "connects to the broker while it is built"),
    ("redis", "connects to the server while it is built"),
];

/// Sinks that register the handle themselves while they run, not while they are built. They count
/// into the same series, which the topology builder already holds from startup.
const REGISTERS_WHEN_RUNNING: &[(&str, &str)] = &[
    ("blackhole", "registers the handle at the start of run()"),
    ("console", "registers the handle at the start of run()"),
    (
        "prometheus_exporter",
        "registers the handle when its server starts",
    ),
    ("websocket", "registers the handle when a connection opens"),
];

/// Components that are registered as sinks but are test helpers, not real sinks.
const NOT_REAL_SINKS: &[&str] = &[
    "test_arc",
    "test_backpressure",
    "test_basic",
    "test_error",
    "test_oneshot",
    "test_panic",
    "unit_test",
    "unit_test_stream",
];

/// What the generated example config lacks to be a complete, buildable config: the fields to set
/// (as a TOML table) and the fields to remove. These are placeholders, never contacted.
struct Fix {
    name: &'static str,
    set: &'static str,
    remove: &'static [&'static str],
}

const AZURE_CONNECTION_STRING: &str = "DefaultEndpointsProtocol=http;AccountName=a;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:1/a;";

const FIXES: &[Fix] = &[
    Fix {
        name: "axiom",
        set: r#"url = "http://127.0.0.1:1"
dataset = "d"
org_id = "o"
token = "t""#,
        remove: &[],
    },
    Fix {
        name: "azure_monitor_logs",
        set: r#"shared_key = "dGVzdA==""#,
        remove: &[],
    },
    Fix {
        name: "datadog_metrics",
        set: r#"default_api_key = "x""#,
        remove: &[],
    },
    Fix {
        name: "elasticsearch",
        set: r#"endpoints = ["http://127.0.0.1:1"]"#,
        remove: &[],
    },
    Fix {
        name: "influxdb_metrics",
        set: r#"endpoint = "http://127.0.0.1:1"
database = "d""#,
        remove: &[],
    },
    Fix {
        name: "loki",
        set: r#"labels = { a = "b" }"#,
        remove: &[],
    },
    Fix {
        name: "prometheus_remote_write",
        set: r#"endpoint = "http://127.0.0.1:1/write""#,
        remove: &[],
    },
    Fix {
        name: "gcp_chronicle_unstructured",
        set: "skip_authentication = true\nendpoint = \"http://127.0.0.1:1\"",
        remove: &["credentials_path"],
    },
    Fix {
        name: "gcp_cloud_storage",
        set: "skip_authentication = true",
        remove: &["credentials_path"],
    },
    Fix {
        name: "gcp_pubsub",
        set: "skip_authentication = true",
        remove: &[],
    },
    Fix {
        name: "gcp_stackdriver_logs",
        set: r#"skip_authentication = true
project_id = "p"
log_id = "l"
resource = { type = "global" }"#,
        remove: &[],
    },
    Fix {
        name: "gcp_stackdriver_metrics",
        set: r#"skip_authentication = true
project_id = "p"
default_namespace = "n"
resource = { type = "global" }"#,
        remove: &[],
    },
];

/// What happened when a sink was built from its example config.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Built, and asked for the handle, which exists at zero.
    GotTheHandle,
    /// Built, but never asked for the handle.
    IgnoredTheHandle,
    /// Could not be built, with the reason.
    FailedToBuild(String),
}

async fn build_from_example(name: &'static str) -> Outcome {
    let mut table = match SinkDescription::example(name) {
        Ok(toml::Value::Table(table)) => table,
        other => return Outcome::FailedToBuild(format!("no usable example config: {other:?}")),
    };
    for fix in FIXES.iter().filter(|fix| fix.name == name) {
        for key in fix.remove {
            table.remove(*key);
        }
        match toml::from_str::<toml::Table>(fix.set) {
            Ok(set) => table.extend(set),
            Err(error) => return Outcome::FailedToBuild(format!("bad fix: {error}")),
        }
    }
    if name == "azure_blob" {
        table.remove("storage_account");
        table.insert(
            "connection_string".to_string(),
            toml::Value::String(AZURE_CONNECTION_STRING.to_string()),
        );
    }
    table.insert("type".to_string(), toml::Value::String(name.to_string()));
    let config: Box<dyn SinkConfig> = match toml::from_str(&table.to_string()) {
        Ok(config) => config,
        Err(error) => return Outcome::FailedToBuild(format!("example config: {error}")),
    };

    // Each sink starts from an empty registry.
    init_test();

    // Starting with an empty registry, the only handle is the context's. When the sink is built the
    // context is consumed, so any handle left afterwards is one the sink keeps.
    let cx = SinkContext::default();
    let built = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), config.build(cx)).await
    })
    .await;

    match built {
        Err(join_error) => Outcome::FailedToBuild(format!("panicked: {join_error}")),
        Ok(Err(_elapsed)) => Outcome::FailedToBuild("timed out".to_string()),
        Ok(Ok(Err(error))) => Outcome::FailedToBuild(error.to_string()),
        Ok(Ok(Ok(_sink_and_healthcheck))) => {
            let held = Controller::get().map_or(0, |controller| {
                controller.outstanding_counter_handles("component_sent_bytes_total")
            });
            if held >= 1 {
                Outcome::GotTheHandle
            } else {
                Outcome::IgnoredTheHandle
            }
        }
    }
}

#[tokio::test]
async fn every_sink_gets_the_sent_bytes_handle_or_is_listed() {
    let names = SinkDescription::types();
    assert!(!names.is_empty(), "no sinks are registered");

    let mut problems = Vec::new();
    let mut got_the_handle = Vec::new();
    let mut registers_later = Vec::new();
    let mut needs_a_backend = Vec::new();

    for name in names {
        if NOT_REAL_SINKS.contains(&name) {
            continue;
        }
        let outcome = build_from_example(name).await;
        let needs_backend = NEEDS_BACKEND.iter().any(|(listed, _)| *listed == name);
        let registers_when_running = REGISTERS_WHEN_RUNNING
            .iter()
            .any(|(listed, _)| *listed == name);

        match outcome {
            Outcome::GotTheHandle => {
                got_the_handle.push(name);
                if needs_backend || registers_when_running {
                    problems.push(format!(
                        "{name}: gets the handle, so remove it from the lists in this file"
                    ));
                }
            }
            Outcome::IgnoredTheHandle if !registers_when_running => problems.push(format!(
                "{name}: builds but does not keep the handle from `cx.bytes_sent()`. Make it count into the handle, or \
                 list it in REGISTERS_WHEN_RUNNING with the reason"
            )),
            Outcome::IgnoredTheHandle => registers_later.push(name),
            Outcome::FailedToBuild(reason) if !needs_backend => problems.push(format!(
                "{name}: could not be built from its example config ({reason}). Fix the example, or \
                 list it in NEEDS_BACKEND with the reason"
            )),
            Outcome::FailedToBuild(_) => needs_a_backend.push(name),
        }
        if needs_backend && registers_when_running {
            problems.push(format!("{name}: is in both lists"));
        }
    }

    // Read by script/verify-all-sinks.sh.
    println!(
        "{} sinks got the handle from their own build()",
        got_the_handle.len()
    );
    println!("GOT_THE_HANDLE: {}", got_the_handle.join(" "));
    println!("REGISTERS_WHEN_RUNNING: {}", registers_later.join(" "));
    println!("NEEDS_BACKEND: {}", needs_a_backend.join(" "));
    println!("NOT_REAL_SINKS: {}", NOT_REAL_SINKS.join(" "));
    assert!(
        problems.is_empty(),
        "sinks that would be missing from component_sent_bytes_total:\n  {}",
        problems.join("\n  ")
    );
}
