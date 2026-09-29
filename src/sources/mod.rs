#![allow(missing_docs)]
use snafu::Snafu;

#[cfg(feature = "sources-amqp")]
pub mod amqp;
#[cfg(feature = "sources-apache_metrics")]
pub mod apache_metrics;
#[cfg(feature = "sources-aws_ecs_metrics")]
pub mod aws_ecs_metrics;
#[cfg(feature = "sources-aws_kinesis_firehose")]
pub mod aws_kinesis_firehose;
#[cfg(feature = "sources-aws_s3")]
pub mod aws_s3;
#[cfg(feature = "sources-aws_sqs")]
pub mod aws_sqs;
#[cfg(feature = "sources-datadog_agent")]
pub mod datadog_agent;
#[cfg(feature = "sources-demo_logs")]
pub mod demo_logs;
#[cfg(feature = "sources-dnstap")]
pub mod dnstap;
#[cfg(feature = "sources-docker_logs")]
pub mod docker_logs;
#[cfg(feature = "sources-eventstoredb_metrics")]
pub mod eventstoredb_metrics;
#[cfg(feature = "sources-exec")]
pub mod exec;
#[cfg(feature = "sources-file")]
pub mod file;
#[cfg(any(
    feature = "sources-stdin",
    all(unix, feature = "sources-file_descriptor")
))]
pub mod file_descriptors;
#[cfg(feature = "sources-fluent")]
pub mod fluent;
#[cfg(feature = "observo")]
pub mod gcp_gcs;
#[cfg(feature = "sources-gcp_pubsub")]
pub mod gcp_pubsub;
#[cfg(feature = "sources-heroku_logs")]
pub mod heroku_logs;
#[cfg(feature = "sources-host_metrics")]
pub mod host_metrics;
#[cfg(feature = "sources-http_client")]
pub mod http_client;
#[cfg(feature = "sources-http_server")]
pub mod http_server;
#[cfg(feature = "sources-internal_logs")]
pub mod internal_logs;
#[cfg(feature = "sources-internal_metrics")]
pub mod internal_metrics;
#[cfg(all(unix, feature = "sources-journald"))]
pub mod journald;
#[cfg(feature = "sources-kafka")]
pub mod kafka;
#[cfg(feature = "sources-kubernetes_logs")]
pub mod kubernetes_logs;
#[cfg(feature = "sources-logstash")]
pub mod logstash;
#[cfg(feature = "sources-mongodb_metrics")]
pub mod mongodb_metrics;
#[cfg(feature = "sources-nats")]
pub mod nats;
#[cfg(feature = "sources-nginx_metrics")]
pub mod nginx_metrics;
#[cfg(feature = "sources-opentelemetry")]
pub mod opentelemetry;
#[cfg(feature = "sources-postgresql_metrics")]
pub mod postgresql_metrics;
#[cfg(any(
    feature = "sources-prometheus-scrape",
    feature = "sources-prometheus-remote-write",
    feature = "sources-prometheus-pushgateway"
))]
pub mod prometheus;
#[cfg(feature = "sources-pulsar")]
pub mod pulsar;
#[cfg(feature = "sources-redis")]
pub mod redis;
#[cfg(feature = "sources-scol")]
pub mod scol;
#[cfg(feature = "sources-socket")]
pub mod socket;
#[cfg(feature = "sources-splunk_hec")]
pub mod splunk_hec;
#[cfg(feature = "sources-static_metrics")]
pub mod static_metrics;
#[cfg(feature = "sources-statsd")]
pub mod statsd;
#[cfg(all(feature = "sources-stcp"))]
pub mod stcp;
#[cfg(feature = "sources-syslog")]
pub mod syslog;
#[cfg(feature = "sources-vector")]
pub mod vector;
#[cfg(all(feature = "sources-wef"))]
pub mod wef;
#[cfg(feature = "sources-websocket")]
pub mod websocket;
#[cfg(feature = "sources-windows_event_log")]
pub mod windows_event_log;

pub mod util;

pub use vector_lib::source::Source;

#[allow(dead_code)] // Easier than listing out all the features that use this
/// Common build errors
#[derive(Debug, Snafu)]
enum BuildError {
    #[snafu(display("URI parse error: {}", source))]
    UriParseError { source: ::http::uri::InvalidUri },
}

#[cfg(test)]
mod framing_limits_guard {
    use std::path::Path;

    /// Drops everything from the first top-level `#[cfg(..test..)]` inline module onward.
    fn production_code(source: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        let end = lines
            .windows(2)
            .position(|pair| {
                pair[0].starts_with("#[cfg(")
                    && pair[0].contains("test")
                    && (pair[1].starts_with("mod ") || pair[1].starts_with("pub mod "))
                    && pair[1].trim_end().ends_with('{')
            })
            .unwrap_or(lines.len());
        lines[..end].join("\n")
    }

    fn is_test_file(path: &Path) -> bool {
        let name = path.file_name().unwrap().to_string_lossy();
        name == "tests.rs" || name.ends_with("integration_tests.rs") || name.starts_with("test")
    }

    fn collect_offenders(dir: &Path, offenders: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_offenders(&path, offenders);
            } else if path.extension().is_some_and(|ext| ext == "rs") && !is_test_file(&path) {
                let code = production_code(&std::fs::read_to_string(&path).unwrap());
                for pattern in [
                    "NewlineDelimitedDecoder::new()",
                    "CharacterDelimitedDecoder::new(",
                ] {
                    for (offset, _) in code.match_indices(pattern) {
                        let line = code[..offset].lines().count() + 1;
                        offenders.push(format!("{}:{line} (hand-built framer)", path.display()));
                    }
                }
                for (offset, _) in code.match_indices("DecodingConfig::new(") {
                    let rest = &code[offset..];
                    let end = [rest.find(".build()"), rest.find(';')]
                        .into_iter()
                        .flatten()
                        .min()
                        .unwrap_or(rest.len());
                    if !rest[..end].contains("with_operational_limits") {
                        let line = code[..offset].lines().count() + 1;
                        offenders.push(format!("{}:{line}", path.display()));
                    }
                }
            }
        }
    }

    /// Without `with_operational_limits`, a source's framer ignores `ops_limits.framing` and
    /// silently falls back to the compiled-in default.
    #[test]
    fn every_source_decoder_honours_ops_limits() {
        let mut offenders = Vec::new();
        collect_offenders(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sources"),
            &mut offenders,
        );
        assert!(
            offenders.is_empty(),
            "`DecodingConfig::new(..)` without `.with_operational_limits(cx.globals.ops_limits)`: {offenders:#?}"
        );
    }
}
