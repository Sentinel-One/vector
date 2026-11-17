use std::time::Duration;

use criterion::{
    black_box, criterion_group, measurement::WallTime, BatchSize, BenchmarkGroup, BenchmarkId,
    Criterion, SamplingMode, Throughput,
};
use vector::conditions::{Condition, ConditionConfig};
use vector_lib::{
    config::LogNamespace,
    event::{Event, LogEvent},
};

const BATCH: usize = 1024;

// Results on an Apple Silicon (aarch64) laptop, 2026-11: per-event cost above the
// `always_pass` baseline (~379 ns, which is dropping the event).
//
//   scenario / event          VRL      equality   predicate
//   conjunct / match          263 ns     90 ns      102 ns
//   conjunct / miss first     144 ns     39 ns       48 ns
//   conjunct / miss last      267 ns     83 ns       81 ns
//   complex  / match         1517 ns       -        299 ns
//   complex  / miss first     293 ns       -         48 ns
//   complex  / miss last     1492 ns       -        284 ns
//
// Predicate matches equality on conjuncts (~40 ns of it is building and unwrapping the
// `VrlTarget`). VRL pays for runtime setup on every event even when the first clause misses,
// and on the complex rule each function call (`to_float`, `ip_cidr_contains`, `match`)
// allocates intermediate values; the predicate keeps those precompiled.

// Each VRL fragment mirrors what the config generator emits for the same UI rules: one
// parenthesised expression per rule, and, when any rule is fallible, the whole expression wrapped
// so that a runtime error logs and fails the condition.
const EQ_VRL: &str = r#"((.operationName == "NSGFlowEvents") && (.category == "NetworkSecurityGroupFlowEvent") && (.decision == "D"))"#;

const EQ_EQUALITY: &str = r#"
type: equality
conjunct:
  - { property: .operationName, value: NSGFlowEvents }
  - { property: .category, value: NetworkSecurityGroupFlowEvent }
  - { property: .decision, value: D }
"#;

const EQ_PREDICATE: &str = r#"
type: predicate
when:
  all:
    - eq: { path: .operationName, value: NSGFlowEvents }
    - eq: { path: .category, value: NetworkSecurityGroupFlowEvent }
    - eq: { path: .decision, value: D }
"#;

const COMPLEX_VRL: &str = r#"{
           x, err = ((.operationName == "NSGFlowEvents") && !exists(.debug) && ((is_string(.rule) && starts_with(.rule, "DefaultRule_Deny")) || (.proto == "T" || .proto == "U")) && (to_float(.bytes) >= 100 && to_float(.bytes) <= 100000) && (is_string(.src_ip) && ip_cidr_contains("10.0.0.0/8", string!(.src_ip))) && (is_string(.resourceId) && contains(string!(.resourceId), "/networkSecurityGroups/")) && to_float(.packets) > 5 && (is_string(.mac) && match(.mac, r'^[0-9A-F]{12}$')))
           if (err != null) {
             log(err)
             false
           } else {
             x
           }
        }"#;

const COMPLEX_PREDICATE: &str = r#"
type: predicate
when:
  all:
    - eq: { path: .operationName, value: NSGFlowEvents }
    - not: { exists: .debug }
    - any:
        - starts_with: { path: .rule, value: DefaultRule_Deny }
        - in: { path: .proto, values: [T, U] }
    - between: { path: .bytes, min: 100, max: 100000 }
    - cidr: { path: .src_ip, ranges: ["10.0.0.0/8"] }
    - contains: { path: .resourceId, value: /networkSecurityGroups/ }
    - gt: { path: .packets, value: 5 }
    - matches: { path: .mac, regex: '^[0-9A-F]{12}$' }
"#;

fn condition(yaml: &str) -> Condition {
    serde_yaml::from_str::<ConditionConfig>(yaml)
        .unwrap()
        .build(&Default::default())
        .unwrap()
}

fn vrl(source: &str) -> Condition {
    condition(&format!(
        "type: vrl\nsource: {}",
        serde_json::to_string(source).unwrap()
    ))
}

fn flow(overrides: serde_json::Value) -> Event {
    let mut event = serde_json::json!({
        "time": "2026-11-10T06:00:00.000Z",
        "systemId": "5ad2d3b4-1f7e-4c55-9d9a-0f1e2d3c4b5a",
        "macAddress": "000D3AF87856",
        "mac": "000D3AF87856",
        "category": "NetworkSecurityGroupFlowEvent",
        "resourceId": "/SUBSCRIPTIONS/0000/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.NETWORK/networkSecurityGroups/web-nsg",
        "operationName": "NSGFlowEvents",
        "rule": "DefaultRule_DenyAllInBound",
        "src_ip": "10.1.2.3",
        "dst_ip": "52.168.4.7",
        "src_port": 51234,
        "dst_port": 443,
        "proto": "T",
        "direction": "I",
        "decision": "D",
        "state": "B",
        "packets": 12,
        "bytes": 4096,
        "message": "1542110377,10.1.2.3,52.168.4.7,51234,443,T,I,D,B,12,4096,0,0"
    });
    event
        .as_object_mut()
        .unwrap()
        .extend(overrides.as_object().unwrap().clone());
    Event::from_json_value(event, LogNamespace::Legacy).unwrap()
}

fn bench(group: &mut BenchmarkGroup<WallTime>, name: &str, cond: &Condition, event: &Event) {
    group.bench_with_input(BenchmarkId::new(name, ""), event, |b, event| {
        // Each event must own its value: `LogEvent` clones share one `Arc`, and unwrapping a shared
        // one into a VRL target deep-copies it, a cost pipelines (which own their events) never pay.
        b.iter_batched(
            || {
                (0..BATCH)
                    .map(|_| Event::Log(LogEvent::from(event.as_log().value().clone())))
                    .collect::<Vec<_>>()
            },
            |events| {
                for e in events {
                    black_box(cond.check(e));
                }
            },
            BatchSize::SmallInput,
        )
    });
}

// Dropping each event dominates the per-event cost, so condition overhead is read as the
// difference from this.
fn baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("vector::conditions::baseline");
    group.throughput(Throughput::Elements(BATCH as u64));
    bench(
        &mut group,
        "always_pass",
        &Condition::AlwaysPass,
        &flow(serde_json::json!({})),
    );
    group.finish();
}

fn equality_conjunct(c: &mut Criterion) {
    let forms = [
        ("vrl", vrl(EQ_VRL)),
        ("equality", condition(EQ_EQUALITY)),
        ("predicate", condition(EQ_PREDICATE)),
    ];
    let events = [
        ("match", flow(serde_json::json!({}))),
        (
            "miss_first",
            flow(serde_json::json!({"operationName": "Other"})),
        ),
        ("miss_last", flow(serde_json::json!({"decision": "A"}))),
    ];
    for (event_name, event) in &events {
        let mut group = c.benchmark_group(format!(
            "vector::conditions::equality_conjunct/{event_name}"
        ));
        group.sampling_mode(SamplingMode::Auto);
        group.throughput(Throughput::Elements(BATCH as u64));
        for (form, cond) in &forms {
            assert_eq!(
                cond.check(event.clone()).0,
                *event_name == "match",
                "{form} on {event_name}"
            );
            bench(&mut group, form, cond, event);
        }
        group.finish();
    }
}

fn complex(c: &mut Criterion) {
    let forms = [
        ("vrl", vrl(COMPLEX_VRL)),
        ("predicate", condition(COMPLEX_PREDICATE)),
    ];
    let events = [
        ("match", flow(serde_json::json!({}))),
        (
            "miss_first",
            flow(serde_json::json!({"operationName": "Other"})),
        ),
        (
            "miss_last",
            flow(serde_json::json!({"mac": "00-0d-3a-f8-78-56"})),
        ),
    ];
    for (event_name, event) in &events {
        let mut group = c.benchmark_group(format!("vector::conditions::complex/{event_name}"));
        group.sampling_mode(SamplingMode::Auto);
        group.throughput(Throughput::Elements(BATCH as u64));
        for (form, cond) in &forms {
            assert_eq!(
                cond.check(event.clone()).0,
                *event_name == "match",
                "{form} on {event_name}"
            );
            bench(&mut group, form, cond, event);
        }
        group.finish();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(10))
        .noise_threshold(0.02);
    targets = baseline, equality_conjunct, complex
);
