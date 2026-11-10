use std::{collections::BTreeMap, time::Duration};

use criterion::{
    criterion_group, measurement::WallTime, BatchSize, BenchmarkGroup, BenchmarkId, Criterion,
    SamplingMode, Throughput,
};
use rand::{rngs::SmallRng, SeedableRng};
use rand_distr::{Distribution, Normal};
use vector::config::TransformContext;
use vector::transforms::{
    route::{Route, RouteConfig},
    TransformOutputsBuf,
};
use vector_lib::{
    config::{DataType, TransformOutput},
    event::{Event, LogEvent, Value},
    transform::SyncTransform,
};

const BATCH: usize = 1024;

// Results on an Apple Silicon (aarch64) laptop, 2026-11, per event:
//
//              VRL        equality   predicate
//   5-way      2.92 µs    0.22 µs    2.33 µs
//   100-way   56.4  µs    0.30 µs   42.0  µs
//
// Equality routes go through `EqIndex`, so their cost barely moves with branch count. Every
// other route is checked in turn, costing ~440 ns per branch for predicate (~570 ns for VRL),
// against 50-100 ns for the same predicate in `condition.rs`. The likely cause, not yet
// isolated: `Route` calls `cond.check(event.clone())` per branch, the clone shares the
// `LogEvent`'s `Arc`, and building a `VrlTarget` from a shared event deep-copies it. A check
// that evaluates read-only conditions (predicate, equality) against one `VrlTarget`, cloning
// only for the branches that match, should bring predicate routes close to their standalone
// cost. VRL conditions still need an owned target.
const UNMATCHED: &str = "_unmatched";

/// Branch `i` routes on a (vendor, product, log_type) triple, so every branch is a three-clause
/// conjunct and branches share field values with their neighbours, as real source-type routing
/// does.
fn branch_key(i: usize) -> [String; 3] {
    [
        format!("vendor_{}", i % 5),
        format!("product_{}", (i / 5) % 5),
        format!("type_{}", i / 25),
    ]
}

const FIELDS: [&str; 3] = ["vendor", "product", "log_type"];

#[derive(Clone, Copy, Debug)]
enum Form {
    Vrl,
    Equality,
    Predicate,
}

impl Form {
    fn condition(self, key: &[String; 3]) -> serde_json::Value {
        match self {
            // Mirrors what the config generator emits for an AND of three equals rules.
            Form::Vrl => serde_json::json!({
                "type": "vrl",
                "source": format!(
                    r#"((.{} == "{}") && (.{} == "{}") && (.{} == "{}"))"#,
                    FIELDS[0], key[0], FIELDS[1], key[1], FIELDS[2], key[2]
                ),
            }),
            Form::Equality => serde_json::json!({
                "type": "equality",
                "conjunct": FIELDS.iter().zip(key).map(|(f, v)| {
                    serde_json::json!({"property": format!(".{f}"), "value": v})
                }).collect::<Vec<_>>(),
            }),
            Form::Predicate => serde_json::json!({
                "type": "predicate",
                "when": {"all": FIELDS.iter().zip(key).map(|(f, v)| {
                    serde_json::json!({"eq": {"path": format!(".{f}"), "value": v}})
                }).collect::<Vec<_>>()},
            }),
        }
    }

    fn route(self, branches: usize) -> Route {
        let routes: serde_json::Map<_, _> = (0..branches)
            .map(|i| (branch_name(i), self.condition(&branch_key(i))))
            .collect();
        let config: RouteConfig =
            serde_json::from_value(serde_json::json!({ "route": routes })).expect("route config");
        Route::new(&config, &TransformContext::default()).expect("route builds")
    }
}

fn branch_name(i: usize) -> String {
    format!("branch_{i}")
}

fn outputs(branches: usize) -> TransformOutputsBuf {
    let ports = (0..branches)
        .map(branch_name)
        .chain([UNMATCHED.to_owned()])
        .map(|name| TransformOutput::new(DataType::Log, Default::default()).with_port(name))
        .collect();
    TransformOutputsBuf::new_with_capacity(ports, BATCH)
}

/// Branch indices drawn from a normal distribution centred on the middle branch (σ = N/6, so
/// ±3σ spans the branches), resampled until they land on a branch. Seeded so runs are comparable.
fn gaussian_branches(branches: usize) -> Vec<usize> {
    let mean = (branches as f64 - 1.0) / 2.0;
    let normal = Normal::new(mean, branches as f64 / 6.0).unwrap();
    let mut rng = SmallRng::seed_from_u64(0x5eed);
    std::iter::repeat_with(|| normal.sample(&mut rng).round())
        .filter(|i| *i >= 0.0 && *i < branches as f64)
        .map(|i| i as usize)
        .take(BATCH)
        .collect()
}

fn event_value(branch: usize) -> Value {
    let key = branch_key(branch);
    let mut value = vrl::value!({
        "timestamp": "2026-11-10T06:00:00.000Z",
        "host": "edge-17.example.internal",
        "src_ip": "10.1.2.3",
        "dst_ip": "52.168.4.7",
        "src_port": 51234,
        "dst_port": 443,
        "action": "allow",
        "bytes": 4096,
        "packets": 12,
        "user": "svc-backup",
        "message": "connection accepted from 10.1.2.3:51234 to 52.168.4.7:443",
    });
    FIELDS
        .iter()
        .zip(key)
        .for_each(|(f, v)| _ = value.insert(*f, v));
    value
}

fn events(values: &[Value]) -> Vec<Event> {
    // Each event must own its value: `LogEvent` clones share one `Arc`, and unwrapping a shared
    // one deep-copies it, a cost pipelines (which own their events) never pay.
    values
        .iter()
        .map(|v| Event::Log(LogEvent::from(v.clone())))
        .collect()
}

/// Every event lands on exactly its own branch, and all forms agree on the per-branch counts.
fn routed_counts(route: &mut Route, branches: usize, values: &[Value]) -> BTreeMap<String, usize> {
    let mut out = outputs(branches);
    events(values)
        .into_iter()
        .for_each(|e| route.transform(e, &mut out));
    (0..branches)
        .map(branch_name)
        .chain([UNMATCHED.to_owned()])
        .map(|name| {
            let n = out.drain_named(&name).count();
            (name, n)
        })
        .filter(|(_, n)| *n > 0)
        .collect()
}

fn bench_branching(c: &mut Criterion, branches: usize) {
    let picks = gaussian_branches(branches);
    let values: Vec<Value> = picks.iter().map(|&i| event_value(i)).collect();
    let expected: BTreeMap<String, usize> = picks.iter().fold(BTreeMap::new(), |mut m, &i| {
        *m.entry(branch_name(i)).or_default() += 1;
        m
    });

    let mut group: BenchmarkGroup<WallTime> = c.benchmark_group(format!(
        "vector::transforms::route::Route/branching_{branches}_way"
    ));
    group.sampling_mode(SamplingMode::Auto);
    group.throughput(Throughput::Elements(BATCH as u64));
    for form in [Form::Vrl, Form::Equality, Form::Predicate] {
        let mut route = form.route(branches);
        assert_eq!(
            routed_counts(&mut route, branches, &values),
            expected,
            "{form:?} must route each event to exactly its own branch"
        );
        group.bench_function(
            BenchmarkId::new(format!("{form:?}").to_lowercase(), ""),
            |b| {
                b.iter_batched(
                    || (events(&values), outputs(branches)),
                    |(events, mut out)| {
                        events
                            .into_iter()
                            .for_each(|e| route.transform(e, &mut out));
                        out
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
    group.finish();
}

fn branching(c: &mut Criterion) {
    bench_branching(c, 5);
    bench_branching(c, 100);
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15))
        .noise_threshold(0.02);
    targets = branching
);
