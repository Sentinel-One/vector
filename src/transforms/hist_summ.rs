use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use metrics::{counter, Counter};
use regex::Regex;
use snafu::Snafu;
use vector_lib::config::LogNamespace;
use vector_lib::configurable::configurable_component;
use vector_lib::event::EventMetadata;
use vector_lib::event::metric::{Bucket, MetricData, MetricSeries, MetricValue, Quantile};

use crate::{
    config::{DataType, Input, OutputId, TransformConfig, TransformContext, TransformOutput},
    event::Event,
    schema,
    transforms::{FunctionTransform, OutputBuffer, Transform},
};

/// Matching criteria for histograms.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(untagged, deny_unknown_fields)]
pub enum HistPredicate {
    /// Match histograms whose name appears in `names`.
    Exact {
        /// Exact metric names to match. The same name must not appear across two rules.
        names: Vec<String>,
    },

    /// Match histograms whose name matches the regular expression `pattern`.
    Pattern {
        /// A regular expression evaluated against the metric name.
        pattern: String,
    },
}

/// Behavior when a matched histogram has `count == 0`.
#[configurable_component]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ZeroBehavior {
    /// Drop the histogram; emit no summary.
    Drop,

    /// Emit a summary with `count = 0`, `sum = 0.0`, and every quantile's value set to `0.0`.
    #[serde(alias = "emit_zero")]
    Zero,

    /// Emit a summary with `count = 0`, `sum = 0.0`, and every quantile's value set to `NaN`.
    #[default]
    #[serde(alias = "emit_nan")]
    Nan,
}

/// A single summarization rule.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// Predicate selecting which histograms this rule applies to.
    ///
    /// Exact predicates take precedence over pattern predicates. In case of overlap among pattern
    /// predicates, the first matching rule (in declaration order) wins.
    #[configurable(metadata(docs::human_name = "Predicate"))]
    #[serde(alias = "match")]
    pub target: HistPredicate,

    /// Quantiles to publish on the output summary. Each value must lie in `[0.0, 1.0]`.
    #[serde(default = "default_quantiles")]
    #[configurable(metadata(docs::human_name = "Quantiles to publish"))]
    #[serde(alias = "qtiles")]
    #[serde(alias = "qs")]
    pub quantiles: Vec<f64>,

    /// Behavior for histograms with `count == 0`.
    #[serde(default)]
    #[configurable(metadata(docs::human_name = "Behavior for zero-sample histograms"))]
    #[serde(alias = "empty")]
    pub zero: ZeroBehavior,
}

fn default_quantiles() -> Vec<f64> {
    vec![0.95, 0.99]
}

const fn default_admit_unmatched() -> bool {
    true
}

/// Configuration for the `hist_summ` transform.
#[configurable_component(transform(
    "hist_summ",
    "Convert matching aggregated histogram metrics into aggregated summary metrics."
))]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HistSummConfig {
    /// Summarization rules evaluated in declaration order.
    #[serde(default)]
    pub policies: Vec<Policy>,

    /// Pass histograms that do not match any rule through unchanged. When `false`, unmatched
    /// histograms are dropped.
    #[serde(default = "default_admit_unmatched")]
    #[configurable(metadata(docs::human_name = "Pass unmatched histograms"))]
    #[serde(alias = "admit_unknown")]
    #[serde(alias = "allow_unknown")]
    pub admit_unmatched: bool,
}

impl Default for HistSummConfig {
    fn default() -> Self {
        Self {
            policies: Vec::new(),
            admit_unmatched: default_admit_unmatched(),
        }
    }
}

impl_generate_config_from_default!(HistSummConfig);

#[async_trait::async_trait]
#[typetag::serde(name = "hist_summ")]
impl TransformConfig for HistSummConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        HistSumm::new(self).map(Transform::function)
    }

    fn input(&self) -> Input {
        Input::metric()
    }

    fn outputs(
        &self,
        _: vector_lib::enrichment::TableRegistry,
        _: &[(OutputId, schema::Definition)],
        _: LogNamespace,
    ) -> Vec<TransformOutput> {
        vec![TransformOutput::new(DataType::Metric, HashMap::new())]
    }
}

#[derive(Debug, Snafu)]
pub enum BuildError {
    #[snafu(display("policy {policy_idx}: exact predicate has no names"))]
    EmptyExactList { policy_idx: usize },

    #[snafu(display("policy {policy_idx}: exact predicate contains an empty name"))]
    EmptyExactName { policy_idx: usize },

    #[snafu(display("policy {policy_idx}: duplicate exact name `{name}`"))]
    DuplicateExactName { policy_idx: usize, name: String },

    #[snafu(display("policy {policy_idx}: quantile {value} is outside [0.0, 1.0]"))]
    QuantileOutOfRange { policy_idx: usize, value: f64 },

    #[snafu(display("policy {policy_idx}: empty quantile list"))]
    EmptyQuantileList { policy_idx: usize },

    #[snafu(display("policy {policy_idx}: invalid regex `{pattern}`: {source}"))]
    InvalidPattern {
        policy_idx: usize,
        pattern: String,
        source: regex::Error,
    },
}

#[derive(Debug)]
struct RuleAction {
    quantiles: Vec<f64>,
    zero: ZeroBehavior,
}

#[derive(Clone, Debug)]
pub struct HistSumm {
    exact: BTreeMap<String, Arc<RuleAction>>,
    patterns: Vec<(Regex, Arc<RuleAction>)>,
    admit_unmatched: bool,
    dropped_no_samples: Counter,
    dropped_no_policy: Counter,
}

impl HistSumm {
    pub fn new(config: &HistSummConfig) -> crate::Result<Self> {
        config
            .policies
            .iter()
            .enumerate()
            .try_fold(
                (BTreeMap::new(), Vec::new()),
                |(exact, patterns), (policy_idx, policy)| {
                    Self::absorb_policy(exact, patterns, policy_idx, policy)
                },
            )
            .map(|(exact, patterns)| Self {
                exact,
                patterns,
                admit_unmatched: config.admit_unmatched,
                dropped_no_samples: counter!("dropped_no_samples"),
                dropped_no_policy: counter!("dropped_no_policy"),
            })
            .map_err(Into::into)
    }

    fn absorb_policy(
        exact: BTreeMap<String, Arc<RuleAction>>,
        mut patterns: Vec<(Regex, Arc<RuleAction>)>,
        policy_idx: usize,
        policy: &Policy,
    ) -> Result<(BTreeMap<String, Arc<RuleAction>>, Vec<(Regex, Arc<RuleAction>)>), BuildError>
    {
        Self::validate_quantiles(policy_idx, &policy.quantiles)?;
        let action = Arc::new(RuleAction {
            quantiles: policy.quantiles.clone(),
            zero: policy.zero.clone(),
        });

        match &policy.target {
            HistPredicate::Exact { names } => {
                Self::validate_exact_names(policy_idx, names)?;
                Self::merge_exact(exact, policy_idx, names, &action)
                    .map(|exact| (exact, patterns))
            }
            HistPredicate::Pattern { pattern } => {
                Self::compile_pattern(policy_idx, pattern).map(|regex| {
                    patterns.push((regex, action));
                    (exact, patterns)
                })
            }
        }
    }

    fn validate_quantiles(policy_idx: usize, quantiles: &[f64]) -> Result<(), BuildError> {
        if quantiles.is_empty() {
            return Err(BuildError::EmptyQuantileList { policy_idx });
        }
        for &q in quantiles {
            if !q.is_finite() || !(0.0..=1.0).contains(&q) {
                return Err(BuildError::QuantileOutOfRange { policy_idx, value: q });
            }
        }
        Ok(())
    }

    fn validate_exact_names(policy_idx: usize, names: &[String]) -> Result<(), BuildError> {
        if names.is_empty() {
            return Err(BuildError::EmptyExactList { policy_idx });
        }
        for n in names {
            if n.is_empty() {
                return Err(BuildError::EmptyExactName { policy_idx });
            }
        }
        Ok(())
    }

    fn merge_exact(
        exact: BTreeMap<String, Arc<RuleAction>>,
        policy_idx: usize,
        names: &[String],
        action: &Arc<RuleAction>,
    ) -> Result<BTreeMap<String, Arc<RuleAction>>, BuildError> {
        names.iter().try_fold(exact, |mut acc, name| {
            if acc.contains_key(name) {
                Err(BuildError::DuplicateExactName {
                    policy_idx,
                    name: name.clone(),
                })
            } else {
                acc.insert(name.clone(), Arc::clone(action));
                Ok(acc)
            }
        })
    }

    fn compile_pattern(policy_idx: usize, pattern: &str) -> Result<Regex, BuildError> {
        Regex::new(pattern).map_err(|source| BuildError::InvalidPattern {
            policy_idx,
            pattern: pattern.to_string(),
            source,
        })
    }

    fn lookup(&self, name: &str) -> Option<&RuleAction> {
        if let Some(action) = self.exact.get(name) {
            Some(action.as_ref())
        } else {
            self.patterns
                .iter()
                .find(|(re, _)| re.is_match(name))
                .map(|(_, action)| action.as_ref())
        }
    }
}

impl FunctionTransform for HistSumm {
    fn transform(&mut self, output: &mut OutputBuffer, in_evt: Event) {
        let out_evt = match in_evt {
            Event::Metric(m) if matches!(&m.value(), MetricValue::AggregatedHistogram { .. }) => {
                let (ser, mut data, meta) = m.into_parts();
                match (self.lookup(ser.name.name.as_str()), self.admit_unmatched) {
                    (Some(act), _) => {
                        let MetricValue::AggregatedHistogram {
                            buckets,
                            count,
                            sum,
                        } = std::mem::replace(&mut data.value, MetricValue::Counter { value: 0.0 }) else {
                            unreachable!("checked above");
                        };
                        let val = if count == 0 {
                            match act.zero {
                                ZeroBehavior::Drop => {
                                    self.dropped_no_samples.increment(1);
                                    None
                                }
                                ZeroBehavior::Zero => Some(0.0),
                                ZeroBehavior::Nan => Some(f64::NAN),
                            }.map(|v| zero_summary(&act.quantiles, v))
                        } else {
                            Some(MetricValue::AggregatedSummary {
                                quantiles: estimate_quantiles(&buckets, count, &act.quantiles),
                                count,
                                sum,
                            })
                        };
                        val.map(|v| {
                            data.value = v;
                            mk_metric(ser, data, meta)
                        })
                    },
                    (None, true) => Some(mk_metric(ser, data, meta)),
                    _ => {
                        self.dropped_no_policy.increment(1);
                        None
                    }
                }
            },
            other => Some(other),
        };
        out_evt.map(|e| output.push(e));
    }
}

fn mk_metric(ser: MetricSeries, data: MetricData, meta: EventMetadata) -> Event {
    Event::Metric(vector_lib::event::Metric::from_parts(ser, data, meta))
}

fn zero_summary(qs: &[f64], value: f64) -> MetricValue {
    MetricValue::AggregatedSummary {
        quantiles: qs
            .iter()
            .map(|&quantile| Quantile { quantile, value })
            .collect(),
        count: 0,
        sum: 0.0,
    }
}

/// Estimate per-quantile values using Prometheus-style linear interpolation across
/// non-cumulative buckets. For target ranks falling in the `+Inf` bucket, returns
/// the previous finite `upper_limit`.
fn estimate_quantiles(buckets: &[Bucket], count: u64, qs: &[f64]) -> Vec<Quantile> {
    let mut cum: Vec<u64> = Vec::with_capacity(buckets.len());
    let mut running: u64 = 0;
    for b in buckets {
        running = running.saturating_add(b.count);
        cum.push(running);
    }

    let count_f = count as f64;
    qs
        .iter()
        .map(|&quantile| Quantile {
            quantile,
            value: interpolate(buckets, &cum, count_f, quantile),
        })
        .collect()
}

fn interpolate(buckets: &[Bucket], cum: &[u64], count: f64, q: f64) -> f64 {
    let target = q * count;
    match cum.iter().position(|&c| (c as f64) >= target) {
        // Total cumulative count < target — only possible if `count` exceeds the sum of
        // bucket counts (malformed input). Fall back to the largest finite upper limit.
        None => last_finite_upper(buckets).unwrap_or(0.0),
        Some(i) if buckets[i].upper_limit.is_infinite() => last_finite_upper(&buckets[..i]).unwrap_or(0.0),
        Some(i) => {
            let prev_cum = if i == 0 { 0.0 } else { cum[i - 1] as f64 };
            let prev_upper = if i == 0 {
                0.0
            } else {
                buckets[i - 1].upper_limit
            };
            let bucket_count = (cum[i] as f64) - prev_cum;
            if bucket_count == 0.0 {
                prev_upper
            } else {
                prev_upper
                    + (buckets[i].upper_limit - prev_upper) * (target - prev_cum) / bucket_count
            }
        }
    }
}

fn last_finite_upper(buckets: &[Bucket]) -> Option<f64> {
    buckets
        .iter()
        .rev()
        .map(|b| b.upper_limit)
        .find(|u| u.is_finite())
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use metrics::HistogramFn;
    use vector_lib::metrics::{self as metrics_lib, Controller};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use vector_lib::event::{Metric, MetricKind};
    use vector_lib::metrics::Histogram as CoreHistogram;

    use super::*;
    use crate::test_util::components::assert_transform_compliance;
    use crate::test_util::metrics::{get_counter, get_distribution, get_gauge, get_set};
    use crate::transforms::test::create_topology;

    // ============================================================================
    // Helpers
    // ============================================================================

    fn make_hist(name: &str, samples: &[f64]) -> Metric {
        let h = CoreHistogram::new();
        for s in samples {
            h.record(*s);
        }
        Metric::new(name, MetricKind::Absolute, h.make_metric())
    }

    fn run_transform(config: HistSummConfig, events: Vec<Event>) -> Vec<Event> {
        let mut transform = HistSumm::new(&config).expect("build");
        let mut out = OutputBuffer::with_capacity(events.len().max(1));
        for ev in events {
            transform.transform(&mut out, ev);
        }
        out.into_events().collect()
    }

    fn quantiles_of(metric: &Metric) -> &[Quantile] {
        match metric.value() {
            MetricValue::AggregatedSummary { quantiles, .. } => quantiles,
            other => panic!("expected AggregatedSummary, got {other:?}"),
        }
    }

    fn read_counter(controller: &Controller, name: &str) -> f64 {
        controller
            .capture_metrics()
            .into_iter()
            .find(|m| m.name() == name)
            .and_then(|m| {
                if let MetricValue::Counter { value } = m.value() {
                    Some(*value)
                } else {
                    None
                }
            })
            .unwrap_or(0.0)
    }

    fn build_err(toml_str: &str) -> String {
        let config: HistSummConfig = toml::from_str(toml_str).unwrap();
        HistSumm::new(&config).unwrap_err().to_string()
    }

    // ============================================================================
    // Generated config
    // ============================================================================

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<HistSummConfig>();
    }

    // ============================================================================
    // A. Config validation
    // ============================================================================

    #[test]
    fn rejects_empty_exact_list() {
        let msg = build_err(indoc!(
            r#"
            [[policies]]
            target = { names = [] }
            quantiles = [0.5]
            "#,
        ));
        assert!(msg.contains("exact predicate has no names"), "{msg}");
    }

    #[test]
    fn rejects_empty_exact_name() {
        let msg = build_err(indoc!(
            r#"
            [[policies]]
            target = { names = [""] }
            quantiles = [0.5]
            "#,
        ));
        assert!(msg.contains("empty name"), "{msg}");
    }

    #[test]
    fn rejects_quantile_below_zero() {
        let msg = build_err(indoc!(
            r#"
            [[policies]]
            target = { names = ["x"] }
            quantiles = [-0.1]
            "#,
        ));
        assert!(msg.contains("outside [0.0, 1.0]"), "{msg}");
    }

    #[test]
    fn rejects_quantile_above_one() {
        let msg = build_err(indoc!(
            r#"
            [[policies]]
            target = { names = ["x"] }
            quantiles = [1.5]
            "#,
        ));
        assert!(msg.contains("outside [0.0, 1.0]"), "{msg}");
    }

    #[test]
    fn rejects_quantile_nan() {
        // NaN cannot be expressed in TOML literally; build the config directly.
        let config = HistSummConfig {
            policies: vec![Policy {
                target: HistPredicate::Exact {
                    names: vec!["x".into()],
                },
                quantiles: vec![f64::NAN],
                zero: ZeroBehavior::default(),
            }],
            admit_unmatched: true,
        };
        let msg = HistSumm::new(&config).unwrap_err().to_string();
        assert!(msg.contains("outside [0.0, 1.0]"), "{msg}");
    }

    #[test]
    fn rejects_invalid_regex() {
        let msg = build_err(indoc!(
            r#"
            [[policies]]
            target = { pattern = "[" }
            quantiles = [0.5]
            "#,
        ));
        assert!(msg.contains("invalid regex"), "{msg}");
    }

    #[test]
    fn rejects_explicit_empty_quantiles() {
        let msg = build_err(indoc!(
            r#"
            [[policies]]
            target = { names = ["x"] }
            quantiles = []
            "#,
        ));
        assert!(msg.contains("empty quantile list"), "{msg}");
    }

    #[test]
    fn rejects_duplicate_exact_name_across_rules() {
        let msg = build_err(indoc!(
            r#"
            [[policies]]
            target = { names = ["foo"] }
            quantiles = [0.5]

            [[policies]]
            target = { names = ["bar", "foo"] }
            quantiles = [0.9]
            "#,
        ));
        assert!(msg.contains("duplicate exact name `foo`"), "{msg}");
    }

    #[test]
    fn rejects_duplicate_exact_name_within_rule() {
        let msg = build_err(indoc!(
            r#"
            [[policies]]
            target = { names = ["x", "x"] }
            quantiles = [0.5]
            "#,
        ));
        assert!(msg.contains("duplicate exact name `x`"), "{msg}");
    }

    // ============================================================================
    // B. Alias equality
    // ============================================================================

    fn assert_eq_toml(a: &str, b: &str) {
        let a: HistSummConfig = toml::from_str(a).expect("a parses");
        let b: HistSummConfig = toml::from_str(b).expect("b parses");
        assert_eq!(a, b);
    }

    #[test]
    fn alias_match_for_target() {
        assert_eq_toml(
            indoc!(
                r#"
                [[policies]]
                target = { names = ["x"] }
                quantiles = [0.5]
                "#,
            ),
            indoc!(
                r#"
                [[policies]]
                match = { names = ["x"] }
                quantiles = [0.5]
                "#,
            ),
        );
    }

    #[test]
    fn alias_qs_qtiles_for_quantiles() {
        let canonical = indoc!(
            r#"
            [[policies]]
            target = { names = ["x"] }
            quantiles = [0.5, 0.95]
            "#,
        );
        for alias in ["qs", "qtiles"] {
            let aliased =
                format!("[[policies]]\ntarget = {{ names = [\"x\"] }}\n{alias} = [0.5, 0.95]\n");
            assert_eq_toml(canonical, &aliased);
        }
    }

    #[test]
    fn alias_empty_for_zero() {
        assert_eq_toml(
            indoc!(
                r#"
                [[policies]]
                target = { names = ["x"] }
                zero = "drop"
                "#,
            ),
            indoc!(
                r#"
                [[policies]]
                target = { names = ["x"] }
                empty = "drop"
                "#,
            ),
        );
    }

    #[test]
    fn alias_admit_unmatched() {
        let canonical = "admit_unmatched = false\n";
        for alias in ["admit_unknown", "allow_unknown"] {
            let aliased = format!("{alias} = false\n");
            assert_eq_toml(canonical, &aliased);
        }
    }

    #[test]
    fn alias_emit_zero_for_zero_behavior() {
        assert_eq_toml(
            indoc!(
                r#"
                [[policies]]
                target = { names = ["x"] }
                zero = "zero"
                "#,
            ),
            indoc!(
                r#"
                [[policies]]
                target = { names = ["x"] }
                zero = "emit_zero"
                "#,
            ),
        );
    }

    #[test]
    fn alias_emit_nan_for_zero_behavior() {
        assert_eq_toml(
            indoc!(
                r#"
                [[policies]]
                target = { names = ["x"] }
                zero = "nan"
                "#,
            ),
            indoc!(
                r#"
                [[policies]]
                target = { names = ["x"] }
                zero = "emit_nan"
                "#,
            ),
        );
    }

    // ============================================================================
    // C. Quantile correctness
    // ============================================================================

    fn policy(target: HistPredicate, quantiles: Vec<f64>) -> Policy {
        Policy {
            target,
            quantiles,
            zero: ZeroBehavior::default(),
        }
    }

    fn exact(names: &[&str]) -> HistPredicate {
        HistPredicate::Exact {
            names: names.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn pattern(p: &str) -> HistPredicate {
        HistPredicate::Pattern { pattern: p.into() }
    }

    fn config_with(rules: Vec<Policy>, admit_unmatched: bool) -> HistSummConfig {
        HistSummConfig {
            policies: rules,
            admit_unmatched,
        }
    }

    #[test]
    fn quantile_single_bucket() {
        // 100 samples all in the (0.5, 1.0] bucket (upper_limit = 1.0). p50 target rank
        // is 50, which lands at the bucket midpoint: 0.5 + 0.5 * 0.5 = 0.75.
        let samples = vec![0.6; 100];
        let hist = make_hist("lat", &samples);
        let cfg = config_with(vec![policy(exact(&["lat"]), vec![0.5])], false);
        let out = run_transform(cfg, vec![hist.into()]);
        assert_eq!(out.len(), 1);
        let summary = out[0].as_metric();
        let qs = quantiles_of(summary);
        assert_eq!(qs.len(), 1);
        assert!((qs[0].value - 0.75).abs() < 1e-9, "value = {}", qs[0].value);
    }

    #[test]
    fn quantile_preserves_count_and_sum() {
        let samples: Vec<f64> = (1..=10).map(|v| f64::from(v) * 0.25).collect();
        let expected_sum: f64 = samples.iter().sum();
        let expected_count = samples.len() as u64;

        let hist = make_hist("lat", &samples);
        let cfg = config_with(vec![policy(exact(&["lat"]), vec![0.5, 0.9])], false);
        let out = run_transform(cfg, vec![hist.into()]);
        let summary = out[0].as_metric();
        match summary.value() {
            MetricValue::AggregatedSummary { count, sum, .. } => {
                assert_eq!(*count, expected_count);
                assert!((*sum - expected_sum).abs() < 1e-9);
            }
            _ => panic!("not a summary"),
        }
    }

    #[test]
    fn quantile_p100_falls_back_for_inf_bucket() {
        // 99 small samples plus 1 enormous sample landing in +Inf.
        let mut samples = vec![0.6; 99];
        samples.push(1.0e30);
        let hist = make_hist("lat", &samples);
        let cfg = config_with(vec![policy(exact(&["lat"]), vec![1.0])], false);
        let out = run_transform(cfg, vec![hist.into()]);
        let qs = quantiles_of(out[0].as_metric());
        // p100 lands in the +Inf bucket, so we fall back to the previous finite upper.
        assert!(qs[0].value.is_finite(), "value = {}", qs[0].value);
        assert!(qs[0].value > 0.0);
    }

    #[test]
    fn quantile_multi_bucket() {
        // 1000 samples spread across 7 of the 20 vector-core buckets. The cumulative
        // counts (100, 300, 500, 700, 900, 990, 1000) are chosen so each target rank
        // lands exactly on a bucket boundary: p50=500 -> end of bucket 6, p90=900 -> end
        // of bucket 8, p99=990 -> end of bucket 9. Interpolation therefore collapses to
        // the bucket's upper limit, giving exact f64 results.
        //
        //   bucket index | bucket range    | sample value | count
        //   -------------+-----------------+--------------+------
        //        4       | (0.125, 0.25 ]  |     0.2      |  100
        //        5       | (0.25 , 0.5  ]  |     0.3      |  200
        //        6       | (0.5  , 1.0  ]  |     0.6      |  200
        //        7       | (1.0  , 2.0  ]  |     1.5      |  200
        //        8       | (2.0  , 4.0  ]  |     3.0      |  200
        //        9       | (4.0  , 8.0  ]  |     5.0      |   90
        //       10       | (8.0  , 16.0 ]  |    10.0      |   10
        let samples: Vec<f64> = [
            (0.2_f64, 100usize),
            (0.3, 200),
            (0.6, 200),
            (1.5, 200),
            (3.0, 200),
            (5.0, 90),
            (10.0, 10),
        ]
        .iter()
        .flat_map(|&(v, n)| std::iter::repeat(v).take(n))
        .collect();

        let hist = make_hist("lat", &samples);
        let cfg = config_with(
            vec![policy(exact(&["lat"]), vec![0.5, 0.9, 0.99])],
            false,
        );
        let out = run_transform(cfg, vec![hist.into()]);
        let qs = quantiles_of(out[0].as_metric());

        assert_eq!(qs.len(), 3);
        assert_eq!(qs[0].quantile, 0.5);
        assert_eq!(qs[0].value, 1.0);
        assert_eq!(qs[1].quantile, 0.9);
        assert_eq!(qs[1].value, 4.0);
        assert_eq!(qs[2].quantile, 0.99);
        assert_eq!(qs[2].value, 8.0);
    }

    #[test]
    fn quantile_two_bucket_split() {
        // 80 small samples in (0.5, 1.0] and 20 larger samples in (1.0, 2.0].
        let mut samples = vec![0.6; 80];
        samples.extend(std::iter::repeat(1.5).take(20));
        let hist = make_hist("lat", &samples);
        let cfg = config_with(vec![policy(exact(&["lat"]), vec![0.5, 0.9])], false);
        let out = run_transform(cfg, vec![hist.into()]);
        let qs = quantiles_of(out[0].as_metric());
        assert_eq!(qs.len(), 2);
        assert!(
            qs[0].value < qs[1].value,
            "p50 {} >= p90 {}",
            qs[0].value,
            qs[1].value
        );
        assert!(qs[0].value > 0.5 && qs[0].value <= 1.0);
        assert!(qs[1].value > 1.0 && qs[1].value <= 2.0);
    }

    #[test]
    fn zero_behavior_drop_emits_nothing() {
        metrics_lib::init_test();
        let controller = Controller::get().unwrap();
        let before = read_counter(&controller, "dropped_no_samples");

        let hist = make_hist("lat", &[]);
        let cfg = config_with(
            vec![Policy {
                target: exact(&["lat"]),
                quantiles: vec![0.5],
                zero: ZeroBehavior::Drop,
            }],
            false,
        );
        let out = run_transform(cfg, vec![hist.into()]);
        assert!(out.is_empty(), "expected no events, got {}", out.len());
        assert_eq!(read_counter(&controller, "dropped_no_samples") - before, 1.0);
    }

    #[test]
    fn zero_behavior_zero_emits_zero_values() {
        let hist = make_hist("lat", &[]);
        let cfg = config_with(
            vec![Policy {
                target: exact(&["lat"]),
                quantiles: vec![0.5, 0.99],
                zero: ZeroBehavior::Zero,
            }],
            false,
        );
        let out = run_transform(cfg, vec![hist.into()]);
        let summary = out[0].as_metric();
        match summary.value() {
            MetricValue::AggregatedSummary {
                quantiles,
                count,
                sum,
            } => {
                assert_eq!(*count, 0);
                assert_eq!(*sum, 0.0);
                assert!(quantiles.iter().all(|q| q.value == 0.0));
            }
            _ => panic!("not a summary"),
        }
    }

    #[test]
    fn zero_behavior_nan_emits_nan_values() {
        let hist = make_hist("lat", &[]);
        let cfg = config_with(
            vec![Policy {
                target: exact(&["lat"]),
                quantiles: vec![0.5, 0.99],
                zero: ZeroBehavior::Nan,
            }],
            false,
        );
        let out = run_transform(cfg, vec![hist.into()]);
        let summary = out[0].as_metric();
        match summary.value() {
            MetricValue::AggregatedSummary {
                quantiles,
                count,
                sum,
            } => {
                assert_eq!(*count, 0);
                assert_eq!(*sum, 0.0);
                assert!(quantiles.iter().all(|q| q.value.is_nan()));
            }
            _ => panic!("not a summary"),
        }
    }

    // ============================================================================
    // D. Precedence
    // ============================================================================

    #[test]
    fn exact_wins_over_pattern() {
        // Pattern matches anything; Exact rule is declared second but must still win.
        let cfg = config_with(
            vec![
                policy(pattern(".*"), vec![0.5]),
                policy(exact(&["lat"]), vec![0.9, 0.99]),
            ],
            false,
        );
        let hist = make_hist("lat", &[0.6; 50]);
        let out = run_transform(cfg, vec![hist.into()]);
        let qs = quantiles_of(out[0].as_metric());
        // Exact has two quantiles; pattern has only one. Quantile count proves which rule fired.
        assert_eq!(qs.len(), 2);
        assert_eq!(qs[0].quantile, 0.9);
        assert_eq!(qs[1].quantile, 0.99);
    }

    #[test]
    fn first_pattern_wins() {
        let cfg = config_with(
            vec![
                policy(pattern("^l"), vec![0.5]),
                policy(pattern("^lat"), vec![0.9, 0.99]),
            ],
            false,
        );
        let hist = make_hist("lat", &[0.6; 50]);
        let out = run_transform(cfg, vec![hist.into()]);
        let qs = quantiles_of(out[0].as_metric());
        assert_eq!(qs.len(), 1);
        assert_eq!(qs[0].quantile, 0.5);
    }

    // ============================================================================
    // E. Unmatched + non-histogram passthrough
    // ============================================================================

    #[test]
    fn unmatched_admitted_passes_through_unchanged() {
        let cfg = config_with(vec![policy(exact(&["other"]), vec![0.5])], true);
        let hist = make_hist("lat", &[0.6; 5]);
        let original_value = hist.value().clone();
        let out = run_transform(cfg, vec![hist.into()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_metric().value(), &original_value);
    }

    #[test]
    fn unmatched_not_admitted_is_dropped() {
        metrics_lib::init_test();
        let controller = Controller::get().unwrap();
        let before = read_counter(&controller, "dropped_no_policy");

        let cfg = config_with(vec![policy(exact(&["other"]), vec![0.5])], false);
        let hist = make_hist("lat", &[0.6; 5]);
        let out = run_transform(cfg, vec![hist.into()]);
        assert!(out.is_empty());
        assert_eq!(read_counter(&controller, "dropped_no_policy") - before, 1.0);
    }

    #[test]
    fn non_histogram_metrics_pass_through() {
        // Exhaustive over every `MetricValue` variant except AggregatedHistogram.
        let summary = Metric::new(
            "summary",
            MetricKind::Absolute,
            MetricValue::AggregatedSummary {
                quantiles: vec![Quantile {
                    quantile: 0.5,
                    value: 1.0,
                }],
                count: 1,
                sum: 1.0,
            },
        );
        let sketch = Metric::new(
            "sketch",
            MetricKind::Absolute,
            MetricValue::from(vector_lib::metrics::AgentDDSketch::with_agent_defaults()),
        );

        let cfg = config_with(Vec::new(), false);
        let inputs: Vec<Event> = vec![
            get_counter(1.0, MetricKind::Absolute).into(),
            get_gauge(1.0, MetricKind::Absolute).into(),
            get_set(vec!["a"], MetricKind::Absolute).into(),
            get_distribution(vec![1.0_f64], MetricKind::Absolute).into(),
            summary.into(),
            sketch.into(),
        ];
        let expected: Vec<_> = inputs
            .iter()
            .map(|e| e.as_metric().value().clone())
            .collect();
        let out = run_transform(cfg, inputs);
        assert_eq!(out.len(), expected.len());
        for (event, expected_value) in out.iter().zip(expected.iter()) {
            assert_eq!(event.as_metric().value(), expected_value);
        }
    }

    // ============================================================================
    // F. Topology-level smoke
    // ============================================================================

    #[tokio::test]
    async fn topology_passthrough_for_unmatched() {
        let config = toml::from_str::<HistSummConfig>(indoc!(
            r#"
            admit_unmatched = true

            [[policies]]
            target = { names = ["matched"] }
            quantiles = [0.5]
            "#,
        ))
        .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let hist: Event = make_hist("unmatched", &[0.6; 10]).into();
            tx.send(hist).await.unwrap();

            let received = out.recv().await.unwrap();
            assert!(matches!(
                received.as_metric().value(),
                MetricValue::AggregatedHistogram { .. }
            ));

            drop(tx);
            topology.stop().await;
            assert_eq!(out.recv().await, None);
        })
        .await;
    }

    #[tokio::test]
    async fn topology_converts_matched_histogram() {
        // Two policies fan in: one exact-name, one regex. Each emits a summary with a
        // distinct quantile count so we can tell which policy fired. A third histogram
        // matches neither and (with admit_unmatched = false) must be dropped.
        let config = toml::from_str::<HistSummConfig>(indoc!(
            r#"
            admit_unmatched = false

            [[policies]]
            target = { names = ["http_request_duration_seconds"] }
            quantiles = [0.5]

            [[policies]]
            target = { pattern = "^db_.*_seconds$" }
            quantiles = [0.9, 0.99]
            "#,
        ))
        .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            // Exact-name policy fires.
            let exact_hist: Event =
                make_hist("http_request_duration_seconds", &[0.6; 100]).into();
            tx.send(exact_hist).await.unwrap();
            let received = out.recv().await.unwrap();
            let metric = received.as_metric();
            assert_eq!(metric.name(), "http_request_duration_seconds");
            match metric.value() {
                MetricValue::AggregatedSummary { quantiles, .. } => {
                    assert_eq!(quantiles.len(), 1);
                    assert_eq!(quantiles[0].quantile, 0.5);
                }
                other => panic!("expected AggregatedSummary, got {other:?}"),
            }

            // Regex policy fires.
            let pattern_hist: Event = make_hist("db_query_duration_seconds", &[0.6; 100]).into();
            tx.send(pattern_hist).await.unwrap();
            let received = out.recv().await.unwrap();
            let metric = received.as_metric();
            assert_eq!(metric.name(), "db_query_duration_seconds");
            match metric.value() {
                MetricValue::AggregatedSummary { quantiles, .. } => {
                    assert_eq!(quantiles.len(), 2);
                    assert_eq!(quantiles[0].quantile, 0.9);
                    assert_eq!(quantiles[1].quantile, 0.99);
                }
                other => panic!("expected AggregatedSummary, got {other:?}"),
            }

            // No policy matches, admit_unmatched = false -> dropped, no output.
            let unmatched_hist: Event = make_hist("memcache_hit_rate", &[0.6; 100]).into();
            tx.send(unmatched_hist).await.unwrap();

            drop(tx);
            topology.stop().await;
            assert_eq!(out.recv().await, None);
        })
        .await;
    }

}
