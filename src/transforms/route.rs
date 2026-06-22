use std::sync::Arc;

use indexmap::IndexMap;
use vector_lib::config::{clone_input_definitions, LogNamespace};
use vector_lib::configurable::configurable_component;
use vector_lib::transform::SyncTransform;

use crate::{
    conditions::{equality::EqIndex, AnyCondition, Condition, ConditionConfig, VrlConfig},
    config::{
        DataType, GenerateConfig, Input, OutputId, TransformConfig, TransformContext,
        TransformOutput,
    },
    event::Event,
    schema,
    transforms::Transform,
};

pub(crate) const UNMATCHED_ROUTE: &str = "_unmatched";

#[derive(Clone)]
pub struct Route {
    eq_index: Option<Arc<EqIndex<String>>>,
    conditions: Vec<(String, Condition)>,
    reroute_unmatched: bool,
}

impl Route {
    pub fn new(config: &RouteConfig, context: &TransformContext) -> crate::Result<Self> {
        let (indexable, conditions) = config.route.iter().try_fold(
            (Vec::new(), Vec::new()),
            |(mut idx, mut cond), (name, any_cond)| -> crate::Result<_> {
                match any_cond.build(&context.enrichment_tables)? {
                    Condition::Equality(eq) if eq.is_indexable() => idx.push((name.clone(), eq)),
                    other => cond.push((name.clone(), other)),
                }
                Ok((idx, cond))
            },
        )?;

        let eq_index = (!indexable.is_empty()).then(|| Arc::new(EqIndex::build(indexable)));
        Ok(Self {
            eq_index,
            conditions,
            reroute_unmatched: config.reroute_unmatched,
        })
    }
}

impl SyncTransform for Route {
    fn transform(&mut self, event: Event, output: &mut vector_lib::transform::TransformOutputsBuf) {
        let (event, idx_hits) = match self.eq_index.as_ref() {
            Some(idx) => {
                let (values, event) = idx.project(event);
                let hits = idx
                    .matches(&values)
                    .inspect(|name| output.push(Some(name), event.clone()))
                    .count();
                (event, hits)
            }
            None => (event, 0),
        };

        let slow_hits = self
            .conditions
            .iter()
            .filter_map(|(name, cond)| {
                let (matched, ev) = cond.check(event.clone());
                matched.then(|| output.push(Some(name), ev))
            })
            .count();

        if self.reroute_unmatched && idx_hits + slow_hits == 0 {
            output.push(Some(UNMATCHED_ROUTE), event);
        }
    }
}

/// Configuration for the `route` transform.
#[configurable_component(transform(
    "route",
    "Split a stream of events into multiple sub-streams based on user-supplied conditions."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Reroutes unmatched events to a named output instead of silently discarding them.
    ///
    /// Normally, if an event doesn't match any defined route, it is sent to the `<transform_name>._unmatched`
    /// output for further processing. In some cases, you may want to simply discard unmatched events and not
    /// process them any further.
    ///
    /// In these cases, `reroute_unmatched` can be set to `false` to disable the `<transform_name>._unmatched`
    /// output and instead silently discard any unmatched events.
    #[serde(default = "crate::serde::default_true")]
    #[configurable(metadata(docs::human_name = "Reroute Unmatched Events"))]
    reroute_unmatched: bool,

    /// A map from route identifiers to logical conditions.
    /// Each condition represents a filter which is applied to each event.
    ///
    /// The following identifiers are reserved output names and thus cannot be used as route IDs:
    /// - `_unmatched`
    /// - `_default`
    ///
    /// Each route can then be referenced as an input by other components with the name
    /// `<transform_name>.<route_id>`. If an event doesn’t match any route, and if `reroute_unmatched`
    /// is set to `true` (the default), it is sent to the `<transform_name>._unmatched` output.
    /// Otherwise, the unmatched event is instead silently discarded.
    #[configurable(metadata(docs::additional_props_description = "An individual route."))]
    #[configurable(metadata(docs::examples = "route_examples()"))]
    route: IndexMap<String, AnyCondition>,
}

fn route_examples() -> IndexMap<String, AnyCondition> {
    IndexMap::from([
        (
            "foo-exists".to_owned(),
            AnyCondition::Map(ConditionConfig::Vrl(VrlConfig {
                source: "exists(.foo)".to_owned(),
                ..Default::default()
            })),
        ),
        (
            "foo-does-not-exist".to_owned(),
            AnyCondition::Map(ConditionConfig::Vrl(VrlConfig {
                source: "!exists(.foo)".to_owned(),
                ..Default::default()
            })),
        ),
    ])
}

impl GenerateConfig for RouteConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            reroute_unmatched: true,
            route: route_examples(),
        })
        .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "route")]
impl TransformConfig for RouteConfig {
    async fn build(&self, context: &TransformContext) -> crate::Result<Transform> {
        let route = Route::new(self, context)?;
        Ok(Transform::synchronous(route))
    }

    fn input(&self) -> Input {
        Input::all()
    }

    fn validate(&self, _: &schema::Definition) -> Result<(), Vec<String>> {
        if self.route.contains_key(UNMATCHED_ROUTE) {
            Err(vec![format!(
                "cannot have a named output with reserved name: `{UNMATCHED_ROUTE}`"
            )])
        } else {
            Ok(())
        }
    }

    fn outputs(
        &self,
        _: vector_lib::enrichment::TableRegistry,
        input_definitions: &[(OutputId, schema::Definition)],
        _: LogNamespace,
    ) -> Vec<TransformOutput> {
        let mut result: Vec<TransformOutput> = self
            .route
            .keys()
            .map(|output_name| {
                TransformOutput::new(
                    DataType::all_bits(),
                    clone_input_definitions(input_definitions),
                )
                .with_port(output_name)
            })
            .collect();
        if self.reroute_unmatched {
            result.push(
                TransformOutput::new(
                    DataType::all_bits(),
                    clone_input_definitions(input_definitions),
                )
                .with_port(UNMATCHED_ROUTE),
            );
        }
        result
    }

    fn enable_concurrency(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use indoc::indoc;
    use vector_lib::transform::TransformOutputsBuf;

    use super::*;
    use crate::{
        config::{build_unit_tests, ConfigBuilder},
        event::{Metric, MetricKind, MetricValue, TraceEvent},
        test_util::components::{init_test, COMPONENT_MULTIPLE_OUTPUTS_TESTS},
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<super::RouteConfig>();
    }

    #[test]
    fn can_serialize_remap() {
        // We need to serialize the config to check if a config has
        // changed when reloading.
        let config = toml::from_str::<RouteConfig>(
            r#"
            route.first.type = "vrl"
            route.first.source = '.message == "hello world"'
        "#,
        )
        .unwrap();

        assert_eq!(
            serde_json::to_string(&config).unwrap(),
            r#"{"reroute_unmatched":true,"route":{"first":{"type":"vrl","source":".message == \"hello world\""}}}"#
        );
    }

    #[test]
    fn route_pass_all_route_conditions() {
        let output_names = vec!["first", "second", "third", UNMATCHED_ROUTE];
        let event = Event::from_json_value(
            serde_json::json!({"message": "hello world", "second": "second", "third": "third"}),
            LogNamespace::Legacy,
        )
        .unwrap();
        let config = toml::from_str::<RouteConfig>(
            r#"
            route.first.type = "vrl"
            route.first.source = '.message == "hello world"'

            route.second.type = "vrl"
            route.second.source = '.second == "second"'

            route.third.type = "vrl"
            route.third.source = '.third == "third"'
        "#,
        )
        .unwrap();

        let mut transform = Route::new(&config, &Default::default()).unwrap();
        let mut outputs = TransformOutputsBuf::new_with_capacity(
            output_names
                .iter()
                .map(|output_name| {
                    TransformOutput::new(DataType::all_bits(), HashMap::new())
                        .with_port(output_name.to_owned())
                })
                .collect(),
            1,
        );

        transform.transform(event.clone(), &mut outputs);
        for output_name in output_names {
            let mut events: Vec<_> = outputs.drain_named(output_name).collect();
            if output_name == UNMATCHED_ROUTE {
                assert!(events.is_empty());
            } else {
                assert_eq!(events.len(), 1);
                assert_eq!(events.pop().unwrap(), event);
            }
        }
    }

    #[test]
    fn route_pass_one_route_condition() {
        let output_names = vec!["first", "second", "third", UNMATCHED_ROUTE];
        let event = Event::from_json_value(
            serde_json::json!({"message": "hello world"}),
            LogNamespace::Legacy,
        )
        .unwrap();
        let config = toml::from_str::<RouteConfig>(
            r#"
            route.first.type = "vrl"
            route.first.source = '.message == "hello world"'

            route.second.type = "vrl"
            route.second.source = '.second == "second"'

            route.third.type = "vrl"
            route.third.source = '.third == "third"'
        "#,
        )
        .unwrap();

        let mut transform = Route::new(&config, &Default::default()).unwrap();
        let mut outputs = TransformOutputsBuf::new_with_capacity(
            output_names
                .iter()
                .map(|output_name| {
                    TransformOutput::new(DataType::all_bits(), HashMap::new())
                        .with_port(output_name.to_owned())
                })
                .collect(),
            1,
        );

        transform.transform(event.clone(), &mut outputs);
        for output_name in output_names {
            let mut events: Vec<_> = outputs.drain_named(output_name).collect();
            if output_name == "first" {
                assert_eq!(events.len(), 1);
                assert_eq!(events.pop().unwrap(), event);
            }
            assert_eq!(events.len(), 0);
        }
    }

    #[test]
    fn route_pass_no_route_condition() {
        let output_names = vec!["first", "second", "third", UNMATCHED_ROUTE];
        let event =
            Event::from_json_value(serde_json::json!({"message": "NOPE"}), LogNamespace::Legacy)
                .unwrap();
        let config = toml::from_str::<RouteConfig>(
            r#"
            route.first.type = "vrl"
            route.first.source = '.message == "hello world"'

            route.second.type = "vrl"
            route.second.source = '.second == "second"'

            route.third.type = "vrl"
            route.third.source = '.third == "third"'
        "#,
        )
        .unwrap();

        let mut transform = Route::new(&config, &Default::default()).unwrap();
        let mut outputs = TransformOutputsBuf::new_with_capacity(
            output_names
                .iter()
                .map(|output_name| {
                    TransformOutput::new(DataType::all_bits(), HashMap::new())
                        .with_port(output_name.to_owned())
                })
                .collect(),
            1,
        );

        transform.transform(event.clone(), &mut outputs);
        for output_name in output_names {
            let mut events: Vec<_> = outputs.drain_named(output_name).collect();
            if output_name == UNMATCHED_ROUTE {
                assert_eq!(events.len(), 1);
                assert_eq!(events.pop().unwrap(), event);
            }
            assert_eq!(events.len(), 0);
        }
    }

    #[test]
    fn route_no_unmatched_output() {
        let output_names = vec!["first", "second", "third", UNMATCHED_ROUTE];
        let event =
            Event::from_json_value(serde_json::json!({"message": "NOPE"}), LogNamespace::Legacy)
                .unwrap();
        let config = toml::from_str::<RouteConfig>(
            r#"
            reroute_unmatched = false

            route.first.type = "vrl"
            route.first.source = '.message == "hello world"'

            route.second.type = "vrl"
            route.second.source = '.second == "second"'

            route.third.type = "vrl"
            route.third.source = '.third == "third"'
        "#,
        )
        .unwrap();

        let mut transform = Route::new(&config, &Default::default()).unwrap();
        let mut outputs = TransformOutputsBuf::new_with_capacity(
            output_names
                .iter()
                .map(|output_name| {
                    TransformOutput::new(DataType::all_bits(), HashMap::new())
                        .with_port(output_name.to_owned())
                })
                .collect(),
            1,
        );

        transform.transform(event.clone(), &mut outputs);
        for output_name in output_names {
            let events: Vec<_> = outputs.drain_named(output_name).collect();
            assert_eq!(events.len(), 0);
        }
    }

    // ---------- equality-condition tests ----------

    fn run(config: RouteConfig, event: Event, output_names: &[&str]) -> HashMap<String, Vec<Event>> {
        let mut transform = Route::new(&config, &Default::default()).unwrap();
        let mut outputs = TransformOutputsBuf::new_with_capacity(
            output_names
                .iter()
                .map(|name| {
                    TransformOutput::new(DataType::all_bits(), HashMap::new())
                        .with_port(name.to_string())
                })
                .collect(),
            1,
        );
        transform.transform(event, &mut outputs);
        output_names
            .iter()
            .map(|n| (n.to_string(), outputs.drain_named(n).collect::<Vec<_>>()))
            .collect()
    }

    fn log_event(json: serde_json::Value) -> Event {
        Event::from_json_value(json, LogNamespace::Legacy).unwrap()
    }

    #[test]
    fn route_equality_all_match() {
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [{ property = ".a", value = 1 }]

            route.second.type = "equality"
            route.second.conjunct = [{ property = ".b", value = "yes" }]

            route.third.type = "equality"
            route.third.conjunct = [{ property = ".c", value = true }]
        "#}).unwrap();
        let event = log_event(serde_json::json!({"a": 1, "b": "yes", "c": true}));
        let out = run(config, event.clone(), &["first", "second", "third", UNMATCHED_ROUTE]);
        for name in &["first", "second", "third"] {
            assert_eq!(out[*name], vec![event.clone()], "expected match on {name}");
        }
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_one_match() {
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [{ property = ".a", value = 1 }]

            route.second.type = "equality"
            route.second.conjunct = [{ property = ".b", value = "no-such" }]

            route.third.type = "equality"
            route.third.conjunct = [{ property = ".c", value = false }]
        "#}).unwrap();
        let event = log_event(serde_json::json!({"a": 1, "b": "yes", "c": true}));
        let out = run(config, event.clone(), &["first", "second", "third", UNMATCHED_ROUTE]);
        assert_eq!(out["first"], vec![event]);
        assert!(out["second"].is_empty());
        assert!(out["third"].is_empty());
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_none_match() {
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [{ property = ".a", value = 999 }]
        "#}).unwrap();
        let event = log_event(serde_json::json!({"a": 1}));
        let out = run(config, event.clone(), &["first", UNMATCHED_ROUTE]);
        assert!(out["first"].is_empty());
        assert_eq!(out[UNMATCHED_ROUTE], vec![event]);
    }

    #[test]
    fn route_equality_no_unmatched_output() {
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            reroute_unmatched = false
            route.first.type = "equality"
            route.first.conjunct = [{ property = ".a", value = 999 }]
        "#}).unwrap();
        let event = log_event(serde_json::json!({"a": 1}));
        let out = run(config, event, &["first", UNMATCHED_ROUTE]);
        assert!(out["first"].is_empty());
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_shared_di_form_distinct_values() {
        // Both routes use the same path subset (.a, .b) but expect different
        // values — exercises the shared di-form / distinct eq_idx entries case.
        let config = serde_yaml::from_str::<RouteConfig>(indoc! {r#"
            route:
              first:
                type: equality
                conjunct:
                  - { property: .a, value: 1 }
                  - { property: .b, value: "x" }
              second:
                type: equality
                conjunct:
                  - { property: .a, value: 2 }
                  - { property: .b, value: "y" }
        "#}).unwrap();
        let event = log_event(serde_json::json!({"a": 1, "b": "x"}));
        let out = run(config, event.clone(), &["first", "second", UNMATCHED_ROUTE]);
        assert_eq!(out["first"], vec![event]);
        assert!(out["second"].is_empty());
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_shared_key() {
        // Two routes with identical clauses → both outputs receive on one event.
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [{ property = ".a", value = 1 }]

            route.second.type = "equality"
            route.second.conjunct = [{ property = ".a", value = 1 }]
        "#}).unwrap();
        let event = log_event(serde_json::json!({"a": 1}));
        let out = run(config, event.clone(), &["first", "second", UNMATCHED_ROUTE]);
        assert_eq!(out["first"], vec![event.clone()]);
        assert_eq!(out["second"], vec![event]);
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_mixed_equality_and_vrl() {
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.via_eq.type = "equality"
            route.via_eq.conjunct = [{ property = ".a", value = 1 }]

            route.via_vrl.type = "vrl"
            route.via_vrl.source = ".b == \"yes\""
        "#}).unwrap();
        let event = log_event(serde_json::json!({"a": 1, "b": "yes"}));
        let out = run(config, event.clone(), &["via_eq", "via_vrl", UNMATCHED_ROUTE]);
        assert_eq!(out["via_eq"], vec![event.clone()]);
        assert_eq!(out["via_vrl"], vec![event]);
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_null_for_missing_path() {
        let config = serde_yaml::from_str::<RouteConfig>(indoc! {r#"
            route:
              first:
                type: equality
                conjunct:
                  - { property: .missing, value: null }
        "#}).unwrap();
        let event = log_event(serde_json::json!({"other": 1}));
        let out = run(config, event.clone(), &["first", UNMATCHED_ROUTE]);
        assert_eq!(out["first"], vec![event]);
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_partial_match_with_missing_path() {
        // Two-clause conjunct; `.a` is present and matches but `.b` is
        // missing from the event. Missing-path projects to `DVal::Null`,
        // which must not match the configured `DVal::Bytes("y")` clause.
        // Route must not fire — event lands in `_unmatched`.
        let config = serde_yaml::from_str::<RouteConfig>(indoc! {r#"
            route:
              first:
                type: equality
                conjunct:
                  - { property: .a, value: "x" }
                  - { property: .b, value: "y" }
        "#}).unwrap();
        let event = log_event(serde_json::json!({"a": "x"}));
        let out = run(config, event.clone(), &["first", UNMATCHED_ROUTE]);
        assert!(out["first"].is_empty());
        assert_eq!(out[UNMATCHED_ROUTE], vec![event]);
    }

    #[test]
    fn route_equality_timestamp_matches_bytes() {
        // Configured value is RFC 3339; event carries the same string under
        // .when as Value::Bytes. Must match via the index's cross-product key.
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [{ property = ".when", value = "2024-01-01T00:00:00Z" }]
        "#}).unwrap();
        let event = log_event(serde_json::json!({"when": "2024-01-01T00:00:00Z"}));
        let out = run(config, event.clone(), &["first", UNMATCHED_ROUTE]);
        assert_eq!(out["first"], vec![event]);
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_same_value_distinct_fields() {
        // Both routes share an `.x = "same"` clause and distinguish on a
        // second clause whose expected value is identical but lives on a
        // different path (`.a` vs `.b`). Guards against an index that
        // accidentally keys on value alone — the value `"v"` is not
        // unique to either route, the (path, value) tuple is.
        let config = serde_yaml::from_str::<RouteConfig>(indoc! {r#"
            route:
              alpha:
                type: equality
                conjunct:
                  - { property: .x, value: "same" }
                  - { property: .a, value: "v" }
              beta:
                type: equality
                conjunct:
                  - { property: .x, value: "same" }
                  - { property: .b, value: "v" }
        "#}).unwrap();

        // .a holds "v" → alpha matches, beta does not.
        let event_a = log_event(serde_json::json!({"x": "same", "a": "v", "b": "other"}));
        let out_a = run(config.clone(), event_a.clone(), &["alpha", "beta", UNMATCHED_ROUTE]);
        assert_eq!(out_a["alpha"], vec![event_a]);
        assert!(out_a["beta"].is_empty());
        assert!(out_a[UNMATCHED_ROUTE].is_empty());

        // .b holds "v" → beta matches, alpha does not.
        let event_b = log_event(serde_json::json!({"x": "same", "a": "other", "b": "v"}));
        let out_b = run(config, event_b.clone(), &["alpha", "beta", UNMATCHED_ROUTE]);
        assert!(out_b["alpha"].is_empty());
        assert_eq!(out_b["beta"], vec![event_b]);
        assert!(out_b[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_float() {
        // Two routes split on the same float-bearing path so the fast-path
        // index has to compare floats exactly. The matching event hits one
        // route; the other route and `_unmatched` stay empty.
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [{ property = ".rate", value = 1.5 }]

            route.second.type = "equality"
            route.second.conjunct = [{ property = ".rate", value = 2.5 }]
        "#}).unwrap();
        let event = log_event(serde_json::json!({"rate": 1.5}));
        let out = run(config, event.clone(), &["first", "second", UNMATCHED_ROUTE]);
        assert_eq!(out["first"], vec![event]);
        assert!(out["second"].is_empty());
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_float_nan_uses_slow_path() {
        // A NaN clause is excluded from the index and routed via the slow
        // path. NaN ≠ anything, so the event must end up at _unmatched.
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [{ property = ".x", value = nan }]
        "#}).unwrap();
        let event = log_event(serde_json::json!({"x": 1.0}));
        let out = run(config, event.clone(), &["first", UNMATCHED_ROUTE]);
        assert!(out["first"].is_empty());
        assert_eq!(out[UNMATCHED_ROUTE], vec![event]);
    }

    #[test]
    fn route_equality_contradictory_clauses_never_match() {
        // Single route, same path bound to two different values. The
        // virtual key built from any event value `v` is
        // `[(idx, v), (idx, v)]`, which can't match the stored key
        // `[(idx, "foo"), (idx, "bar")]` for any `v`. Route never fires
        // regardless of what the event carries at `.a`.
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [
                { property = ".a", value = "foo" },
                { property = ".a", value = "bar" },
            ]
        "#}).unwrap();

        for v in ["foo", "bar", "baz"] {
            let event = log_event(serde_json::json!({"a": v}));
            let out = run(config.clone(), event.clone(), &["first", UNMATCHED_ROUTE]);
            assert!(out["first"].is_empty(), "event {v:?} should not match");
            assert_eq!(out[UNMATCHED_ROUTE], vec![event]);
        }
    }

    #[test]
    fn route_equality_partial_match_wrong_value() {
        // Two 2-clause routes whose clauses cross-mix: the event satisfies
        // one clause of each route but neither route fully — both must
        // skip; event lands in `_unmatched`.
        let config = serde_yaml::from_str::<RouteConfig>(indoc! {r#"
            route:
              alpha:
                type: equality
                conjunct:
                  - { property: .a, value: 1 }
                  - { property: .b, value: "x" }
              beta:
                type: equality
                conjunct:
                  - { property: .a, value: 2 }
                  - { property: .b, value: "y" }
        "#}).unwrap();
        let event = log_event(serde_json::json!({"a": 1, "b": "y"}));
        let out = run(config, event.clone(), &["alpha", "beta", UNMATCHED_ROUTE]);
        assert!(out["alpha"].is_empty());
        assert!(out["beta"].is_empty());
        assert_eq!(out[UNMATCHED_ROUTE], vec![event]);
    }

    #[test]
    fn route_equality_disjoint_di_forms() {
        // Two 2-clause routes with non-overlapping path subsets: alpha on
        // [.a,.b] and beta on [.c,.d]. Exercises multiple distinct
        // di_forms in one config; only the route whose paths line up
        // should fire.
        let config = serde_yaml::from_str::<RouteConfig>(indoc! {r#"
            route:
              alpha:
                type: equality
                conjunct:
                  - { property: .a, value: 1 }
                  - { property: .b, value: 2 }
              beta:
                type: equality
                conjunct:
                  - { property: .c, value: 3 }
                  - { property: .d, value: 4 }
        "#}).unwrap();

        let event_a = log_event(serde_json::json!({"a": 1, "b": 2, "c": 99, "d": 99}));
        let out_a = run(config.clone(), event_a.clone(), &["alpha", "beta", UNMATCHED_ROUTE]);
        assert_eq!(out_a["alpha"], vec![event_a]);
        assert!(out_a["beta"].is_empty());
        assert!(out_a[UNMATCHED_ROUTE].is_empty());

        let event_b = log_event(serde_json::json!({"a": 99, "b": 99, "c": 3, "d": 4}));
        let out_b = run(config, event_b.clone(), &["alpha", "beta", UNMATCHED_ROUTE]);
        assert!(out_b["alpha"].is_empty());
        assert_eq!(out_b["beta"], vec![event_b]);
        assert!(out_b[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_metadata_path() {
        // Configured clause uses the metadata prefix `%`; event has the
        // matching value under `%mark`. Verifies the index forwards
        // metadata-prefix paths through `VrlTarget::target_get` correctly.
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [{ property = "%mark", value = "ok" }]
        "#}).unwrap();

        let mut log = crate::event::LogEvent::default();
        log.insert(vector_lib::lookup::metadata_path!("mark"), "ok");
        let event = Event::Log(log);

        let out = run(config, event.clone(), &["first", UNMATCHED_ROUTE]);
        assert_eq!(out["first"], vec![event]);
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_timestamp_matches_value_timestamp() {
        // Configured clause is RFC 3339 string; event carries the parsed
        // instant as a true `Value::Timestamp`. Match goes through the
        // index's Timestamp-form expanded key (not the Bytes fallback).
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [{ property = ".when", value = "2024-01-01T00:00:00Z" }]
        "#}).unwrap();

        let dt = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut log = crate::event::LogEvent::default();
        log.insert("when", dt);
        let event = Event::Log(log);

        let out = run(config, event.clone(), &["first", UNMATCHED_ROUTE]);
        assert_eq!(out["first"], vec![event]);
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[test]
    fn route_equality_invalid_metric_path() {
        // Metrics restrict which paths `target_get` accepts (`.name`,
        // `.kind`, `.namespace`, `.tags`, `.timestamp`, etc.) — anything
        // else returns `Err`, which the index projects to
        // `DVal::Unmatchable`. Any di_form touching that position
        // short-circuits, so a route that pairs a valid clause with an
        // invalid one must not fire on a Metric event.
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [
                { property = ".name", value = "my_metric" },
                { property = ".message", value = "anything" },
            ]
        "#}).unwrap();

        let metric = Event::Metric(Metric::new(
            "my_metric",
            MetricKind::Incremental,
            MetricValue::Counter { value: 1.0 },
        ));
        let out = run(config, metric.clone(), &["first", UNMATCHED_ROUTE]);
        assert!(out["first"].is_empty());
        assert_eq!(out[UNMATCHED_ROUTE], vec![metric]);
    }

    #[test]
    fn route_equality_trace_mixed_data_and_metadata() {
        // Trace event with one clause on a data path (`.kind`) and one on
        // a metadata path (`%tag`). Both must match for the route to fire
        // — exercises the index against `Event::Trace` and a di_form
        // spanning both `PathPrefix::Event` and `PathPrefix::Metadata`.
        let config = toml::from_str::<RouteConfig>(indoc! {r#"
            route.first.type = "equality"
            route.first.conjunct = [
                { property = ".kind", value = "server" },
                { property = "%tag", value = "ok" },
            ]
        "#}).unwrap();

        let mut log = crate::event::LogEvent::default();
        log.insert("kind", "server");
        log.insert(vector_lib::lookup::metadata_path!("tag"), "ok");
        let event = Event::Trace(TraceEvent::from(log));

        let out = run(config, event.clone(), &["first", UNMATCHED_ROUTE]);
        assert_eq!(out["first"], vec![event]);
        assert!(out[UNMATCHED_ROUTE].is_empty());
    }

    #[tokio::test]
    async fn route_metrics_with_output_tag() {
        init_test();

        let config: ConfigBuilder = toml::from_str(indoc! {r#"
            [transforms.foo]
            inputs = []
            type = "route"
            [transforms.foo.route.first]
                type = "is_log"

            [[tests]]
            name = "metric output"

            [tests.input]
                insert_at = "foo"
                value = "none"

            [[tests.outputs]]
                extract_from = "foo.first"
                [[tests.outputs.conditions]]
                type = "vrl"
                source = "true"
        "#})
        .unwrap();

        let mut tests = build_unit_tests(config).await.unwrap();
        assert!(tests.remove(0).run().await.errors.is_empty());
        // Check that metrics were emitted with output tag
        COMPONENT_MULTIPLE_OUTPUTS_TESTS.assert(&["output"]);
    }
}
