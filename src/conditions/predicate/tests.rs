use indoc::indoc;
use vector_lib::event::LogEvent;
use vrl::value::Value;

use super::PredicateConfig;
use crate::conditions::{AnyCondition, Condition, ConditionConfig, ConditionalConfig, VrlConfig};
use crate::event::{Event, Metric, MetricKind, MetricValue};

fn predicate(yaml: &str) -> Condition {
    let when = serde_yaml::from_str(yaml).expect("predicate yaml");
    PredicateConfig { when }
        .build(&Default::default())
        .expect("predicate builds")
}

fn vrl(source: &str) -> Condition {
    VrlConfig {
        source: source.to_owned(),
        runtime: Default::default(),
    }
    .build(&Default::default())
    .unwrap_or_else(|error| panic!("VRL `{source}` failed to build: {error}"))
}

/// What `ConditionToVrl` in the manager's `condition-gen.go` emits around an expression that has
/// a fallible leaf.
fn vrl_fallible(expr: &str) -> Condition {
    vrl(&format!(
        "{{\n x, err = {expr}\n if (err != null) {{\n log(err)\n false\n }} else {{\n x\n }}\n}}"
    ))
}

fn log(value: Value) -> Event {
    Event::Log(LogEvent::from(value))
}

#[derive(serde::Deserialize)]
struct Wrapper {
    condition: AnyCondition,
}

#[test]
fn predicate_condition_deserializes_from_yaml_toml_and_json() {
    let yaml: Wrapper = serde_yaml::from_str(indoc! {r#"
        condition:
          type: predicate
          when:
            all:
              - eq: { path: .a, value: 1 }
              - not: { exists: .b }
    "#})
    .unwrap();
    let toml: Wrapper = toml::from_str(indoc! {r#"
        [condition]
        type = "predicate"
        when.all = [{ eq = { path = ".a", value = 1 } }, { not = { exists = ".b" } }]
    "#})
    .unwrap();
    let json: Wrapper = serde_json::from_str(
        r#"{"condition": {"type": "predicate", "when": {"all": [
            {"eq": {"path": ".a", "value": 1}}, {"not": {"exists": ".b"}}]}}}"#,
    )
    .unwrap();

    let configs = [yaml, toml, json].map(|w| match w.condition {
        AnyCondition::Map(ConditionConfig::Predicate(c)) => c,
        other => panic!("expected a predicate condition, got {other:?}"),
    });
    assert_eq!(configs[0], configs[1]);
    assert_eq!(configs[0], configs[2]);
}

#[test]
fn predicate_condition_rejects_unknown_fields() {
    let res = serde_yaml::from_str::<Wrapper>(indoc! {r#"
        condition:
          type: predicate
          when: { exists: .a }
          negate: true
    "#});
    assert!(res.is_err());
}

#[test]
fn predicate_condition_build_reports_invalid_regex() {
    let when = serde_yaml::from_str("matches: { path: .a, regex: '[' }").unwrap();
    let error = PredicateConfig { when }
        .build(&Default::default())
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("invalid regex \"[\""), "{error}");
}

#[test]
fn predicate_condition_reads_metric_fields_and_tags() {
    let condition = predicate(indoc! {r#"
        all:
          - eq: { path: .name, value: requests }
          - eq: { path: .tags.host, value: web-1 }
          - eq: { path: .kind, value: incremental }
    "#});
    let metric = |host| {
        Event::Metric(
            Metric::new(
                "requests",
                MetricKind::Incremental,
                MetricValue::Counter { value: 1.0 },
            )
            .with_tags(Some(crate::event::metric::MetricTags::from_iter([(
                "host".to_owned(),
                host,
            )]))),
        )
    };
    assert!(condition.check(metric("web-1".to_owned())).0);
    assert!(!condition.check(metric("web-2".to_owned())).0);
}

#[test]
fn predicate_condition_reads_event_metadata() {
    let condition = predicate("eq: { path: '%tenant', value: acme }");
    let mut event = LogEvent::from(vrl::value!({message: "x"}));
    assert!(!condition.check(Event::Log(event.clone())).0);
    event.metadata_mut().value_mut().insert("tenant", "acme");
    assert!(condition.check(Event::Log(event)).0);
}

#[test]
fn predicate_condition_returns_the_event_unchanged() {
    let condition = predicate("exists: .a");
    let event = log(vrl::value!({a: 1, b: [1, 2]}));
    let (_, returned) = condition.check(event.clone());
    assert_eq!(returned, event);
}

#[test]
fn predicate_condition_context_reports_mismatch() {
    let condition = predicate("exists: .a");
    assert_eq!(
        condition.check_with_context(log(vrl::value!({a: 1}))).0,
        Ok(())
    );
    assert_eq!(
        condition.check_with_context(log(vrl::value!({}))).0,
        Err("predicate did not match".to_owned())
    );
}

fn parity_events() -> Vec<Event> {
    [
        vrl::value!({}),
        vrl::value!({x: null}),
        vrl::value!({x: "ok"}),
        vrl::value!({x: "OK"}),
        vrl::value!({x: ""}),
        vrl::value!({x: "hello world"}),
        vrl::value!({x: "abc123xyz"}),
        vrl::value!({x: "200"}),
        vrl::value!({x: "99.5"}),
        vrl::value!({x: "not-a-number"}),
        vrl::value!({x: 200}),
        vrl::value!({x: 100}),
        vrl::value!({x: 99}),
        vrl::value!({x: 1000}),
        vrl::value!({x: 1001}),
        vrl::value!({x: 99.5}),
        vrl::value!({x: 200.0}),
        vrl::value!({x: 0.5}),
        vrl::value!({x: (-3)}),
        vrl::value!({x: true}),
        vrl::value!({x: false}),
        vrl::value!({x: []}),
        vrl::value!({x: [1]}),
        vrl::value!({x: {}}),
        vrl::value!({x: {k: 1}}),
        vrl::value!({x: "10.1.2.3"}),
        vrl::value!({x: "192.168.0.1"}),
        vrl::value!({x: "2001:db8::1"}),
        vrl::value!({x: r#"{"a": 1}"#}),
        vrl::value!({x: "[1, 2"}),
        vrl::value!({x: "ok", y: 5}),
        vrl::value!({x: "nope", y: 500}),
    ]
    .into_iter()
    .map(log)
    .collect()
}

/// Each case pairs the VRL that the manager's `condition-gen.go` emits for a rule with the
/// predicate a mapper should emit for the same rule; the two must agree on every event.
fn parity_cases() -> Vec<(&'static str, Condition, Condition)> {
    vec![
        (
            "equals string",
            vrl(r#"((.x == "ok"))"#),
            predicate("eq: { path: .x, value: ok }"),
        ),
        (
            "equals integer",
            vrl("((.x == 200))"),
            predicate("eq: { path: .x, value: 200 }"),
        ),
        (
            "equals float",
            vrl("((.x == 0.5))"),
            predicate("eq: { path: .x, value: 0.5 }"),
        ),
        (
            "equals boolean",
            vrl("((.x == true))"),
            predicate("eq: { path: .x, value: true }"),
        ),
        (
            "not equals",
            vrl(r#"(!(.x == "ok"))"#),
            predicate("not: { eq: { path: .x, value: ok } }"),
        ),
        (
            "greater_than",
            vrl_fallible("(to_float(.x) > 100)"),
            predicate("gt: { path: .x, value: 100 }"),
        ),
        (
            "greater_or_equal",
            vrl_fallible("(to_float(.x) >= 100)"),
            predicate("gte: { path: .x, value: 100 }"),
        ),
        (
            "less_than",
            vrl_fallible("(to_float(.x) < 99.5)"),
            predicate("lt: { path: .x, value: 99.5 }"),
        ),
        (
            "less_or_equal",
            vrl_fallible("(to_float(.x) <= 99.5)"),
            predicate("lte: { path: .x, value: 99.5 }"),
        ),
        (
            "between",
            vrl_fallible("((to_float(.x) >= 100 && to_float(.x) <= 1000))"),
            predicate("between: { path: .x, min: 100, max: 1000 }"),
        ),
        (
            "contains",
            vrl(r#"((is_string(.x) && contains(string!(.x), "o w")))"#),
            predicate("contains: { path: .x, value: o w }"),
        ),
        (
            "not contains",
            vrl(r#"(!(is_string(.x) && contains(string!(.x), "o")))"#),
            predicate("not: { contains: { path: .x, value: o } }"),
        ),
        ("exists", vrl("(exists(.x))"), predicate("exists: .x")),
        (
            "not exists",
            vrl("(!exists(.x))"),
            predicate("not: { exists: .x }"),
        ),
        (
            "is_ip_in_cidr_range",
            vrl_fallible(r#"((is_string(.x) && ip_cidr_contains("10.0.0.0/8", string!(.x))))"#),
            predicate("cidr: { path: .x, ranges: [10.0.0.0/8] }"),
        ),
        (
            "is_array",
            vrl("(is_array(.x))"),
            predicate("is: { path: .x, type: array }"),
        ),
        (
            "is_boolean",
            vrl("(is_boolean(.x))"),
            predicate("is: { path: .x, type: boolean }"),
        ),
        (
            "is_empty",
            vrl_fallible("(((is_array(.x) || is_object(.x) || is_string(.x)) && is_empty(.x)))"),
            predicate("empty: .x"),
        ),
        (
            "is_null",
            vrl("(is_null(.x))"),
            predicate("is: { path: .x, type: null }"),
        ),
        (
            "is_number",
            vrl("((is_float(.x) || is_integer(.x)))"),
            predicate("is: { path: .x, type: number }"),
        ),
        (
            "is_object",
            vrl("(is_object(.x))"),
            predicate("is: { path: .x, type: object }"),
        ),
        (
            "is_json",
            vrl("((is_string(.x) && is_json(string!(.x))))"),
            predicate("json: .x"),
        ),
        (
            "is_string",
            vrl("(is_string(.x))"),
            predicate("is: { path: .x, type: string }"),
        ),
        (
            "ends_with",
            vrl_fallible(r#"((is_string(.x) &&  ends_with(.x, "xyz")))"#),
            predicate("ends_with: { path: .x, value: xyz }"),
        ),
        (
            "starts_with",
            vrl_fallible(r#"((is_string(.x) && starts_with(.x, "hello")))"#),
            predicate("starts_with: { path: .x, value: hello }"),
        ),
        (
            "in",
            vrl(r#"(((.x == "ok" || .x == 200 || .x == true)))"#),
            predicate("in: { path: .x, values: [ok, 200, true] }"),
        ),
        (
            "matches_regex",
            vrl_fallible(r"((is_string(.x) && match(.x, r'^[a-z]+\d+')))"),
            predicate(r"matches: { path: .x, regex: '^[a-z]+\d+' }"),
        ),
        (
            "and of or",
            vrl(r#"((.x == "ok") && ((exists(.y)) || (is_string(.x))))"#),
            predicate(indoc! {r#"
                all:
                  - eq: { path: .x, value: ok }
                  - any:
                      - exists: .y
                      - is: { path: .x, type: string }
            "#}),
        ),
        (
            "or of fallible leaves that never error together",
            vrl_fallible(r#"((to_float(.y) > 100) || (.x == "ok"))"#),
            predicate(indoc! {r#"
                any:
                  - gt: { path: .y, value: 100 }
                  - eq: { path: .x, value: ok }
            "#}),
        ),
    ]
}

#[test]
fn predicate_matches_manager_generated_vrl_on_every_event() {
    let events = parity_events();
    let mismatches: Vec<String> = parity_cases()
        .into_iter()
        .flat_map(|(name, vrl, predicate)| {
            events
                .iter()
                .filter_map(|event| {
                    let expected = vrl.check(event.clone()).0;
                    let actual = predicate.check(event.clone()).0;
                    (expected != actual).then(|| {
                        format!(
                            "{name}: vrl={expected} predicate={actual} on {:?}",
                            event.as_log().value()
                        )
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(mismatches, Vec::<String>::new());
}

// A runtime error anywhere in a manager-generated VRL condition makes the whole condition false;
// the predicate keeps the failure local to the leaf. These tests pin the two places that shows.
#[test]
fn unusable_leaf_under_any_does_not_veto_a_matching_sibling_unlike_vrl() {
    let event = log(vrl::value!({x: "ok", y: "not-a-number"}));
    let vrl = vrl_fallible(r#"((to_float(.y) > 100) || (.x == "ok"))"#);
    let predicate = predicate(indoc! {r#"
        any:
          - gt: { path: .y, value: 100 }
          - eq: { path: .x, value: ok }
    "#});
    assert!(!vrl.check(event.clone()).0);
    assert!(predicate.check(event).0);
}

#[test]
fn negated_cidr_on_a_non_ip_string_matches_unlike_vrl() {
    let event = log(vrl::value!({x: "not-an-ip"}));
    let vrl = vrl_fallible(r#"(!(is_string(.x) && ip_cidr_contains("10.0.0.0/8", string!(.x))))"#);
    let predicate = predicate("not: { cidr: { path: .x, ranges: [10.0.0.0/8] } }");
    assert!(!vrl.check(event.clone()).0);
    assert!(predicate.check(event).0);
}
