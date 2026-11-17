use vrl::{compiler::TargetValue, value, value::Secrets, value::Value};

use super::{Predicate, PredicateConfig, PredicateError};

fn parse(yaml: &str) -> Result<PredicateConfig, serde_yaml::Error> {
    serde_yaml::from_str(yaml)
}

fn build(yaml: &str) -> Predicate {
    parse(yaml).unwrap().build().unwrap()
}

fn build_err(yaml: &str) -> String {
    parse(yaml).unwrap().build().unwrap_err().to_string()
}

fn target(value: Value) -> TargetValue {
    TargetValue {
        value,
        metadata: value!({}),
        secrets: Secrets::default(),
    }
}

fn eval(yaml: &str, event: Value) -> bool {
    build(yaml).eval(&target(event))
}

#[test]
fn nested_predicate_from_yaml_matches_only_events_satisfying_every_branch() {
    let p = build(
        r#"
all:
  - eq: { path: .operationName, value: NSGFlowEvents }
  - not:
      exists: .debug
  - any:
      - starts_with: { path: .rule, value: Allow }
      - in: { path: .proto, values: [T, U] }
  - between: { path: .bytes, min: 100, max: 100000 }
  - cidr: { path: .src_ip, ranges: ["10.0.0.0/8", "192.168.0.0/16"] }
"#,
    );
    let matching = value!({
        operationName: "NSGFlowEvents",
        rule: "DenyAll",
        proto: "U",
        bytes: 1500,
        src_ip: "192.168.4.2",
    });
    assert!(p.eval(&target(matching.clone())));

    let mut debug = matching.clone();
    debug.insert("debug", true);
    assert!(!p.eval(&target(debug)));

    let mut public_ip = matching;
    public_ip.insert("src_ip", "8.8.8.8");
    assert!(!p.eval(&target(public_ip)));
}

#[test]
fn unknown_operator_is_rejected() {
    let error = parse("equals: { path: .a, value: 1 }")
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown variant `equals`"), "{error}");
}

#[test]
fn unknown_field_in_leaf_is_rejected() {
    let error = parse("eq: { path: .a, value: 1, case_sensitive: false }")
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown field `case_sensitive`"), "{error}");
}

#[test]
fn node_with_two_operators_is_rejected() {
    assert!(parse("{ exists: .a, empty: .b }").is_err());
}

#[test]
fn empty_all_and_any_fail_to_build() {
    assert_eq!(build_err("all: []"), "`all` requires at least one child");
    assert_eq!(build_err("any: []"), "`any` requires at least one child");
}

#[test]
fn empty_in_and_cidr_lists_fail_to_build() {
    assert_eq!(
        build_err("in: { path: .a, values: [] }"),
        "`in` requires at least one value"
    );
    assert_eq!(
        build_err("cidr: { path: .a, ranges: [] }"),
        "`cidr` requires at least one range"
    );
}

#[test]
fn nan_literal_fails_to_build() {
    assert_eq!(
        parse("eq: { path: .a, value: .nan }")
            .unwrap()
            .build()
            .unwrap_err(),
        PredicateError::NaN
    );
    assert_eq!(
        build_err("gt: { path: .a, value: .nan }"),
        "NaN is not a valid literal"
    );
}

#[test]
fn between_with_min_above_max_fails_to_build() {
    let error = build_err("between: { path: .a, min: 10, max: 1 }");
    assert!(
        error.contains("min Integer(10) is greater than max Integer(1)"),
        "{error}"
    );
}

#[test]
fn invalid_regex_fails_to_build() {
    let error = build_err("matches: { path: .a, regex: '(' }");
    assert!(error.starts_with("invalid regex \"(\""), "{error}");
}

#[test]
fn invalid_cidr_range_is_rejected_at_parse() {
    let error = parse("cidr: { path: .a, ranges: [10.0.0.0/33] }")
        .unwrap_err()
        .to_string();
    assert!(error.contains("invalid IP address or network"), "{error}");
}

#[test]
fn eq_compares_integers_and_floats_numerically() {
    assert!(eval("eq: { path: .a, value: 5 }", value!({a: 5.0})));
    assert!(eval("eq: { path: .a, value: 5.0 }", value!({a: 5})));
    assert!(!eval("eq: { path: .a, value: 5 }", value!({a: 5.5})));
}

#[test]
fn eq_does_not_coerce_strings_to_numbers() {
    assert!(!eval("eq: { path: .a, value: 5 }", value!({a: "5"})));
    assert!(!eval("eq: { path: .a, value: '5' }", value!({a: 5})));
    assert!(eval("eq: { path: .a, value: '5' }", value!({a: "5"})));
}

#[test]
fn eq_null_matches_missing_and_null_fields() {
    assert!(eval("eq: { path: .a, value: null }", value!({})));
    assert!(eval("eq: { path: .a, value: null }", value!({a: null})));
    assert!(!eval("eq: { path: .a, value: null }", value!({a: false})));
}

#[test]
fn eq_on_boolean_and_nested_path() {
    assert!(eval(
        "eq: { path: .a.b, value: true }",
        value!({a: {b: true}})
    ));
    assert!(!eval(
        "eq: { path: .a.b, value: true }",
        value!({a: {b: "true"}})
    ));
}

#[test]
fn in_matches_any_listed_literal() {
    let p = "in: { path: .a, values: [x, 2, null] }";
    assert!(eval(p, value!({a: "x"})));
    assert!(eval(p, value!({a: 2.0})));
    assert!(eval(p, value!({})));
    assert!(!eval(p, value!({a: "y"})));
}

#[test]
fn relational_operators_respect_bound_inclusivity() {
    let event = value!({a: 5});
    assert!(!eval("gt: { path: .a, value: 5 }", event.clone()));
    assert!(eval("gte: { path: .a, value: 5 }", event.clone()));
    assert!(!eval("lt: { path: .a, value: 5 }", event.clone()));
    assert!(eval("lte: { path: .a, value: 5 }", event.clone()));
    assert!(eval("between: { path: .a, min: 5, max: 5 }", event));
}

#[test]
fn relational_operators_do_not_truncate_float_fields() {
    assert!(eval("gt: { path: .a, value: 5 }", value!({a: 5.5})));
    assert!(eval("lt: { path: .a, value: 5.5 }", value!({a: 5})));
}

#[test]
fn relational_operators_compare_large_integers_exactly() {
    assert!(eval(
        "gt: { path: .a, value: 9007199254740992 }",
        value!({a: 9_007_199_254_740_993_i64})
    ));
}

#[test]
fn relational_operators_coerce_fields_like_vrl_to_float() {
    assert!(eval("gt: { path: .a, value: 5 }", value!({a: "10"})));
    assert!(eval("gt: { path: .a, value: 5 }", value!({a: "5.5"})));
    assert!(eval("eq: { path: .a, value: true }", value!({a: true})));
    assert!(eval("gte: { path: .a, value: 1 }", value!({a: true})));
    assert!(eval(
        "between: { path: .a, min: 1700000000, max: 1800000000 }",
        value!({a: (chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap().with_timezone(&chrono::Utc))})
    ));
}

#[test]
fn relational_operators_treat_missing_and_null_fields_as_zero_like_vrl() {
    assert!(eval("lt: { path: .a, value: 1 }", value!({})));
    assert!(eval("lt: { path: .a, value: 1 }", value!({a: null})));
}

#[test]
fn relational_operators_are_false_for_values_that_cannot_become_numbers() {
    assert!(!eval("gt: { path: .a, value: 0 }", value!({a: "abc"})));
    assert!(!eval("lt: { path: .a, value: 0 }", value!({a: "abc"})));
    assert!(!eval("gt: { path: .a, value: 0 }", value!({a: [1]})));
    assert!(!eval("gt: { path: .a, value: 0 }", value!({a: {b: 1}})));
}

#[test]
fn string_operators_are_case_sensitive_and_false_for_non_strings() {
    let event = value!({a: "Hello World", n: 12345});
    assert!(eval("contains: { path: .a, value: 'o W' }", event.clone()));
    assert!(!eval("contains: { path: .a, value: 'o w' }", event.clone()));
    assert!(eval("contains: { path: .a, value: '' }", event.clone()));
    assert!(eval(
        "starts_with: { path: .a, value: Hell }",
        event.clone()
    ));
    assert!(eval("ends_with: { path: .a, value: World }", event.clone()));
    assert!(!eval("contains: { path: .n, value: '23' }", event.clone()));
    assert!(!eval("starts_with: { path: .missing, value: '' }", event));
}

#[test]
fn matches_searches_anywhere_unless_anchored() {
    let event = value!({a: "user=alice id=42"});
    assert!(eval(
        r"matches: { path: .a, regex: 'id=\d+' }",
        event.clone()
    ));
    assert!(!eval(
        r"matches: { path: .a, regex: '^id=\d+' }",
        event.clone()
    ));
    assert!(!eval(r"matches: { path: .n, regex: '.*' }", event));
}

#[test]
fn cidr_matches_ipv4_ipv6_and_bare_address_ranges() {
    let p = r#"cidr: { path: .ip, ranges: ["10.0.0.0/8", "2001:db8::/32", "172.16.0.1"] }"#;
    assert!(eval(p, value!({ip: "10.200.1.1"})));
    assert!(eval(p, value!({ip: "2001:db8::1"})));
    assert!(eval(p, value!({ip: "172.16.0.1"})));
    assert!(!eval(p, value!({ip: "172.16.0.2"})));
    assert!(!eval(p, value!({ip: "not-an-ip"})));
    assert!(!eval(p, value!({ip: 167772161})));
}

#[test]
fn exists_is_true_for_null_fields_and_false_for_missing_ones() {
    assert!(eval("exists: .a", value!({a: null})));
    assert!(!eval("exists: .a", value!({b: 1})));
}

#[test]
fn empty_applies_only_to_strings_arrays_and_objects() {
    assert!(eval("empty: .a", value!({a: ""})));
    assert!(eval("empty: .a", value!({a: []})));
    assert!(eval("empty: .a", value!({a: {}})));
    assert!(!eval("empty: .a", value!({a: "x"})));
    assert!(!eval("empty: .a", value!({a: 0})));
    assert!(!eval("empty: .a", value!({a: null})));
    assert!(!eval("empty: .a", value!({})));
}

#[test]
fn json_requires_a_string_holding_valid_json() {
    assert!(eval("json: .a", value!({a: r#"{"k": [1, 2]}"#})));
    assert!(eval("json: .a", value!({a: "42"})));
    assert!(!eval("json: .a", value!({a: "{k: 1}"})));
    assert!(!eval("json: .a", value!({a: {k: 1}})));
}

#[test]
fn is_checks_value_types() {
    let event = value!({s: "x", i: 1, f: 1.5, b: false, a: [], o: {}, n: null});
    let is = |path: &str, kind: &str| {
        eval(
            &format!("is: {{ path: {path}, type: {kind} }}"),
            event.clone(),
        )
    };
    assert!(is(".s", "string"));
    assert!(is(".i", "integer") && is(".i", "number") && !is(".i", "float"));
    assert!(is(".f", "float") && is(".f", "number") && !is(".f", "integer"));
    assert!(is(".b", "boolean"));
    assert!(is(".a", "array") && !is(".a", "object"));
    assert!(is(".o", "object"));
    assert!(is(".n", "null") && is(".missing", "null"));
    assert!(!is(".missing", "string"));
    assert!(!is(".s", "timestamp"));
}

#[test]
fn not_inverts_its_child() {
    assert!(eval("not: { eq: { path: .a, value: 1 } }", value!({a: 2})));
    assert!(!eval("not: { eq: { path: .a, value: 1 } }", value!({a: 1})));
}

#[test]
fn metadata_paths_read_target_metadata() {
    let p = build("eq: { path: '%source', value: kafka }");
    let mut t = target(value!({source: "file"}));
    assert!(!p.eval(&t));
    t.metadata = value!({source: "kafka"});
    assert!(p.eval(&t));
}

#[test]
fn target_queries_lists_each_read_path_once() {
    let p = build(
        r#"
any:
  - exists: .b
  - all:
      - eq: { path: .a, value: 1 }
      - not: { gt: { path: .a, value: 0 } }
  - exists: '%m'
"#,
    );
    let paths: Vec<String> = p
        .target_queries()
        .into_iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(paths, vec![".a", ".b", "%m"]);
}

#[test]
fn recursive_config_generates_a_schema() {
    let schema = vector_config::schema::generate_root_schema::<PredicateConfig>().unwrap();
    let json = serde_json::to_string(&schema).unwrap();
    assert!(json.contains("starts_with"), "{json}");
}
