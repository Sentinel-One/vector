use std::{collections::BTreeMap, mem};

use bytes::BytesMut;
use indoc::{formatdoc, indoc};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use serde_json::json;
use smallvec::SmallVec;
use tokio_util::codec::Decoder as _;
use tracing_test::traced_test;
use vector_common::limits::OperationalLimits;
use vector_core::{config::LogNamespace, event::Event};
use vrl::value::{KeyString, Value};

use crate::{
    actions::{Decoder, DecodingConfig, Stream},
    decoding::{DeserializerConfig, Error, FramingConfig},
    StreamDecodingError,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Codec {
    framing: FramingConfig,
    decoding: DeserializerConfig,
}

fn codec(yaml: &str) -> Result<Codec, serde_yaml::Error> {
    serde_yaml::from_str(yaml)
}

fn build(yaml: &str) -> vector_common::Result<Decoder> {
    let codec = codec(yaml).expect("codec yaml");
    DecodingConfig::new(
        codec.framing,
        codec.decoding,
        LogNamespace::Legacy,
        OperationalLimits::default(),
    )
    .build::<Stream>()
    .map(|factory| factory.build())
}

fn decoder(yaml: &str) -> Decoder {
    build(yaml).expect("decoder builds")
}

fn build_error(yaml: &str) -> String {
    build(yaml).err().expect("build fails").to_string()
}

fn indent(text: &str, by: usize) -> String {
    text.lines()
        .map(|l| format!("{}{l}\n", " ".repeat(by)))
        .collect()
}

/// Newline-delimited JSON, assembled by `assembler` (the body of the `assembler` key).
fn ndjson_yaml(assembler: &str) -> String {
    formatdoc! {"
        framing: {{ method: newline_delimited }}
        decoding:
          codec: assembled
          deserializer: {{ codec: json }}
          assembler:
        {}", indent(assembler, 4)}
}

fn ndjson(assembler: &str) -> Decoder {
    decoder(&ndjson_yaml(assembler))
}

/// One decode step: the frame's events, or whether the error lets the stream continue.
type Step = Result<Vec<Event>, bool>;

type Decoded = Result<Option<(SmallVec<[Event; 1]>, usize)>, Error>;

fn step(r: Decoded) -> Option<Step> {
    match r {
        Ok(Some((events, _))) => Some(Ok(events.into_vec())),
        Ok(None) => None,
        Err(error) => Some(Err(error.can_continue())),
    }
}

/// Drives the decoder the way `FramedRead` does: decode after each chunk until it yields nothing,
/// then call `decode_eof` until it yields nothing. Like a source, it stops at an error that does
/// not let the stream continue.
fn run(decoder: &mut Decoder, chunks: &[&str]) -> Vec<Step> {
    let mut buf = BytesMut::new();
    let mut steps: Vec<Step> = chunks
        .iter()
        .flat_map(|chunk| {
            buf.extend_from_slice(chunk.as_bytes());
            std::iter::from_fn(|| step(decoder.decode(&mut buf))).collect::<Vec<_>>()
        })
        .collect();
    match steps.iter().position(|s| matches!(s, Err(false))) {
        Some(fatal) => steps.truncate(fatal + 1),
        None => steps.extend(std::iter::from_fn(|| step(decoder.decode_eof(&mut buf)))),
    }
    steps
}

/// Event values, without the ingest `timestamp` the `json` deserializer adds in the Legacy
/// namespace. A `timestamp` that came from the input is a string or number and is kept.
fn values(steps: &[Step]) -> Vec<serde_json::Value> {
    steps
        .iter()
        .flatten()
        .flatten()
        .map(|e| {
            let mut value = e.as_log().value().clone();
            if matches!(
                value.get("timestamp"),
                Some(vrl::value::Value::Timestamp(_))
            ) {
                value.remove("timestamp", false);
            }
            serde_json::to_value(value).unwrap()
        })
        .collect()
}

fn errors(steps: &[Step]) -> Vec<bool> {
    steps
        .iter()
        .filter_map(|s| s.as_ref().err().copied())
        .collect()
}

fn lines(docs: &[serde_json::Value]) -> String {
    docs.iter().map(|d| format!("{d}\n")).collect()
}

fn ndjson_run(assembler: &str, docs: &[serde_json::Value]) -> Vec<Step> {
    run(&mut ndjson(assembler), &[&lines(docs)])
}

// ---- config ----

#[test]
fn assembled_config_reads_the_same_from_yaml_and_json() {
    let yaml = ndjson_yaml(indoc! {r#"
        resumable: false
        max_register_bytes: 1024
        process:
          - if:
              when: { exists: .header }
              then:
                - merge: { from: .header, to: "%h", move: true, zip: true }
                - stop
              else:
                - merge: { from: "%h", to: ., move: false }
          - foreach:
              target: .items
              do:
                - append: { from: ., to: "%seen", move: false }
          - emit: { from: "%h.extra", move: true }
          - reset: { to: .tmp, value: { a: [1, "x", null] } }
          - merge: { from: .v, to: "%m", key: .k, move: true }
        flush:
          metadata_from: last
          actions:
            - emit: { from: "%seen", move: true }
            - stop
    "#});
    let from_yaml = codec(&yaml).unwrap().decoding;
    let json =
        serde_json::to_string(&serde_yaml::from_str::<serde_json::Value>(&yaml).unwrap()).unwrap();
    let from_json = serde_json::from_str::<Codec>(&json).unwrap().decoding;
    assert_eq!(from_yaml, from_json);
    build(&yaml).expect("builds");
}

#[test]
fn stop_reads_as_a_bare_string_or_an_empty_map() {
    assert!(codec(&ndjson_yaml("process: [stop]")).is_ok());
    assert!(codec(&ndjson_yaml("process: [{ stop: {} }]")).is_ok());
    assert!(codec(&ndjson_yaml("process: [{ stop: { emit: true } }]")).is_err());
}

#[test]
fn unknown_action_is_rejected() {
    let error = codec(&ndjson_yaml("process: [{ drop: {} }]"))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("unknown variant `drop`"), "{error}");
}

#[test]
fn unknown_action_field_is_rejected() {
    let error = codec(&ndjson_yaml(
        "process: [{ merge: { from: .a, to: .b, move: false, deep: true } }]",
    ))
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("unknown field `deep`"), "{error}");
}

#[test]
fn action_with_two_keys_is_rejected() {
    assert!(codec(&ndjson_yaml(
        "process: [{ emit: { from: .a, move: false }, stop: {} }]"
    ))
    .is_err());
}

#[test]
fn move_must_be_given() {
    let error = codec(&ndjson_yaml("process: [{ emit: { from: .a } }]"))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("missing field `move`"), "{error}");
}

#[test]
fn unknown_assembler_option_is_rejected() {
    let error = codec(&ndjson_yaml("process: []\non_error: drop"))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("unknown field `on_error`"), "{error}");
}

#[test]
fn stop_must_be_last_in_its_list() {
    let error = build_error(&ndjson_yaml(
        "process: [stop, { emit: { from: .a, move: false } }]",
    ));
    assert_eq!(error, "`stop` must be the last action in its list");
}

#[test]
fn bare_percent_path_is_rejected() {
    let error = codec(&ndjson_yaml(
        r#"process: [{ emit: { from: "%", move: false } }]"#,
    ))
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("Invalid field path"), "{error}");
}

#[test]
fn percent_path_starting_with_an_index_fails_to_build() {
    let error = build_error(&ndjson_yaml(
        r#"process: [{ emit: { from: "%[0]", move: false } }]"#,
    ));
    assert!(
        error.contains("must start with a register name or `meta`"),
        "{error}"
    );
}

#[test]
fn foreach_body_touching_its_register_target_fails_to_build() {
    let error = build_error(&ndjson_yaml(indoc! {r#"
        process:
          - foreach:
              target: "%buf.items"
              do:
                - merge: { from: ., to: "%buf.items.copy", move: false }
    "#}));
    assert_eq!(
        error,
        "`foreach` over `%buf.items` may not use `%buf.items.copy`, which overlaps it"
    );
}

#[test]
fn foreach_body_reading_a_parent_of_its_target_in_a_predicate_fails_to_build() {
    let error = build_error(&ndjson_yaml(indoc! {r#"
        process:
          - foreach:
              target: "%buf.items"
              do:
                - if:
                    when: { exists: "%buf" }
                    then: [stop]
    "#}));
    assert!(error.contains("may not use `%buf`"), "{error}");
}

#[test]
fn foreach_body_using_a_sibling_register_builds() {
    build(&ndjson_yaml(indoc! {r#"
        process:
          - foreach:
              target: "%buf.items"
              do:
                - merge: { from: "%buf.header", to: ., move: false }
                - merge: { from: ., to: "%other", move: false }
    "#}))
    .expect("siblings do not overlap");
}

#[test]
fn invalid_if_predicate_fails_to_build() {
    let error = build_error(&ndjson_yaml(
        "process: [{ if: { when: { all: [] }, then: [stop] } }]",
    ));
    assert_eq!(
        error,
        "invalid `if` predicate: `all` requires at least one child"
    );
}

#[test]
fn recursive_deserializer_config_generates_a_schema() {
    vector_config::schema::generate_root_schema::<DeserializerConfig>().expect("schema");
}

// ---- actions ----

#[test]
fn events_no_action_touches_pass_through_unchanged() {
    let steps = ndjson_run(
        "process: [{ if: { when: { eq: { path: .kind, value: header } }, then: [stop] } }]",
        &[
            json!({"kind": "data", "n": 1}),
            json!({"kind": "header"}),
            json!({"kind": "data", "n": 2}),
        ],
    );
    assert_eq!(
        values(&steps),
        vec![
            json!({"kind": "data", "n": 1}),
            json!({"kind": "data", "n": 2})
        ]
    );
}

#[test]
fn merge_deep_merges_objects_and_replaces_arrays() {
    let steps = ndjson_run(
        "process: [{ merge: { from: .patch, to: .base, move: true } }]",
        &[json!({
            "base": {"a": 1, "o": {"x": 1, "y": 2}, "arr": [1, 2, 3]},
            "patch": {"b": 2, "o": {"y": 20, "z": 30}, "arr": [9]}
        })],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"base": {"a": 1, "b": 2, "o": {"x": 1, "y": 20, "z": 30}, "arr": [9]}})]
    );
}

#[test]
fn merge_with_zip_merges_arrays_by_position() {
    let steps = ndjson_run(
        "process: [{ merge: { from: .patch, to: .base, move: true, zip: true } }]",
        &[json!({"base": [{"a": 1}, {"a": 2}], "patch": [{"b": 1}, {"b": 2}, {"b": 3}]})],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"base": [{"a": 1, "b": 1}, {"a": 2, "b": 2}, {"b": 3}]})]
    );
}

#[test]
fn merge_into_a_missing_path_copies_the_value() {
    let steps = ndjson_run(
        "process: [{ merge: { from: .a, to: .b.c, move: false } }]",
        &[json!({"a": {"x": 1}})],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"a": {"x": 1}, "b": {"c": {"x": 1}}})]
    );
}

#[test]
fn merge_of_a_scalar_overwrites_a_scalar() {
    let steps = ndjson_run(
        "process: [{ merge: { from: .a, to: .b, move: false } }]",
        &[json!({"a": "new", "b": 7})],
    );
    assert_eq!(values(&steps), vec![json!({"a": "new", "b": "new"})]);
}

#[test]
#[traced_test]
fn missing_or_null_from_is_logged_and_counted_per_action() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let steps = metrics::with_local_recorder(&recorder, || {
        ndjson_run(
            indoc! {r#"
                process:
                  - merge: { from: .nope, to: .b, move: false }
                  - append: { from: .n, to: .l, move: false }
                  - emit: { from: "%gone", move: true }
                  - emit: { from: .n, move: false }
            "#},
            &[json!({"n": null})],
        )
    });
    assert_eq!(values(&steps), vec![json!({"n": null})]);
    let counts: BTreeMap<String, u64> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, ..)| key.key().name() == "assembler_missing_from_total")
        .filter_map(|(key, _, _, value)| match value {
            DebugValue::Counter(n) => key
                .key()
                .labels()
                .find(|l| l.key() == "action")
                .map(|l| (l.value().to_string(), n)),
            _ => None,
        })
        .collect();
    assert_eq!(
        counts,
        BTreeMap::from([
            ("append".to_string(), 1),
            ("emit".to_string(), 2),
            ("merge".to_string(), 1),
        ])
    );
    assert!(logs_contain("action=\"merge\" path=.nope"));
    assert!(logs_contain("path=%gone"));
}

#[test]
fn merge_from_a_missing_path_does_nothing() {
    let steps = ndjson_run(
        "process: [{ merge: { from: .nope, to: .b, move: true } }]",
        &[json!({"b": 1})],
    );
    assert_eq!(values(&steps), vec![json!({"b": 1})]);
}

#[test]
fn merge_of_a_different_kind_into_a_container_fails_the_frame_and_the_stream_continues() {
    let steps = ndjson_run(
        "process: [{ merge: { from: .from, to: .to, move: false } }]",
        &[
            json!({"from": {"a": 1}, "to": [1]}),
            json!({"from": "s", "to": {"a": 1}}),
            json!({"from": 1, "to": 2}),
        ],
    );
    assert_eq!(errors(&steps), vec![true, true]);
    assert_eq!(values(&steps), vec![json!({"from": 1, "to": 1})]);
}

#[test]
fn keyed_merge_uses_the_key_as_one_literal_field_name() {
    let steps = ndjson_run(
        "process: [{ merge: { from: .v, to: .out, key: .k, move: true } }]",
        &[json!({"k": "a.b[99999999]", "v": 1})],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"k": "a.b[99999999]", "out": {"a.b[99999999]": 1}})]
    );
}

#[test]
fn keyed_merge_fails_on_a_missing_or_non_string_key() {
    let steps = ndjson_run(
        "process: [{ merge: { from: .v, to: .out, key: .k, move: false } }]",
        &[
            json!({"k": 5, "v": 1}),
            json!({"v": 1}),
            json!({"k": "ok", "v": 1}),
        ],
    );
    assert_eq!(errors(&steps), vec![true, true]);
    assert_eq!(
        values(&steps),
        vec![json!({"k": "ok", "v": 1, "out": {"ok": 1}})]
    );
}

#[test]
fn keyed_merge_writes_into_metadata() {
    let steps = ndjson_run(
        r#"process: [{ merge: { from: .v, to: "%meta", key: .k, move: true } }]"#,
        &[json!({"k": "tenant", "v": "acme"})],
    );
    let event = &steps[0].as_ref().unwrap()[0];
    assert_eq!(
        serde_json::to_value(event.metadata().value()).unwrap(),
        json!({"tenant": "acme"})
    );
    assert_eq!(values(&steps), vec![json!({"k": "tenant"})]);
}

#[test]
fn append_creates_and_extends_an_array() {
    let steps = ndjson_run(
        "process: [{ append: { from: .n, to: .list, move: true } }, { append: { from: .m, to: .list, move: true } }]",
        &[json!({"n": 1, "m": 2}), json!({"n": 1, "m": 2, "list": null})],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"list": [1, 2]}), json!({"list": [1, 2]})]
    );
}

#[test]
fn append_to_a_non_array_fails_the_frame() {
    let steps = ndjson_run(
        "process: [{ append: { from: .n, to: .s, move: false } }]",
        &[json!({"n": 1, "s": "x"})],
    );
    assert_eq!(errors(&steps), vec![true]);
}

#[test]
fn emitted_events_come_before_the_surviving_event() {
    let steps = ndjson_run(
        indoc! {"
            process:
              - emit: { from: .a, move: true }
              - emit: { from: .b, move: false }
        "},
        &[json!({"a": {"x": 1}, "b": {"y": 2}, "c": 3})],
    );
    assert_eq!(
        values(&steps),
        vec![
            json!({"x": 1}),
            json!({"y": 2}),
            json!({"b": {"y": 2}, "c": 3})
        ]
    );
}

#[test]
fn emitting_a_scalar_puts_it_under_the_message_key() {
    let steps = ndjson_run(
        "process: [{ emit: { from: .s, move: false } }]",
        &[json!({"s": "hi"})],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"message": "hi"}), json!({"s": "hi"})]
    );
}

#[test]
fn emitting_a_missing_or_null_value_emits_nothing() {
    let steps = ndjson_run(
        "process: [{ emit: { from: .n, move: false } }, { emit: { from: .missing, move: false } }]",
        &[json!({"n": null})],
    );
    assert_eq!(values(&steps), vec![json!({"n": null})]);
}

#[test]
fn moving_the_whole_event_out_leaves_nothing_to_survive() {
    let steps = ndjson_run(
        "process: [{ emit: { from: ., move: true } }]",
        &[json!({"a": 1})],
    );
    assert_eq!(values(&steps), vec![json!({"a": 1})]);
}

#[test]
fn emitted_events_carry_the_triggering_events_metadata() {
    let steps = ndjson_run(
        indoc! {r#"
            process:
              - reset: { to: "%meta.origin", value: "s3" }
              - emit: { from: .a, move: true }
        "#},
        &[json!({"a": {"x": 1}})],
    );
    let events = steps[0].as_ref().unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| {
        serde_json::to_value(e.metadata().value()).unwrap() == json!({"origin": "s3"})
    }));
}

#[test]
fn reset_sets_or_removes_a_path() {
    let steps = ndjson_run(
        indoc! {"
            process:
              - reset: { to: .a, value: { z: [1] } }
              - reset: { to: .b }
        "},
        &[json!({"a": 1, "b": 2, "c": 3})],
    );
    assert_eq!(values(&steps), vec![json!({"a": {"z": [1]}, "c": 3})]);
}

#[test]
fn stop_drops_the_event_and_skips_later_actions() {
    let steps = ndjson_run(
        indoc! {"
            process:
              - if: { when: { exists: .drop }, then: [stop] }
              - reset: { to: .seen, value: true }
        "},
        &[json!({"drop": 1}), json!({"keep": 1})],
    );
    assert_eq!(values(&steps), vec![json!({"keep": 1, "seen": true})]);
}

#[test]
fn if_runs_else_when_the_predicate_does_not_match() {
    let steps = ndjson_run(
        indoc! {"
            process:
              - if:
                  when: { gt: { path: .n, value: 10 } }
                  then: [{ reset: { to: .size, value: big } }]
                  else: [{ reset: { to: .size, value: small } }]
        "},
        &[json!({"n": 50}), json!({"n": 5})],
    );
    assert_eq!(
        values(&steps),
        vec![
            json!({"n": 50, "size": "big"}),
            json!({"n": 5, "size": "small"})
        ]
    );
}

#[test]
fn foreach_fans_out_array_elements_with_header_fields() {
    let steps = ndjson_run(
        indoc! {r#"
            process:
              - merge: { from: .host, to: "%h.host", move: true }
              - foreach:
                  target: .items
                  do:
                    - merge: { from: "%h", to: ., move: false }
                    - emit: { from: ., move: true }
              - stop
        "#},
        &[json!({"host": "a", "items": [{"n": 1}, {"n": 2}]})],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"n": 1, "host": "a"}), json!({"n": 2, "host": "a"})]
    );
}

#[test]
fn foreach_over_a_missing_or_null_target_does_nothing() {
    let steps = ndjson_run(
        "process: [{ foreach: { target: .items, do: [{ emit: { from: ., move: false } }] } }]",
        &[json!({"a": 1}), json!({"items": null})],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"a": 1}), json!({"items": null})]
    );
}

#[test]
fn foreach_over_a_non_array_fails_the_frame() {
    let steps = ndjson_run(
        "process: [{ foreach: { target: .items, do: [{ emit: { from: ., move: false } }] } }]",
        &[json!({"items": {"a": 1}})],
    );
    assert_eq!(errors(&steps), vec![true]);
}

#[test]
fn foreach_puts_its_register_target_back_when_its_body_stops() {
    let steps = ndjson_run(
        indoc! {r#"
            process:
              - append: { from: .n, to: "%buf", move: false }
              - if:
                  when: { eq: { path: .n, value: 2 } }
                  then:
                    - foreach:
                        target: "%buf"
                        do:
                          - if: { when: { eq: { path: ., value: 1 } }, then: [stop] }
            flush:
              actions:
                - merge: { from: "%buf", to: .buf, move: true }
        "#},
        &[json!({"n": 1}), json!({"n": 2})],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"n": 1}), json!({"buf": [1, 2]})]
    );
}

#[test]
fn foreach_elements_can_be_modified_in_place() {
    let steps = ndjson_run(
        indoc! {"
            process:
              - foreach:
                  target: .items
                  do:
                    - reset: { to: .seen, value: true }
        "},
        &[json!({"items": [{"n": 1}, {"n": 2}]})],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"items": [{"n": 1, "seen": true}, {"n": 2, "seen": true}]})]
    );
}

// ---- registers and limits ----

#[test]
fn registers_carry_values_across_events() {
    let steps = ndjson_run(
        indoc! {r#"
            process:
              - if:
                  when: { exists: .header }
                  then:
                    - merge: { from: .header, to: "%h", move: true }
                    - stop
              - merge: { from: "%h", to: ., move: false }
        "#},
        &[
            json!({"header": {"src": "a"}}),
            json!({"n": 1}),
            json!({"header": {"src": "b"}}),
            json!({"n": 2}),
        ],
    );
    assert_eq!(
        values(&steps),
        vec![json!({"n": 1, "src": "a"}), json!({"n": 2, "src": "b"})]
    );
}

/// What a string of `len` bytes takes in a register.
fn string_size(len: usize) -> usize {
    mem::size_of::<Value>() + len
}

/// What an array takes in a register besides its elements: `ByteSizeOf` counts the `Vec` header
/// on top of the `Value` holding it.
fn array_size() -> usize {
    mem::size_of::<Value>() + mem::size_of::<Vec<Value>>()
}

/// What a field named `name`, holding a string of `len` bytes, takes in a register.
fn string_field_size(name: &str, len: usize) -> usize {
    mem::size_of::<KeyString>() + name.len() + string_size(len)
}

#[test]
fn exceeding_the_register_limit_ends_the_stream_even_when_resumable() {
    let steps = ndjson_run(
        &formatdoc! {r#"
            max_register_bytes: {limit}
            process:
              - merge: {{ from: .s, to: "%r", key: .k, move: false }}
              - merge: {{ from: "%r", to: .regs, move: false }}
        "#, limit = string_field_size("a", 9)},
        &[
            json!({"k": "a", "s": "123456789"}),
            json!({"k": "b", "s": "x"}),
            json!({"k": "c", "s": "y"}),
        ],
    );
    assert_eq!(errors(&steps), vec![false]);
    assert_eq!(
        values(&steps),
        vec![json!({"k": "a", "s": "123456789", "regs": {"a": "123456789"}})]
    );
}

#[test]
fn overwriting_a_register_field_does_not_grow_the_register() {
    let docs: Vec<_> = (0..100)
        .map(|i| json!({"s": format!("value-{i:04}")}))
        .collect();
    let steps = ndjson_run(
        &formatdoc! {r#"
            max_register_bytes: {limit}
            process:
              - merge: {{ from: .s, to: "%h.s", move: false }}
        "#, limit = string_field_size("s", 10)},
        &docs,
    );
    assert_eq!(errors(&steps), Vec::<bool>::new());
    assert_eq!(values(&steps).len(), 100);
}

#[test]
fn moving_out_of_a_register_frees_its_space() {
    let docs: Vec<_> = (0..50).map(|i| json!({"s": format!("v{i:08}")})).collect();
    let steps = ndjson_run(
        &formatdoc! {r#"
            max_register_bytes: {limit}
            process:
              - append: {{ from: .s, to: "%buf", move: false }}
              - emit: {{ from: "%buf", move: true }}
              - stop
        "#, limit = string_field_size("buf", 9) + array_size()},
        &docs,
    );
    assert_eq!(errors(&steps), Vec::<bool>::new());
    assert_eq!(values(&steps).len(), 50);
}

#[test]
fn appending_past_the_register_limit_ends_the_stream() {
    let docs: Vec<_> = (0..5).map(|i| json!({"s": format!("{i:09}")})).collect();
    let two_elements = string_field_size("buf", 9) + array_size() + string_size(9);
    let steps = ndjson_run(
        &formatdoc! {r#"
            max_register_bytes: {two_elements}
            process:
              - append: {{ from: .s, to: "%buf", move: false }}
        "#},
        &docs,
    );
    assert_eq!(errors(&steps), vec![false]);
    assert_eq!(values(&steps).len(), 2);
}

// ---- errors ----

#[test]
fn non_resumable_assembler_errors_end_the_stream() {
    let steps = ndjson_run(
        indoc! {"
            resumable: false
            process:
              - append: { from: .n, to: .s, move: false }
        "},
        &[json!({"n": 1, "s": "x"})],
    );
    assert_eq!(errors(&steps), vec![false]);
}

#[test]
fn non_resumable_inner_deserializer_errors_end_the_stream() {
    let mut decoder = ndjson("resumable: false\nprocess: []");
    let steps = run(&mut decoder, &["not json\n"]);
    assert_eq!(errors(&steps), vec![false]);
}

#[test]
fn resumable_inner_deserializer_errors_only_fail_their_frame() {
    let mut decoder = ndjson("process: []");
    let steps = run(&mut decoder, &["not json\n{\"a\":1}\n"]);
    assert_eq!(errors(&steps), vec![true]);
    assert_eq!(values(&steps), vec![json!({"a": 1})]);
}

#[test]
fn register_writes_before_a_failing_action_persist() {
    let steps = ndjson_run(
        indoc! {r#"
            process:
              - append: { from: .n, to: "%buf", move: false }
              - append: { from: .n, to: .bad, move: false }
            flush:
              actions:
                - merge: { from: "%buf", to: .buf, move: true }
        "#},
        &[json!({"n": 1, "bad": "x"}), json!({"n": 2, "bad": "y"})],
    );
    assert_eq!(errors(&steps), vec![true, true]);
    assert_eq!(values(&steps), vec![json!({"buf": [1, 2]})]);
}

// ---- flush ----

#[test]
fn flush_runs_once_at_the_end_of_the_unit() {
    let mut decoder = ndjson(indoc! {"
        process: []
        flush:
          actions:
            - reset: { to: .done, value: true }
    "});
    let steps = run(&mut decoder, &["{\"a\":1}\n"]);
    assert_eq!(values(&steps), vec![json!({"a": 1}), json!({"done": true})]);
    let mut buf = BytesMut::new();
    assert!(step(decoder.decode_eof(&mut buf)).is_none());
}

#[test]
fn flush_does_not_run_for_a_unit_with_nothing_decoded() {
    let mut decoder = ndjson(indoc! {"
        process: []
        flush:
          actions:
            - reset: { to: .done, value: true }
    "});
    assert_eq!(
        values(&run(&mut decoder, &[])),
        Vec::<serde_json::Value>::new()
    );
}

#[test]
fn flush_emits_what_registers_still_hold_and_then_clears_them() {
    let mut decoder = ndjson(indoc! {r#"
        process:
          - append: { from: .n, to: "%buf", move: true }
          - stop
        flush:
          actions:
            - merge: { from: "%buf", to: .batch, move: true }
    "#});
    assert_eq!(
        values(&run(&mut decoder, &["{\"n\":1}\n{\"n\":2}\n"])),
        vec![json!({"batch": [1, 2]})]
    );
    assert_eq!(
        values(&run(&mut decoder, &["{\"n\":3}\n"])),
        vec![json!({"batch": [3]})]
    );
}

#[test]
fn flush_that_sets_nothing_emits_nothing() {
    let mut decoder = ndjson(indoc! {r#"
        process: [stop]
        flush:
          actions:
            - emit: { from: "%missing", move: true }
    "#});
    assert_eq!(
        values(&run(&mut decoder, &["{\"n\":1}\n"])),
        Vec::<serde_json::Value>::new()
    );
}

#[test]
fn assembled_inside_assembled_runs_each_layer_with_its_own_registers_and_flush() {
    let mut decoder = decoder(indoc! {r#"
        framing: { method: newline_delimited }
        decoding:
          codec: assembled
          deserializer:
            codec: assembled
            deserializer: { codec: json }
            assembler:
              process:
                - append: { from: .n, to: "%buf", move: false }
                - reset: { to: .inner, value: true }
              flush:
                actions:
                  - merge: { from: "%buf", to: .inner_saw, move: true }
          assembler:
            process:
              - if:
                  when: { exists: .n }
                  then:
                    - append: { from: .n, to: "%buf", move: false }
              - reset: { to: .outer, value: true }
            flush:
              actions:
                - merge: { from: "%buf", to: .outer_saw, move: true }
    "#});
    assert_eq!(
        values(&run(&mut decoder, &["{\"n\":1}\n{\"n\":2}\n"])),
        vec![
            json!({"n": 1, "inner": true, "outer": true}),
            json!({"n": 2, "inner": true, "outer": true}),
            json!({"inner_saw": [1, 2], "outer": true}),
            json!({"outer_saw": [1, 2]}),
        ]
    );
}

fn flush_metadata(metadata_from: &str) -> Vec<(serde_json::Value, serde_json::Value)> {
    let mut decoder = decoder(&formatdoc! {r#"
        framing: {{ method: newline_delimited }}
        decoding:
          codec: assembled
          deserializer:
            codec: assembled
            deser: {{ codec: json }}
            assembler:
              process:
                - merge: {{ from: .seq, to: "%meta.seq", move: false }}
          assembler:
            process: [stop]
            flush:
              metadata_from: {metadata_from}
              actions:
                - reset: {{ to: .flushed, value: true }}
                - merge: {{ from: "%meta.seq", to: .seq, move: false }}
    "#});
    run(&mut decoder, &["{\"seq\":1}\n{\"seq\":2}\n{\"seq\":3}\n"])
        .iter()
        .flatten()
        .flatten()
        .map(|e| {
            (
                serde_json::to_value(e.as_log().value()).unwrap(),
                serde_json::to_value(e.metadata().value()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn flush_starts_with_empty_metadata_by_default() {
    assert_eq!(
        flush_metadata("none"),
        vec![(json!({"flushed": true}), json!({}))]
    );
}

#[test]
fn flush_can_start_with_the_first_events_metadata() {
    assert_eq!(
        flush_metadata("first"),
        vec![(json!({"flushed": true, "seq": 1}), json!({"seq": 1}))]
    );
}

#[test]
fn flush_can_start_with_the_last_events_metadata() {
    assert_eq!(
        flush_metadata("last"),
        vec![(json!({"flushed": true, "seq": 3}), json!({"seq": 3}))]
    );
}

#[test]
fn flush_can_restore_metadata_cached_in_a_register() {
    let mut decoder = ndjson(indoc! {r#"
        process:
          - reset: { to: "%meta.source", value: s3 }
          - if:
              when: { not: { exists: "%first_meta" } }
              then:
                - merge: { from: "%meta", to: "%first_meta", move: false }
          - stop
        flush:
          actions:
            - merge: { from: "%first_meta", to: "%meta", move: true }
            - reset: { to: .flushed, value: true }
    "#});
    let steps = run(&mut decoder, &["{\"a\":1}\n"]);
    let event = &steps.last().unwrap().as_ref().unwrap()[0];
    assert_eq!(
        serde_json::to_value(event.metadata().value()).unwrap(),
        json!({"source": "s3"})
    );
}

// ---- event kinds ----

#[test]
fn metrics_can_be_matched_and_projected_into_log_events() {
    let mut decoder = decoder(indoc! {r#"
        framing: { method: newline_delimited }
        decoding:
          codec: assembled
          deser: { codec: native_json }
          assembler:
            process:
              - if:
                  when: { eq: { path: .name, value: requests } }
                  then:
                    - emit: { from: .tags, move: false }
    "#});
    let steps = run(
        &mut decoder,
        &[concat!(
            r#"{"metric":{"name":"requests","tags":{"host":"web-1"},"kind":"incremental","counter":{"value":1.0}}}"#,
            "\n",
            r#"{"metric":{"name":"other","kind":"incremental","counter":{"value":1.0}}}"#,
            "\n",
        )],
    );
    let events: Vec<_> = steps.into_iter().flatten().flatten().collect();
    assert_eq!(events.len(), 3);
    assert_eq!(
        serde_json::to_value(events[0].as_log().value()).unwrap(),
        json!({"host": "web-1"})
    );
    assert_eq!(events[1].as_metric().name(), "requests");
    assert_eq!(events[2].as_metric().name(), "other");
}

// ---- demos ----

/// Written out rather than built with `json!`, which sorts keys: streaming assembly relies on
/// each record's header fields preceding its flow tuples, as they do in the files Azure writes.
fn nsg_doc(system_id: &str, rule: &str, mac: &str, tuples: &[&str]) -> String {
    let tuples = serde_json::to_string(tuples).unwrap();
    format!(
        r#"{{"records":[{{"time":"2024-01-01T00:00:00Z","systemId":"{system_id}","operationName":"NSGFlowEvents","resourceId":"/SUBS/RG/NSG","properties":{{"Version":1,"flows":[{{"rule":"{rule}","flows":[{{"mac":"{mac}","flowTuples":{tuples}}}]}}]}}}}]}}"#
    )
}

fn nsg_record(system_id: &str, rule: &str, mac: &str, tuple: &str) -> serde_json::Value {
    json!({
        "time": "2024-01-01T00:00:00Z",
        "systemId": system_id,
        "operationName": "NSGFlowEvents",
        "rule": rule,
        "mac": mac,
        "flowTuples": tuple,
    })
}

/// Azure NSG flow logs, streamed by `json_paths` as one `{expr, data}` event per scalar: header
/// fields are kept in `%r` under their (dotted, literal) path, and each flow tuple is emitted as a
/// flat record carrying the header fields of the record it belongs to.
fn nsg_decoder(framing: &str) -> Decoder {
    decoder(&formatdoc! {r#"
        framing: {framing}
        decoding:
          codec: assembled
          deserializer:
            codec: json_paths
            config:
              paths:
                "records.*": {{ op: identity }}
                "records.resourceId": {{ op: drop }}
                "records.*.*": {{ op: identity }}
                "records.*.*.*": {{ op: identity }}
                "records.*.*.*.*": {{ op: identity }}
                "records.*.*.*.flowTuples": {{ op: explode }}
          assembler:
            process:
              - if:
                  when: {{ eq: {{ path: .expr, value: records.properties.flows.flows.flowTuples }} }}
                  then:
                    - reset: {{ to: .expr }}
                    - merge: {{ from: .data, to: .flowTuples, move: true }}
                    - merge: {{ from: '%r."records.time"', to: .time, move: false }}
                    - merge: {{ from: '%r."records.systemId"', to: .systemId, move: false }}
                    - merge: {{ from: '%r."records.operationName"', to: .operationName, move: false }}
                    - merge: {{ from: '%r."records.properties.flows.rule"', to: .rule, move: false }}
                    - merge: {{ from: '%r."records.properties.flows.flows.mac"', to: .mac, move: false }}
                  else:
                    - merge: {{ from: .data, to: "%r", key: .expr, move: true }}
                    - stop
    "#})
}

fn nsg_input() -> String {
    [
        nsg_doc(
            "SYS-01",
            "AllowInbound",
            "AABB01",
            &["1700001,10.0.0.1,T", "1700002,10.0.0.2,T"],
        ),
        nsg_doc("SYS-02", "DenyTelnet", "AABB02", &["1700003,10.0.0.3,U"]),
    ]
    .join("\n")
        + "\n"
}

fn nsg_expected() -> Vec<serde_json::Value> {
    vec![
        nsg_record("SYS-01", "AllowInbound", "AABB01", "1700001,10.0.0.1,T"),
        nsg_record("SYS-01", "AllowInbound", "AABB01", "1700002,10.0.0.2,T"),
        nsg_record("SYS-02", "DenyTelnet", "AABB02", "1700003,10.0.0.3,U"),
    ]
}

#[test]
fn demo_nsg_flow_logs_assemble_identically_across_framings() {
    let input = nsg_input();
    for framing in [
        "{ method: bytes, bytes: { min_chunk_bytes: 16 } }",
        "{ method: bytes }",
        "{ method: newline_delimited }",
        "{ method: character_delimited, character_delimited: { delimiter: \"\\n\" } }",
    ] {
        let steps = run(&mut nsg_decoder(framing), &[&input]);
        assert_eq!(errors(&steps), Vec::<bool>::new(), "{framing}");
        assert_eq!(values(&steps), nsg_expected(), "{framing}");
    }
}

#[test]
fn demo_nsg_flow_logs_assemble_when_the_document_arrives_in_small_reads() {
    let input = nsg_input();
    let chunks: Vec<String> = input
        .as_bytes()
        .chunks(7)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect();
    let chunks: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let steps = run(
        &mut nsg_decoder("{ method: bytes, bytes: { min_chunk_bytes: 32 } }"),
        &chunks,
    );
    assert_eq!(values(&steps), nsg_expected());
}

/// In the field order CloudWatch Logs writes, with `logEvents` last (see `nsg_doc`).
fn vpc_doc(log_stream: &str, events: &[(&str, &str)]) -> String {
    let events: Vec<String> = events
        .iter()
        .map(|(id, message)| {
            format!(r#"{{"id":"{id}","timestamp":1700000000000,"message":"{message}"}}"#)
        })
        .collect();
    format!(
        r#"{{"messageType":"DATA_MESSAGE","owner":"123456789012","logGroup":"vpc-flow-logs","logStream":"{log_stream}","subscriptionFilters":["to-firehose"],"logEvents":[{}]}}"#,
        events.join(",")
    )
}

fn vpc_record(log_stream: &str, id: &str, message: &str) -> serde_json::Value {
    json!({
        "owner": "123456789012",
        "logGroup": "vpc-flow-logs",
        "logStream": log_stream,
        "id": id,
        "timestamp": 1_700_000_000_000_i64,
        "message": message,
    })
}

const VPC_ACCEPT: &str =
    "2 123456789012 eni-0a1b 10.0.0.1 10.0.0.2 443 49152 6 10 840 1700000000 1700000060 ACCEPT OK";
const VPC_REJECT: &str =
    "2 123456789012 eni-0a1b 10.0.0.9 10.0.0.2 22 50000 6 1 60 1700000000 1700000060 REJECT OK";

fn vpc_input() -> Vec<String> {
    vec![
        vpc_doc("eni-0a1b-all", &[("e1", VPC_ACCEPT), ("e2", VPC_REJECT)]),
        r#"{"messageType":"CONTROL_MESSAGE","owner":"CloudwatchLogs","logGroup":"","logStream":"","subscriptionFilters":[],"logEvents":[{"id":"c1","timestamp":0,"message":"CWL CONTROL MESSAGE: Checking health of destination Firehose."}]}"#.to_owned(),
        vpc_doc("eni-0c3d-all", &[("e3", VPC_ACCEPT)]),
    ]
}

fn vpc_expected() -> Vec<serde_json::Value> {
    vec![
        vpc_record("eni-0a1b-all", "e1", VPC_ACCEPT),
        vpc_record("eni-0a1b-all", "e2", VPC_REJECT),
        vpc_record("eni-0c3d-all", "e3", VPC_ACCEPT),
    ]
}

/// AWS VPC flow logs from a CloudWatch Logs subscription, delivered to S3 by Firehose: one JSON
/// document per batch, each `logEvents` entry fanned out with the batch's header fields.
#[test]
fn demo_vpc_flow_logs_fan_out_whole_documents_with_foreach() {
    let input: String = vpc_input().iter().map(|d| format!("{d}\n")).collect();
    let mut decoder = ndjson(indoc! {r#"
            process:
              - if:
                  when: { eq: { path: .messageType, value: CONTROL_MESSAGE } }
                  then: [stop]
              - merge: { from: .owner, to: "%h.owner", move: true }
              - merge: { from: .logGroup, to: "%h.logGroup", move: true }
              - merge: { from: .logStream, to: "%h.logStream", move: true }
              - foreach:
                  target: .logEvents
                  do:
                    - merge: { from: "%h", to: ., move: false }
                    - emit: { from: ., move: true }
              - stop
        "#});
    let steps = run(&mut decoder, &[&input]);
    assert_eq!(errors(&steps), Vec::<bool>::new());
    assert_eq!(values(&steps), vpc_expected());
}

/// The same logs streamed by `json_paths`, so a batch never has to be held in memory whole.
/// Firehose concatenates documents without a separator, which the streaming parser takes as is.
#[test]
fn demo_vpc_flow_logs_stream_concatenated_documents_with_json_paths() {
    let mut decoder = decoder(indoc! {r#"
        framing: { method: bytes, bytes: { min_chunk_bytes: 64 } }
        decoding:
          codec: assembled
          deser:
            codec: json_paths
            config:
              paths:
                messageType: { op: identity }
                owner: { op: identity }
                logGroup: { op: identity }
                logStream: { op: identity }
                logEvents: { op: explode }
          assembler:
            process:
              - if:
                  when: { eq: { path: .expr, value: logEvents } }
                  then:
                    - if:
                        when: { eq: { path: '%h.messageType', value: CONTROL_MESSAGE } }
                        then: [stop]
                    - merge: { from: .data, to: ., move: true }
                    - reset: { to: .expr }
                    - merge: { from: '%h.owner', to: .owner, move: false }
                    - merge: { from: '%h.logGroup', to: .logGroup, move: false }
                    - merge: { from: '%h.logStream', to: .logStream, move: false }
                  else:
                    - merge: { from: .data, to: "%h", key: .expr, move: true }
                    - stop
    "#});
    let input: String = vpc_input().concat();
    let steps = run(&mut decoder, &[&input]);
    assert_eq!(errors(&steps), Vec::<bool>::new());
    assert_eq!(values(&steps), vpc_expected());
}

/// A capture reports packets, then a summary of how many packets the ring buffer lost. Each
/// packet is held until the summary arrives, then emitted with the loss fraction; packets still
/// held when the capture ends are emitted at flush, marked incomplete.
#[test]
fn demo_packet_capture_summary_is_denormalized_onto_earlier_packets() {
    let steps = ndjson_run(
        indoc! {r#"
            process:
              - if:
                  when: { exists: .summary }
                  then:
                    - reset: { to: "%s", value: { complete: true } }
                    - merge: { from: .summary.lost_fraction, to: "%s.lost_fraction", move: true }
                    - foreach:
                        target: "%buf"
                        do:
                          - merge: { from: "%s", to: ., move: false }
                          - emit: { from: ., move: true }
                    - reset: { to: "%buf" }
                    - stop
                  else:
                    - append: { from: ., to: "%buf", move: true }
                    - stop
            flush:
              actions:
                - reset: { to: "%s", value: { complete: false } }
                - foreach:
                    target: "%buf"
                    do:
                      - merge: { from: "%s", to: ., move: false }
                      - emit: { from: ., move: true }
        "#},
        &[
            json!({"pkt": 1, "len": 60}),
            json!({"pkt": 2, "len": 1500}),
            json!({"summary": {"captured": 2, "lost_fraction": 0.25}}),
            json!({"pkt": 3, "len": 40}),
        ],
    );
    assert_eq!(errors(&steps), Vec::<bool>::new());
    assert_eq!(
        values(&steps),
        vec![
            json!({"pkt": 1, "len": 60, "complete": true, "lost_fraction": 0.25}),
            json!({"pkt": 2, "len": 1500, "complete": true, "lost_fraction": 0.25}),
            json!({"pkt": 3, "len": 40, "complete": false}),
        ]
    );
}
