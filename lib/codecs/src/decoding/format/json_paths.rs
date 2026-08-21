use actson::feeder::PushJsonFeeder;
use actson::options::JsonParserOptionsBuilder;
use actson::{JsonEvent, JsonParser};
use bytes::Bytes;
use derivative::Derivative;
use lookup::OwnedValuePath;
use smallvec::{smallvec, SmallVec};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use vector_config::configurable_component;
use vector_core::{
    config::{DataType, LogNamespace},
    event::{Event, LogEvent},
    schema,
};
use vrl::value::{Kind, Value};

use super::{default_lossy, Deserializer};

/// Operations that can be performed on JSON paths
#[configurable_component]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PathOperation {
    /// Emit the value as-is when encountered
    Identity,
    /// Emit each array element as a separate event
    Explode,
    /// Emit the value as bytes
    Bytes,
    /// Suppress the value: emit nothing.
    Drop,
}

fn default_wildcard() -> String {
    "*".to_string()
}

/// A single path rule: the operation to perform plus the wildcard character used
/// to interpret this rule's key.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    /// The operation to perform on values at this path.
    #[serde(alias = "operation")]
    pub op: PathOperation,

    /// The match-any wildcard segment for this rule's key. Defaults to `*`;
    /// override it (e.g. `_`) to use a literal `*` as an object key.
    #[serde(default = "default_wildcard")]
    pub wildcard: String,
}

impl PathRule {
    fn new(op: PathOperation, wildcard: String) -> Self {
        Self { op, wildcard }
    }
}

impl From<PathOperation> for PathRule {
    fn from(op: PathOperation) -> Self {
        Self::new(op, default_wildcard())
    }
}

/// Configuration for path-based operations
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathOperationConfig {
    /// Map of JSON paths (as strings) to the rule to apply at each path.
    ///
    /// Keys may be written as `.` (root), `.meta`, or `meta`. A single
    /// leading `.` is optional and stripped on load, so `.` ≡ `""`,
    /// `.meta` ≡ `meta`, `.a.b` ≡ `a.b`. Two keys that normalize to the
    /// same value (e.g. `.meta` and `meta`) are rejected at load time.
    ///
    /// A key segment equal to the rule's wildcard (default `*`) matches any
    /// single key. Rules are resolved specific-first: a concrete segment
    /// shadows the wildcard branch at that level.
    #[serde(deserialize_with = "deserialize_paths")]
    pub paths: BTreeMap<String, PathRule>,
}

impl PathOperationConfig {
    /// Create a new configuration with at least one path
    pub fn new(first_path: OwnedValuePath, first_rule: PathRule) -> Self {
        let mut paths = BTreeMap::new();
        paths.insert(first_path.to_string(), first_rule);
        Self { paths }
    }

    /// Add a rule to the configuration (builder pattern)
    pub fn with_rule(mut self, path: OwnedValuePath, rule: PathRule) -> Self {
        self.paths.insert(path.to_string(), rule);
        self
    }

    /// Create from HashMap (fallible, for compatibility)
    pub fn from_map(paths: HashMap<OwnedValuePath, PathRule>) -> Result<Self, String> {
        if paths.is_empty() {
            return Err("At least one path must be configured".to_string());
        }
        Ok(Self {
            paths: paths.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        })
    }
}

/// Normalize a user-facing path key into the internal runtime form
/// produced by `ParserState::current_path()`.
///
/// - `.` and `""` both mean root → stored as `""`
/// - A single leading `.` on non-root keys is stripped (`.meta` → `meta`)
/// - Everything else is left as-is (including `..meta`, `meta.`, etc.)
fn normalize_config_key(k: &str) -> &str {
    match k {
        "." | "" => "",
        s if s.starts_with('.') => &s[1..],
        s => s,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Segment<'a> {
    Concrete(&'a str),
    Wildcard,
}

fn canonical_segments<'a>(key: &'a str, wildcard: &str) -> Vec<Segment<'a>> {
    if key.is_empty() {
        Vec::new()
    } else {
        key.split('.')
            .map(|segment| {
                if segment == wildcard {
                    Segment::Wildcard
                } else {
                    Segment::Concrete(segment)
                }
            })
            .collect()
    }
}

fn deserialize_paths<'de, D>(de: D) -> Result<BTreeMap<String, PathRule>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    use serde::Deserialize;

    let raw: BTreeMap<String, PathRule> = BTreeMap::deserialize(de)?;

    {
        let mut seen: BTreeMap<Vec<Segment<'_>>, &str> = BTreeMap::new();
        for (k, rule) in &raw {
            let canonical = canonical_segments(normalize_config_key(k), &rule.wildcard);
            if let Some(prev) = seen.get(&canonical) {
                return Err(D::Error::custom(format!(
                    "duplicate path key after normalization: {:?} and {:?} resolve to the same path",
                    prev, k
                )));
            }
            seen.insert(canonical, k);
        }
    }

    Ok(raw
        .into_iter()
        .map(|(k, rule)| (normalize_config_key(&k).to_string(), rule))
        .collect())
}

#[derive(Debug)]
struct PathRules {
    concrete: BTreeMap<String, PathRules>,
    default: Option<Box<PathRules>>,
    op: PathOperation,
    is_wildcard: bool,
}

impl PathRules {
    fn node(is_wildcard: bool) -> Self {
        Self {
            concrete: BTreeMap::new(),
            default: None,
            op: PathOperation::Drop,
            is_wildcard,
        }
    }

    fn insert(self, segments: &[Segment<'_>], op: PathOperation) -> PathRules {
        let PathRules {
            mut concrete,
            default,
            op: current,
            is_wildcard,
        } = self;
        match segments.split_first() {
            None => PathRules {
                concrete,
                default,
                op,
                is_wildcard,
            },
            Some((Segment::Wildcard, rest)) => {
                let child = default
                    .map(|node| *node)
                    .unwrap_or_else(|| PathRules::node(true));
                PathRules {
                    concrete,
                    default: Some(Box::new(child.insert(rest, op))),
                    op: current,
                    is_wildcard,
                }
            }
            Some((Segment::Concrete(name), rest)) => {
                let child = concrete
                    .remove(*name)
                    .unwrap_or_else(|| PathRules::node(false));
                concrete.insert((*name).to_string(), child.insert(rest, op));
                PathRules {
                    concrete,
                    default,
                    op: current,
                    is_wildcard,
                }
            }
        }
    }

    fn has_children(&self) -> bool {
        !self.concrete.is_empty() || self.default.is_some()
    }

    fn lookup(&self, path: &[String]) -> Option<&PathRules> {
        let mut node = self;
        for segment in path {
            node = node.concrete.get(segment).or(node.default.as_deref())?;
        }
        Some(node)
    }
}

/// Config used to build a `JsonPathDeserializer`.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPathDeserializerConfig {
    /// Path-based operation configuration
    pub config: PathOperationConfig,

    /// JSON-specific decoding options
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub options: JsonPathDeserializerOptions,
}

impl JsonPathDeserializerConfig {
    /// Creates a new `JsonPathDeserializerConfig`.
    pub fn new(config: PathOperationConfig, options: JsonPathDeserializerOptions) -> Self {
        Self { config, options }
    }

    /// Build the `JsonPathDeserializer` from this configuration.
    pub fn build(&self) -> JsonPathDeserializer {
        JsonPathDeserializer::new(&self.config, &self.options)
    }

    /// Return the type of event built by this deserializer.
    pub fn output_type(&self) -> DataType {
        DataType::Log
    }

    /// The schema produced by the deserializer.
    pub fn schema_definition(&self, log_namespace: LogNamespace) -> schema::Definition {
        match log_namespace {
            LogNamespace::Legacy => {
                schema::Definition::empty_legacy_namespace().unknown_fields(Kind::json())
            }
            LogNamespace::Vector => {
                schema::Definition::new_with_default_metadata(Kind::json(), [log_namespace])
            }
        }
    }
}

fn default_feeder_capacity() -> usize {
    8192
}

/// JSON-specific decoding options for path-based decoder.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct JsonPathDeserializerOptions {
    /// Determines whether or not to replace invalid UTF-8 sequences instead of failing.
    #[serde(
        default = "default_lossy",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    #[derivative(Default(value = "default_lossy()"))]
    pub lossy: bool,

    /// Initial capacity for the JSON feeder buffer.
    #[serde(
        default = "default_feeder_capacity",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    #[derivative(Default(value = "default_feeder_capacity()"))]
    pub feeder_capacity: usize,
}

/// Deserializer that builds `Event`s from JSON using path-based operations.
///
/// This deserializer maintains parser state across calls to support streaming,
/// allowing JSON to be split across multiple `parse()` calls.
#[derive(Clone)]
pub struct JsonPathDeserializer {
    rules: Arc<PathRules>,
    lossy: bool,
    /// Streaming parser state (wrapped in Arc<Mutex> for interior mutability)
    parser_state: Arc<std::sync::Mutex<StreamingParserState>>,
}

/// State maintained across parse() calls for streaming
struct StreamingParserState {
    parser: JsonParser<PushJsonFeeder>,
    state: ParserState,
}

impl JsonPathDeserializer {
    /// Creates a new `JsonPathDeserializer`.
    pub fn new(config: &PathOperationConfig, options: &JsonPathDeserializerOptions) -> Self {
        let rules = config
            .paths
            .iter()
            .fold(PathRules::node(false), |rules, (key, rule)| {
                rules.insert(&canonical_segments(key, &rule.wildcard), rule.op)
            });

        let feeder = PushJsonFeeder::with_capacity(options.feeder_capacity);
        let parser_options = JsonParserOptionsBuilder::default()
            .with_streaming(true)
            .build();
        let parser = JsonParser::new_with_options(feeder, parser_options);

        Self {
            rules: Arc::new(rules),
            lossy: options.lossy,
            parser_state: Arc::new(std::sync::Mutex::new(StreamingParserState {
                parser,
                state: ParserState::new(),
            })),
        }
    }
}

/// Internal state for tracking during parsing
#[derive(Debug)]
struct ParserState {
    /// Current path segments
    path: Vec<String>,
    /// Stack of values being built
    value_stack: Vec<ValueBuilder>,
    /// Events that have been emitted
    events: Vec<(String, Value)>,
    /// Depth (`path.len()`) of the array currently being exploded, if any
    explode_depth: Option<usize>,
}

#[derive(Debug)]
enum ValueBuilder {
    Object(BTreeMap<String, Value>),
    Array(Vec<Value>),
}

impl ParserState {
    fn new() -> Self {
        Self {
            path: Vec::with_capacity(8),
            value_stack: Vec::with_capacity(8),
            events: Vec::with_capacity(16),
            explode_depth: None,
        }
    }

    /// Build current path string from segments. Only called when emitting an
    /// event, so the trie lookups on the hot path stay allocation-free.
    fn current_path(&self) -> String {
        self.path.join(".")
    }

    fn push_path(&mut self, segment: String) {
        self.path.push(segment);
    }

    fn pop_path(&mut self) {
        self.path.pop();
    }
}

fn value_to_bytes(value: &Value) -> Value {
    match value {
        Value::Bytes(bytes) => Value::Bytes(bytes.clone()),
        other => Value::Bytes(other.to_string().into()),
    }
}

impl Deserializer for JsonPathDeserializer {
    fn parse(
        &self,
        bytes: Bytes,
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        if bytes.is_empty() {
            return Ok(smallvec![]);
        }

        let bytes_slice = if self.lossy {
            match std::str::from_utf8(&bytes) {
                Ok(_) => bytes.to_vec(),
                Err(_) => String::from_utf8_lossy(&bytes).into_owned().into_bytes(),
            }
        } else {
            bytes.to_vec()
        };

        let mut streaming_state = self
            .parser_state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());

        let mut byte_offset = 0usize;
        let total_len = bytes_slice.len();
        while byte_offset < total_len {
            if streaming_state.parser.feeder.is_full() {
                self.drain_parser_events(&mut streaming_state)?;
                if streaming_state.parser.feeder.is_full() {
                    return Err("JSON feeder is full and cannot accept more bytes".into());
                }
            }

            let pushed = streaming_state
                .parser
                .feeder
                .push_bytes(&bytes_slice[byte_offset..]);
            if pushed == 0 {
                return Err("JSON feeder could not accept bytes (0 bytes pushed)".into());
            }
            byte_offset += pushed;
        }

        self.drain_parser_events(&mut streaming_state)?;

        let mut result = SmallVec::new();
        let events_to_emit = std::mem::take(&mut streaming_state.state.events);

        for (expr, data) in events_to_emit {
            let mut map = vrl::value::ObjectMap::new();
            map.insert("expr".into(), Value::from(expr));
            map.insert("data".into(), data);

            let log = LogEvent::from_map(map, vector_core::event::EventMetadata::default());
            let _ = log_namespace;

            result.push(Event::Log(log));
        }

        Ok(result)
    }
}

impl JsonPathDeserializer {
    /// Process events from the parser until NeedMoreInput or None
    fn drain_parser_events(
        &self,
        streaming_state: &mut StreamingParserState,
    ) -> Result<(), String> {
        loop {
            match streaming_state
                .parser
                .next_event()
                .map_err(|e| format!("JSON parsing error: {:?}", e))?
            {
                Some(JsonEvent::NeedMoreInput) => break,
                Some(event) => {
                    self.process_event_with_streaming_state(streaming_state, event)?;
                }
                None => break,
            }
        }
        Ok(())
    }

    fn process_event_with_streaming_state(
        &self,
        streaming_state: &mut StreamingParserState,
        event: JsonEvent,
    ) -> Result<(), String> {
        self.process_event(&mut streaming_state.state, event, &streaming_state.parser)
    }

    fn process_event(
        &self,
        state: &mut ParserState,
        event: JsonEvent,
        parser: &JsonParser<PushJsonFeeder>,
    ) -> Result<(), String> {
        match event {
            JsonEvent::StartObject => {
                state
                    .value_stack
                    .push(ValueBuilder::Object(BTreeMap::new()));
            }
            JsonEvent::EndObject => {
                if let Some(ValueBuilder::Object(map)) = state.value_stack.pop() {
                    let value =
                        Value::Object(map.into_iter().map(|(k, v)| (k.into(), v)).collect());
                    self.handle_value_and_pop_if_in_object(state, value)?;
                }
            }
            JsonEvent::StartArray => {
                let should_explode = self
                    .rules
                    .lookup(&state.path)
                    .map(|node| node.op == PathOperation::Explode)
                    .unwrap_or(false);

                if should_explode && state.explode_depth.is_none() {
                    state.explode_depth = Some(state.path.len());
                }

                state.value_stack.push(ValueBuilder::Array(Vec::new()));
            }
            JsonEvent::EndArray => {
                let is_exploded = state.explode_depth == Some(state.path.len());

                if let Some(ValueBuilder::Array(arr)) = state.value_stack.pop() {
                    if is_exploded {
                        state.explode_depth = None;
                    } else {
                        self.handle_value(state, Value::Array(arr))?;
                    }
                }

                state.pop_path();
            }
            JsonEvent::FieldName => {
                let field_name = parser
                    .current_str()
                    .map_err(|e| format!("Error reading field name: {:?}", e))?
                    .to_string();
                state.push_path(field_name);
            }
            JsonEvent::ValueString => {
                let s = parser
                    .current_str()
                    .map_err(|e| format!("Error reading string: {:?}", e))?
                    .to_string();
                let value = Value::from(s);
                self.handle_value_and_pop_if_in_object(state, value)?;
            }
            JsonEvent::ValueInt => {
                let i: i64 = parser
                    .current_int()
                    .map_err(|e| format!("Error reading int: {:?}", e))?;
                let value = Value::from(i);
                self.handle_value_and_pop_if_in_object(state, value)?;
            }
            JsonEvent::ValueFloat => {
                let f: f64 = parser
                    .current_float()
                    .map_err(|e| format!("Error reading float: {:?}", e))?;
                let value = Value::from(f);
                self.handle_value_and_pop_if_in_object(state, value)?;
            }
            JsonEvent::ValueTrue => {
                self.handle_value_and_pop_if_in_object(state, Value::from(true))?;
            }
            JsonEvent::ValueFalse => {
                self.handle_value_and_pop_if_in_object(state, Value::from(false))?;
            }
            JsonEvent::ValueNull => {
                self.handle_value_and_pop_if_in_object(state, Value::Null)?;
            }
            JsonEvent::NeedMoreInput => {}
        }
        Ok(())
    }

    fn handle_value(&self, state: &mut ParserState, value: Value) -> Result<(), String> {
        let inside_exploded_array = state.explode_depth == Some(state.path.len())
            && matches!(state.value_stack.last(), Some(ValueBuilder::Array(_)));

        let is_container = matches!(value, Value::Object(_) | Value::Array(_));

        let emitted: Option<Value> = if inside_exploded_array {
            Some(value.clone())
        } else {
            match self.rules.lookup(&state.path) {
                Some(node) if node.is_wildcard && node.has_children() && is_container => None,
                Some(node) => match node.op {
                    PathOperation::Identity => Some(value.clone()),
                    PathOperation::Bytes => Some(value_to_bytes(&value)),
                    PathOperation::Explode | PathOperation::Drop => None,
                },
                None => None,
            }
        };

        if let Some(data) = emitted {
            let expr = state.current_path();
            state.events.push((expr, data));
        }

        if !inside_exploded_array {
            if let Some(parent) = state.value_stack.last_mut() {
                match parent {
                    ValueBuilder::Object(map) => {
                        if let Some(key) = state.path.last() {
                            map.insert(key.clone(), value);
                        }
                    }
                    ValueBuilder::Array(arr) => {
                        arr.push(value);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_value_and_pop_if_in_object(
        &self,
        state: &mut ParserState,
        value: Value,
    ) -> Result<(), String> {
        self.handle_value(state, value)?;
        if matches!(state.value_stack.last(), Some(ValueBuilder::Object(_))) {
            state.pop_path();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lookup::owned_value_path;

    #[test]
    fn test_identity_operation() {
        let config =
            PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"meta": {"source": "foo"}}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 1);
        let log = events[0].as_log();
        assert_eq!(log["expr"], "meta".into());
    }

    #[test]
    fn test_explode_operation() {
        let config = PathOperationConfig::new(
            owned_value_path!("results", "records"),
            PathOperation::Explode.into(),
        );
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"results": {"records": [{"log": "bar"}, {"log": "baz"}]}}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].as_log()["expr"], "results.records".into());
        assert_eq!(events[1].as_log()["expr"], "results.records".into());
    }

    #[test]
    fn test_bytes_operation() {
        let config =
            PathOperationConfig::new(owned_value_path!("tail"), PathOperation::Bytes.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"tail": "foo bar baz"}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 1);
        let log = events[0].as_log();
        assert_eq!(log["expr"], "tail".into());
    }

    #[test]
    fn test_multiple_operations() {
        let config =
            PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity.into())
                .with_rule(
                    owned_value_path!("results", "records"),
                    PathOperation::Explode.into(),
                )
                .with_rule(owned_value_path!("tail"), PathOperation::Bytes.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(
            r#"{"meta": {"source": "foo"}, "results": {"records": [{"log": "bar"}, {"log": "baz"}]}, "tail": "foo bar baz"}"#,
        );
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 4);

        let exprs: Vec<Value> = events.iter().map(|e| e.as_log()["expr"].clone()).collect();

        assert!(exprs.contains(&"meta".into()));
        assert!(
            exprs
                .iter()
                .filter(|e| *e == &Value::from("results.records"))
                .count()
                == 2
        );
        assert!(exprs.contains(&"tail".into()));
    }

    #[test]
    fn test_order_preservation() {
        let config =
            PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity.into())
                .with_rule(
                    owned_value_path!("results", "records"),
                    PathOperation::Explode.into(),
                )
                .with_rule(owned_value_path!("tail"), PathOperation::Bytes.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(
            r#"{"meta": {"source": "foo"}, "results": {"records": [{"log": "bar"}, {"log": "baz"}]}, "tail": "foo bar baz"}"#,
        );
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        let exprs: Vec<Value> = events.iter().map(|e| e.as_log()["expr"].clone()).collect();

        assert_eq!(events.len(), 4);
        assert_eq!(exprs[0], "meta".into());
        assert_eq!(exprs[1], "results.records".into());
        assert_eq!(exprs[2], "results.records".into());
        assert_eq!(exprs[3], "tail".into());
    }

    #[test]
    fn test_multiple_concatenated_json() {
        let config =
            PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity.into())
                .with_rule(
                    owned_value_path!("results", "records"),
                    PathOperation::Explode.into(),
                );
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(
            r#"{"meta": {"source": "first"}, "results": {"records": [{"log": "a"}]}}{"meta": {"source": "second"}, "results": {"records": [{"log": "b"}, {"log": "c"}]}}"#,
        );
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 5);

        let exprs: Vec<Value> = events.iter().map(|e| e.as_log()["expr"].clone()).collect();

        assert_eq!(exprs[0], "meta".into());
        assert_eq!(exprs[1], "results.records".into());
        assert_eq!(exprs[2], "meta".into());
        assert_eq!(exprs[3], "results.records".into());
        assert_eq!(exprs[4], "results.records".into());

        let first_meta = &events[0].as_log()["data"];
        let second_meta = &events[2].as_log()["data"];
        assert_ne!(first_meta, second_meta);
    }

    #[test]
    fn test_newline_delimited_json() {
        let config =
            PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity.into())
                .with_rule(
                    owned_value_path!("results", "records"),
                    PathOperation::Explode.into(),
                );
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(
            r#"{"meta": {"source": "line1"}, "results": {"records": [{"log": "x"}]}}
{"meta": {"source": "line2"}, "results": {"records": [{"log": "y"}]}}
{"meta": {"source": "line3"}, "results": {"records": [{"log": "z"}]}}"#,
        );
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 6);

        let exprs: Vec<Value> = events.iter().map(|e| e.as_log()["expr"].clone()).collect();

        for i in 0..3 {
            assert_eq!(exprs[i * 2], "meta".into());
            assert_eq!(exprs[i * 2 + 1], "results.records".into());
        }
    }

    #[test]
    fn test_streaming_maintains_state_across_calls() {
        let config =
            PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity.into())
                .with_rule(
                    owned_value_path!("results", "records"),
                    PathOperation::Explode.into(),
                );
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let chunk1 = Bytes::from(
            r#"{"meta": {"source": "first"}, "results": {"records": [{"log": {"a":"b"}}]}}"#,
        );
        let result1 = deserializer.parse(chunk1, LogNamespace::Vector).unwrap();
        assert_eq!(result1.len(), 2);

        let chunk2 = Bytes::from(
            r#"{"meta": {"source": "second"}, "results": {"records": [{"log": "b"}]}}"#,
        );
        let result2 = deserializer.parse(chunk2, LogNamespace::Vector).unwrap();
        assert_eq!(result2.len(), 2);

        assert_eq!(result1[0].as_log()["expr"], "meta".into());
        assert_eq!(result2[0].as_log()["expr"], "meta".into());
    }

    #[test]
    fn test_multiple_parse_calls_with_complete_objects() {
        let config =
            PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity.into())
                .with_rule(
                    owned_value_path!("results", "records"),
                    PathOperation::Explode.into(),
                );
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let frame1 =
            Bytes::from(r#"{"meta": {"source": "first"}, "results": {"records": [{"log": "a"}]}}"#);
        let events1 = deserializer.parse(frame1, LogNamespace::Vector).unwrap();

        assert_eq!(events1.len(), 2);
        assert_eq!(events1[0].as_log()["expr"], "meta".into());
        assert_eq!(events1[1].as_log()["expr"], "results.records".into());

        let frame2 = Bytes::from(
            r#"{"meta": {"source": "second"}, "results": {"records": [{"log": "b"}, {"log": "c"}]}}"#,
        );
        let events2 = deserializer.parse(frame2, LogNamespace::Vector).unwrap();

        assert_eq!(events2.len(), 3);
        assert_eq!(events2[0].as_log()["expr"], "meta".into());
        assert_eq!(events2[1].as_log()["expr"], "results.records".into());
        assert_eq!(events2[2].as_log()["expr"], "results.records".into());

        let first_meta = &events1[0].as_log()["data"];
        let second_meta = &events2[0].as_log()["data"];
        assert_ne!(first_meta, second_meta);
    }

    #[test]
    fn test_split_json_object_across_parse_calls() {
        let config =
            PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity.into())
                .with_rule(
                    owned_value_path!("results", "records"),
                    PathOperation::Explode.into(),
                );
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let chunk1 =
            Bytes::from(r#"{"meta": {"source": "foo"}, "results": {"records": [{"log": "ba"#);
        let result1 = deserializer.parse(chunk1, LogNamespace::Vector).unwrap();

        assert_eq!(result1.len(), 1);
        assert_eq!(result1[0].as_log()["expr"], "meta".into());

        let chunk2 = Bytes::from(r#"r"}]}}"#);
        let result2 = deserializer.parse(chunk2, LogNamespace::Vector).unwrap();

        assert_eq!(result2.len(), 1);
        assert_eq!(result2[0].as_log()["expr"], "results.records".into());

        let log_value = &result2[0].as_log()["data"];
        let obj = log_value.as_object().expect("data should be an object");
        assert_eq!(obj.get("log"), Some(&Value::from("bar")));
    }

    #[test]
    fn test_invalid_path_validation() {
        assert!(OwnedValuePath::try_from("".to_string()).is_err());
        assert!(OwnedValuePath::try_from("[0]".to_string()).is_ok());

        assert!(OwnedValuePath::try_from(".".to_string()).is_ok());
        assert!(OwnedValuePath::try_from("meta".to_string()).is_ok());
        assert!(OwnedValuePath::try_from("results.records".to_string()).is_ok());
    }

    #[test]
    fn test_empty_config_rejected() {
        let empty_map: HashMap<OwnedValuePath, PathRule> = HashMap::new();
        let result = PathOperationConfig::from_map(empty_map);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "At least one path must be configured");
    }

    #[test]
    fn test_duplicate_paths_handled() {
        let config =
            PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity.into())
                .with_rule(owned_value_path!("meta"), PathOperation::Bytes.into());

        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());
        let input = Bytes::from(r#"{"meta": "test"}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].as_log()["data"], Value::Bytes(_)));
    }

    #[test]
    fn test_multiple_arrays_at_same_depth() {
        let config =
            PathOperationConfig::new(owned_value_path!("array1"), PathOperation::Explode.into())
                .with_rule(owned_value_path!("array2"), PathOperation::Explode.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"array1": [1, 2], "array2": [3, 4, 5]}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 5);

        let array1_events: Vec<_> = events
            .iter()
            .filter(|e| e.as_log()["expr"] == "array1".into())
            .collect();
        let array2_events: Vec<_> = events
            .iter()
            .filter(|e| e.as_log()["expr"] == "array2".into())
            .collect();

        assert_eq!(array1_events.len(), 2);
        assert_eq!(array2_events.len(), 3);
    }

    #[test]
    fn test_explode_with_deeply_nested_objects() {
        let config =
            PathOperationConfig::new(owned_value_path!("events"), PathOperation::Explode.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(
            r#"{"events": [{"id": 1, "user": {"name": "Alice", "profile": {"age": 30}}}]}"#,
        );

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_log()["expr"], "events".into());

        let data = &events[0].as_log()["data"];
        let obj = data.as_object().expect("data should be an object");
        assert_eq!(obj.get("id"), Some(&Value::Integer(1)));
    }

    #[test]
    fn test_explode_primitive_array() {
        let config =
            PathOperationConfig::new(owned_value_path!("numbers"), PathOperation::Explode.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"numbers": [1, 2, 3]}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 3);

        for event in &events {
            assert_eq!(event.as_log()["expr"], "numbers".into());
        }

        assert_eq!(events[0].as_log()["data"], Value::Integer(1));
        assert_eq!(events[1].as_log()["data"], Value::Integer(2));
        assert_eq!(events[2].as_log()["data"], Value::Integer(3));
    }

    #[test]
    fn test_explode_string_array() {
        let config =
            PathOperationConfig::new(owned_value_path!("items"), PathOperation::Explode.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"items": ["a", "b", "c"]}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 3);

        assert_eq!(events[0].as_log()["data"], Value::from("a"));
        assert_eq!(events[1].as_log()["data"], Value::from("b"));
        assert_eq!(events[2].as_log()["data"], Value::from("c"));
    }

    #[test]
    fn test_explode_mixed_primitive_array() {
        let config =
            PathOperationConfig::new(owned_value_path!("mixed"), PathOperation::Explode.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"mixed": [1, "two", true, null]}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 4);

        assert_eq!(events[0].as_log()["data"], Value::Integer(1));
        assert_eq!(events[1].as_log()["data"], Value::from("two"));
        assert_eq!(events[2].as_log()["data"], Value::from(true));
        assert_eq!(events[3].as_log()["data"], Value::Null);
    }

    #[test]
    fn test_large_complex_nested_json_with_explode() {
        let config = PathOperationConfig::new(
            owned_value_path!("departments"),
            PathOperation::Identity.into(),
        )
        .with_rule(
            owned_value_path!("departments", "teams"),
            PathOperation::Explode.into(),
        )
        .with_rule(owned_value_path!("metrics"), PathOperation::Identity.into());

        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let large_json = r#"{
  "company": "Acme Corporation",
  "year": 2024,
  "metrics": {
    "revenue": 1000000,
    "employees": 250,
    "growth_rate": 0.15
  },
  "departments": {
    "name": "Engineering",
    "budget": 5000000,
    "teams": [
      {
        "team_id": 1,
        "team_name": "Backend Team",
        "location": "San Francisco",
        "members": [
          {
            "id": 101,
            "name": "Alice Johnson",
            "role": "Senior Engineer",
            "skills": ["Rust", "Python", "Docker"],
            "projects": [
              {"name": "API Gateway", "status": "active", "priority": "high"},
              {"name": "Data Pipeline", "status": "completed", "priority": "medium"}
            ]
          },
          {
            "id": 102,
            "name": "Bob Smith",
            "role": "Tech Lead",
            "skills": ["Go", "Kubernetes", "PostgreSQL"],
            "projects": [
              {"name": "Microservices", "status": "active", "priority": "critical"},
              {"name": "Monitoring", "status": "active", "priority": "high"}
            ]
          },
          {
            "id": 103,
            "name": "Carol White",
            "role": "Engineer",
            "skills": ["JavaScript", "React", "Node.js"],
            "projects": [
              {"name": "Admin Dashboard", "status": "planning", "priority": "medium"}
            ]
          }
        ],
        "quarterly_goals": {
          "q1": "Improve latency by 50%",
          "q2": "Launch new API version",
          "q3": "Scale to 10M requests/day",
          "q4": "Reduce costs by 30%"
        }
      },
      {
        "team_id": 2,
        "team_name": "Frontend Team",
        "location": "New York",
        "members": [
          {
            "id": 201,
            "name": "David Brown",
            "role": "Senior Engineer",
            "skills": ["TypeScript", "React", "GraphQL"],
            "projects": [
              {"name": "User Portal", "status": "active", "priority": "critical"},
              {"name": "Mobile App", "status": "active", "priority": "high"}
            ]
          },
          {
            "id": 202,
            "name": "Emma Davis",
            "role": "UI/UX Engineer",
            "skills": ["CSS", "Figma", "Accessibility"],
            "projects": [
              {"name": "Design System", "status": "completed", "priority": "high"}
            ]
          }
        ],
        "quarterly_goals": {
          "q1": "Redesign homepage",
          "q2": "Mobile-first approach",
          "q3": "A11y compliance",
          "q4": "Performance optimization"
        }
      },
      {
        "team_id": 3,
        "team_name": "Data Science Team",
        "location": "Austin",
        "members": [
          {
            "id": 301,
            "name": "Frank Miller",
            "role": "Data Scientist",
            "skills": ["Python", "TensorFlow", "SQL"],
            "projects": [
              {"name": "Recommendation Engine", "status": "active", "priority": "critical"},
              {"name": "Anomaly Detection", "status": "research", "priority": "medium"}
            ]
          },
          {
            "id": 302,
            "name": "Grace Lee",
            "role": "ML Engineer",
            "skills": ["PyTorch", "Kubernetes", "MLOps"],
            "projects": [
              {"name": "Model Training Pipeline", "status": "active", "priority": "high"}
            ]
          },
          {
            "id": 303,
            "name": "Henry Wilson",
            "role": "Data Analyst",
            "skills": ["R", "Tableau", "Statistics"],
            "projects": [
              {"name": "Business Intelligence", "status": "active", "priority": "medium"}
            ]
          }
        ],
        "quarterly_goals": {
          "q1": "Deploy ML model v2",
          "q2": "Real-time predictions",
          "q3": "Expand datasets by 5x",
          "q4": "Automated retraining"
        }
      }
    ]
  }
}"#;

        assert!(
            large_json.len() > 1024,
            "JSON should be larger than 1KB, got {} bytes",
            large_json.len()
        );

        let input = Bytes::from(large_json);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(
            events.len(),
            5,
            "Expected 5 events: 2 identity + 3 exploded teams"
        );

        let metrics_events: Vec<_> = events
            .iter()
            .filter(|e| e.as_log()["expr"] == "metrics".into())
            .collect();
        assert_eq!(metrics_events.len(), 1);
        let metrics_obj = metrics_events[0].as_log()["data"]
            .as_object()
            .expect("metrics data should be an object");
        assert_eq!(metrics_obj.get("revenue"), Some(&Value::Integer(1000000)));
        assert_eq!(metrics_obj.get("employees"), Some(&Value::Integer(250)));

        let dept_events: Vec<_> = events
            .iter()
            .filter(|e| e.as_log()["expr"] == "departments".into())
            .collect();
        assert_eq!(dept_events.len(), 1);
        let dept_obj = dept_events[0].as_log()["data"]
            .as_object()
            .expect("departments data should be an object");
        assert_eq!(dept_obj.get("name"), Some(&Value::from("Engineering")));
        assert_eq!(dept_obj.get("budget"), Some(&Value::Integer(5000000)));

        let team_events: Vec<_> = events
            .iter()
            .filter(|e| e.as_log()["expr"] == "departments.teams".into())
            .collect();
        assert_eq!(team_events.len(), 3, "Expected 3 exploded team events");

        let team = team_events[0].as_log()["data"]
            .as_object()
            .expect("team data should be an object");
        assert_eq!(team.get("team_id"), Some(&Value::Integer(1)));
        assert_eq!(team.get("team_name"), Some(&Value::from("Backend Team")));
        assert_eq!(team.get("location"), Some(&Value::from("San Francisco")));

        let members = team
            .get("members")
            .and_then(|v| v.as_array())
            .expect("members should be an array");
        assert_eq!(members.len(), 3, "Backend team should have 3 members");

        let member = members[0].as_object().expect("member should be an object");
        assert_eq!(member.get("id"), Some(&Value::Integer(101)));
        assert_eq!(member.get("name"), Some(&Value::from("Alice Johnson")));
        assert_eq!(member.get("role"), Some(&Value::from("Senior Engineer")));

        let skills = member
            .get("skills")
            .and_then(|v| v.as_array())
            .expect("skills should be an array");
        assert_eq!(skills.len(), 3);
        assert_eq!(skills[0], Value::from("Rust"));

        let projects = member
            .get("projects")
            .and_then(|v| v.as_array())
            .expect("projects should be an array");
        assert_eq!(projects.len(), 2);
        let project = projects[0]
            .as_object()
            .expect("project should be an object");
        assert_eq!(project.get("name"), Some(&Value::from("API Gateway")));
        assert_eq!(project.get("status"), Some(&Value::from("active")));

        let goals = team
            .get("quarterly_goals")
            .and_then(|v| v.as_object())
            .expect("quarterly_goals should be an object");
        assert_eq!(
            goals.get("q1"),
            Some(&Value::from("Improve latency by 50%"))
        );

        let team2 = team_events[1].as_log()["data"]
            .as_object()
            .expect("team data should be an object");
        assert_eq!(team2.get("team_id"), Some(&Value::Integer(2)));
        assert_eq!(team2.get("team_name"), Some(&Value::from("Frontend Team")));

        let members2 = team2
            .get("members")
            .and_then(|v| v.as_array())
            .expect("members should be an array");
        assert_eq!(members2.len(), 2, "Frontend team should have 2 members");

        let team3 = team_events[2].as_log()["data"]
            .as_object()
            .expect("team data should be an object");
        assert_eq!(team3.get("team_id"), Some(&Value::Integer(3)));
        assert_eq!(
            team3.get("team_name"),
            Some(&Value::from("Data Science Team"))
        );

        let members3 = team3
            .get("members")
            .and_then(|v| v.as_array())
            .expect("members should be an array");
        assert_eq!(members3.len(), 3, "Data Science team should have 3 members");
    }

    #[test]
    fn test_bad_json() {
        let config =
            PathOperationConfig::new(owned_value_path!("data"), PathOperation::Explode.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{invalid json}"#);

        let result = deserializer.parse(input, LogNamespace::Vector);
        assert!(result.is_err(), "Should fail on malformed JSON");
    }

    #[test]
    fn test_partial_json_then_bogus() {
        let config =
            PathOperationConfig::new(owned_value_path!("items"), PathOperation::Explode.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        // First parse with partial but valid JSON
        let input1 = Bytes::from(r#"{"items": [1"#);
        let result1 = deserializer.parse(input1, LogNamespace::Vector);
        assert!(
            result1.is_ok(),
            "Partial JSON should be accepted in streaming mode"
        );

        // Now send completely invalid JSON that cannot be parsed
        let input2 = Bytes::from(r#"xxx invalid xxx"#);
        let result2 = deserializer.parse(input2, LogNamespace::Vector);
        assert!(result2.is_err(), "Should fail on bogus continuation");
    }

    #[test]
    fn test_explode_on_non_array() {
        let config =
            PathOperationConfig::new(owned_value_path!("user"), PathOperation::Explode.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"user": {"id": 1, "name": "Alice"}}"#);

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(
            events.len(),
            0,
            "Explode on non-array should produce no events"
        );
    }

    #[test]
    fn test_normalized_path_keys_are_equivalent() {
        use crate::decoding::{Deserializer, DeserializerConfig};

        // Each inner slice is a class of keys that should normalize to the same
        // runtime key, and therefore produce identical output for the same input.
        let equivalence_classes: &[&[&str]] = &[&[".", ""], &[".meta", "meta"], &[".a.b", "a.b"]];

        let input = r#"{"meta":{"x":1},"a":{"b":42}}"#;

        for class in equivalence_classes {
            let mut counts: Vec<(String, usize)> = Vec::new();
            for key in class.iter() {
                let toml_config = format!(
                    "codec = \"json_paths\"\n[config.paths.\"{}\"]\nop = \"identity\"\n",
                    key
                );
                let cfg: DeserializerConfig = toml::from_str(&toml_config)
                    .unwrap_or_else(|e| panic!("toml parse for key {:?}: {}", key, e));
                let deser = cfg.build().unwrap();
                let events = match deser {
                    Deserializer::JsonPaths(d) => {
                        d.parse(Bytes::from(input), LogNamespace::Vector).unwrap()
                    }
                    _ => panic!("expected JsonPaths"),
                };
                counts.push((key.to_string(), events.len()));
            }
            eprintln!("class {:?}: {:?}", class, counts);
            let first = counts[0].1;
            for (key, count) in &counts {
                assert_eq!(
                    *count, first,
                    "key {:?} produced {} events, expected {} (equivalence class {:?})",
                    key, count, first, class
                );
            }
        }
    }

    #[test]
    fn test_normalized_path_keys_collision_errors() {
        use crate::decoding::DeserializerConfig;

        let toml_config = r#"
codec = "json_paths"
[config.paths.".meta"]
op = "identity"
[config.paths.meta]
op = "explode"
"#;
        let result: Result<DeserializerConfig, _> = toml::from_str(toml_config);
        assert!(result.is_err(), "duplicate path keys should be rejected");
        let err = result.unwrap_err().to_string();
        eprintln!("collision error: {}", err);
        assert!(
            err.contains("duplicate"),
            "error message should mention duplicate, got: {}",
            err
        );
    }

    #[test]
    fn test_identity_for_array() {
        let config =
            PathOperationConfig::new(owned_value_path!("items"), PathOperation::Identity.into());
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"items": [1, 2, 3, 4, 5]}"#);

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        // Find the event that contains the complete array
        let array_event = events
            .iter()
            .find(|e| {
                e.as_log()["expr"] == Value::from("items")
                    && matches!(e.as_log()["data"], Value::Array(_))
            })
            .expect("Should have an event with the full array");

        assert_eq!(array_event.as_log()["expr"], Value::from("items"));

        let arr = array_event.as_log()["data"]
            .as_array()
            .expect("data should be an array");

        assert_eq!(arr.len(), 5);
        assert_eq!(arr[0], Value::Integer(1));
        assert_eq!(arr[1], Value::Integer(2));
        assert_eq!(arr[2], Value::Integer(3));
        assert_eq!(arr[3], Value::Integer(4));
        assert_eq!(arr[4], Value::Integer(5));
    }

    fn wildcard_config(entries: &[(&str, PathOperation, &str)]) -> PathOperationConfig {
        let paths = entries
            .iter()
            .map(|(key, op, wildcard)| {
                (
                    (*key).to_string(),
                    PathRule {
                        op: *op,
                        wildcard: (*wildcard).to_string(),
                    },
                )
            })
            .collect();
        PathOperationConfig { paths }
    }

    fn parse_all(config: &PathOperationConfig, input: &str) -> Vec<(String, Value)> {
        let deserializer =
            JsonPathDeserializer::new(config, &JsonPathDeserializerOptions::default());
        deserializer
            .parse(Bytes::from(input.to_owned()), LogNamespace::Vector)
            .unwrap()
            .iter()
            .map(|event| {
                let log = event.as_log();
                (
                    log["expr"].to_string_lossy().into_owned(),
                    log["data"].clone(),
                )
            })
            .collect()
    }

    #[test]
    fn test_wildcard_identity_emits_each_scalar_child() {
        let config = wildcard_config(&[("record.*", PathOperation::Identity, "*")]);
        let events = parse_all(&config, r#"{"record": {"a": 1, "b": "two", "c": true}}"#);

        assert_eq!(
            events,
            vec![
                ("record.a".to_string(), Value::from(1)),
                ("record.b".to_string(), Value::from("two")),
                ("record.c".to_string(), Value::from(true)),
            ]
        );
    }

    #[test]
    fn test_wildcard_identity_descends_when_deeper_rule_exists() {
        let config = wildcard_config(&[
            ("record.*", PathOperation::Identity, "*"),
            ("record.*.*", PathOperation::Identity, "*"),
        ]);
        let events = parse_all(
            &config,
            r#"{"record": {"scalar": 1, "nested": {"x": 10, "y": 20}}}"#,
        );

        assert_eq!(
            events,
            vec![
                ("record.scalar".to_string(), Value::from(1)),
                ("record.nested.x".to_string(), Value::from(10)),
                ("record.nested.y".to_string(), Value::from(20)),
            ]
        );
    }

    #[test]
    fn test_wildcard_identity_leaf_emits_whole_container() {
        let config = wildcard_config(&[("record.*", PathOperation::Identity, "*")]);
        let events = parse_all(&config, r#"{"record": {"nested": {"x": 10}}}"#);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "record.nested");
        let obj = events[0].1.as_object().expect("data should be an object");
        assert_eq!(obj.get("x"), Some(&Value::from(10)));
    }

    #[test]
    fn test_concrete_identity_emits_whole_container_even_with_deeper_rule() {
        let config = wildcard_config(&[
            ("record", PathOperation::Identity, "*"),
            ("record.teams", PathOperation::Explode, "*"),
        ]);
        let events = parse_all(
            &config,
            r#"{"record": {"name": "eng", "teams": [{"id": 1}, {"id": 2}]}}"#,
        );

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].0, "record.teams");
        assert_eq!(events[1].0, "record.teams");
        assert_eq!(events[2].0, "record");
        let record = events[2].1.as_object().expect("record is object");
        assert_eq!(record.get("name"), Some(&Value::from("eng")));
        assert_eq!(record.get("teams"), None);
    }

    #[test]
    fn test_drop_shadows_wildcard_identity() {
        let config = wildcard_config(&[
            ("record.*", PathOperation::Identity, "*"),
            ("record.secret", PathOperation::Drop, "*"),
        ]);
        let events = parse_all(&config, r#"{"record": {"keep": 1, "secret": 2}}"#);

        assert_eq!(events, vec![("record.keep".to_string(), Value::from(1))]);
    }

    #[test]
    fn test_custom_wildcard_char_keeps_literal_star_usable() {
        let config = wildcard_config(&[
            ("record._", PathOperation::Identity, "_"),
            ("record.*", PathOperation::Drop, "_"),
        ]);
        let events = parse_all(&config, r#"{"record": {"*": "literal-star", "b": 2}}"#);

        assert_eq!(events, vec![("record.b".to_string(), Value::from(2))]);
    }

    #[test]
    fn test_wildcard_explode() {
        let config = wildcard_config(&[("record.*", PathOperation::Explode, "*")]);
        let events = parse_all(&config, r#"{"record": {"nums": [1, 2, 3]}}"#);

        assert_eq!(
            events,
            vec![
                ("record.nums".to_string(), Value::from(1)),
                ("record.nums".to_string(), Value::from(2)),
                ("record.nums".to_string(), Value::from(3)),
            ]
        );
    }

    #[test]
    fn test_map_form_config_parses() {
        let json = serde_json::json!({
            "paths": {
                "result.records": {"op": "explode"},
                "requestToken": {"operation": "bytes"},
            }
        });
        let config: PathOperationConfig = serde_json::from_value(json).unwrap();
        let events = parse_all(
            &config,
            r#"{"result": {"records": [{"log": "a"}, {"log": "b"}]}, "requestToken": "tok"}"#,
        );

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].0, "result.records");
        assert_eq!(events[1].0, "result.records");
        assert_eq!(events[2].0, "requestToken");
        assert!(matches!(events[2].1, Value::Bytes(_)));
    }

    #[test]
    fn test_wildcard_collision_across_wildcard_chars_rejected() {
        let json = serde_json::json!({
            "paths": {
                "a.*": {"op": "identity", "wildcard": "*"},
                "a._": {"op": "explode", "wildcard": "_"},
            }
        });
        let result: Result<PathOperationConfig, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "colliding wildcard rules should be rejected"
        );
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn test_wildcard_descend_split_across_parse_calls() {
        let config = wildcard_config(&[
            ("record.*", PathOperation::Identity, "*"),
            ("record.*.*", PathOperation::Identity, "*"),
        ]);
        let deserializer =
            JsonPathDeserializer::new(&config, &JsonPathDeserializerOptions::default());

        let chunk1 = Bytes::from(r#"{"record": {"scalar": 1, "nested": {"x": 1"#);
        let events1 = deserializer.parse(chunk1, LogNamespace::Vector).unwrap();
        assert_eq!(events1.len(), 1);
        assert_eq!(events1[0].as_log()["expr"], "record.scalar".into());

        let chunk2 = Bytes::from(r#"0}}}"#);
        let events2 = deserializer.parse(chunk2, LogNamespace::Vector).unwrap();
        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0].as_log()["expr"], "record.nested.x".into());
        assert_eq!(events2[0].as_log()["data"], Value::from(10));
    }

    #[test]
    fn test_azure_nsg_flow_logs_denormalized() {
        let config = wildcard_config(&[
            ("records.*", PathOperation::Identity, "*"),
            ("records.resourceId", PathOperation::Drop, "*"),
            ("records.*.*", PathOperation::Identity, "*"),
            ("records.*.*.*", PathOperation::Identity, "*"),
            ("records.*.*.*.*", PathOperation::Identity, "*"),
            ("records.*.*.*.flowTuples", PathOperation::Explode, "*"),
        ]);

        let input = r#"{
            "records": [
                {
                    "time": "2024-01-01T00:00:00.0000000Z",
                    "systemId": "11111111-1111-1111-1111-111111111111",
                    "category": "NetworkSecurityGroupFlowEvent",
                    "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/EXAMPLE-RG/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/EXAMPLE-NSG",
                    "operationName": "NetworkSecurityGroupFlowEvents",
                    "properties": {
                        "Version": 1,
                        "flows": [
                            {
                                "rule": "DefaultRule_AllowVnetInBound",
                                "flows": [
                                    {
                                        "mac": "AABBCCDDEE01",
                                        "flowTuples": [
                                            "1700000001,192.0.2.1,10.0.0.1,40001,443,T,I,A"
                                        ]
                                    }
                                ]
                            },
                            {
                                "rule": "UserRule_allow-ssh-inbound",
                                "flows": [
                                    {
                                        "mac": "AABBCCDDEE01",
                                        "flowTuples": [
                                            "1700000002,192.0.2.2,10.0.0.1,40002,22,T,I,A",
                                            "1700000003,192.0.2.3,10.0.0.1,40003,22,T,I,A"
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                },
                {
                    "time": "2024-06-15T12:30:45.1230000Z",
                    "systemId": "22222222-2222-2222-2222-222222222222",
                    "category": "NetworkSecurityGroupFlowEvent",
                    "resourceId": "/SUBSCRIPTIONS/99999999-9999-9999-9999-999999999999/RESOURCEGROUPS/EXAMPLE-RG-2/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/EXAMPLE-NSG-2",
                    "operationName": "NetworkSecurityGroupFlowEvents",
                    "properties": {
                        "Version": 2,
                        "flows": [
                            {
                                "rule": "DefaultRule_DenyAllInBound",
                                "flows": [
                                    {
                                        "mac": "AABBCCDDEE02",
                                        "flowTuples": [
                                            "1700000004,198.51.100.1,10.0.0.1,40004,53,U,I,D"
                                        ]
                                    }
                                ]
                            },
                            {
                                "rule": "UserRule_deny-telnet",
                                "flows": [
                                    {
                                        "mac": "AABBCCDDEE03",
                                        "flowTuples": [
                                            "1700000005,198.51.100.2,10.0.0.1,40005,23,T,I,D",
                                            "1700000006,198.51.100.3,10.0.0.1,40006,23,T,I,D",
                                            "1700000007,198.51.100.4,10.0.0.1,40007,23,T,I,D"
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }"#;

        let events = parse_all(&config, input);

        let expected: Vec<(String, Value)> = vec![
            (
                "records.time".into(),
                Value::from("2024-01-01T00:00:00.0000000Z"),
            ),
            (
                "records.systemId".into(),
                Value::from("11111111-1111-1111-1111-111111111111"),
            ),
            (
                "records.category".into(),
                Value::from("NetworkSecurityGroupFlowEvent"),
            ),
            (
                "records.operationName".into(),
                Value::from("NetworkSecurityGroupFlowEvents"),
            ),
            ("records.properties.Version".into(), Value::from(1)),
            (
                "records.properties.flows.rule".into(),
                Value::from("DefaultRule_AllowVnetInBound"),
            ),
            (
                "records.properties.flows.flows.mac".into(),
                Value::from("AABBCCDDEE01"),
            ),
            (
                "records.properties.flows.flows.flowTuples".into(),
                Value::from("1700000001,192.0.2.1,10.0.0.1,40001,443,T,I,A"),
            ),
            (
                "records.properties.flows.rule".into(),
                Value::from("UserRule_allow-ssh-inbound"),
            ),
            (
                "records.properties.flows.flows.mac".into(),
                Value::from("AABBCCDDEE01"),
            ),
            (
                "records.properties.flows.flows.flowTuples".into(),
                Value::from("1700000002,192.0.2.2,10.0.0.1,40002,22,T,I,A"),
            ),
            (
                "records.properties.flows.flows.flowTuples".into(),
                Value::from("1700000003,192.0.2.3,10.0.0.1,40003,22,T,I,A"),
            ),
            (
                "records.time".into(),
                Value::from("2024-06-15T12:30:45.1230000Z"),
            ),
            (
                "records.systemId".into(),
                Value::from("22222222-2222-2222-2222-222222222222"),
            ),
            (
                "records.category".into(),
                Value::from("NetworkSecurityGroupFlowEvent"),
            ),
            (
                "records.operationName".into(),
                Value::from("NetworkSecurityGroupFlowEvents"),
            ),
            ("records.properties.Version".into(), Value::from(2)),
            (
                "records.properties.flows.rule".into(),
                Value::from("DefaultRule_DenyAllInBound"),
            ),
            (
                "records.properties.flows.flows.mac".into(),
                Value::from("AABBCCDDEE02"),
            ),
            (
                "records.properties.flows.flows.flowTuples".into(),
                Value::from("1700000004,198.51.100.1,10.0.0.1,40004,53,U,I,D"),
            ),
            (
                "records.properties.flows.rule".into(),
                Value::from("UserRule_deny-telnet"),
            ),
            (
                "records.properties.flows.flows.mac".into(),
                Value::from("AABBCCDDEE03"),
            ),
            (
                "records.properties.flows.flows.flowTuples".into(),
                Value::from("1700000005,198.51.100.2,10.0.0.1,40005,23,T,I,D"),
            ),
            (
                "records.properties.flows.flows.flowTuples".into(),
                Value::from("1700000006,198.51.100.3,10.0.0.1,40006,23,T,I,D"),
            ),
            (
                "records.properties.flows.flows.flowTuples".into(),
                Value::from("1700000007,198.51.100.4,10.0.0.1,40007,23,T,I,D"),
            ),
        ];

        assert_eq!(events, expected);
        assert!(
            !events.iter().any(|(expr, _)| expr == "records.resourceId"),
            "resourceId must be dropped"
        );
    }

    #[test]
    fn test_wildcard_is_per_rule() {
        let config = wildcard_config(&[
            ("foo.*", PathOperation::Identity, "*"),
            ("bar.*", PathOperation::Identity, "_"),
        ]);
        let events = parse_all(
            &config,
            r#"{"foo": {"a": 1, "b": 2}, "bar": {"*": 9, "other": 8}}"#,
        );

        assert_eq!(
            events,
            vec![
                ("foo.a".to_string(), Value::from(1)),
                ("foo.b".to_string(), Value::from(2)),
                ("bar.*".to_string(), Value::from(9)),
            ]
        );
    }

    #[test]
    fn test_different_wildcard_chars_share_branch() {
        let config = wildcard_config(&[
            ("record._", PathOperation::Identity, "_"),
            ("record.*.deep", PathOperation::Explode, "*"),
        ]);
        let events = parse_all(&config, r#"{"record": {"x": 5, "grp": {"deep": [1, 2]}}}"#);

        assert_eq!(
            events,
            vec![
                ("record.x".to_string(), Value::from(5)),
                ("record.grp.deep".to_string(), Value::from(1)),
                ("record.grp.deep".to_string(), Value::from(2)),
            ]
        );
    }

    #[test]
    fn test_multichar_and_empty_wildcard() {
        let config = wildcard_config(&[("record.__ANY__", PathOperation::Identity, "__ANY__")]);
        let events = parse_all(&config, r#"{"record": {"alpha": 1, "beta": 2}}"#);
        assert_eq!(
            events,
            vec![
                ("record.alpha".to_string(), Value::from(1)),
                ("record.beta".to_string(), Value::from(2)),
            ]
        );

        let config = wildcard_config(&[("record.*", PathOperation::Identity, "")]);
        let events = parse_all(&config, r#"{"record": {"*": 7, "other": 8}}"#);
        assert_eq!(events, vec![("record.*".to_string(), Value::from(7))]);
    }

    #[test]
    fn test_literal_star_mid_path_and_with_explode() {
        let config = wildcard_config(&[("a.*.b", PathOperation::Identity, "_")]);
        let events = parse_all(&config, r#"{"a": {"*": {"b": 5}}}"#);
        assert_eq!(events, vec![("a.*.b".to_string(), Value::from(5))]);

        let config = wildcard_config(&[("record.*", PathOperation::Explode, "_")]);
        let events = parse_all(&config, r#"{"record": {"*": [1, 2, 3]}}"#);
        assert_eq!(
            events,
            vec![
                ("record.*".to_string(), Value::from(1)),
                ("record.*".to_string(), Value::from(2)),
                ("record.*".to_string(), Value::from(3)),
            ]
        );
    }

    #[test]
    fn test_wildcard_char_inside_segment_is_literal() {
        let config = wildcard_config(&[("a.b*c.d", PathOperation::Identity, "*")]);
        let events = parse_all(&config, r#"{"a": {"b*c": {"d": 7}, "other": {"d": 8}}}"#);
        assert_eq!(events, vec![("a.b*c.d".to_string(), Value::from(7))]);
    }

    #[test]
    fn test_dot_as_wildcard_is_inert() {
        let config = wildcard_config(&[("a.b", PathOperation::Identity, ".")]);
        let events = parse_all(&config, r#"{"a": {"b": 5, "c": 6}}"#);
        assert_eq!(events, vec![("a.b".to_string(), Value::from(5))]);
    }

    #[test]
    fn test_top_level_array_emits_nothing_and_does_not_underflow_path() {
        let config = wildcard_config(&[(".", PathOperation::Identity, "*")]);
        let events = parse_all(&config, r#"[1, 2, 3]"#);
        assert_eq!(events, vec![]);
    }

    #[test]
    fn test_top_level_array_does_not_corrupt_path_for_following_object() {
        let config = wildcard_config(&[("a", PathOperation::Identity, "*")]);
        let events = parse_all(&config, r#"[1, 2, 3]{"a": 5}"#);
        assert_eq!(events, vec![("a".to_string(), Value::from(5))]);
    }
}
