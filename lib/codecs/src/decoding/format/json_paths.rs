use actson::feeder::PushJsonFeeder;
use actson::options::JsonParserOptionsBuilder;
use actson::{JsonEvent, JsonParser};
use bytes::Bytes;
use derivative::Derivative;
use lookup::OwnedValuePath;
use smallvec::{smallvec, SmallVec};
use std::collections::{BTreeMap, HashMap};
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
}


/// Configuration for path-based operations
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathOperationConfig {
    /// Map of JSON paths (as strings) to operations to perform on them.
    ///
    /// Keys may be written as `.` (root), `.meta`, or `meta`. A single
    /// leading `.` is optional and stripped on load, so `.` ≡ `""`,
    /// `.meta` ≡ `meta`, `.a.b` ≡ `a.b`. Two keys that normalize to the
    /// same value (e.g. `.meta` and `meta`) are rejected at load time.
    #[serde(deserialize_with = "deserialize_paths")]
    pub paths: BTreeMap<String, PathOperation>,
}

impl PathOperationConfig {
    /// Create a new configuration with at least one path
    pub fn new(first_path: OwnedValuePath, first_op: PathOperation) -> Self {
        let mut paths = BTreeMap::new();
        paths.insert(first_path.to_string(), first_op);
        Self { paths }
    }

    /// Add a path to the configuration (builder pattern)
    pub fn with_path(mut self, path: OwnedValuePath, operation: PathOperation) -> Self {
        self.paths.insert(path.to_string(), operation);
        self
    }

    /// Create from HashMap (fallible, for compatibility)
    pub fn from_map(paths: HashMap<OwnedValuePath, PathOperation>) -> Result<Self, String> {
        if paths.is_empty() {
            return Err("At least one path must be configured".to_string());
        }
        Ok(Self {
            paths: paths.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        })
    }

    /// Get the paths as a BTreeMap
    fn as_map(&self) -> BTreeMap<String, PathOperation> {
        self.paths.clone()
    }
}

/// Normalize a user-facing path key into the internal runtime form
/// produced by `ParserState::current_path()`.
///
/// - `.` and `""` both mean root → stored as `""`
/// - A single leading `.` on non-root keys is stripped (`.meta` → `meta`)
/// - Everything else is left as-is (including `..meta`, `meta.`, etc.)
fn normalize_config_key(k: &str) -> String {
    match k {
        "." | "" => String::new(),
        s if s.starts_with('.') => s[1..].to_string(),
        s => s.to_string(),
    }
}

fn deserialize_paths<'de, D>(de: D) -> Result<BTreeMap<String, PathOperation>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    use serde::Deserialize;

    let raw: BTreeMap<String, PathOperation> = BTreeMap::deserialize(de)?;
    let mut out: BTreeMap<String, PathOperation> = BTreeMap::new();
    let mut originals: BTreeMap<String, String> = BTreeMap::new();

    for (k, v) in raw {
        let normalized = normalize_config_key(&k);
        if let Some(prev) = originals.get(&normalized) {
            return Err(D::Error::custom(format!(
                "duplicate path key after normalization: {:?} and {:?} both map to {:?}",
                prev, k, normalized
            )));
        }
        originals.insert(normalized.clone(), k);
        out.insert(normalized, v);
    }

    Ok(out)
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
        JsonPathDeserializer::new(self.config.clone(), self.options.clone())
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
pub struct JsonPathDeserializer {
    path_map: BTreeMap<String, PathOperation>,
    lossy: bool,
    feeder_capacity: usize,
    /// Streaming parser state (wrapped in Arc<Mutex> for interior mutability).
    ///
    /// A JSON document may span several frames, so this has to persist between `parse` calls —
    /// but only within one stream. See the `Clone` impl.
    parser_state: std::sync::Arc<std::sync::Mutex<StreamingParserState>>,
}

/// Cloning yields an independent parser, not a second handle to the same one.
///
/// `Decoder` is cloned once per accepted connection (and per datagram for message-based sources),
/// so sharing the `Arc` would feed every client's bytes into a single streaming document: one
/// client's frame could complete another's half-open object, and one malformed frame would leave
/// the shared parser in an error state that no later frame from any client could recover from.
impl Clone for JsonPathDeserializer {
    fn clone(&self) -> Self {
        Self {
            path_map: self.path_map.clone(),
            lossy: self.lossy,
            feeder_capacity: self.feeder_capacity,
            parser_state: std::sync::Arc::new(std::sync::Mutex::new(Self::new_parser_state(
                self.feeder_capacity,
            ))),
        }
    }
}

/// State maintained across parse() calls for streaming
struct StreamingParserState {
    parser: JsonParser<PushJsonFeeder>,
    state: ParserState,
}

impl JsonPathDeserializer {
    /// Creates a new `JsonPathDeserializer`.
    pub fn new(config: PathOperationConfig, options: JsonPathDeserializerOptions) -> Self {
        Self {
            path_map: config.as_map(),
            lossy: options.lossy,
            feeder_capacity: options.feeder_capacity,
            parser_state: std::sync::Arc::new(std::sync::Mutex::new(Self::new_parser_state(
                options.feeder_capacity,
            ))),
        }
    }

    /// Builds a parser with no residual state.
    ///
    /// Used for a new deserializer, for each clone, and to recover after a parse error — actson's
    /// push parser cannot resynchronise once it reports a syntax error, so the only way back is a
    /// new parser.
    fn new_parser_state(feeder_capacity: usize) -> StreamingParserState {
        let feeder = PushJsonFeeder::with_capacity(feeder_capacity);
        let parser_options = JsonParserOptionsBuilder::default()
            .with_streaming(true)
            .build();
        StreamingParserState {
            parser: JsonParser::new_with_options(feeder, parser_options),
            state: ParserState::new(),
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
    /// Track the path of the array that should be exploded
    explode_path: Option<String>,
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
            explode_path: None,
        }
    }

    /// Build current path string from segments
    fn current_path(&self) -> String {
        if self.path.is_empty() {
            String::new()
        } else {
            self.path.join(".")
        }
    }

    fn push_path(&mut self, segment: String) {
        self.path.push(segment);
    }

    fn pop_path(&mut self) {
        self.path.pop();
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

        // Any failure below leaves actson in an error state and `ParserState.path` /
        // `value_stack` holding fragments of the half-parsed document. actson's push parser cannot
        // resynchronise after a syntax error, and `Error::ParsingError` is continuable, so without
        // this the source would keep calling a permanently wrecked parser: every later frame on
        // this stream fails or decodes against stale path residue. Discard the state so the next
        // frame starts from a clean parser.
        let result = self.parse_frame(&mut streaming_state, &bytes_slice, log_namespace);
        if result.is_err() {
            *streaming_state = Self::new_parser_state(self.feeder_capacity);
        }
        result
    }
}

impl JsonPathDeserializer {
    fn parse_frame(
        &self,
        streaming_state: &mut StreamingParserState,
        bytes_slice: &[u8],
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        let mut byte_offset = 0usize;
        let total_len = bytes_slice.len();
        while byte_offset < total_len {
            if streaming_state.parser.feeder.is_full() {
                self.drain_parser_events(streaming_state)?;
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

        self.drain_parser_events(streaming_state)?;

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
    fn drain_parser_events(&self, streaming_state: &mut StreamingParserState) -> Result<(), String> {
        loop {
            match streaming_state.parser.next_event().map_err(|e| format!("JSON parsing error: {:?}", e))? {
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
                state.value_stack.push(ValueBuilder::Object(BTreeMap::new()));
            }
            JsonEvent::EndObject => {
                if let Some(ValueBuilder::Object(map)) = state.value_stack.pop() {
                    let value = Value::Object(map.into_iter().map(|(k, v)| (k.into(), v)).collect());
                    self.handle_value_and_pop_if_in_object(state, value)?;
                }
            }
            JsonEvent::StartArray => {
                let current_path = state.current_path();
                let should_explode = self
                    .path_map
                    .get(&current_path)
                    .map(|op| *op == PathOperation::Explode)
                    .unwrap_or(false);

                if should_explode && state.explode_path.is_none() {
                    state.explode_path = Some(current_path.clone());
                }

                state.value_stack.push(ValueBuilder::Array(Vec::new()));
            }
            JsonEvent::EndArray => {
                let should_pop_path = !state.path.is_empty();
                let current_path_owned = state.current_path().to_owned();
                let is_exploded = state.explode_path.as_ref().map(|s| s.as_str()) == Some(current_path_owned.as_str());

                if let Some(ValueBuilder::Array(arr)) = state.value_stack.pop() {
                    if is_exploded {
                        state.explode_path = None;
                    } else {
                        let value = Value::Array(arr);
                        self.handle_value(state, value)?;
                    }
                }

                if should_pop_path {
                    state.pop_path();
                }
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
        let current_path = state.current_path();
        let operation = self.path_map.get(&current_path).copied();

        let inside_exploded_array = state.explode_path.as_ref().map(|s| s.as_str()) == Some(current_path.as_str())
            && matches!(state.value_stack.last(), Some(ValueBuilder::Array(_)));

        if inside_exploded_array {
            state.events.push((current_path.clone(), value.clone()));
        } else if let Some(operation) = operation {
            match operation {
                PathOperation::Identity => {
                    state.events.push((current_path.clone(), value.clone()));
                }
                PathOperation::Bytes => {
                    let bytes_value = match &value {
                        Value::Bytes(b) => Value::Bytes(b.clone()),
                        v => {
                            let s = v.to_string();
                            Value::Bytes(s.into())
                        }
                    };
                    state.events.push((current_path.clone(), bytes_value));
                }
                PathOperation::Explode => {
                    // Don't emit the array itself, elements are emitted above
                }
            }
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

    fn handle_value_and_pop_if_in_object(&self, state: &mut ParserState, value: Value) -> Result<(), String> {
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
        let config = PathOperationConfig::new(
            owned_value_path!("meta"),
            PathOperation::Identity,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"meta": {"source": "foo"}}"#);
        let events = deserializer
            .parse(input, LogNamespace::Vector)
            .unwrap();

        assert_eq!(events.len(), 1);
        let log = events[0].as_log();
        assert_eq!(log["expr"], "meta".into());
    }

    #[test]
    fn test_explode_operation() {
        let config = PathOperationConfig::new(
            owned_value_path!("results", "records"),
            PathOperation::Explode,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input =
            Bytes::from(r#"{"results": {"records": [{"log": "bar"}, {"log": "baz"}]}}"#);
        let events = deserializer
            .parse(input, LogNamespace::Vector)
            .unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].as_log()["expr"], "results.records".into());
        assert_eq!(events[1].as_log()["expr"], "results.records".into());
    }

    #[test]
    fn test_bytes_operation() {
        let config = PathOperationConfig::new(
            owned_value_path!("tail"),
            PathOperation::Bytes,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"tail": "foo bar baz"}"#);
        let events = deserializer
            .parse(input, LogNamespace::Vector)
            .unwrap();

        assert_eq!(events.len(), 1);
        let log = events[0].as_log();
        assert_eq!(log["expr"], "tail".into());
    }

    #[test]
    fn test_multiple_operations() {
        let config = PathOperationConfig::new(
            owned_value_path!("meta"),
            PathOperation::Identity,
        )
        .with_path(owned_value_path!("results", "records"), PathOperation::Explode)
        .with_path(owned_value_path!("tail"), PathOperation::Bytes);
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input = Bytes::from(
            r#"{"meta": {"source": "foo"}, "results": {"records": [{"log": "bar"}, {"log": "baz"}]}, "tail": "foo bar baz"}"#,
        );
        let events = deserializer
            .parse(input, LogNamespace::Vector)
            .unwrap();

        assert_eq!(events.len(), 4);

        let exprs: Vec<Value> = events
            .iter()
            .map(|e| e.as_log()["expr"].clone())
            .collect();

        assert!(exprs.contains(&"meta".into()));
        assert!(exprs.iter().filter(|e| *e == &Value::from("results.records")).count() == 2);
        assert!(exprs.contains(&"tail".into()));
    }

    #[test]
    fn test_order_preservation() {
        let config = PathOperationConfig::new(
            owned_value_path!("meta"),
            PathOperation::Identity,
        )
        .with_path(owned_value_path!("results", "records"), PathOperation::Explode)
        .with_path(owned_value_path!("tail"), PathOperation::Bytes);
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input = Bytes::from(
            r#"{"meta": {"source": "foo"}, "results": {"records": [{"log": "bar"}, {"log": "baz"}]}, "tail": "foo bar baz"}"#,
        );
        let events = deserializer
            .parse(input, LogNamespace::Vector)
            .unwrap();

        let exprs: Vec<Value> = events
            .iter()
            .map(|e| e.as_log()["expr"].clone())
            .collect();

        assert_eq!(events.len(), 4);
        assert_eq!(exprs[0], "meta".into());
        assert_eq!(exprs[1], "results.records".into());
        assert_eq!(exprs[2], "results.records".into());
        assert_eq!(exprs[3], "tail".into());
    }

    #[test]
    fn test_multiple_concatenated_json() {
        let config = PathOperationConfig::new(
            owned_value_path!("meta"),
            PathOperation::Identity,
        )
        .with_path(owned_value_path!("results", "records"), PathOperation::Explode);
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input = Bytes::from(
            r#"{"meta": {"source": "first"}, "results": {"records": [{"log": "a"}]}}{"meta": {"source": "second"}, "results": {"records": [{"log": "b"}, {"log": "c"}]}}"#,
        );
        let events = deserializer
            .parse(input, LogNamespace::Vector)
            .unwrap();

        assert_eq!(events.len(), 5);

        let exprs: Vec<Value> = events
            .iter()
            .map(|e| e.as_log()["expr"].clone())
            .collect();

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
        let config = PathOperationConfig::new(
            owned_value_path!("meta"),
            PathOperation::Identity,
        )
        .with_path(owned_value_path!("results", "records"), PathOperation::Explode);
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input = Bytes::from(
            r#"{"meta": {"source": "line1"}, "results": {"records": [{"log": "x"}]}}
{"meta": {"source": "line2"}, "results": {"records": [{"log": "y"}]}}
{"meta": {"source": "line3"}, "results": {"records": [{"log": "z"}]}}"#,
        );
        let events = deserializer
            .parse(input, LogNamespace::Vector)
            .unwrap();

        assert_eq!(events.len(), 6);

        let exprs: Vec<Value> = events
            .iter()
            .map(|e| e.as_log()["expr"].clone())
            .collect();

        for i in 0..3 {
            assert_eq!(exprs[i * 2], "meta".into());
            assert_eq!(exprs[i * 2 + 1], "results.records".into());
        }
    }

    #[test]
    fn test_streaming_maintains_state_across_calls() {
        let config = PathOperationConfig::new(
            owned_value_path!("meta"),
            PathOperation::Identity,
        )
        .with_path(owned_value_path!("results", "records"), PathOperation::Explode);
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let chunk1 = Bytes::from(r#"{"meta": {"source": "first"}, "results": {"records": [{"log": {"a":"b"}}]}}"#);
        let result1 = deserializer.parse(chunk1, LogNamespace::Vector).unwrap();
        assert_eq!(result1.len(), 2);

        let chunk2 = Bytes::from(r#"{"meta": {"source": "second"}, "results": {"records": [{"log": "b"}]}}"#);
        let result2 = deserializer.parse(chunk2, LogNamespace::Vector).unwrap();
        assert_eq!(result2.len(), 2);

        assert_eq!(result1[0].as_log()["expr"], "meta".into());
        assert_eq!(result2[0].as_log()["expr"], "meta".into());
    }

    #[test]
    fn test_multiple_parse_calls_with_complete_objects() {
        let config = PathOperationConfig::new(
            owned_value_path!("meta"),
            PathOperation::Identity,
        )
        .with_path(owned_value_path!("results", "records"), PathOperation::Explode);
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let frame1 = Bytes::from(
            r#"{"meta": {"source": "first"}, "results": {"records": [{"log": "a"}]}}"#,
        );
        let events1 = deserializer
            .parse(frame1, LogNamespace::Vector)
            .unwrap();

        assert_eq!(events1.len(), 2);
        assert_eq!(events1[0].as_log()["expr"], "meta".into());
        assert_eq!(events1[1].as_log()["expr"], "results.records".into());

        let frame2 = Bytes::from(
            r#"{"meta": {"source": "second"}, "results": {"records": [{"log": "b"}, {"log": "c"}]}}"#,
        );
        let events2 = deserializer
            .parse(frame2, LogNamespace::Vector)
            .unwrap();

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
        let config = PathOperationConfig::new(
            owned_value_path!("meta"),
            PathOperation::Identity,
        )
        .with_path(owned_value_path!("results", "records"), PathOperation::Explode);
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let chunk1 = Bytes::from(r#"{"meta": {"source": "foo"}, "results": {"records": [{"log": "ba"#);
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
        let empty_map: HashMap<OwnedValuePath, PathOperation> = HashMap::new();
        let result = PathOperationConfig::from_map(empty_map);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "At least one path must be configured");
    }

    #[test]
    fn test_duplicate_paths_handled() {
        let config = PathOperationConfig::new(
            owned_value_path!("meta"),
            PathOperation::Identity,
        )
        .with_path(owned_value_path!("meta"), PathOperation::Bytes);

        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());
        let input = Bytes::from(r#"{"meta": "test"}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].as_log()["data"], Value::Bytes(_)));
    }

    #[test]
    fn test_multiple_arrays_at_same_depth() {
        let config = PathOperationConfig::new(
            owned_value_path!("array1"),
            PathOperation::Explode,
        )
        .with_path(owned_value_path!("array2"), PathOperation::Explode);
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

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
        let config = PathOperationConfig::new(
            owned_value_path!("events"),
            PathOperation::Explode,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

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
        let config = PathOperationConfig::new(
            owned_value_path!("numbers"),
            PathOperation::Explode,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

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
        let config = PathOperationConfig::new(
            owned_value_path!("items"),
            PathOperation::Explode,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"items": ["a", "b", "c"]}"#);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 3);

        assert_eq!(events[0].as_log()["data"], Value::from("a"));
        assert_eq!(events[1].as_log()["data"], Value::from("b"));
        assert_eq!(events[2].as_log()["data"], Value::from("c"));
    }

    #[test]
    fn test_explode_mixed_primitive_array() {
        let config = PathOperationConfig::new(
            owned_value_path!("mixed"),
            PathOperation::Explode,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

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
            PathOperation::Identity,
        )
        .with_path(owned_value_path!("departments", "teams"), PathOperation::Explode)
        .with_path(owned_value_path!("metrics"), PathOperation::Identity);

        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

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

        assert!(large_json.len() > 1024, "JSON should be larger than 1KB, got {} bytes", large_json.len());

        let input = Bytes::from(large_json);
        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();

        assert_eq!(events.len(), 5, "Expected 5 events: 2 identity + 3 exploded teams");

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

        let members = team.get("members")
            .and_then(|v| v.as_array())
            .expect("members should be an array");
        assert_eq!(members.len(), 3, "Backend team should have 3 members");

        let member = members[0].as_object().expect("member should be an object");
        assert_eq!(member.get("id"), Some(&Value::Integer(101)));
        assert_eq!(member.get("name"), Some(&Value::from("Alice Johnson")));
        assert_eq!(member.get("role"), Some(&Value::from("Senior Engineer")));

        let skills = member.get("skills")
            .and_then(|v| v.as_array())
            .expect("skills should be an array");
        assert_eq!(skills.len(), 3);
        assert_eq!(skills[0], Value::from("Rust"));

        let projects = member.get("projects")
            .and_then(|v| v.as_array())
            .expect("projects should be an array");
        assert_eq!(projects.len(), 2);
        let project = projects[0].as_object().expect("project should be an object");
        assert_eq!(project.get("name"), Some(&Value::from("API Gateway")));
        assert_eq!(project.get("status"), Some(&Value::from("active")));

        let goals = team.get("quarterly_goals")
            .and_then(|v| v.as_object())
            .expect("quarterly_goals should be an object");
        assert_eq!(goals.get("q1"), Some(&Value::from("Improve latency by 50%")));

        let team2 = team_events[1].as_log()["data"]
            .as_object()
            .expect("team data should be an object");
        assert_eq!(team2.get("team_id"), Some(&Value::Integer(2)));
        assert_eq!(team2.get("team_name"), Some(&Value::from("Frontend Team")));

        let members2 = team2.get("members")
            .and_then(|v| v.as_array())
            .expect("members should be an array");
        assert_eq!(members2.len(), 2, "Frontend team should have 2 members");

        let team3 = team_events[2].as_log()["data"]
            .as_object()
            .expect("team data should be an object");
        assert_eq!(team3.get("team_id"), Some(&Value::Integer(3)));
        assert_eq!(team3.get("team_name"), Some(&Value::from("Data Science Team")));

        let members3 = team3.get("members")
            .and_then(|v| v.as_array())
            .expect("members should be an array");
        assert_eq!(members3.len(), 3, "Data Science team should have 3 members");

    }

    #[test]
    fn test_bad_json() {
        let config = PathOperationConfig::new(
            owned_value_path!("data"),
            PathOperation::Explode,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{invalid json}"#);

        let result = deserializer.parse(input, LogNamespace::Vector);
        assert!(result.is_err(), "Should fail on malformed JSON");
    }

    #[test]
    fn test_partial_json_then_bogus() {
        let config = PathOperationConfig::new(
            owned_value_path!("items"),
            PathOperation::Explode,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        // First parse with partial but valid JSON
        let input1 = Bytes::from(r#"{"items": [1"#);
        let result1 = deserializer.parse(input1, LogNamespace::Vector);
        assert!(result1.is_ok(), "Partial JSON should be accepted in streaming mode");

        // Now send completely invalid JSON that cannot be parsed
        let input2 = Bytes::from(r#"xxx invalid xxx"#);
        let result2 = deserializer.parse(input2, LogNamespace::Vector);
        assert!(result2.is_err(), "Should fail on bogus continuation");
    }

    #[test]
    fn test_explode_on_non_array() {
        let config = PathOperationConfig::new(
            owned_value_path!("user"),
            PathOperation::Explode,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

        let input = Bytes::from(r#"{"user": {"id": 1, "name": "Alice"}}"#);

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 0, "Explode on non-array should produce no events");
    }

    #[test]
    fn test_normalized_path_keys_are_equivalent() {
        use crate::decoding::{Deserializer, DeserializerConfig};

        // Each inner slice is a class of keys that should normalize to the same
        // runtime key, and therefore produce identical output for the same input.
        let equivalence_classes: &[&[&str]] = &[
            &[".", ""],
            &[".meta", "meta"],
            &[".a.b", "a.b"],
        ];

        let input = r#"{"meta":{"x":1},"a":{"b":42}}"#;

        for class in equivalence_classes {
            let mut counts: Vec<(String, usize)> = Vec::new();
            for key in class.iter() {
                let toml_config = format!(
                    "codec = \"json_paths\"\n[config.paths]\n\"{}\" = \"identity\"\n",
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
[config.paths]
".meta" = "identity"
"meta" = "explode"
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
        let config = PathOperationConfig::new(
            owned_value_path!("items"),
            PathOperation::Identity,
        );
        let deserializer = JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default());

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

    // ---- parser isolation and recovery (OBE-11567) --------------------------------------------

    fn test_deserializer() -> JsonPathDeserializer {
        let config = PathOperationConfig::new(owned_value_path!("meta"), PathOperation::Identity);
        JsonPathDeserializer::new(config, JsonPathDeserializerOptions::default())
    }

    fn parse_ok(d: &JsonPathDeserializer, raw: &str) -> usize {
        d.parse(Bytes::from(raw.to_owned()), LogNamespace::Vector)
            .expect("should parse")
            .len()
    }

    /// A clone is a separate parser, not another handle to the same one.
    ///
    /// `Decoder` is cloned per connection, so a shared parser would let one client's bytes land in
    /// the middle of another client's document.
    #[test]
    fn clones_do_not_share_parser_state() {
        let first = test_deserializer();
        let second = first.clone();

        // `first` is left mid-document, with an unterminated object.
        assert_eq!(parse_ok(&first, r#"{"meta": {"source": "#), 0);

        // `second` must see a clean parser: a whole document decodes normally.
        assert_eq!(
            parse_ok(&second, r#"{"meta": {"source": "foo"}}"#),
            1,
            "a clone inherited another parser's half-open document"
        );
    }

    /// The mirror of the above: one client's bytes must not be able to complete another's
    /// half-open object, which would forge an event out of two senders' data.
    #[test]
    fn a_clone_cannot_complete_another_clones_document() {
        let victim = test_deserializer();
        let attacker = victim.clone();

        assert_eq!(parse_ok(&victim, r#"{"meta": {"source": "#), 0);

        // On a shared parser these bytes would close the victim's half-open object and emit an
        // event stitched from two senders. On its own the fragment is not valid JSON, so an error
        // is the expected outcome; what matters is that no event is produced either way.
        let emitted = attacker
            .parse(Bytes::from(r#""spoofed"}}"#), LogNamespace::Vector)
            .map(|events| events.len())
            .unwrap_or(0);
        assert_eq!(
            emitted, 0,
            "one clone completed another clone's document, forging an event"
        );
    }

    /// A malformed frame must not wedge the parser: actson cannot resynchronise after a syntax
    /// error, and parse errors are continuable, so without a reset every later frame on this
    /// stream would fail forever.
    #[test]
    fn parser_recovers_after_a_malformed_frame() {
        let deserializer = test_deserializer();

        assert_eq!(parse_ok(&deserializer, r#"{"meta": {"source": "foo"}}"#), 1);

        assert!(
            deserializer
                .parse(Bytes::from("xxx not json xxx"), LogNamespace::Vector)
                .is_err(),
            "a malformed frame should be reported as an error"
        );

        assert_eq!(
            parse_ok(&deserializer, r#"{"meta": {"source": "bar"}}"#),
            1,
            "the parser stayed wedged after a malformed frame"
        );
    }

    /// Residue from an abandoned document must not leak into the next one — a disconnect
    /// mid-object leaves `path` and `value_stack` populated.
    #[test]
    fn abandoned_document_does_not_corrupt_the_next_one() {
        let deserializer = test_deserializer();

        assert_eq!(parse_ok(&deserializer, r#"{"meta": {"source": "#), 0);
        assert!(deserializer
            .parse(Bytes::from("!!!"), LogNamespace::Vector)
            .is_err());

        let events = deserializer
            .parse(
                Bytes::from(r#"{"meta": {"source": "clean"}}"#),
                LogNamespace::Vector,
            )
            .expect("should parse after the reset");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_log()["expr"], "meta".into());
    }

    /// The feature must survive the fix: a document split across frames still decodes within one
    /// parser. Isolation must not be achieved by simply resetting on every call.
    #[test]
    fn a_document_split_across_frames_still_decodes() {
        let deserializer = test_deserializer();

        assert_eq!(parse_ok(&deserializer, r#"{"meta": {"sou"#), 0);
        assert_eq!(
            parse_ok(&deserializer, r#"rce": "foo"}}"#),
            1,
            "streaming across frames broke"
        );
    }

}
