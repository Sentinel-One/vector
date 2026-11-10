use std::{cell::RefCell, fmt};

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use vector_config::{
    configurable_component,
    schema::{SchemaGenerator, SchemaObject},
    Configurable, GenerateError, Metadata, ToValue,
};
use vector_core::predicate::PredicateConfig;

/// A path into the event (`.field`), a register (`%name.field`) or the event's metadata
/// (`%meta.field`).
pub type Ref = lookup::lookup_v2::ConfigTargetPath;

/// An action the assembler applies to each event, in order.
#[configurable_component(no_deser)]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionConfig {
    /// Deep-merges `from` into `to`: objects merge key by key, everything else (including arrays,
    /// unless `zip` is set) is replaced by the value from `from`.
    Merge(MergeConfig),

    /// Pushes `from` onto the array at `to`, creating the array if `to` is missing or null.
    Append(AppendConfig),

    /// Emits `from` as a new event, ahead of the event being processed.
    Emit(EmitConfig),

    /// Sets `to` to `value`, or removes it when `value` is not given.
    Reset(ResetConfig),

    /// Runs `do` once per element of the array at `target`, with `.` referring to the element.
    Foreach(ForeachConfig),

    /// Runs `then` if `when` matches, `else` otherwise.
    If(IfConfig),

    /// Drops the event being processed and ends processing it.
    Stop,
}

/// Merges one value into another.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MergeConfig {
    /// The value to merge. Nothing happens if it is missing or null, which is logged
    /// and counted in `assembler_missing_from_total`.
    pub from: Ref,

    /// Where to merge it.
    pub to: Ref,

    /// Removes `from` instead of copying it.
    #[serde(rename = "move")]
    pub move_: bool,

    /// Merges arrays element by element instead of replacing them.
    #[serde(default)]
    pub zip: bool,

    /// Merges into `to.<key>`, where `<key>` is the string read from this path. The key is used
    /// as a single field name, never parsed as a path.
    #[serde(default)]
    pub key: Option<Ref>,
}

/// Appends a value to an array.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppendConfig {
    /// The value to append. Nothing happens if it is missing or null, which is logged
    /// and counted in `assembler_missing_from_total`.
    pub from: Ref,

    /// The array to append to.
    pub to: Ref,

    /// Removes `from` instead of copying it.
    #[serde(rename = "move")]
    pub move_: bool,
}

/// Emits a value as a new event.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EmitConfig {
    /// The value to emit. Nothing is emitted if it is missing or null, which is logged
    /// and counted in `assembler_missing_from_total`.
    pub from: Ref,

    /// Removes `from` instead of copying it.
    #[serde(rename = "move")]
    pub move_: bool,
}

/// Sets or removes a value.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResetConfig {
    /// The path to set.
    pub to: Ref,

    /// The value to set. The path is removed when this is not given.
    #[serde(default)]
    pub value: Option<JsonValue>,
}

/// Iterates over an array.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForeachConfig {
    /// The array to iterate. Nothing happens if it is missing or null.
    pub target: Ref,

    /// The actions to run for each element. Inside them `.` is the element; they may not touch
    /// `target` or any path above or below it.
    #[serde(rename = "do")]
    pub actions: Vec<ActionConfig>,
}

/// Branches on a predicate.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IfConfig {
    /// The predicate to test. `%name` paths read registers and `%meta` paths read metadata.
    pub when: PredicateConfig,

    /// The actions to run when `when` matches.
    #[serde(default)]
    pub then: Vec<ActionConfig>,

    /// The actions to run when `when` does not match.
    #[serde(default, rename = "else")]
    pub else_: Vec<ActionConfig>,
}

/// Any JSON value.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonValue(pub serde_json::Value);

impl Configurable for JsonValue {
    fn metadata() -> Metadata {
        Metadata::with_description("Any JSON value.")
    }

    fn generate_schema(_: &RefCell<SchemaGenerator>) -> Result<SchemaObject, GenerateError> {
        Ok(SchemaObject::default())
    }
}

impl ToValue for JsonValue {
    fn to_value(&self) -> serde_json::Value {
        self.0.clone()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

// Hand-written for the same reason as `PredicateConfig`'s: a single-key map (or the bare string
// `stop`) reads the same whether a config is deserialized from YAML, TOML or JSON.
impl<'de> Deserialize<'de> for ActionConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ActionVisitor)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Merge,
    Append,
    Emit,
    Reset,
    Foreach,
    If,
    Stop,
}

struct ActionVisitor;

impl<'de> Visitor<'de> for ActionVisitor {
    type Value = ActionConfig;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("`stop`, or a map with exactly one action")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        match v {
            "stop" => Ok(ActionConfig::Stop),
            other => Err(E::invalid_value(de::Unexpected::Str(other), &self)),
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let action = map
            .next_key::<Action>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let config = match action {
            Action::Merge => ActionConfig::Merge(map.next_value()?),
            Action::Append => ActionConfig::Append(map.next_value()?),
            Action::Emit => ActionConfig::Emit(map.next_value()?),
            Action::Reset => ActionConfig::Reset(map.next_value()?),
            Action::Foreach => ActionConfig::Foreach(map.next_value()?),
            Action::If => ActionConfig::If(map.next_value()?),
            Action::Stop => map.next_value::<NoParams>().map(|_| ActionConfig::Stop)?,
        };
        match map.next_key::<de::IgnoredAny>()? {
            Some(_) => Err(de::Error::invalid_length(2, &self)),
            None => Ok(config),
        }
    }
}
