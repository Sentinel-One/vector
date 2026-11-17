use std::{cmp::Ordering, fmt, ops::Bound, ops::RangeBounds};

use bytes::Bytes;
use ipnet::IpNet;
use lookup::{lookup_v2::ConfigTargetPath, OwnedTargetPath};
use ordered_float::NotNan;
use regex::bytes::Regex;
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use snafu::Snafu;
use vector_config::configurable_component;
use vrl::compiler::{value::VrlValueArithmetic, ProgramInfo, Target};
use vrl::value::Value;

use crate::ipallowlist::IpNetConfig;

/// A predicate over an event, written as a tree of single-key nodes.
#[configurable_component(no_deser)]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PredicateConfig {
    /// Matches when every child matches.
    All(Vec<PredicateConfig>),

    /// Matches when at least one child matches.
    Any(Vec<PredicateConfig>),

    /// Matches when the child does not match.
    Not(Box<PredicateConfig>),

    /// Matches when the field equals the value. Integers and floats compare numerically, and a
    /// missing field equals `null`.
    Eq(ValueMatch),

    /// Matches when the field equals any of the values.
    In(ValuesMatch),

    /// Matches when the field, coerced to a number, is greater than the value.
    Gt(NumberMatch),

    /// Matches when the field, coerced to a number, is greater than or equal to the value.
    Gte(NumberMatch),

    /// Matches when the field, coerced to a number, is less than the value.
    Lt(NumberMatch),

    /// Matches when the field, coerced to a number, is less than or equal to the value.
    Lte(NumberMatch),

    /// Matches when the field, coerced to a number, lies within `[min, max]`.
    Between(RangeMatch),

    /// Matches when the field is a string containing the value.
    Contains(StringMatch),

    /// Matches when the field is a string starting with the value.
    StartsWith(StringMatch),

    /// Matches when the field is a string ending with the value.
    EndsWith(StringMatch),

    /// Matches when the field is a string in which the regular expression finds a match.
    Matches(RegexMatch),

    /// Matches when the field is a string holding an IP address inside any of the ranges.
    Cidr(CidrMatch),

    /// Matches when the field is present, even if its value is `null`.
    Exists(ConfigTargetPath),

    /// Matches when the field is an empty string, array or object.
    Empty(ConfigTargetPath),

    /// Matches when the field is a string holding valid JSON.
    Json(ConfigTargetPath),

    /// Matches when the field has the given type.
    Is(TypeMatch),
}

// Hand-written because the derived externally tagged form only accepts YAML tags (`!eq {...}`)
// when a config is deserialized straight from YAML, as `load_from_str` does; a single-key map
// reads the same in YAML, TOML and JSON.
impl<'de> Deserialize<'de> for PredicateConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(NodeVisitor)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operator {
    All,
    Any,
    Not,
    Eq,
    In,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
    Cidr,
    Exists,
    Empty,
    Json,
    Is,
}

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = PredicateConfig;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a map with exactly one predicate operator")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let op = map
            .next_key::<Operator>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let node = match op {
            Operator::All => PredicateConfig::All(map.next_value()?),
            Operator::Any => PredicateConfig::Any(map.next_value()?),
            Operator::Not => PredicateConfig::Not(map.next_value()?),
            Operator::Eq => PredicateConfig::Eq(map.next_value()?),
            Operator::In => PredicateConfig::In(map.next_value()?),
            Operator::Gt => PredicateConfig::Gt(map.next_value()?),
            Operator::Gte => PredicateConfig::Gte(map.next_value()?),
            Operator::Lt => PredicateConfig::Lt(map.next_value()?),
            Operator::Lte => PredicateConfig::Lte(map.next_value()?),
            Operator::Between => PredicateConfig::Between(map.next_value()?),
            Operator::Contains => PredicateConfig::Contains(map.next_value()?),
            Operator::StartsWith => PredicateConfig::StartsWith(map.next_value()?),
            Operator::EndsWith => PredicateConfig::EndsWith(map.next_value()?),
            Operator::Matches => PredicateConfig::Matches(map.next_value()?),
            Operator::Cidr => PredicateConfig::Cidr(map.next_value()?),
            Operator::Exists => PredicateConfig::Exists(map.next_value()?),
            Operator::Empty => PredicateConfig::Empty(map.next_value()?),
            Operator::Json => PredicateConfig::Json(map.next_value()?),
            Operator::Is => PredicateConfig::Is(map.next_value()?),
        };
        match map.next_key::<de::IgnoredAny>()? {
            Some(_) => Err(de::Error::invalid_length(2, &self)),
            None => Ok(node),
        }
    }
}

/// A field compared against a literal.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ValueMatch {
    /// The field to test.
    pub path: ConfigTargetPath,

    /// The literal to compare against.
    pub value: Literal,
}

/// A field compared against a set of literals.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ValuesMatch {
    /// The field to test.
    pub path: ConfigTargetPath,

    /// The literals to compare against.
    pub values: Vec<Literal>,
}

/// A field compared against a number.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NumberMatch {
    /// The field to test.
    pub path: ConfigTargetPath,

    /// The number to compare against.
    pub value: Number,
}

/// A field compared against an inclusive numeric range.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RangeMatch {
    /// The field to test.
    pub path: ConfigTargetPath,

    /// The lower bound, inclusive.
    pub min: Number,

    /// The upper bound, inclusive.
    pub max: Number,
}

/// A string field compared against a substring.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StringMatch {
    /// The field to test.
    pub path: ConfigTargetPath,

    /// The substring to look for. Matching is case-sensitive.
    pub value: String,
}

/// A string field searched with a regular expression.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegexMatch {
    /// The field to test.
    pub path: ConfigTargetPath,

    /// The regular expression. It may match anywhere in the string; anchor it with `^`/`$` to
    /// match the whole string.
    pub regex: String,
}

/// A string field holding an IP address, tested against IP ranges.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CidrMatch {
    /// The field to test.
    pub path: ConfigTargetPath,

    /// IP ranges in CIDR notation (e.g. `10.0.0.0/8`), or bare IP addresses.
    pub ranges: Vec<IpNetConfig>,
}

/// A field tested for its type.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TypeMatch {
    /// The field to test.
    pub path: ConfigTargetPath,

    /// The expected type.
    #[serde(rename = "type")]
    pub kind: ValueType,
}

/// A literal value.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum Literal {
    /// Null.
    Null,

    /// A boolean.
    Boolean(bool),

    /// An integer.
    Integer(i64),

    /// A float.
    Float(f64),

    /// A string.
    String(String),
}

/// A numeric literal.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq)]
#[serde(untagged)]
pub enum Number {
    /// An integer.
    Integer(i64),

    /// A float.
    Float(f64),
}

/// The type of a value.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    /// A string.
    String,

    /// An integer or a float.
    Number,

    /// An integer.
    Integer,

    /// A float.
    Float,

    /// A boolean.
    Boolean,

    /// An array.
    Array,

    /// An object.
    Object,

    /// Null, or a missing field.
    Null,

    /// A timestamp.
    Timestamp,
}

#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum PredicateError {
    #[snafu(display("`{op}` requires at least one {what}"))]
    Empty {
        op: &'static str,
        what: &'static str,
    },

    #[snafu(display("NaN is not a valid literal"))]
    NaN,

    #[snafu(display("`between` at {path}: min {min} is greater than max {max}"))]
    InvertedRange {
        path: String,
        min: String,
        max: String,
    },

    #[snafu(display("invalid regex {regex:?}: {reason}"))]
    InvalidRegex { regex: String, reason: String },
}

/// A compiled [`PredicateConfig`]: literals are converted, regexes compiled and IP ranges parsed
/// once, at build time.
#[derive(Clone, Debug)]
pub enum Predicate {
    All(Vec<Predicate>),
    Any(Vec<Predicate>),
    Not(Box<Predicate>),
    Eq(OwnedTargetPath, Value),
    In(OwnedTargetPath, Vec<Value>),
    Range(OwnedTargetPath, Bound<Num>, Bound<Num>),
    Contains(OwnedTargetPath, Bytes),
    StartsWith(OwnedTargetPath, Bytes),
    EndsWith(OwnedTargetPath, Bytes),
    Matches(OwnedTargetPath, Regex),
    Cidr(OwnedTargetPath, Vec<IpNet>),
    Exists(OwnedTargetPath),
    Empty(OwnedTargetPath),
    Json(OwnedTargetPath),
    Is(OwnedTargetPath, ValueType),
}

/// A number coerced from an event value the way VRL's `to_float` coerces it, except that integers
/// stay integers: comparing two integers is exact rather than going through `f64`, and nothing is
/// truncated the way `to_int` would truncate `5.5` to `5`.
#[derive(Clone, Copy, Debug)]
pub enum Num {
    Int(i64),
    Float(f64),
}

// The `i64 -> f64` casts are VRL's own (`to_float`), kept so results agree with VRL conditions.
#[allow(clippy::cast_precision_loss)]
impl Num {
    fn coerce(value: &Value) -> Option<Self> {
        match value {
            Value::Integer(i) => Some(Num::Int(*i)),
            Value::Float(f) => Some(Num::Float(f.into_inner())),
            Value::Boolean(b) => Some(Num::Int(i64::from(*b))),
            Value::Null => Some(Num::Int(0)),
            Value::Bytes(b) => std::str::from_utf8(b).ok().and_then(|s| {
                s.parse::<i64>().map(Num::Int).ok().or_else(|| {
                    s.parse::<f64>()
                        .ok()
                        .filter(|f| !f.is_nan())
                        .map(Num::Float)
                })
            }),
            Value::Timestamp(ts) => ts
                .timestamp_nanos_opt()
                .map(|nanos| Num::Float(nanos as f64 / 1_000_000_000_f64)),
            _ => None,
        }
    }

    fn as_f64(self) -> f64 {
        match self {
            Num::Int(i) => i as f64,
            Num::Float(f) => f,
        }
    }
}

impl From<Number> for Num {
    fn from(n: Number) -> Self {
        match n {
            Number::Integer(i) => Num::Int(i),
            Number::Float(f) => Num::Float(f),
        }
    }
}

impl PartialEq for Num {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl PartialOrd for Num {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Num::Int(a), Num::Int(b)) => Some(a.cmp(b)),
            (a, b) => a.as_f64().partial_cmp(&b.as_f64()),
        }
    }
}

impl Number {
    fn to_num(self) -> Result<Num, PredicateError> {
        match self {
            Number::Float(f) if f.is_nan() => Err(PredicateError::NaN),
            n => Ok(n.into()),
        }
    }
}

impl Literal {
    fn to_value(&self) -> Result<Value, PredicateError> {
        match self {
            Literal::Null => Ok(Value::Null),
            Literal::Boolean(b) => Ok(Value::Boolean(*b)),
            Literal::Integer(i) => Ok(Value::Integer(*i)),
            Literal::Float(f) => NotNan::new(*f)
                .map(Value::Float)
                .map_err(|_| PredicateError::NaN),
            Literal::String(s) => Ok(Value::Bytes(Bytes::copy_from_slice(s.as_bytes()))),
        }
    }
}

impl ValueType {
    fn matches(self, value: Option<&Value>) -> bool {
        match (self, value) {
            (ValueType::Null, None | Some(Value::Null)) => true,
            (_, None) | (ValueType::Null, Some(_)) => false,
            (ValueType::String, Some(v)) => v.is_bytes(),
            (ValueType::Number, Some(v)) => v.is_integer() || v.is_float(),
            (ValueType::Integer, Some(v)) => v.is_integer(),
            (ValueType::Float, Some(v)) => v.is_float(),
            (ValueType::Boolean, Some(v)) => v.is_boolean(),
            (ValueType::Array, Some(v)) => v.is_array(),
            (ValueType::Object, Some(v)) => v.is_object(),
            (ValueType::Timestamp, Some(v)) => v.is_timestamp(),
        }
    }
}

fn non_empty<T>(op: &'static str, what: &'static str, items: &[T]) -> Result<(), PredicateError> {
    if items.is_empty() {
        Err(PredicateError::Empty { op, what })
    } else {
        Ok(())
    }
}

impl TryFrom<&PredicateConfig> for Predicate {
    type Error = PredicateError;

    fn try_from(config: &PredicateConfig) -> Result<Self, Self::Error> {
        let children = |op, nodes: &[PredicateConfig]| {
            non_empty(op, "child", nodes)?;
            nodes
                .iter()
                .map(Predicate::try_from)
                .collect::<Result<Vec<_>, _>>()
        };
        let range = |m: &NumberMatch, min: fn(Num) -> Bound<Num>, max: fn(Num) -> Bound<Num>| {
            m.value
                .to_num()
                .map(|n| Predicate::Range(m.path.0.clone(), min(n), max(n)))
        };
        let unbounded = |_| Bound::Unbounded;
        let bytes = |s: &str| Bytes::copy_from_slice(s.as_bytes());

        match config {
            PredicateConfig::All(nodes) => children("all", nodes).map(Predicate::All),
            PredicateConfig::Any(nodes) => children("any", nodes).map(Predicate::Any),
            PredicateConfig::Not(node) => {
                Predicate::try_from(node.as_ref()).map(|p| Predicate::Not(Box::new(p)))
            }
            PredicateConfig::Eq(m) => m
                .value
                .to_value()
                .map(|v| Predicate::Eq(m.path.0.clone(), v)),
            PredicateConfig::In(m) => {
                non_empty("in", "value", &m.values)?;
                m.values
                    .iter()
                    .map(Literal::to_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map(|vs| Predicate::In(m.path.0.clone(), vs))
            }
            PredicateConfig::Gt(m) => range(m, Bound::Excluded, unbounded),
            PredicateConfig::Gte(m) => range(m, Bound::Included, unbounded),
            PredicateConfig::Lt(m) => range(m, unbounded, Bound::Excluded),
            PredicateConfig::Lte(m) => range(m, unbounded, Bound::Included),
            PredicateConfig::Between(m) => {
                let (min, max) = (m.min.to_num()?, m.max.to_num()?);
                if min > max {
                    Err(PredicateError::InvertedRange {
                        path: m.path.to_string(),
                        min: format!("{:?}", m.min),
                        max: format!("{:?}", m.max),
                    })
                } else {
                    Ok(Predicate::Range(
                        m.path.0.clone(),
                        Bound::Included(min),
                        Bound::Included(max),
                    ))
                }
            }
            PredicateConfig::Contains(m) => {
                Ok(Predicate::Contains(m.path.0.clone(), bytes(&m.value)))
            }
            PredicateConfig::StartsWith(m) => {
                Ok(Predicate::StartsWith(m.path.0.clone(), bytes(&m.value)))
            }
            PredicateConfig::EndsWith(m) => {
                Ok(Predicate::EndsWith(m.path.0.clone(), bytes(&m.value)))
            }
            PredicateConfig::Matches(m) => Regex::new(&m.regex)
                .map(|re| Predicate::Matches(m.path.0.clone(), re))
                .map_err(|error| PredicateError::InvalidRegex {
                    regex: m.regex.clone(),
                    reason: error.to_string(),
                }),
            PredicateConfig::Cidr(m) => {
                non_empty("cidr", "range", &m.ranges)?;
                Ok(Predicate::Cidr(
                    m.path.0.clone(),
                    m.ranges.iter().map(|r| r.0).collect(),
                ))
            }
            PredicateConfig::Exists(p) => Ok(Predicate::Exists(p.0.clone())),
            PredicateConfig::Empty(p) => Ok(Predicate::Empty(p.0.clone())),
            PredicateConfig::Json(p) => Ok(Predicate::Json(p.0.clone())),
            PredicateConfig::Is(m) => Ok(Predicate::Is(m.path.0.clone(), m.kind)),
        }
    }
}

impl PredicateConfig {
    /// # Errors
    ///
    /// Fails on an empty `all`/`any`/`in`/`cidr` list, a NaN literal, a `between` whose `min`
    /// exceeds its `max`, or an invalid regex.
    pub fn build(&self) -> Result<Predicate, PredicateError> {
        Predicate::try_from(self)
    }
}

impl Predicate {
    /// Evaluates against any VRL [`Target`], so the same predicate serves conditions (over a
    /// `VrlTarget`) and targets that resolve `%` paths to something other than event metadata.
    ///
    /// Each leaf decides on its own: a field that is unreadable, or whose type the operator cannot
    /// use, makes that leaf false. VRL instead fails the whole expression, so a fallible leaf
    /// under `any` or `not` can match here where the equivalent VRL condition would not.
    pub fn eval<T: Target + ?Sized>(&self, target: &T) -> bool {
        match self {
            Predicate::All(ps) => ps.iter().all(|p| p.eval(target)),
            Predicate::Any(ps) => ps.iter().any(|p| p.eval(target)),
            Predicate::Not(p) => !p.eval(target),
            Predicate::Eq(p, lit) => Self::field(target, p, |v| v.eq_lossy(lit)),
            Predicate::In(p, lits) => {
                Self::field(target, p, |v| lits.iter().any(|l| v.eq_lossy(l)))
            }
            Predicate::Range(p, min, max) => Self::field(target, p, |v| {
                Num::coerce(v).is_some_and(|n| (*min, *max).contains(&n))
            }),
            Predicate::Contains(p, s) => Self::string(target, p, |b| {
                s.is_empty() || b.windows(s.len()).any(|w| w == s.as_ref())
            }),
            Predicate::StartsWith(p, s) => Self::string(target, p, |b| b.starts_with(s)),
            Predicate::EndsWith(p, s) => Self::string(target, p, |b| b.ends_with(s)),
            Predicate::Matches(p, re) => Self::string(target, p, |b| re.is_match(b)),
            Predicate::Cidr(p, nets) => Self::string(target, p, |b| {
                std::str::from_utf8(b)
                    .ok()
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|ip| nets.iter().any(|n| n.contains(&ip)))
            }),
            Predicate::Exists(p) => matches!(target.target_get(p), Ok(Some(_))),
            Predicate::Empty(p) => matches!(
                target.target_get(p),
                Ok(Some(v)) if match v {
                    Value::Bytes(b) => b.is_empty(),
                    Value::Array(a) => a.is_empty(),
                    Value::Object(o) => o.is_empty(),
                    _ => false,
                }
            ),
            Predicate::Json(p) => Self::string(target, p, |b| {
                serde_json::from_slice::<serde::de::IgnoredAny>(b).is_ok()
            }),
            Predicate::Is(p, kind) => target.target_get(p).is_ok_and(|v| kind.matches(v)),
        }
    }

    /// A missing field reads as `null`, as a VRL path query does.
    fn field<T: Target + ?Sized>(
        target: &T,
        path: &OwnedTargetPath,
        f: impl FnOnce(&Value) -> bool,
    ) -> bool {
        match target.target_get(path) {
            Ok(Some(v)) => f(v),
            Ok(None) => f(&Value::Null),
            Err(_) => false,
        }
    }

    fn string<T: Target + ?Sized>(
        target: &T,
        path: &OwnedTargetPath,
        f: impl FnOnce(&[u8]) -> bool,
    ) -> bool {
        matches!(target.target_get(path), Ok(Some(Value::Bytes(b))) if f(b))
    }

    /// Every path the predicate reads, for building the [`ProgramInfo`] that tells a `VrlTarget`
    /// which metric fields to precompute.
    pub fn target_queries(&self) -> Vec<OwnedTargetPath> {
        let mut paths = Vec::new();
        self.collect_paths(&mut paths);
        paths.sort();
        paths.dedup();
        paths
    }

    fn collect_paths(&self, out: &mut Vec<OwnedTargetPath>) {
        match self {
            Predicate::All(ps) | Predicate::Any(ps) => {
                ps.iter().for_each(|p| p.collect_paths(out));
            }
            Predicate::Not(p) => p.collect_paths(out),
            Predicate::Eq(p, _)
            | Predicate::In(p, _)
            | Predicate::Range(p, _, _)
            | Predicate::Contains(p, _)
            | Predicate::StartsWith(p, _)
            | Predicate::EndsWith(p, _)
            | Predicate::Matches(p, _)
            | Predicate::Cidr(p, _)
            | Predicate::Exists(p)
            | Predicate::Empty(p)
            | Predicate::Json(p)
            | Predicate::Is(p, _) => out.push(p.clone()),
        }
    }

    pub fn program_info(&self) -> ProgramInfo {
        ProgramInfo {
            fallible: false,
            abortable: false,
            target_queries: self.target_queries(),
            target_assignments: vec![],
        }
    }
}

#[cfg(test)]
mod tests;
