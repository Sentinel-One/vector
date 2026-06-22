use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use ordered_float::NotNan;
use vector_lib::config::LogNamespace;
use vector_lib::configurable::{configurable_component, ConfigurableString};
use vector_lib::event::{TargetEvents, VrlTarget};
use vector_lib::{event::Event, lookup::lookup_v2::ConfigTargetPath};
use vrl::compiler::{ProgramInfo, Target};
use vrl::core::Value;
use vrl::path::OwnedTargetPath;

use crate::conditions::{Condition, ConditionalConfig};

/// Timestamp literal
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(try_from = "String", into = "String")]
pub struct TsLit {
    dt: DateTime<Utc>,
    repr: String,
}

impl TsLit {
    pub fn from_dt(dt: DateTime<Utc>) -> Self {
        Self { repr: dt.to_rfc3339(), dt }
    }
}

impl TryFrom<String> for TsLit {
    type Error = chrono::ParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let dt = DateTime::parse_from_rfc3339(&s)?.with_timezone(&Utc);
        Ok(Self { dt, repr: s })
    }
}

impl From<TsLit> for String {
    fn from(t: TsLit) -> Self { t.repr }
}

// Equality and hashing key on the parsed instant; the `repr` is just a
// pre-computed byte-comparison aid and may differ for the same instant
// (e.g. `...Z` vs `...+00:00`).
impl PartialEq for TsLit {
    fn eq(&self, other: &Self) -> bool { self.dt == other.dt }
}

impl Eq for TsLit {}

impl Hash for TsLit {
    fn hash<H: Hasher>(&self, state: &mut H) { self.dt.hash(state); }
}

impl fmt::Display for TsLit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.repr)
    }
}

impl ConfigurableString for TsLit {}

/// Literal to use in equality predicate
#[configurable_component]
#[derive(PartialEq, Debug, Clone)]
#[serde(deny_unknown_fields, untagged)]
pub enum Constant {
    /// Timestamp (UTC).
    ///
    /// Listed first so that RFC 3339 strings parse as timestamps; otherwise
    /// the untagged deserializer would intercept them as `String`.
    Timestamp(TsLit),

    /// Represents a UTF8 String.
    String(String),

    /// Integer.
    Integer(i64),

    /// Float - not NaN.
    Float(f64),

    /// Boolean.
    Boolean(bool),

    /// Null.
    Null,
}

impl Eq for Constant {}

impl PartialEq<Value> for Constant {
    fn eq(&self, v: &Value) -> bool {
        match (self, v) {
            (Constant::String(c), Value::Bytes(v)) =>  v.eq(c.as_bytes()),
            (Constant::Timestamp(c), Value::Bytes(v)) => v.eq(c.repr.as_bytes()),
            (Constant::Timestamp(c), Value::Timestamp(v)) => &c.dt == v,
            (Constant::Float(c), Value::Float(v)) => v == c,
            (Constant::Integer(c), Value::Integer(v)) => c == v,
            (Constant::Boolean(c), Value::Boolean(v)) => c == v,
            (Constant::Null, Value::Null) => true,
            _ => false,
        }
    }
}

impl Constant {
    /// True unless this clause cannot participate in the fast-path index
    /// (currently only `Float(NaN)` violates the precondition).
    pub(crate) fn is_indexable(&self) -> bool {
        !matches!(self, Constant::Float(f) if f.is_nan())
    }

    /// Runtime forms this constant matches. Singleton for every variant
    /// except `Timestamp`, which yields both the parsed-instant form and
    /// the literal `repr` as bytes (mirrors the two arms of
    /// `PartialEq<Value>`).
    pub(crate) fn dvals(&self) -> impl Iterator<Item = DVal> {
        let secondary = match self {
            Constant::Timestamp(t) => Some(DVal::Bytes(Bytes::copy_from_slice(t.repr.as_bytes()))),
            _ => None,
        };
        std::iter::once(DVal::from(self)).chain(secondary)
    }
}

/// Runtime projection of either a configured `Constant` or an event-side
/// `Value`. Used as the value half of the index key in `EqIndex`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DVal {
    Bytes(Bytes),
    Integer(i64),
    Float(NotNan<f64>),
    Boolean(bool),
    Timestamp(DateTime<Utc>),
    Null,
    /// Path errored, or runtime `Value` variant has no equatable `Constant`
    /// counterpart (Array / Object / Regex). A `DiForm` containing any
    /// `Unmatchable` short-circuits.
    Unmatchable,
}

impl From<&Constant> for DVal {
    fn from(c: &Constant) -> Self {
        match c {
            Constant::String(s) => DVal::Bytes(Bytes::copy_from_slice(s.as_bytes())),
            Constant::Integer(i) => DVal::Integer(*i),
            // Caller must filter NaN via `Constant::is_indexable` first.
            Constant::Float(f) => DVal::Float(NotNan::new(*f).expect("NaN must be filtered upstream")),
            Constant::Boolean(b) => DVal::Boolean(*b),
            Constant::Timestamp(t) => DVal::Timestamp(t.dt),
            Constant::Null => DVal::Null,
        }
    }
}

impl From<&Value> for DVal {
    fn from(v: &Value) -> Self {
        match v {
            Value::Bytes(b) => DVal::Bytes(b.clone()),
            Value::Integer(i) => DVal::Integer(*i),
            Value::Float(f) => DVal::Float(*f),
            Value::Boolean(b) => DVal::Boolean(*b),
            Value::Timestamp(t) => DVal::Timestamp(*t),
            Value::Null => DVal::Null,
            _ => DVal::Unmatchable,
        }
    }
}

impl DVal {
    pub(crate) fn from_target_get(r: Result<Option<&Value>, String>) -> Self {
        match r {
            Ok(Some(v)) => v.into(),
            Ok(None) => DVal::Null,
            Err(_) => DVal::Unmatchable,
        }
    }
}

/// Config for a single simple equality expresion (lhs = rhs)
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EqConfig {
    /// Event property of interest
    pub property: ConfigTargetPath,

    /// Value (a literal).
    pub value: Constant,
}

/// An equality predicate config
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EqConjConfig {
    /// Equality expressions
    pub conjunct: Vec<EqConfig>,
}

type EqClause = (OwnedTargetPath, Constant);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Equality {
    pg_info: ProgramInfo,

    eqs: Vec<EqClause>,
}

impl Equality {
    pub(crate) fn make_target(pg_info: &ProgramInfo, e: Event) -> (LogNamespace, VrlTarget) {
        let log_ns = e.maybe_as_log().map(|log| log.namespace()).unwrap_or(LogNamespace::Legacy);
        let target = VrlTarget::new(e, pg_info, false);
        (log_ns, target)
    }

    pub(crate) fn into_event(target: VrlTarget, log_ns: LogNamespace) -> Event {
        match target.into_events(log_ns) {
            TargetEvents::One(event) => event,
            _ => panic!("Event was modified in a condition. This is an internal compiler error."),
        }
    }

    pub(crate) fn check(&self, e: Event) -> (bool, Event) {
        let (log_ns, target) = Self::make_target(&self.pg_info, e);
        let is_eq = self.eqs.iter().all(|(p, ev)| {
            match target.target_get(p) {
                Ok(Some(av)) => ev == av,
                Ok(None) => ev == &Constant::Null,
                Err(_) => false,
            }
        });
        (is_eq, Self::into_event(target, log_ns))
    }

    pub(crate) fn check_with_context(&self, e: Event) -> (Result<(), String>, Event) {
        let (log_ns, target) = Self::make_target(&self.pg_info, e);
        let result = self.eqs.iter().find_map(|(p, ev)| {
            let matched = match target.target_get(p) {
                Ok(Some(av)) => ev == av,
                Ok(None) => ev == &Constant::Null,
                Err(_) => false,
            };
            (!matched).then(|| format!("equality mismatch at {p}: expected {ev:?}"))
        }).map_or(Ok(()), Err);
        (result, Self::into_event(target, log_ns))
    }

    /// Every clause's constant is fast-path indexable.
    pub(crate) fn is_indexable(&self) -> bool {
        self.eqs.iter().all(|(_, c)| c.is_indexable())
    }

    /// Consume into the underlying clauses so callers (e.g., the route
    /// transform) can build an index without cloning.
    pub(crate) fn into_clauses(self) -> Vec<EqClause> {
        self.eqs
    }
}

impl ConditionalConfig for EqConjConfig {
    fn build(
        &self,
        _enrichment_tables: &vector_lib::enrichment::TableRegistry,
    ) -> crate::Result<Condition> {
        if self.conjunct.is_empty() {
            return Err("equality condition requires at least one clause".into());
        }
        let eqs = self.conjunct.iter().map(|c| (c.property.clone().into(), c.value.clone())).collect::<Vec<EqClause>>();
        let target_queries = eqs.iter().map(|c| c.0.clone()).collect();
        let pg_info = ProgramInfo{target_queries, fallible: false,abortable: true, target_assignments: vec![] };
        Ok(Condition::Equality(Equality {pg_info, eqs}))
    }
}

/// Sorted, deduplicated path-index subset used by one or more indexed
/// routes. Lookup-time helpers live here to keep the iterator chain in
/// `EqIndex::matches` declarative.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiForm(Vec<usize>);

impl DiForm {
    pub fn is_unmatchable(&self, values: &[DVal]) -> bool {
        self.0.iter().any(|&i| matches!(values[i], DVal::Unmatchable))
    }
}

/// Build-time-flattened equality index.
#[derive(Debug)]
pub struct EqIndex<K> {
    paths: Vec<OwnedTargetPath>,
    pg_info: ProgramInfo,
    di_forms: Vec<DiForm>,
    /// Entries sorted by key (canonical lex order). Lookup is
    /// `binary_search_by` with a comparator that walks the stored key
    /// against a virtual key formed from `(di_form, values)` — no
    /// per-lookup allocation or `DVal` clone.
    entries: Vec<(Vec<(usize, DVal)>, Vec<K>)>,
}

impl<K> EqIndex<K> {
    /// Project all discriminator paths from the event. Consumes and returns
    /// the event so the caller can keep using it without an extra clone.
    pub fn project(&self, event: Event) -> (Vec<DVal>, Event) {
        let (log_ns, target) = Equality::make_target(&self.pg_info, event);
        let values: Vec<DVal> = self
            .paths
            .iter()
            .map(|p| DVal::from_target_get(target.target_get(p)))
            .collect();
        (values, Equality::into_event(target, log_ns))
    }

    pub fn matches<'a>(&'a self, values: &'a [DVal]) -> impl Iterator<Item = &'a K> + 'a {
        self.di_forms
            .iter()
            .filter(|f| !f.is_unmatchable(values))
            .filter_map(|f| self.lookup(f, values))
            .flatten()
    }

    fn lookup<'a>(&'a self, di_form: &DiForm, values: &'a [DVal]) -> Option<&'a Vec<K>> {
        self.entries
            .binary_search_by(|(stored, _)| {
                let stored_iter = stored.iter().map(|(i, v)| (*i, v));
                let virtual_iter = di_form.0.iter().map(|&i| (i, &values[i]));
                stored_iter.cmp(virtual_iter)
            })
            .ok()
            .map(|i| &self.entries[i].1)
    }
}

impl<K: Clone> EqIndex<K> {
    /// Build from `(key, equality)` pairs. Caller must filter equalities
    /// via [`Equality::is_indexable`] beforehand.
    pub fn build(routes: impl IntoIterator<Item = (K, Equality)>) -> Self {
        // Discover every distinct path and remember its insertion order as
        // the stable index. `paths` and `path_ids` are built in lockstep
        // inside the fold so neither needs a function-scoped mutable.
        let (path_ids, paths, clause_lists) = routes.into_iter().fold(
            (
                BTreeMap::<OwnedTargetPath, usize>::new(),
                Vec::<OwnedTargetPath>::new(),
                Vec::<(K, Vec<EqClause>)>::new(),
            ),
            |(mut path_ids, mut paths, mut clauses_acc), (k, eq)| {
                let clauses = eq.into_clauses();
                for (p, _) in &clauses {
                    path_ids.entry(p.clone()).or_insert_with(|| {
                        paths.push(p.clone());
                        paths.len() - 1
                    });
                }
                clauses_acc.push((k, clauses));
                (path_ids, paths, clauses_acc)
            },
        );

        let pg_info = ProgramInfo {
            target_queries: paths.clone(),
            fallible: false,
            abortable: true,
            target_assignments: vec![],
        };

        let (di_forms_set, eq_idx) = clause_lists.into_iter().fold(
            (
                BTreeSet::<DiForm>::new(),
                BTreeMap::<Vec<(usize, DVal)>, Vec<K>>::new(),
            ),
            |(mut di_forms, mut eq_idx), (key, clauses)| {
                // Canonical clause order: ascending by path-index.
                let mut indexed: Vec<(usize, &Constant)> =
                    clauses.iter().map(|(p, c)| (path_ids[p], c)).collect();
                indexed.sort_by_key(|(i, _)| *i);

                di_forms.insert(DiForm(indexed.iter().map(|(i, _)| *i).collect()));

                // Cartesian product across each clause's DVal forms.
                let expanded = indexed.iter().fold(
                    vec![Vec::<(usize, DVal)>::new()],
                    |acc, (i, c)| {
                        c.dvals()
                            .flat_map(|dv| {
                                acc.iter().map(move |prefix| {
                                    let mut next = prefix.clone();
                                    next.push((*i, dv.clone()));
                                    next
                                })
                            })
                            .collect()
                    },
                );

                for k in expanded {
                    eq_idx.entry(k).or_default().push(key.clone());
                }
                (di_forms, eq_idx)
            },
        );

        Self {
            paths,
            pg_info,
            di_forms: di_forms_set.into_iter().collect(),
            // BTreeMap iterator yields entries in sorted key order, which is
            // exactly what `lookup`'s binary search requires.
            entries: eq_idx.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{LogEvent, Metric, MetricKind, MetricValue};
    use crate::log_event;
    use chrono::TimeZone;
    use indoc::indoc;
    use ordered_float::NotNan;

    fn build(eqs: Vec<(&str, Constant)>) -> Equality {
        let conjunct = eqs
            .into_iter()
            .map(|(p, v)| EqConfig { property: p.into(), value: v })
            .collect();
        match (EqConjConfig { conjunct }).build(&Default::default()).unwrap() {
            Condition::Equality(eq) => eq,
            _ => panic!("expected Condition::Equality"),
        }
    }

    fn vfloat(f: f64) -> Value {
        Value::Float(NotNan::new(f).unwrap())
    }

    // ---------- Constant <-> Value cross-type equality ----------

    #[test]
    fn constant_eq_value_string() {
        let c = Constant::String("hello".into());
        assert_eq!(c, Value::Bytes("hello".into()));
        assert_ne!(c, Value::Bytes("world".into()));
        assert_ne!(c, Value::Bytes("".into()));
    }

    #[test]
    fn constant_eq_value_integer() {
        let c = Constant::Integer(42);
        assert_eq!(c, Value::Integer(42));
        assert_ne!(c, Value::Integer(-42));
        assert_ne!(c, Value::Integer(0));
    }

    #[test]
    fn constant_eq_value_float_exact() {
        assert_eq!(Constant::Float(1.5), vfloat(1.5));
    }

    #[test]
    fn constant_eq_value_float_within_epsilon() {
        assert_eq!(Constant::Float(1.0), vfloat(1.0 + 1e-20));
    }

    #[test]
    fn constant_eq_value_float_outside_epsilon() {
        let c = Constant::Float(1.0);
        assert_ne!(c, vfloat(1.0 + 1e-6));
        assert_ne!(c, vfloat(2.0));
    }

    #[test]
    fn constant_eq_value_boolean() {
        assert_eq!(Constant::Boolean(true), Value::Boolean(true));
        assert_eq!(Constant::Boolean(false), Value::Boolean(false));
        assert_ne!(Constant::Boolean(true), Value::Boolean(false));
    }

    #[test]
    fn constant_eq_value_timestamp() {
        let t1 = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 1).unwrap();
        assert_eq!(Constant::Timestamp(TsLit::from_dt(t1)), Value::Timestamp(t1));
        assert_ne!(Constant::Timestamp(TsLit::from_dt(t1)), Value::Timestamp(t2));
    }

    #[test]
    fn constant_eq_value_timestamp_against_bytes() {
        // Repr is captured from the input string, so byte-equality compares
        // against the user's literal form.
        let lit = TsLit::try_from("2024-01-01T00:00:00Z".to_string()).unwrap();
        assert_eq!(Constant::Timestamp(lit.clone()), Value::Bytes("2024-01-01T00:00:00Z".into()));
        // Same instant, different RFC 3339 spelling → byte-compare fails.
        assert_ne!(Constant::Timestamp(lit), Value::Bytes("2024-01-01T00:00:00+00:00".into()));
    }

    #[test]
    fn constant_eq_value_null() {
        assert_eq!(Constant::Null, Value::Null);
        assert_ne!(Constant::Null, Value::Integer(0));
        assert_ne!(Constant::Null, Value::Boolean(false));
        assert_ne!(Constant::Null, Value::Bytes("".into()));
    }

    #[test]
    fn constant_eq_value_type_mismatch() {
        let c = Constant::Integer(1);
        assert_ne!(c, Value::Bytes("1".into()));
        assert_ne!(c, vfloat(1.0));
        assert_ne!(c, Value::Boolean(true));
        assert_ne!(c, Value::Null);
    }

    // ---------- Constant <-> Constant equality (derived PartialEq + manual Eq) ----------

    #[test]
    fn constant_self_equality() {
        assert_eq!(Constant::Integer(7), Constant::Integer(7));
        assert_ne!(Constant::Integer(7), Constant::Integer(8));
        assert_eq!(Constant::Float(1.5), Constant::Float(1.5));
        assert_ne!(Constant::String("a".into()), Constant::String("b".into()));
        assert_eq!(Constant::Null, Constant::Null);
        assert_ne!(Constant::Integer(0), Constant::String("0".into()));
    }

    // ---------- Equality::check (AND semantics) ----------

    #[test]
    fn build_rejects_empty_conjunct() {
        let cfg = EqConjConfig { conjunct: vec![] };
        let err = cfg.build(&Default::default()).expect_err("empty conjunct must fail to build");
        assert!(err.to_string().contains("at least one clause"));
    }

    #[test]
    fn check_single_clause_match() {
        let eq = build(vec![(".foo", Constant::Integer(42))]);
        assert!(eq.check(log_event!["foo" => 42]).0);
    }

    #[test]
    fn check_single_clause_mismatch() {
        let eq = build(vec![(".foo", Constant::Integer(42))]);
        assert!(!eq.check(log_event!["foo" => 7]).0);
    }

    #[test]
    fn check_missing_path_expecting_null_matches() {
        let eq = build(vec![(".missing", Constant::Null)]);
        assert!(eq.check(log_event!["other" => 1]).0);
    }

    #[test]
    fn check_missing_path_expecting_non_null_fails() {
        let eq = build(vec![(".missing", Constant::Integer(0))]);
        assert!(!eq.check(log_event!["other" => 1]).0);
    }

    #[test]
    fn check_all_clauses_match() {
        let eq = build(vec![
            (".a", Constant::Integer(1)),
            (".b", Constant::String("x".into())),
            (".c", Constant::Boolean(true)),
        ]);
        assert!(eq.check(log_event!["a" => 1, "b" => "x", "c" => true]).0);
    }

    #[test]
    fn check_one_failing_clause_short_circuits() {
        let eq = build(vec![
            (".a", Constant::Integer(1)),
            (".b", Constant::String("x".into())),
            (".c", Constant::Boolean(true)),
        ]);
        assert!(!eq.check(log_event!["a" => 1, "b" => "x", "c" => false]).0);
    }

    #[test]
    fn check_contradictory_clauses_never_match() {
        // Same path bound to two different values — no event value can
        // satisfy both clauses simultaneously.
        let eq = build(vec![
            (".a", Constant::String("foo".into())),
            (".a", Constant::String("bar".into())),
        ]);
        assert!(!eq.check(log_event!["a" => "foo"]).0);
        assert!(!eq.check(log_event!["a" => "bar"]).0);
        assert!(!eq.check(log_event!["a" => "baz"]).0);
    }

    #[test]
    fn check_preserves_event() {
        let eq = build(vec![(".foo", Constant::Integer(42))]);
        let mut log = LogEvent::default();
        log.insert("foo", 42);
        log.insert("bar", "untouched");
        let original = Event::Log(log);
        let (_, returned) = eq.check(original.clone());
        assert_eq!(original, returned);
    }

    #[test]
    fn check_on_metric_event() {
        let metric = Event::Metric(Metric::new(
            "my_metric",
            MetricKind::Incremental,
            MetricValue::Counter { value: 1.0 },
        ));
        let eq = build(vec![(".name", Constant::String("my_metric".into()))]);
        assert!(eq.check(metric.clone()).0);

        let eq_wrong = build(vec![(".name", Constant::String("other".into()))]);
        assert!(!eq_wrong.check(metric).0);
    }

    // ---------- Equality::check_with_context ----------

    #[test]
    fn check_with_context_ok_when_all_match() {
        let eq = build(vec![
            (".a", Constant::Integer(1)),
            (".b", Constant::Boolean(true)),
        ]);
        let (result, _) = eq.check_with_context(log_event!["a" => 1, "b" => true]);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn check_with_context_err_names_path_and_expected() {
        let eq = build(vec![(".foo", Constant::Integer(42))]);
        let (result, _) = eq.check_with_context(log_event!["foo" => 7]);
        let err = result.expect_err("should fail");
        assert!(err.contains(".foo"), "missing path in error: {err}");
        assert!(err.contains("Integer(42)"), "missing expected value in error: {err}");
    }

    #[test]
    fn check_with_context_reports_first_failure() {
        let eq = build(vec![
            (".a", Constant::Integer(1)),
            (".b", Constant::Integer(2)),
            (".c", Constant::Integer(3)),
        ]);
        let (result, _) = eq.check_with_context(log_event!["a" => 1, "b" => 99, "c" => 99]);
        let err = result.expect_err("should fail");
        assert!(err.contains(".b"), "expected first-failure to be .b, got: {err}");
        assert!(!err.contains(".c"), "should short-circuit before .c, got: {err}");
    }

    #[test]
    fn check_with_context_missing_path_expecting_non_null_fails() {
        let eq = build(vec![(".missing", Constant::Integer(0))]);
        let (result, _) = eq.check_with_context(log_event![]);
        let err = result.expect_err("should fail");
        assert!(err.contains(".missing"));
    }

    #[test]
    fn check_with_context_preserves_event() {
        let eq = build(vec![(".foo", Constant::Integer(42))]);
        let mut log = LogEvent::default();
        log.insert("foo", 42);
        let original = Event::Log(log);
        let (_, returned) = eq.check_with_context(original.clone());
        assert_eq!(original, returned);
    }

    // ---------- EqualityConjunctConfig::build ----------

    #[test]
    fn build_yields_equality_variant_with_clauses_in_order() {
        let cfg = EqConjConfig {
            conjunct: vec![
                EqConfig { property: ".x".into(), value: Constant::Integer(1) },
                EqConfig { property: ".y".into(), value: Constant::Null },
            ],
        };
        match cfg.build(&Default::default()).unwrap() {
            Condition::Equality(eq) => {
                assert!(eq.check(log_event!["x" => 1, "y" => Value::Null]).0);
                assert!(!eq.check(log_event!["x" => 2]).0);
            }
            _ => panic!("expected Condition::Equality"),
        }
    }

    // ---------- Deserialization ----------

    #[test]
    fn deserialize_integer_value() {
        let conf: EqConjConfig = toml::from_str(indoc! {r#"
            conjunct = [{ property = ".foo", value = 42 }]
        "#}).unwrap();
        assert_eq!(conf, EqConjConfig {
            conjunct: vec![EqConfig {
                property: ".foo".into(),
                value: Constant::Integer(42),
            }],
        });
    }

    #[test]
    fn deserialize_string_value() {
        let conf: EqConjConfig = toml::from_str(indoc! {r#"
            conjunct = [{ property = ".name", value = "hello" }]
        "#}).unwrap();
        assert_eq!(conf, EqConjConfig {
            conjunct: vec![EqConfig {
                property: ".name".into(),
                value: Constant::String("hello".into()),
            }],
        });
    }

    #[test]
    fn deserialize_float_value() {
        let conf: EqConjConfig = toml::from_str(indoc! {r#"
            conjunct = [{ property = ".rate", value = 3.14 }]
        "#}).unwrap();
        assert_eq!(conf, EqConjConfig {
            conjunct: vec![EqConfig {
                property: ".rate".into(),
                value: Constant::Float(3.14),
            }],
        });
    }

    #[test]
    fn deserialize_boolean_value() {
        let conf: EqConjConfig = toml::from_str(indoc! {r#"
            conjunct = [{ property = ".active", value = true }]
        "#}).unwrap();
        assert_eq!(conf, EqConjConfig {
            conjunct: vec![EqConfig {
                property: ".active".into(),
                value: Constant::Boolean(true),
            }],
        });
    }

    #[test]
    fn deserialize_timestamp_value() {
        // TOML's native datetime literal doesn't bridge to chrono's string-based
        // deserializer, so we send the timestamp as a quoted RFC 3339 string.
        let conf: EqConjConfig = toml::from_str(indoc! {r#"
            conjunct = [{ property = ".when", value = "2024-01-01T00:00:00Z" }]
        "#}).unwrap();
        assert_eq!(conf, EqConjConfig {
            conjunct: vec![EqConfig {
                property: ".when".into(),
                value: Constant::Timestamp(TsLit::from_dt(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap())),
            }],
        });
    }

    #[test]
    fn deserialize_null_value_json() {
        // TOML has no null literal, so this uses JSON.
        let conf: EqConjConfig = serde_json::from_str(
            r#"{ "conjunct": [{ "property": ".missing", "value": null }] }"#,
        ).unwrap();
        assert_eq!(conf, EqConjConfig {
            conjunct: vec![EqConfig {
                property: ".missing".into(),
                value: Constant::Null,
            }],
        });
    }

    #[test]
    fn deserialize_null_value_yaml() {
        let conf: EqConjConfig = serde_yaml::from_str(indoc! {r#"
            conjunct:
              - property: .missing
                value: null
        "#}).unwrap();
        assert_eq!(conf, EqConjConfig {
            conjunct: vec![EqConfig {
                property: ".missing".into(),
                value: Constant::Null,
            }],
        });
    }

    #[test]
    fn deserialize_multiple_clauses() {
        let conf: EqConjConfig = toml::from_str(indoc! {r#"
            conjunct = [
                { property = ".a", value = 1 },
                { property = ".b", value = "x" },
                { property = ".c", value = true },
            ]
        "#}).unwrap();
        assert_eq!(conf, EqConjConfig {
            conjunct: vec![
                EqConfig { property: ".a".into(), value: Constant::Integer(1) },
                EqConfig { property: ".b".into(), value: Constant::String("x".into()) },
                EqConfig { property: ".c".into(), value: Constant::Boolean(true) },
            ],
        });
    }

    #[test]
    fn deserialize_empty_conjunct() {
        let conf: EqConjConfig = toml::from_str("conjunct = []").unwrap();
        assert_eq!(conf, EqConjConfig { conjunct: vec![] });
    }

    #[test]
    fn deserialize_rejects_unknown_field_on_clause() {
        let result: Result<EqConjConfig, _> = toml::from_str(indoc! {r#"
            conjunct = [{ property = ".foo", value = 1, extra = "nope" }]
        "#});
        assert!(result.is_err(), "deny_unknown_fields should reject `extra`");
    }
}
