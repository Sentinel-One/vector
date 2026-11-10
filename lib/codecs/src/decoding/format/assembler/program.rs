use std::{fmt, mem};

use lookup::{lookup_v2::OwnedSegment, OwnedTargetPath, OwnedValuePath, PathPrefix};
use metrics::{counter, Counter};
use smallvec::SmallVec;
use snafu::Snafu;
use tracing::warn;
use vector_common::byte_size_of::ByteSizeOf;
use vector_core::{
    config::LogNamespace,
    event::{Event, EventMetadata, VrlTarget},
    predicate::{Predicate, PredicateError},
};
use vrl::{
    compiler::{ProgramInfo, SecretTarget, Target},
    value::{KeyString, ObjectMap, Value},
};

use super::config::{ActionConfig, Ref};

const META: &str = "meta";

#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum BuildError {
    #[snafu(display("`{path}`: a `%` path must start with a register name or `meta`"))]
    BadRegisterPath { path: String },

    #[snafu(display("`stop` must be the last action in its list"))]
    StopNotLast,

    #[snafu(display("`foreach` over `{target}` may not use `{path}`, which overlaps it"))]
    ForeachOverlap { target: String, path: String },

    #[snafu(display("invalid `if` predicate: {source}"))]
    Predicate { source: PredicateError },
}

#[derive(Debug, Snafu)]
pub enum ActionError {
    #[snafu(display("`{path}`: {reason}"))]
    Access { path: String, reason: String },

    #[snafu(display("cannot merge {from} into {to} at `{path}`"))]
    TypeMismatch {
        path: String,
        from: &'static str,
        to: &'static str,
    },

    #[snafu(display("`{path}` is {kind}, not an array"))]
    NotAnArray { path: String, kind: &'static str },

    #[snafu(display("merge key `{path}` is {kind}, not a string"))]
    InvalidKey { path: String, kind: &'static str },

    #[snafu(display("registers exceed {limit} bytes"))]
    RegisterLimit { limit: usize },
}

impl ActionError {
    /// Fails the stream whatever `resumable` says: dropping register contents would assemble
    /// the events that follow with the wrong shape.
    pub(super) const fn is_fatal(&self) -> bool {
        matches!(self, Self::RegisterLimit { .. })
    }
}

/// Where an action reads or writes. `src` is the configured path, which for a register includes
/// the register name as its first segment.
#[derive(Clone, Debug)]
struct Slot {
    src: OwnedTargetPath,
    kind: SlotKind,
}

#[derive(Clone, Debug)]
enum SlotKind {
    /// The event, or the element inside `foreach`.
    Dot,
    /// The event's metadata, at this path.
    Meta(OwnedTargetPath),
    /// A register.
    Reg,
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.src.fmt(f)
    }
}

impl Slot {
    fn compile(path: &OwnedTargetPath) -> Result<Self, BuildError> {
        let kind = match (path.prefix, path.path.segments.first()) {
            (PathPrefix::Event, _) => Ok(SlotKind::Dot),
            (PathPrefix::Metadata, Some(OwnedSegment::Field(name))) if name.as_str() == META => {
                Ok(SlotKind::Meta(OwnedTargetPath::metadata(OwnedValuePath {
                    segments: path.path.segments[1..].to_vec(),
                })))
            }
            (PathPrefix::Metadata, Some(OwnedSegment::Field(_))) => Ok(SlotKind::Reg),
            (PathPrefix::Metadata, _) => Err(BuildError::BadRegisterPath {
                path: path.to_string(),
            }),
        }?;
        Ok(Self {
            src: path.clone(),
            kind,
        })
    }

    fn from_ref(r: &Ref) -> Result<Self, BuildError> {
        Self::compile(&r.0)
    }

    /// The path a [`VrlTarget`] knows this slot by; registers live outside it.
    fn vrl_path(&self) -> Option<OwnedTargetPath> {
        match &self.kind {
            SlotKind::Dot => Some(self.src.clone()),
            SlotKind::Meta(meta) => Some(meta.clone()),
            SlotKind::Reg => None,
        }
    }

    /// What the field holding this slot's value takes, beyond the value.
    fn field_size(&self) -> usize {
        match self.src.path.segments.last() {
            Some(OwnedSegment::Field(name)) => key_size(name),
            _ => 0,
        }
    }

    fn is_reg(&self) -> bool {
        matches!(self.kind, SlotKind::Reg)
    }

    /// `%` paths outside a `foreach` body that overlap: equal, or one above the other. `.` paths
    /// never overlap across a `foreach` boundary, because inside the body `.` is the element.
    fn overlaps(&self, other: &Slot) -> bool {
        let shared = self
            .src
            .path
            .segments
            .len()
            .min(other.src.path.segments.len());
        match (&self.kind, &other.kind) {
            (SlotKind::Reg, SlotKind::Reg) => {
                self.src.path.segments[..shared] == other.src.path.segments[..shared]
            }
            (SlotKind::Meta(a), SlotKind::Meta(b)) => {
                let shared = a.path.segments.len().min(b.path.segments.len());
                a.path.segments[..shared] == b.path.segments[..shared]
            }
            _ => false,
        }
    }

    fn keyed(&self, key: &str) -> Self {
        Self {
            src: self.src.with_field_appended(key),
            kind: match &self.kind {
                SlotKind::Meta(meta) => SlotKind::Meta(meta.with_field_appended(key)),
                kind => kind.clone(),
            },
        }
    }
}

#[derive(Clone, Debug)]
enum Action {
    Merge {
        from: Slot,
        to: Slot,
        take: bool,
        zip: bool,
        key: Option<Slot>,
    },
    Append {
        from: Slot,
        to: Slot,
        take: bool,
    },
    Emit {
        from: Slot,
        take: bool,
    },
    Reset {
        to: Slot,
        value: Option<Value>,
    },
    Foreach {
        target: Slot,
        body: Vec<Action>,
    },
    If {
        when: Predicate,
        then: Vec<Action>,
        otherwise: Vec<Action>,
    },
    Stop,
}

impl Action {
    fn compile_list(configs: &[ActionConfig]) -> Result<Vec<Self>, BuildError> {
        let stop_position = configs.iter().position(|c| matches!(c, ActionConfig::Stop));
        match stop_position {
            Some(i) if i + 1 != configs.len() => Err(BuildError::StopNotLast),
            _ => configs.iter().map(Action::compile).collect(),
        }
    }

    fn compile(config: &ActionConfig) -> Result<Self, BuildError> {
        match config {
            ActionConfig::Merge(c) => Ok(Action::Merge {
                from: Slot::from_ref(&c.from)?,
                to: Slot::from_ref(&c.to)?,
                take: c.move_,
                zip: c.zip,
                key: c.key.as_ref().map(Slot::from_ref).transpose()?,
            }),
            ActionConfig::Append(c) => Ok(Action::Append {
                from: Slot::from_ref(&c.from)?,
                to: Slot::from_ref(&c.to)?,
                take: c.move_,
            }),
            ActionConfig::Emit(c) => Ok(Action::Emit {
                from: Slot::from_ref(&c.from)?,
                take: c.move_,
            }),
            ActionConfig::Reset(c) => Ok(Action::Reset {
                to: Slot::from_ref(&c.to)?,
                value: c.value.as_ref().map(|v| Value::from(v.0.clone())),
            }),
            ActionConfig::Foreach(c) => {
                let target = Slot::from_ref(&c.target)?;
                let body = Action::compile_list(&c.actions)?;
                let clash = body
                    .iter()
                    .flat_map(Action::slots)
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .find(|s| target.overlaps(s));
                match clash {
                    Some(path) => Err(BuildError::ForeachOverlap {
                        target: target.to_string(),
                        path: path.to_string(),
                    }),
                    None => Ok(Action::Foreach { target, body }),
                }
            }
            ActionConfig::If(c) => Ok(Action::If {
                when: c
                    .when
                    .build()
                    .map_err(|source| BuildError::Predicate { source })?,
                then: Action::compile_list(&c.then)?,
                otherwise: Action::compile_list(&c.else_)?,
            }),
            ActionConfig::Stop => Ok(Action::Stop),
        }
    }

    /// Every path this action and the actions nested in it read or write, `foreach` targets
    /// included.
    fn slots(&self) -> Vec<Result<Slot, BuildError>> {
        match self {
            Action::Merge { from, to, key, .. } => [Some(from), Some(to), key.as_ref()]
                .into_iter()
                .flatten()
                .cloned()
                .map(Ok)
                .collect(),
            Action::Append { from, to, .. } => vec![Ok(from.clone()), Ok(to.clone())],
            Action::Emit { from, .. } => vec![Ok(from.clone())],
            Action::Reset { to, .. } => vec![Ok(to.clone())],
            Action::Foreach { target, body } => std::iter::once(Ok(target.clone()))
                .chain(body.iter().flat_map(Action::slots))
                .collect(),
            Action::If {
                when,
                then,
                otherwise,
            } => when
                .target_queries()
                .iter()
                .map(Slot::compile)
                .chain(then.iter().chain(otherwise).flat_map(Action::slots))
                .collect(),
            Action::Stop => vec![],
        }
    }

    /// Event and metadata paths read or written outside any `foreach` body, which a
    /// [`VrlTarget`] needs to know up front to project metric fields.
    fn event_paths(&self) -> Vec<OwnedTargetPath> {
        match self {
            Action::Foreach { target, .. } => target.vrl_path().into_iter().collect(),
            Action::If {
                when,
                then,
                otherwise,
            } => when
                .target_queries()
                .into_iter()
                .filter(|p| p.prefix == PathPrefix::Event)
                .chain(then.iter().chain(otherwise).flat_map(Action::event_paths))
                .collect(),
            other => other
                .slots()
                .into_iter()
                .flatten()
                .filter_map(|s| s.vrl_path())
                .collect(),
        }
    }
}

/// A compiled assembler program, shared by every deserializer a factory builds.
#[derive(Debug)]
pub struct Program {
    process: Vec<Action>,
    flush: Vec<Action>,
    info: ProgramInfo,
}

impl Program {
    pub(super) fn compile(
        process: &[ActionConfig],
        flush: &[ActionConfig],
    ) -> Result<Self, BuildError> {
        let process = Action::compile_list(process)?;
        let flush = Action::compile_list(flush)?;
        let mut queries: Vec<_> = process.iter().flat_map(Action::event_paths).collect();
        queries.sort();
        queries.dedup();
        Ok(Self {
            info: ProgramInfo {
                fallible: true,
                abortable: false,
                target_queries: queries.clone(),
                target_assignments: queries,
            },
            process,
            flush,
        })
    }

    pub(super) fn has_flush(&self) -> bool {
        !self.flush.is_empty()
    }

    /// Runs `process` over one event, pushing what it emits and then the event itself, unless it
    /// was stopped or emptied, onto `out`.
    pub(super) fn process(
        &self,
        event: Event,
        regs: &mut Registers,
        out: &mut SmallVec<[Event; 1]>,
        metrics: &Metrics,
        log_namespace: LogNamespace,
    ) -> Result<(), ActionError> {
        let target = VrlTarget::new(event, &self.info, false);
        Self::run(&self.process, target, regs, out, metrics, log_namespace)
    }

    /// Runs `flush` once, as if over an event whose value is null and whose metadata is
    /// `metadata`.
    pub(super) fn flush(
        &self,
        metadata: EventMetadata,
        regs: &mut Registers,
        out: &mut SmallVec<[Event; 1]>,
        metrics: &Metrics,
        log_namespace: LogNamespace,
    ) -> Result<(), ActionError> {
        let target = VrlTarget::LogEvent(Value::Null, metadata);
        Self::run(&self.flush, target, regs, out, metrics, log_namespace)
    }

    fn run(
        actions: &[Action],
        mut target: VrlTarget,
        regs: &mut Registers,
        out: &mut SmallVec<[Event; 1]>,
        metrics: &Metrics,
        log_namespace: LogNamespace,
    ) -> Result<(), ActionError> {
        let flow = View {
            target: &mut target,
            cursor: None,
            regs,
            out,
            metrics,
            log_namespace,
        }
        .run(actions)?;
        let survives = match (&flow, &target) {
            (Flow::Stop, _) => false,
            (_, VrlTarget::LogEvent(value, _) | VrlTarget::Trace(value, _)) => !value.is_null(),
            (_, VrlTarget::Metric { .. }) => true,
        };
        if survives {
            out.push(target.into_event(log_namespace));
        }
        Ok(())
    }
}

/// An action whose `from` is missing or null does nothing.
#[derive(Clone, Copy, Debug)]
enum Reader {
    Merge,
    Append,
    Emit,
}

/// Counters a factory registers once, so every deserializer it builds shares them.
#[derive(Clone, Debug)]
pub(super) struct Metrics {
    merge_from_missing: Counter,
    append_from_missing: Counter,
    emit_from_missing: Counter,
}

impl Metrics {
    /// Must be called within the component's span, which tags the counters with the component.
    pub(super) fn new() -> Self {
        let missing =
            |action: &'static str| counter!("assembler_missing_from_total", "action" => action);
        Self {
            merge_from_missing: missing("merge"),
            append_from_missing: missing("append"),
            emit_from_missing: missing("emit"),
        }
    }

    /// Usually means the input is not shaped as the config expects, which would otherwise go
    /// unnoticed since the action just does nothing.
    fn missing_from(&self, reader: Reader, from: &Slot) {
        let (action, counter) = match reader {
            Reader::Merge => ("merge", &self.merge_from_missing),
            Reader::Append => ("append", &self.append_from_missing),
            Reader::Emit => ("emit", &self.emit_from_missing),
        };
        warn!(
            message = "Assembler action skipped, its `from` is missing or null.",
            action,
            path = %from,
            internal_log_rate_limit = true,
        );
        counter.increment(1);
    }
}

/// Values the assembler carries across events, until the stream is flushed.
#[derive(Debug)]
pub struct Registers {
    value: Value,
    bytes: usize,
    max_bytes: usize,
}

impl Registers {
    pub(super) fn new(max_bytes: usize) -> Self {
        Self {
            value: Value::Object(ObjectMap::new()),
            bytes: 0,
            max_bytes,
        }
    }

    pub(super) fn reset(&mut self) {
        self.value = Value::Object(ObjectMap::new());
        self.bytes = 0;
    }

    fn adjust(&mut self, delta: isize) -> Result<(), ActionError> {
        self.bytes = self.bytes.saturating_add_signed(delta);
        if self.bytes > self.max_bytes {
            Err(ActionError::RegisterLimit {
                limit: self.max_bytes,
            })
        } else {
            Ok(())
        }
    }
}

/// Register limits are checked against memory use, not payload size: every value and key also
/// counts its in-memory header, as [`ByteSizeOf`] measures it.
fn size(value: &Value) -> usize {
    value.size_of()
}

/// A key as [`ByteSizeOf`] counts it inside an object.
const fn key_size(name: &str) -> usize {
    mem::size_of::<KeyString>() + name.len()
}

fn signed(n: usize) -> isize {
    isize::try_from(n).unwrap_or(isize::MAX)
}

fn kind_name(value: &Value) -> &'static str {
    match value {
        Value::Bytes(_) => "a string",
        Value::Regex(_) => "a regex",
        Value::Integer(_) => "an integer",
        Value::Float(_) => "a float",
        Value::Boolean(_) => "a boolean",
        Value::Timestamp(_) => "a timestamp",
        Value::Object(_) => "an object",
        Value::Array(_) => "an array",
        Value::Null => "null",
    }
}

/// Deep merge, `src` winning. Returns the change in [`size`] when `measure` is set, and 0
/// otherwise so writes to the event pay nothing for register accounting.
fn merge(dst: &mut Value, src: Value, zip: bool, measure: bool) -> isize {
    match (dst, src) {
        (Value::Object(d), Value::Object(s)) => s
            .into_iter()
            .map(|(k, v)| match d.get_mut(&k) {
                Some(existing) => merge(existing, v, zip, measure),
                None => {
                    let added = if measure {
                        signed(key_size(&k) + size(&v))
                    } else {
                        0
                    };
                    d.insert(k, v);
                    added
                }
            })
            .sum(),
        (Value::Array(d), Value::Array(s)) if zip => s
            .into_iter()
            .enumerate()
            .map(|(i, v)| match d.get_mut(i) {
                Some(existing) => merge(existing, v, zip, measure),
                None => {
                    let added = if measure { signed(size(&v)) } else { 0 };
                    d.push(v);
                    added
                }
            })
            .sum(),
        (dst, src) => {
            let delta = if measure {
                signed(size(&src)) - signed(size(dst))
            } else {
                0
            };
            *dst = src;
            delta
        }
    }
}

/// Containers only merge with their own kind at the top level, so a misconfigured `to` fails
/// loudly instead of being silently overwritten; below it, `src` wins.
fn merge_top(
    slot: &Slot,
    dst: &mut Value,
    src: Value,
    zip: bool,
    measure: bool,
) -> Result<isize, ActionError> {
    let compatible = match (&*dst, &src) {
        (Value::Object(_), Value::Object(_)) | (Value::Array(_), Value::Array(_)) => true,
        (Value::Object(_) | Value::Array(_), _) => false,
        _ => true,
    };
    if compatible {
        Ok(merge(dst, src, zip, measure))
    } else {
        Err(ActionError::TypeMismatch {
            path: slot.to_string(),
            from: kind_name(&src),
            to: kind_name(dst),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

/// What actions see: `.` is the event, or the element inside `foreach`; `%meta` is the event's
/// metadata; any other `%name` is a register.
#[derive(Debug)]
struct View<'a> {
    target: &'a mut VrlTarget,
    cursor: Option<&'a mut Value>,
    regs: &'a mut Registers,
    out: &'a mut SmallVec<[Event; 1]>,
    metrics: &'a Metrics,
    log_namespace: LogNamespace,
}

fn access(slot: &Slot) -> impl FnOnce(String) -> ActionError + '_ {
    move |reason| ActionError::Access {
        path: slot.to_string(),
        reason,
    }
}

impl View<'_> {
    fn run(&mut self, actions: &[Action]) -> Result<Flow, ActionError> {
        actions
            .iter()
            .map(|action| self.apply(action))
            .find(|res| !matches!(res, Ok(Flow::Continue)))
            .unwrap_or(Ok(Flow::Continue))
    }

    fn apply(&mut self, action: &Action) -> Result<Flow, ActionError> {
        match action {
            Action::Merge {
                from,
                to,
                take,
                zip,
                key,
            } => {
                let keyed = key
                    .as_ref()
                    .map(|k| self.key(k).map(|name| to.keyed(&name)))
                    .transpose()?;
                let to = keyed.as_ref().unwrap_or(to);
                self.read_from(Reader::Merge, from, *take)?
                    .map(|v| self.merge_into(to, v, *zip))
                    .transpose()
                    .map(|_| Flow::Continue)
            }
            Action::Append { from, to, take } => self
                .read_from(Reader::Append, from, *take)?
                .map(|v| self.append(to, v))
                .transpose()
                .map(|_| Flow::Continue),
            Action::Emit { from, take } => {
                if let Some(value) = self.read_from(Reader::Emit, from, *take)? {
                    let event = self.emit(value);
                    self.out.push(event);
                }
                Ok(Flow::Continue)
            }
            Action::Reset { to, value } => {
                self.take(to)?;
                value
                    .clone()
                    .map(|v| self.insert(to, v))
                    .transpose()
                    .map(|_| Flow::Continue)
            }
            Action::Foreach { target, body } => self.foreach(target, body),
            Action::If {
                when,
                then,
                otherwise,
            } => {
                let branch = if when.eval(&*self) { then } else { otherwise };
                self.run(branch)
            }
            Action::Stop => Ok(Flow::Stop),
        }
    }

    fn key(&self, key: &Slot) -> Result<String, ActionError> {
        match self.get(key)? {
            Some(Value::Bytes(b)) => Ok(String::from_utf8_lossy(b).into_owned()),
            other => Err(ActionError::InvalidKey {
                path: key.to_string(),
                kind: other.map_or("missing", kind_name),
            }),
        }
    }

    fn read_from(
        &mut self,
        reader: Reader,
        from: &Slot,
        take: bool,
    ) -> Result<Option<Value>, ActionError> {
        self.read(from, take)
            .map(|value| match value.filter(|v| !v.is_null()) {
                None => {
                    self.metrics.missing_from(reader, from);
                    None
                }
                present => present,
            })
    }

    fn read(&mut self, slot: &Slot, take: bool) -> Result<Option<Value>, ActionError> {
        if take {
            self.take(slot)
        } else {
            self.get(slot).map(|v| v.cloned())
        }
    }

    fn get(&self, slot: &Slot) -> Result<Option<&Value>, ActionError> {
        match (&slot.kind, &self.cursor) {
            (SlotKind::Dot, Some(cursor)) => Ok(cursor.get(&slot.src.path)),
            (SlotKind::Dot, None) => self.target.target_get(&slot.src).map_err(access(slot)),
            (SlotKind::Meta(meta), _) => self.target.target_get(meta).map_err(access(slot)),
            (SlotKind::Reg, _) => Ok(self.regs.value.get(&slot.src.path)),
        }
    }

    fn get_mut(&mut self, slot: &Slot) -> Result<Option<&mut Value>, ActionError> {
        match (&slot.kind, &mut self.cursor) {
            (SlotKind::Dot, Some(cursor)) => Ok(cursor.get_mut(&slot.src.path)),
            (SlotKind::Dot, None) => self.target.target_get_mut(&slot.src).map_err(access(slot)),
            (SlotKind::Meta(meta), _) => self.target.target_get_mut(meta).map_err(access(slot)),
            (SlotKind::Reg, _) => Ok(self.regs.value.get_mut(&slot.src.path)),
        }
    }

    /// Removes the value at `slot`; a root (`.`, `%meta`) is left null instead.
    fn take_unmeasured(&mut self, slot: &Slot) -> Result<Option<Value>, ActionError> {
        let path = match &slot.kind {
            SlotKind::Meta(meta) => meta,
            _ => &slot.src,
        };
        if path.path.is_root() {
            self.get_mut(slot)
                .map(|v| v.map(|v| std::mem::replace(v, Value::Null)))
        } else {
            match (&slot.kind, &mut self.cursor) {
                (SlotKind::Dot, Some(cursor)) => Ok(cursor.remove(&slot.src.path, false)),
                (SlotKind::Reg, _) => Ok(self.regs.value.remove(&slot.src.path, false)),
                _ => self.target.target_remove(path, false).map_err(access(slot)),
            }
        }
    }

    fn take(&mut self, slot: &Slot) -> Result<Option<Value>, ActionError> {
        let value = self.take_unmeasured(slot)?;
        match (&value, slot.is_reg()) {
            (Some(v), true) => self
                .regs
                .adjust(-signed(size(v) + slot.field_size()))
                .map(|_| value),
            _ => Ok(value),
        }
    }

    fn insert_unmeasured(
        &mut self,
        slot: &Slot,
        value: Value,
    ) -> Result<Option<Value>, ActionError> {
        match (&slot.kind, &mut self.cursor) {
            (SlotKind::Dot, Some(cursor)) => Ok(cursor.insert(&slot.src.path, value)),
            (SlotKind::Dot, None) => self
                .target
                .target_insert(&slot.src, value)
                .map(|_| None)
                .map_err(access(slot)),
            (SlotKind::Meta(meta), _) => self
                .target
                .target_insert(meta, value)
                .map(|_| None)
                .map_err(access(slot)),
            (SlotKind::Reg, _) => Ok(self.regs.value.insert(&slot.src.path, value)),
        }
    }

    /// A new field also costs its key, as it would inside a merged object.
    fn insert(&mut self, slot: &Slot, value: Value) -> Result<(), ActionError> {
        let added = if slot.is_reg() {
            signed(size(&value))
        } else {
            0
        };
        let replaced = self.insert_unmeasured(slot, value)?;
        match (slot.is_reg(), replaced) {
            (false, _) => Ok(()),
            (true, Some(old)) => self.regs.adjust(added - signed(size(&old))),
            (true, None) => self.regs.adjust(added + signed(slot.field_size())),
        }
    }

    fn merge_into(&mut self, slot: &Slot, src: Value, zip: bool) -> Result<(), ActionError> {
        let measure = slot.is_reg();
        let pending = match self.get_mut(slot)? {
            Some(dst) => Ok(merge_top(slot, dst, src, zip, measure)?),
            None => Err(src),
        };
        match pending {
            Ok(delta) if measure => self.regs.adjust(delta),
            Ok(_) => Ok(()),
            Err(src) => self.insert(slot, src),
        }
    }

    fn append(&mut self, slot: &Slot, item: Value) -> Result<(), ActionError> {
        let added = if slot.is_reg() {
            signed(size(&item))
        } else {
            0
        };
        let pending = match self.get_mut(slot)? {
            Some(Value::Array(items)) => {
                items.push(item);
                Ok(None)
            }
            Some(v) if v.is_null() => {
                *v = Value::Array(vec![item]);
                Ok(None)
            }
            Some(other) => Err(ActionError::NotAnArray {
                path: slot.to_string(),
                kind: kind_name(other),
            }),
            None => Ok(Some(item)),
        }?;
        match pending {
            Some(item) => self.insert(slot, Value::Array(vec![item])),
            None if slot.is_reg() => self.regs.adjust(added),
            None => Ok(()),
        }
    }

    fn emit(&self, value: Value) -> Event {
        match &*self.target {
            VrlTarget::Trace(_, metadata) => VrlTarget::Trace(value, metadata.clone()),
            VrlTarget::LogEvent(_, metadata) => VrlTarget::LogEvent(value, metadata.clone()),
            VrlTarget::Metric { metric, .. } => {
                VrlTarget::LogEvent(value, metric.metadata().clone())
            }
        }
        .into_event(self.log_namespace)
    }

    /// The array is taken out of its slot for the loop and always put back, also when the body
    /// stops or fails, so a register being iterated is never lost.
    fn foreach(&mut self, target: &Slot, body: &[Action]) -> Result<Flow, ActionError> {
        match self.take_unmeasured(target)? {
            None => Ok(Flow::Continue),
            Some(Value::Array(mut items)) => {
                let before = if target.is_reg() {
                    size_of_all(&items)
                } else {
                    0
                };
                let outcome = items
                    .iter_mut()
                    .map(|item| {
                        View {
                            target: &mut *self.target,
                            cursor: Some(item),
                            regs: &mut *self.regs,
                            out: &mut *self.out,
                            metrics: self.metrics,
                            log_namespace: self.log_namespace,
                        }
                        .run(body)
                    })
                    .find(|res| !matches!(res, Ok(Flow::Continue)))
                    .unwrap_or(Ok(Flow::Continue));
                let after = if target.is_reg() {
                    size_of_all(&items)
                } else {
                    0
                };
                self.insert_unmeasured(target, Value::Array(items))?;
                let accounted = if target.is_reg() {
                    self.regs.adjust(signed(after) - signed(before))
                } else {
                    Ok(())
                };
                outcome.and_then(|flow| accounted.map(|_| flow))
            }
            Some(Value::Null) => self
                .insert_unmeasured(target, Value::Null)
                .map(|_| Flow::Continue),
            Some(other) => {
                let kind = kind_name(&other);
                self.insert_unmeasured(target, other)?;
                Err(ActionError::NotAnArray {
                    path: target.to_string(),
                    kind,
                })
            }
        }
    }
}

fn size_of_all(items: &[Value]) -> usize {
    items.iter().map(size).sum()
}

// `if` predicates evaluate against the same view actions use. They only read; every write is
// refused.
impl Target for View<'_> {
    fn target_insert(&mut self, _: &OwnedTargetPath, _: Value) -> Result<(), String> {
        Err(READ_ONLY.to_owned())
    }

    fn target_get(&self, path: &OwnedTargetPath) -> Result<Option<&Value>, String> {
        match (path.prefix, path.path.segments.first(), &self.cursor) {
            (PathPrefix::Event, _, Some(cursor)) => Ok(cursor.get(&path.path)),
            (PathPrefix::Event, _, None) => self.target.target_get(path),
            (PathPrefix::Metadata, Some(OwnedSegment::Field(name)), _) if name.as_str() == META => {
                self.target
                    .target_get(&OwnedTargetPath::metadata(OwnedValuePath {
                        segments: path.path.segments[1..].to_vec(),
                    }))
            }
            (PathPrefix::Metadata, _, _) => Ok(self.regs.value.get(&path.path)),
        }
    }

    fn target_get_mut(&mut self, _: &OwnedTargetPath) -> Result<Option<&mut Value>, String> {
        Err(READ_ONLY.to_owned())
    }

    fn target_remove(&mut self, _: &OwnedTargetPath, _: bool) -> Result<Option<Value>, String> {
        Err(READ_ONLY.to_owned())
    }
}

const READ_ONLY: &str = "assembler predicates are read-only";

impl SecretTarget for View<'_> {
    fn get_secret(&self, key: &str) -> Option<&str> {
        self.target.get_secret(key)
    }

    fn insert_secret(&mut self, _: &str, _: &str) {}

    fn remove_secret(&mut self, _: &str) {}
}
