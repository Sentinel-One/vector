//! Rewrites, re-arranges and fans out the events of an inner deserializer by running a small
//! program of actions over each one, with registers that carry values from one event to the next
//! until the stream is flushed.

mod config;
mod program;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use bytes::Bytes;
use smallvec::SmallVec;
use vector_common::limits::OperationalLimits;
use vector_config::configurable_component;
use vector_core::{
    config::{DataType, LogNamespace},
    event::{Event, EventMetadata},
    schema,
};
use vrl::value::Kind;

pub use self::config::{
    ActionConfig, AppendConfig, EmitConfig, ForeachConfig, IfConfig, JsonValue, MergeConfig,
    ResetConfig,
};
use self::program::{ActionError, Metrics, Program, Registers};
use crate::decoding::{Deserializer, DeserializerConfig, DeserializerFactory, NonResumable};

const fn default_resumable() -> bool {
    true
}

/// Which inner-deserializer event's metadata the `flush` event starts with.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlushMetadata {
    /// Empty metadata. A config can still carry metadata into `flush` through a register.
    #[default]
    None,

    /// The first event's metadata since the previous flush.
    First,

    /// The last event's metadata. Keeping it shares each event's metadata, so the next write to
    /// it (sources set some on every event) copies it once per event.
    Last,
}

/// What happens when a unit of input (a stream, an object, a datagram) ends.
#[configurable_component]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FlushConfig {
    /// Actions run once when the unit ends, if anything was decoded since the previous flush.
    /// They run as if over an event whose value is null, so their output is what they `emit`,
    /// plus `.` if they set it. Registers are cleared afterwards.
    #[serde(default)]
    pub actions: Vec<ActionConfig>,

    /// The metadata the flush event starts with.
    #[serde(default)]
    pub metadata_from: FlushMetadata,
}

/// Assembler options.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssemblerConfig {
    /// The actions applied, in order, to each event the inner deserializer produces.
    ///
    /// An event that no action stops or empties is emitted after anything the actions emit.
    pub process: Vec<ActionConfig>,

    /// What happens when the unit of input ends.
    #[serde(default)]
    pub flush: FlushConfig,

    /// Whether the stream keeps being decoded after an error, from the inner deserializer or
    /// from an action. Either way the events of the failing frame are dropped. Exceeding
    /// `max_register_bytes` always ends the stream.
    #[serde(default = "default_resumable")]
    pub resumable: bool,

    /// The most memory the registers may use together, counting each value's and key's
    /// in-memory size, not just its payload. Exceeding it ends the stream, since dropping what
    /// the registers hold would assemble the events that follow with the wrong shape.
    ///
    /// Defaults to the framing limit `max_frame_length_bytes`.
    #[serde(default)]
    pub max_register_bytes: Option<usize>,
}

/// Config for the `assembled` codec.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssembledDeserializerConfig {
    /// The deserializer whose events are assembled.
    #[serde(alias = "deser")]
    pub deserializer: Box<DeserializerConfig>,

    /// How the events are assembled.
    pub assembler: AssemblerConfig,
}

impl AssembledDeserializerConfig {
    /// Builds the factory, compiling the assembler program once.
    pub fn build(
        &self,
        limits: OperationalLimits,
    ) -> vector_common::Result<AssembledDeserializerFactory> {
        Ok(AssembledDeserializerFactory {
            inner: Box::new(self.deserializer.build(limits)?),
            program: Arc::new(Program::compile(
                &self.assembler.process,
                &self.assembler.flush.actions,
            )?),
            flush_metadata: self.assembler.flush.metadata_from,
            resumable: self.assembler.resumable,
            max_register_bytes: self
                .assembler
                .max_register_bytes
                .unwrap_or(limits.framing.max_frame_length_bytes),
            metrics: Metrics::new(),
        })
    }

    /// Actions can emit log events, whatever the inner deserializer produces.
    pub fn output_type(&self) -> DataType {
        self.deserializer.output_type() | DataType::Log
    }

    /// Actions can reshape events arbitrarily, so the schema is unknown.
    pub fn schema_definition(&self, log_namespace: LogNamespace) -> schema::Definition {
        match log_namespace {
            LogNamespace::Legacy => {
                schema::Definition::empty_legacy_namespace().unknown_fields(Kind::any())
            }
            LogNamespace::Vector => {
                schema::Definition::new_with_default_metadata(Kind::any(), [log_namespace])
            }
        }
    }
}

/// Builds `AssembledDeserializer`s that share one compiled program.
#[derive(Debug, Clone)]
pub struct AssembledDeserializerFactory {
    inner: Box<DeserializerFactory>,
    program: Arc<Program>,
    flush_metadata: FlushMetadata,
    resumable: bool,
    max_register_bytes: usize,
    metrics: Metrics,
}

impl AssembledDeserializerFactory {
    /// Builds a deserializer with empty registers.
    pub fn build(&self) -> AssembledDeserializer {
        AssembledDeserializer {
            inner: Box::new(self.inner.build()),
            program: Arc::clone(&self.program),
            registers: Registers::new(self.max_register_bytes),
            flush_metadata: self.flush_metadata,
            kept_metadata: None,
            decoded: false,
            resumable: self.resumable,
            metrics: self.metrics.clone(),
        }
    }
}

/// Runs an assembler program over the events of an inner deserializer.
pub struct AssembledDeserializer {
    inner: Box<Deserializer>,
    program: Arc<Program>,
    registers: Registers,
    flush_metadata: FlushMetadata,
    kept_metadata: Option<EventMetadata>,
    /// Whether anything was decoded since the last flush. `FramedRead` calls `decode_eof` until it
    /// yields nothing, so a flush that emits must not run twice.
    decoded: bool,
    resumable: bool,
    metrics: Metrics,
}

impl AssembledDeserializer {
    fn keep_metadata(&mut self, event: &Event) {
        match (self.flush_metadata, &self.kept_metadata) {
            (FlushMetadata::First, None) | (FlushMetadata::Last, _) => {
                self.kept_metadata = Some(event.metadata().clone());
            }
            _ => {}
        }
    }

    fn run_process(
        &mut self,
        events: SmallVec<[Event; 1]>,
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        let program = Arc::clone(&self.program);
        events
            .into_iter()
            .try_fold(SmallVec::new(), |mut out, event| {
                self.keep_metadata(&event);
                program
                    .process(
                        event,
                        &mut self.registers,
                        &mut out,
                        &self.metrics,
                        log_namespace,
                    )
                    .map(|_| out)
            })
            .map_err(|error| self.fail_action(error))
    }

    fn fail_action(&self, error: ActionError) -> vector_common::Error {
        if error.is_fatal() {
            Box::new(NonResumable(Box::new(error)))
        } else {
            self.fail(Box::new(error))
        }
    }

    fn fail(&self, error: vector_common::Error) -> vector_common::Error {
        if self.resumable {
            error
        } else {
            Box::new(NonResumable(error))
        }
    }
}

impl super::Deserializer for AssembledDeserializer {
    fn parse(
        &mut self,
        bytes: Bytes,
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        self.decoded = true;
        let events = self
            .inner
            .parse(bytes, log_namespace)
            .map_err(|error| self.fail(error))?;
        self.run_process(events, log_namespace)
    }

    /// The inner deserializer's flush output goes through `process` first, then `flush` runs.
    /// Registers and kept metadata are cleared whether or not it succeeds.
    fn flush(
        &mut self,
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        let inner = self
            .inner
            .flush(log_namespace)
            .map_err(|error| self.fail(error))
            .and_then(|events| self.run_process(events, log_namespace));
        let decoded = std::mem::take(&mut self.decoded);
        let metadata = self.kept_metadata.take().unwrap_or_default();
        let result = inner.and_then(|mut out| {
            if decoded && self.program.has_flush() {
                self.program
                    .flush(
                        metadata,
                        &mut self.registers,
                        &mut out,
                        &self.metrics,
                        log_namespace,
                    )
                    .map(|_| out)
                    .map_err(|error| self.fail_action(error))
            } else {
                Ok(out)
            }
        });
        self.registers.reset();
        result
    }
}
