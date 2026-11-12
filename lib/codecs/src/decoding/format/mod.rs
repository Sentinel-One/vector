//! A collection of formats that can be used to convert from byte frames to
//! structured events.

#![deny(missing_docs)]

mod assembler;
mod avro;
mod bytes;
mod csv;
mod gelf;
mod influxdb;
mod json;
mod json_paths;
mod native;
mod native_json;
mod protobuf;
mod strata;
#[cfg(feature = "syslog")]
mod syslog;
mod vrl;

use ::bytes::Bytes;
pub use assembler::{
    ActionConfig, AppendConfig, AssembledDeserializer, AssembledDeserializerConfig,
    AssembledDeserializerFactory, AssemblerConfig, EmitConfig, FlushConfig, FlushMetadata,
    ForeachConfig, IfConfig, JsonValue, MergeConfig, ResetConfig,
};
pub use avro::{
    AvroDeserializer, AvroDeserializerConfig, AvroDeserializerFactory, AvroDeserializerOptions,
};
pub use self::csv::{CsvDeserializer, CsvDeserializerConfig, CsvDeserializerOptions};
pub use gelf::{GelfDeserializer, GelfDeserializerConfig, GelfDeserializerOptions};
pub use influxdb::{InfluxdbDeserializer, InfluxdbDeserializerConfig};
pub use json::{JsonDeserializer, JsonDeserializerConfig, JsonDeserializerOptions};
pub use json_paths::{
    JsonPathDeserializer, JsonPathDeserializerConfig, JsonPathDeserializerFactory,
    JsonPathDeserializerOptions, PathOperation, PathOperationConfig,
};
pub use native::{NativeDeserializer, NativeDeserializerConfig};
pub use native_json::{
    NativeJsonDeserializer, NativeJsonDeserializerConfig, NativeJsonDeserializerOptions,
};
pub use protobuf::{
    ProtobufDeserializer, ProtobufDeserializerConfig, ProtobufDeserializerFactory,
    ProtobufDeserializerOptions,
};
use smallvec::SmallVec;
pub use strata::{StrataDeserializer, StrataDeserializerConfig, StrataDeserializerOptions};
#[cfg(feature = "syslog")]
pub use syslog::{SyslogDeserializer, SyslogDeserializerConfig, SyslogDeserializerOptions};
use vector_core::config::LogNamespace;
use vector_core::event::Event;

pub use self::bytes::{BytesDeserializer, BytesDeserializerConfig};

pub use self::vrl::{
    VrlDeserializer, VrlDeserializerConfig, VrlDeserializerFactory, VrlDeserializerOptions,
};

/// Parse structured events from bytes.
pub trait Deserializer: Send {
    /// Parses structured events from bytes.
    ///
    /// It returns a `SmallVec` rather than an `Event` directly, since one byte
    /// frame can potentially hold multiple events, e.g. when parsing a JSON
    /// array. However, we optimize the most common case of emitting one event
    /// by not requiring heap allocations for it.
    fn parse(
        &mut self,
        bytes: Bytes,
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>>;

    /// Ends the current unit of input (a stream, an object, a datagram): returns any events still
    /// held for it, and discards state carried across its frames.
    fn flush(
        &mut self,
        _log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        Ok(SmallVec::new())
    }
}

/// A `Box` containing a `Deserializer`.
pub type BoxedDeserializer = Box<dyn Deserializer>;

/// Default value for the UTF-8 lossy option.
const fn default_lossy() -> bool {
    true
}
