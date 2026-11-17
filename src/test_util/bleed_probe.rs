//! Detects decoder state leaking between two units of input (connections, datagrams, messages,
//! requests): unit 1 leaves a `json_paths` document half open, unit 2 sends a complete one. With
//! isolated decoders unit 2 yields `{"b": 2}`; with a shared decoder it only extends unit 1's
//! document and yields nothing.

use std::{future::Future, time::Duration};

use vector_lib::codecs::decoding::{
    format::{PathOperation, PathOperationConfig},
    DeserializerConfig, JsonPathDeserializerConfig, JsonPathDeserializerOptions,
};
use vector_lib::lookup::owned_value_path;
use vrl::value::Value;

use crate::event::Event;

pub const HALF_OPEN: &str = r#"{"a":"#;
pub const COMPLETE: &str = r#"{"b":2}"#;

pub fn decoding() -> DeserializerConfig {
    JsonPathDeserializerConfig::new(
        PathOperationConfig::new(owned_value_path!(), PathOperation::Identity.into()),
        JsonPathDeserializerOptions::default(),
    )
    .into()
}

pub fn assert_only_complete_document(events: &[Event]) {
    assert_eq!(events.len(), 1);
    assert_every_event_is_complete_document(events);
}

pub fn assert_every_event_is_complete_document(events: &[Event]) {
    assert_ne!(events.len(), 0, "no event from the later units");
    for event in events {
        assert_eq!(event.as_log().get("data.b"), Some(&Value::from(2)));
    }
}

pub async fn within_deadline<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("no event from the second unit: decoder state is likely shared across units")
}
