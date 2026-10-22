use std::fmt::{self, Write as _};

use chrono::{DateTime, Timelike, Utc};
use vector_lib::configurable::configurable_component;
use vrl::value::Value;

/// Algorithm used to compute the `vector_effective_bytes_total` metric - a per-destination
/// approximation of the bytes the destination actually charges for.
///
/// The Observo manager sets this per destination when it generates the Vector config.
// Phase 2 will add a `RawBytes` variant (Splunk HEC raw ingested volume). It is intentionally
// omitted until its exact definition is settled - see the design doc open question §10.2:
// https://sentinelone.atlassian.net/wiki/spaces/ENGINEERIN/pages/6173622376
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveBytesAlgorithm {
    /// Sum of the byte-lengths of every scalar JSON *value* sent for the event, excluding key names
    /// at every depth: the event as the codec sends it (with a non-JSON codec, its encoded text
    /// counts as a single string value), plus the `host`, `source`, `sourcetype` and `index` sent
    /// with it, and on the event endpoint the indexed `fields` and `time`. Metadata counts once per
    /// event on either endpoint, and a value sent twice (such as an indexed field also kept in the
    /// event) counts twice. Counted only for batches the destination accepts. Approximates AI SIEM
    /// (SDL) billable value bytes (`sca:bytesToCharge`).
    ValueBytes,

    /// Do not compute effective bytes. The `vector_effective_bytes_total` metric is not emitted,
    /// and downstream analytics falls back to network/raw bytes.
    #[default]
    None,
}

/// What a sink's codec sends as one event.
pub enum SentEvent<'a> {
    /// A JSON codec's value tree, as built for sending.
    Json(&'a serde_json::Value),

    /// A JSON codec's event, measured from the event itself where no value tree is built for
    /// sending. Matches what is sent for the `json` codec.
    Value(&'a Value),

    /// Any other codec's encoded text: a single string value, counted by the bytes actually sent.
    Text(&'a [u8]),
}

/// HEC metadata sent with one event.
#[derive(Default)]
pub struct SentMetadata<'a> {
    pub host: Option<&'a str>,
    pub source: Option<&'a str>,
    pub sourcetype: Option<&'a str>,
    pub index: Option<&'a str>,
    /// The indexed `fields` sent on the event endpoint.
    pub fields: Option<&'a Value>,
    /// The `time` sent on the event endpoint.
    pub time: Option<f64>,
}

impl EffectiveBytesAlgorithm {
    /// Effective bytes of one sent event and its metadata. Always `0` for `none`, without walking
    /// the event.
    pub fn measure(self, event: SentEvent<'_>, metadata: &SentMetadata<'_>) -> u64 {
        match self {
            Self::ValueBytes => {
                let event_bytes = match event {
                    SentEvent::Json(json) => json_value_bytes(json),
                    SentEvent::Value(value) => value_bytes(value),
                    SentEvent::Text(text) => text.len() as u64,
                };
                let metadata_bytes = [
                    metadata.host,
                    metadata.source,
                    metadata.sourcetype,
                    metadata.index,
                ]
                .into_iter()
                .flatten()
                .map(|text| text.len() as u64)
                .sum::<u64>()
                    + metadata.fields.map_or(0, value_bytes)
                    + metadata.time.map_or(0, float_len);
                event_bytes + metadata_bytes
            }
            Self::None => 0,
        }
    }
}

/// Sum of the byte-lengths of every scalar in `value` as serialized to JSON, excluding key names at
/// every depth. Strings count without quotes; other scalars count by their JSON textual form.
fn value_bytes(value: &Value) -> u64 {
    match value {
        Value::Bytes(bytes) => String::from_utf8_lossy(bytes).len() as u64,
        Value::Regex(regex) => regex.as_str().len() as u64,
        Value::Integer(integer) => display_len(integer),
        Value::Float(float) => float_len(float.into_inner()),
        Value::Boolean(true) => 4,
        Value::Boolean(false) => 5,
        Value::Timestamp(timestamp) => timestamp_len(timestamp),
        Value::Object(object) => object.values().map(value_bytes).sum(),
        Value::Array(array) => array.iter().map(value_bytes).sum(),
        Value::Null => 4,
    }
}

/// [`value_bytes`] for a value tree already serialized to JSON.
fn json_value_bytes(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::String(string) => string.len() as u64,
        serde_json::Value::Number(number) => display_len(number),
        serde_json::Value::Bool(true) => 4,
        serde_json::Value::Bool(false) => 5,
        serde_json::Value::Null => 4,
        serde_json::Value::Array(array) => array.iter().map(json_value_bytes).sum(),
        serde_json::Value::Object(object) => object.values().map(json_value_bytes).sum(),
    }
}

/// Length of `timestamp` as serialized (RFC 3339 with `SecondsFormat::AutoSi`), without
/// allocating: 20 bytes plus a 0, 3, 6 or 9 digit fraction and its dot. Leap seconds keep the same
/// width (`:60`). Assumes a year in 0..=9999; years outside that range serialize 1-2 bytes longer
/// and would be slightly under-counted, which real log timestamps never hit.
fn timestamp_len(timestamp: &DateTime<Utc>) -> u64 {
    let fraction = match timestamp.nanosecond() % 1_000_000_000 {
        0 => 0,
        nanos if nanos % 1_000_000 == 0 => 4,
        nanos if nanos % 1_000 == 0 => 7,
        _ => 10,
    };
    20 + fraction
}

/// Length of `float` as serialized to JSON. serde_json writes non-finite floats as `null`.
fn float_len(float: f64) -> u64 {
    serde_json::Number::from_f64(float).map_or(4, |number| display_len(&number))
}

/// Length of `value`'s `Display` form, without allocating.
fn display_len(value: &impl fmt::Display) -> u64 {
    struct Len(u64);

    impl fmt::Write for Len {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            self.0 += text.len() as u64;
            Ok(())
        }
    }

    let mut len = Len(0);
    _ = write!(len, "{value}");
    len.0
}

#[cfg(test)]
mod tests {
    use super::{EffectiveBytesAlgorithm, SentEvent, SentMetadata};
    use chrono::{NaiveDate, TimeZone, Utc};
    use vrl::value::Value;

    fn measure(event: SentEvent<'_>) -> u64 {
        EffectiveBytesAlgorithm::ValueBytes.measure(event, &SentMetadata::default())
    }

    fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
        Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    /// Reference count over the serialized JSON, which both walks must match.
    fn serialized_value_bytes(value: &serde_json::Value) -> u64 {
        match value {
            serde_json::Value::String(string) => string.len() as u64,
            serde_json::Value::Array(array) => array.iter().map(serialized_value_bytes).sum(),
            serde_json::Value::Object(object) => object.values().map(serialized_value_bytes).sum(),
            scalar => scalar.to_string().len() as u64,
        }
    }

    #[test]
    fn value_bytes_excludes_key_names() {
        // The design doc example: "high" (4) + "alice" (5) = 9.
        let value = object([("severity", "high".into()), ("user", "alice".into())]);
        assert_eq!(measure(SentEvent::Value(&value)), 9);
    }

    #[test]
    fn value_bytes_matches_serialized_json() {
        let at = |nanos| Value::from(Utc.timestamp_nanos(nanos));
        let leap_second = NaiveDate::from_ymd_opt(2016, 12, 31)
            .and_then(|date| date.and_hms_milli_opt(23, 59, 59, 1_500))
            .unwrap()
            .and_utc();
        let value = object([
            ("text", Value::from("café")),
            (
                "invalid_utf8",
                Value::Bytes(bytes::Bytes::from_static(b"a\xffb")),
            ),
            ("negative", Value::from(-1234)),
            ("float", Value::from(3.0)),
            ("small_float", Value::from(-2.5e-7)),
            ("large_float", Value::from(1e21)),
            ("infinity", Value::from(f64::INFINITY)),
            ("flag", Value::from(false)),
            ("null", Value::Null),
            ("seconds", at(1_638_366_107_000_000_000)),
            ("millis", at(1_638_366_107_111_000_000)),
            ("micros", at(1_638_366_107_111_456_000)),
            ("nanos", at(1_638_366_107_111_456_123)),
            ("leap_second", Value::from(leap_second)),
            ("nested", object([("user", "alice".into())])),
            (
                "array",
                Value::from(vec![Value::from(1), Value::from("bb"), Value::from(true)]),
            ),
            ("empty", Value::from(Vec::<Value>::new())),
        ]);
        let json = serde_json::to_value(&value).unwrap();
        let expected = serialized_value_bytes(&json);
        assert_eq!(measure(SentEvent::Value(&value)), expected);
        assert_eq!(measure(SentEvent::Json(&json)), expected);
    }

    #[test]
    fn value_bytes_counts_text_payload_as_one_string_value() {
        assert_eq!(measure(SentEvent::Text(b"hello world")), 11);
    }

    #[test]
    fn value_bytes_counts_text_by_bytes_sent() {
        // Not the lossy UTF-8 length, which would count each invalid byte as 3.
        assert_eq!(measure(SentEvent::Text(b"a\xffb")), 3);
    }

    #[test]
    fn value_bytes_counts_sent_metadata() {
        let fields = object([("user", "alice".into())]);
        let metadata = SentMetadata {
            host: Some("web1"),
            source: Some("src"),
            sourcetype: Some("type"),
            index: None,
            fields: Some(&fields),
            time: Some(1_638_366_107.111),
        };
        // "hello"(5) + "web1"(4) + "src"(3) + "type"(4) + "alice"(5) + "1638366107.111"(14) = 35.
        assert_eq!(
            EffectiveBytesAlgorithm::ValueBytes.measure(SentEvent::Text(b"hello"), &metadata),
            35
        );
    }

    #[test]
    fn none_measures_nothing() {
        let value = Value::from("hello world");
        let metadata = SentMetadata {
            source: Some("src"),
            ..SentMetadata::default()
        };
        assert_eq!(
            EffectiveBytesAlgorithm::None.measure(SentEvent::Value(&value), &metadata),
            0
        );
        assert_eq!(
            EffectiveBytesAlgorithm::None.measure(SentEvent::Text(b"hello"), &metadata),
            0
        );
    }
}
