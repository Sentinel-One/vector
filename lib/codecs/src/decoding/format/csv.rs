use bytes::Bytes;
use chrono::Utc;
use derivative::Derivative;
use smallvec::{smallvec, SmallVec};
use vector_config::configurable_component;
use vector_core::{
    config::{log_schema, DataType, LogNamespace},
    event::Event,
    schema,
};
use vrl::value::Kind;

use super::Deserializer;

/// Config used to build a `CsvDeserializer`.
#[configurable_component]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CsvDeserializerConfig {
    /// CSV-specific decoding options.
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub csv: CsvDeserializerOptions,
}

/// CSV-specific decoding options.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct CsvDeserializerOptions {
    /// The field delimiter character.
    #[serde(default = "default_delimiter")]
    #[derivative(Default(value = "','"))]
    pub delimiter: char,

    /// How CSV header field names are resolved.
    ///
    /// - A list of strings (e.g. `[host, message]`) supplies headers directly.
    /// - `snoop` consumes the first row of input as headers.
    /// - `none` (default) emits each row as a positional array under `message`.
    #[serde(default)]
    pub headers: Headers,
}

fn default_delimiter() -> char {
    ','
}

/// How CSV headers are resolved.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Headers {
    /// Use the supplied list of column names as field keys for every row.
    Provided {
        /// Column names.
        columns: Vec<String>,
    },
    /// Consume the first row of input as headers.
    Snoop,
    /// No headers; emit each row as a positional array under `message`.
    None,
}

impl Default for Headers {
    fn default() -> Self {
        Headers::None
    }
}

impl CsvDeserializerConfig {
    /// Build the `CsvDeserializer` from this configuration.
    pub fn build(&self) -> CsvDeserializer {
        CsvDeserializer::from(self)
    }

    /// Return the type of event built by this deserializer.
    pub fn output_type(&self) -> DataType {
        DataType::Log
    }

    /// The schema produced by the deserializer.
    pub fn schema_definition(&self, log_namespace: LogNamespace) -> schema::Definition {
        match log_namespace {
            LogNamespace::Legacy => {
                let mut definition =
                    schema::Definition::empty_legacy_namespace().unknown_fields(Kind::bytes());

                if let Some(timestamp_key) = log_schema().timestamp_key() {
                    definition = definition.try_with_field(
                        timestamp_key,
                        Kind::bytes().or_timestamp(),
                        Some("timestamp"),
                    );
                }
                definition
            }
            LogNamespace::Vector => {
                schema::Definition::new_with_default_metadata(Kind::bytes(), [log_namespace])
            }
        }
    }
}

/// Deserializer that builds `Event`s from a byte frame containing CSV data.
///
/// Each `parse()` call is treated as a complete, self-contained CSV chunk.
/// This pairs naturally with `Bytes` framing (the default for CSV); other
/// framers that fragment a CSV stream across frames are not supported, since
/// quoted fields containing newlines would already be corrupted at the
/// framer layer.
#[derive(Debug, Clone)]
pub struct CsvDeserializer {
    delimiter: u8,
    headers: Headers,
}

impl Default for CsvDeserializer {
    fn default() -> Self {
        CsvDeserializerConfig::default().build()
    }
}

impl From<&CsvDeserializerConfig> for CsvDeserializer {
    fn from(config: &CsvDeserializerConfig) -> Self {
        Self {
            delimiter: config.csv.delimiter as u8,
            headers: config.csv.headers.clone(),
        }
    }
}

impl Deserializer for CsvDeserializer {
    fn parse(
        &mut self,
        bytes: Bytes,
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        if bytes.is_empty() {
            return Ok(smallvec![]);
        }

        let mut reader = csv::ReaderBuilder::new()
            .delimiter(self.delimiter)
            .has_headers(false)
            .flexible(true)
            .from_reader(&bytes[..]);

        let mut records = reader.records();

        // Resolve headers for this call.
        let headers: Option<Vec<String>> = match &self.headers {
            Headers::Provided { columns } => Some(columns.clone()),
            Headers::Snoop => match records.next().transpose() {
                Ok(Some(r)) => Some(r.iter().map(String::from).collect()),
                Ok(None) => return Ok(smallvec![]),
                Err(e) => return Err(format!("CSV parse error: {}", e).into()),
            },
            Headers::None => None,
        };

        let timestamp = Utc::now();
        let mut events = SmallVec::new();

        for record in records {
            let record = record.map_err(|e| format!("CSV parse error: {}", e))?;

            let log = match &headers {
                Some(hdrs) => {
                    let mut obj = vrl::value::ObjectMap::new();
                    for (key, field) in hdrs.iter().zip(record.iter()) {
                        obj.insert(key.clone().into(), vrl::value::Value::from(field.to_string()));
                    }
                    vrl::value::Value::Object(obj)
                }
                None => {
                    let arr: Vec<vrl::value::Value> = record
                        .iter()
                        .map(|f| vrl::value::Value::from(f.to_string()))
                        .collect();
                    let mut obj = vrl::value::ObjectMap::new();
                    obj.insert("message".into(), vrl::value::Value::Array(arr));
                    vrl::value::Value::Object(obj)
                }
            };

            let mut event = Event::from(vector_core::event::LogEvent::from(log));
            if log_namespace == LogNamespace::Legacy {
                if let Some(timestamp_key) = log_schema().timestamp_key_target_path() {
                    let log = event.as_mut_log();
                    if !log.contains(timestamp_key) {
                        log.insert(timestamp_key, timestamp);
                    }
                }
            }
            events.push(event);
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vector_core::config::log_schema;
    use vrl::core::Value;

    fn config_with_header() -> CsvDeserializerConfig {
        CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                headers: Headers::Snoop,
                ..Default::default()
            },
        }
    }

    #[test]
    fn deserialize_csv_simple() {
        let input = Bytes::from("host,message,severity\nserver01,hello,info\nserver02,world,warning");
        let config = config_with_header();

        for namespace in [LogNamespace::Legacy, LogNamespace::Vector] {
            let mut deserializer = config.build();
            let events = deserializer.parse(input.clone(), namespace).unwrap();
            assert_eq!(events.len(), 2);

            let event1 = events[0].as_log();
            assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
            assert_eq!(event1.get("message").unwrap(), &Value::from("hello"));
            assert_eq!(event1.get("severity").unwrap(), &Value::from("info"));

            let event2 = events[1].as_log();
            assert_eq!(event2.get("host").unwrap(), &Value::from("server02"));
            assert_eq!(event2.get("message").unwrap(), &Value::from("world"));
            assert_eq!(event2.get("severity").unwrap(), &Value::from("warning"));
        }
    }

    #[test]
    fn deserialize_csv_multiline_quoted_fields() {
        let input = Bytes::from(
            "host,message,severity\nserver01,\"this is a\nmulti-line\nmessage\",warning\nserver02,simple,info",
        );
        let mut deserializer = config_with_header().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(
            event1.get("message").unwrap(),
            &Value::from("this is a\nmulti-line\nmessage")
        );
        assert_eq!(event1.get("severity").unwrap(), &Value::from("warning"));
    }

    #[test]
    fn deserialize_csv_heavily_multiline() {
        let input = Bytes::from(
            r#"host,message,details
server01,"line 1
line 2
line 3","error details:
  code: 500
  reason: internal"
server02,"ok","all good""#,
        );
        let mut deserializer = config_with_header().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(
            event1.get("message").unwrap(),
            &Value::from("line 1\nline 2\nline 3")
        );
        assert_eq!(
            event1.get("details").unwrap(),
            &Value::from("error details:\n  code: 500\n  reason: internal")
        );
    }

    #[test]
    fn deserialize_csv_quoted_commas() {
        let input = Bytes::from("name,location\n\"Doe, John\",\"New York, NY\"\nJane,Boston");
        let mut deserializer = config_with_header().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("name").unwrap(), &Value::from("Doe, John"));
        assert_eq!(event1.get("location").unwrap(), &Value::from("New York, NY"));
    }

    #[test]
    fn deserialize_csv_with_configured_headers() {
        let input = Bytes::from("server01,hello,info\nserver02,world,warning");
        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                headers: Headers::Provided {
                    columns: vec![
                        "host".to_string(),
                        "message".to_string(),
                        "severity".to_string(),
                    ],
                },
                ..Default::default()
            },
        };
        let mut deserializer = config.build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(event1.get("message").unwrap(), &Value::from("hello"));
    }

    #[test]
    fn deserialize_csv_no_headers_returns_array() {
        let input = Bytes::from("server01,hello,info");
        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                headers: Headers::None,
                ..Default::default()
            },
        };
        let mut deserializer = config.build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 1);

        let event = events[0].as_log();
        assert_eq!(
            event.get("message").unwrap(),
            &Value::Array(vec![
                Value::from("server01"),
                Value::from("hello"),
                Value::from("info"),
            ])
        );
    }

    #[test]
    fn deserialize_csv_custom_delimiter() {
        let input = Bytes::from("host\tmessage\nserver01\thello");
        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                delimiter: '\t',
                headers: Headers::Snoop,
            },
        };
        let mut deserializer = config.build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 1);

        let event = events[0].as_log();
        assert_eq!(event.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(event.get("message").unwrap(), &Value::from("hello"));
    }

    #[test]
    fn deserialize_csv_empty() {
        let mut deserializer = CsvDeserializerConfig::default().build();
        let events = deserializer
            .parse(Bytes::from(""), LogNamespace::Vector)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn deserialize_csv_legacy_adds_timestamp() {
        let input = Bytes::from("host\nserver01");
        let mut deserializer = config_with_header().build();

        let events = deserializer.parse(input, LogNamespace::Legacy).unwrap();
        assert_eq!(events.len(), 1);

        let event = events[0].as_log();
        assert!(event
            .get((
                lookup::PathPrefix::Event,
                log_schema().timestamp_key().unwrap()
            ))
            .is_some());
    }

    #[tokio::test]
    async fn bytes_framing_csv_decoder_multiline_fields() {
        use crate::actions::Decoder;
        use crate::decoding::{Deserializer as DeserializerEnum, Framer};
        use crate::BytesDecoder;
        use bytes::Bytes;
        use futures::{stream, StreamExt};
        use tokio_util::{codec::FramedRead, io::StreamReader};

        let csv_data =
            "host,message,severity\nserver01,\"multi\nline\nlog\",warning\nserver02,ok,info";

        let iter = stream::iter([csv_data].into_iter().map(Bytes::from));
        let stream = iter.map(Ok::<_, std::io::Error>);
        let reader = StreamReader::new(stream);

        let decoder = Decoder::new(
            Framer::Bytes(BytesDecoder::new()),
            DeserializerEnum::Csv(config_with_header().build()),
        );
        let mut stream = FramedRead::new(reader, decoder);

        let next = stream.next().await.unwrap();
        let events = next.unwrap().0;
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(
            event1.get("message").unwrap(),
            &Value::from("multi\nline\nlog")
        );

        assert!(stream.next().await.is_none());
    }

    #[test]
    fn deserialize_csv_variable_field_counts() {
        let input = Bytes::from("a,b,c\n1,2,3\n4,5");
        let mut deserializer = config_with_header().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event2 = events[1].as_log();
        assert_eq!(event2.get("a").unwrap(), &Value::from("4"));
        assert_eq!(event2.get("b").unwrap(), &Value::from("5"));
        assert!(event2.get("c").is_none());
    }

    #[test]
    fn deserialize_csv_header_only_no_events() {
        let input = Bytes::from("host,message,severity");
        let mut deserializer = config_with_header().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn deserialize_csv_extra_fields_are_dropped() {
        let input = Bytes::from("a,b\n1,2,3");
        let mut deserializer = config_with_header().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 1);

        let event = events[0].as_log();
        assert_eq!(event.get("a").unwrap(), &Value::from("1"));
        assert_eq!(event.get("b").unwrap(), &Value::from("2"));
        assert!(event.get("column_2").is_none());
    }

    #[test]
    fn headers_variants_round_trip() {
        let provided: Headers =
            serde_json::from_str(r#"{"type":"provided","columns":["a","b","c"]}"#).unwrap();
        assert_eq!(
            provided,
            Headers::Provided {
                columns: vec!["a".into(), "b".into(), "c".into()]
            }
        );

        let snoop: Headers = serde_json::from_str(r#"{"type":"snoop"}"#).unwrap();
        assert_eq!(snoop, Headers::Snoop);

        let none: Headers = serde_json::from_str(r#"{"type":"none"}"#).unwrap();
        assert_eq!(none, Headers::None);
    }
}
