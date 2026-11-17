use bytes::Bytes;
use chrono::Utc;
use derivative::Derivative;
use lookup::lookup_v2::ConfigTargetPath;
use serde_json::Value;
use smallvec::{smallvec, SmallVec};
use vector_config::configurable_component;
use vector_core::{
    config::{log_schema, DataType, LogNamespace},
    event::Event,
    schema,
};
use vrl::value::Kind;

use super::{default_lossy, Deserializer};

/// Configuration for the Strata deserializer.
#[configurable_component]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StrataDeserializerConfig {
    /// Strata-specific decoding options.
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub strata: StrataDeserializerOptions,
}

impl StrataDeserializerConfig {
    /// Creates a new StrataDeserializerConfig with the given options.
    pub fn new(options: StrataDeserializerOptions) -> Self {
        Self { strata: options }
    }

    /// Builds the StrataDeserializer from the configuration.
    pub fn build(&self) -> StrataDeserializer {
        Into::<StrataDeserializer>::into(self)
    }

    /// Returns the output data type of this deserializer.
    pub fn output_type(&self) -> DataType {
        DataType::Log
    }

    /// Returns the schema definition for the given log namespace.
    pub fn schema_definition(&self, log_namespace: LogNamespace) -> schema::Definition {
        match log_namespace {
            LogNamespace::Legacy => {
                let mut definition =
                    schema::Definition::empty_legacy_namespace().unknown_fields(Kind::json());

                if let Some(timestamp_key) = log_schema().timestamp_key() {
                    definition = definition.try_with_field(
                        timestamp_key,
                        Kind::json().or_timestamp(),
                        Some("timestamp"),
                    );
                }
                definition
            }
            LogNamespace::Vector => {
                schema::Definition::new_with_default_metadata(Kind::json(), [log_namespace])
            }
        }
    }
}

fn default_header_field_name() -> ConfigTargetPath {
    "strata_file_header".into()
}

/// Strata-specific decoding options.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct StrataDeserializerOptions {
    /// Determines whether or not to replace invalid UTF-8 sequences instead of failing.
    ///
    /// When true, invalid UTF-8 sequences are replaced with the [`U+FFFD REPLACEMENT CHARACTER`][U+FFFD].
    ///
    /// [U+FFFD]: https://en.wikipedia.org/wiki/Specials_(Unicode_block)#Replacement_character
    #[serde(
        default = "default_lossy",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    #[derivative(Default(value = "default_lossy()"))]
    pub lossy: bool,

    /// Field name for storing the header metadata object.
    /// The entire header JSON object will be added to each log event under this field name.
    ///
    /// Default: "strata_file_header"
    #[serde(default = "default_header_field_name")]
    #[derivative(Default(value = "default_header_field_name()"))]
    pub header_field_name: ConfigTargetPath,
}

/// Deserializer for Strata log format.
#[derive(Debug, Clone)]
pub struct StrataDeserializer {
    lossy: bool,
    header_field_name: ConfigTargetPath,
}

impl StrataDeserializer {
    /// Creates a new StrataDeserializer with the given options.
    pub fn new(lossy: bool, header_field_name: ConfigTargetPath) -> Self {
        Self { lossy, header_field_name }
    }

    fn extract_header(&self, first_line: &str) -> Result<Value, String> {
        let header: Value = serde_json::from_str(first_line)
            .map_err(|error| format!("Error parsing Strata header JSON: {:?}", error))?;

        Ok(header)
    }

    fn enrich_with_header(&self, event: &mut Event, header: &Value) {
        event.as_mut_log().insert(&self.header_field_name, header.clone());
    }
}

impl Deserializer for StrataDeserializer {
    fn parse(
        &mut self,
        bytes: Bytes,
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        let mut events: SmallVec<[Event; 1]> = smallvec![];
        if bytes.is_empty() {
            return Ok(events);
        }

        let data = match self.lossy {
            true => String::from_utf8_lossy(&bytes).to_string(),
            false => String::from_utf8(bytes.into())
                .map_err(|error| format!("Invalid UTF-8 in Strata log: {:?}", error))?,
        };

        let mut lines = data.lines();

        // First line is the header
        let header_line = lines
            .next()
            .ok_or_else(|| "No header line found in Strata log".to_string())?;

        let header = self.extract_header(header_line)?;

        // Parse remaining lines as log entries

        for line in lines {
            if line.trim().is_empty() {
                continue; // Skip empty lines
            }

            let json: Value = serde_json::from_str(line)
                .map_err(|error| format!("Error parsing log JSON: {:?}", error))?;

            let mut event = Event::from_json_value(json, log_namespace)
                .map_err(|error| format!("Error creating event from JSON: {:?}", error))?;

            // Enrich with header metadata
            self.enrich_with_header(&mut event, &header);

            // Add timestamp if needed (Legacy namespace)
            if matches!(log_namespace, LogNamespace::Legacy) {
                if let Some(timestamp_key) = log_schema().timestamp_key_target_path() {
                    let log = event.as_mut_log();
                    if !log.contains(timestamp_key) {
                        log.insert(timestamp_key, Utc::now());
                    }
                }
            }

            events.push(event);
        }

        Ok(events)
    }
}

impl From<&StrataDeserializerConfig> for StrataDeserializer {
    fn from(config: &StrataDeserializerConfig) -> Self {
        Self {
            lossy: config.strata.lossy,
            header_field_name: config.strata.header_field_name.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_strata_simple() {
        let header = r#"{"bucket":"test-bucket","region":"us-east-1","timestamp":"2024-01-01T00:00:00Z"}"#;
        let log1 = r#"{"level":"info","message":"Log entry 1"}"#;
        let log2 = r#"{"level":"warn","message":"Log entry 2"}"#;

        let input = format!("{}\n{}\n{}", header, log1, log2);

        let mut deserializer =
            StrataDeserializer::new(true, "strata_file_header".try_into().unwrap());
        let events = deserializer
            .parse(Bytes::from(input), LogNamespace::Legacy)
            .unwrap();

        assert_eq!(events.len(), 2);

        // Check first event
        let event1 = &events[0];
        let log1 = event1.as_log();
        assert_eq!(log1.get("level").unwrap().to_string_lossy(), "info");
        assert_eq!(log1.get("message").unwrap().to_string_lossy(), "Log entry 1");

        // Header should be a nested object
        let header_field = log1.get("strata_file_header").unwrap();
        let header_obj: serde_json::Value = serde_json::from_str(&header_field.to_string_lossy()).unwrap();
        assert_eq!(header_obj["bucket"], "test-bucket");
        assert_eq!(header_obj["region"], "us-east-1");
        assert_eq!(header_obj["timestamp"], "2024-01-01T00:00:00Z");

        // Check second event has same header
        let event2 = &events[1];
        let log2 = event2.as_log();
        assert_eq!(log2.get("level").unwrap().to_string_lossy(), "warn");
        let header_field2 = log2.get("strata_file_header").unwrap();
        let header_obj2: serde_json::Value = serde_json::from_str(&header_field2.to_string_lossy()).unwrap();
        assert_eq!(header_obj2["bucket"], "test-bucket");
    }

    #[test]
    fn deserialize_strata_custom_field_name() {
        let header = r#"{"bucket":"test-bucket","region":"us-west-2"}"#;
        let log = r#"{"event":"test"}"#;

        let input = format!("{}\n{}", header, log);

        let mut deserializer = StrataDeserializer::new(true, "metadata".try_into().unwrap());
        let events = deserializer
            .parse(Bytes::from(input), LogNamespace::Legacy)
            .unwrap();

        assert_eq!(events.len(), 1);

        let event = &events[0];
        let log = event.as_log();

        // Should be under custom field name
        let header_field = log.get("metadata").unwrap();
        let header_obj: serde_json::Value = serde_json::from_str(&header_field.to_string_lossy()).unwrap();
        assert_eq!(header_obj["bucket"], "test-bucket");
        assert_eq!(header_obj["region"], "us-west-2");
    }

    #[test]
    fn deserialize_strata_with_nested_message() {
        let header = r#"{"bucket":"test","message":"{\"compression\":\"snappy\",\"num_records\":2}"}"#;
        let log = r#"{"event":"test"}"#;

        let input = format!("{}\n{}", header, log);

        let mut deserializer =
            StrataDeserializer::new(true, "strata_file_header".try_into().unwrap());
        let events = deserializer
            .parse(Bytes::from(input), LogNamespace::Legacy)
            .unwrap();

        assert_eq!(events.len(), 1);

        let event = &events[0];
        let log = event.as_log();

        // Header contains the nested message as-is
        let header_field = log.get("strata_file_header").unwrap();
        let header_obj: serde_json::Value = serde_json::from_str(&header_field.to_string_lossy()).unwrap();
        assert_eq!(header_obj["bucket"], "test");

        // Message field is still a JSON string (user can parse with VRL if needed)
        assert!(header_obj["message"].is_string());
    }

    #[test]
    fn deserialize_strata_empty_lines() {
        let header = r#"{"bucket":"test"}"#;
        let log = r#"{"event":"test"}"#;

        let input = format!("{}\n{}\n\n", header, log);

        let mut deserializer =
            StrataDeserializer::new(true, "strata_file_header".try_into().unwrap());
        let events = deserializer
            .parse(Bytes::from(input), LogNamespace::Legacy)
            .unwrap();

        // Should only get 1 event (empty line skipped)
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn deserialize_strata_no_header() {
        let input = "";

        let mut deserializer =
            StrataDeserializer::new(true, "strata_file_header".try_into().unwrap());
        let result = deserializer.parse(Bytes::from(input), LogNamespace::Legacy);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn deserialize_strata_invalid_header_json() {
        let input = "not valid json\n{\"event\":\"test\"}";

        let mut deserializer =
            StrataDeserializer::new(true, "strata_file_header".try_into().unwrap());
        let result = deserializer.parse(Bytes::from(input), LogNamespace::Legacy);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_strata_invalid_log_json() {
        let header = r#"{"bucket":"test"}"#;
        let input = format!("{}\nnot valid json", header);

        let mut deserializer =
            StrataDeserializer::new(true, "strata_file_header".try_into().unwrap());
        let result = deserializer.parse(Bytes::from(input), LogNamespace::Legacy);

        assert!(result.is_err());
    }
}
