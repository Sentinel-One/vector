use std::{collections::BTreeMap, sync::Arc};

use chrono::{TimeZone, Utc};
use futures_util::StreamExt;
use indexmap::IndexMap;
use serde::{de, Deserialize};
use vector_lib::codecs::{JsonSerializerConfig, TextSerializerConfig};
use vector_lib::config::{LegacyKey, LogNamespace};
use vector_lib::event::EventMetadata;
use vector_lib::lookup::lookup_v2::{ConfigValuePath, OptionalTargetPath};
use vector_lib::schema::{meaning, Definition};
use vector_lib::{
    config::log_schema,
    event::{Event, LogEvent, Value},
};
use vrl::path::OwnedTargetPath;
use vrl::value::Kind;
use vrl::{event_path, metadata_path, owned_value_path};

use super::sink::{HecLogsProcessedEventMetadata, HecProcessedEvent};
use crate::sinks::util::processed_event::ProcessedEvent;
use crate::{
    codecs::{Encoder, EncodingConfig},
    config::{SinkConfig, SinkContext},
    sinks::{
        splunk_hec::{
            common::EndpointTarget,
            logs::{config::{BatchHeader, BatchHeaders, HecLogsSinkConfig}, encoder::HecLogsEncoder, sink::process_log},
        },
        util::{encoding::Encoder as _, http::RequestConfig, test::build_test_server, Compression},
    },
    template::Template,
    test_util::next_addr,
};
use vector_lib::config::{TimePrecision, TimestampFormat};
use crate::sinks::splunk_hec::logs::config::TimestampConfiguration;
use crate::sinks::prelude::TowerRequestConfig;
use crate::sinks::util::test::load_sink;

#[derive(Deserialize, Debug)]
struct HecEventJson {
    time: Option<f64>,
    event: BTreeMap<String, serde_json::Value>,
    fields: BTreeMap<String, String>,
    source: Option<String>,
    sourcetype: Option<String>,
    index: Option<String>,
    host: Option<String>,
}

#[derive(Deserialize, Debug)]
struct HecEventText {
    time: f64,
    event: String,
    fields: BTreeMap<String, String>,
    source: Option<String>,
    sourcetype: Option<String>,
    index: Option<String>,
    host: Option<String>,
}

fn get_encoded_event<D: de::DeserializeOwned>(
    encoding: EncodingConfig,
    processed_event: ProcessedEvent<LogEvent, HecLogsProcessedEventMetadata>,
) -> D {
    let encoder = hec_encoder(encoding);
    let mut bytes = Vec::new();
    encoder
        .encode_input(vec![processed_event], &mut bytes)
        .unwrap();
    serde_json::from_slice::<D>(&bytes).unwrap()
}

fn get_processed_event_timestamp(
    timestamp: Option<Value>,
    timestamp_key: Option<OptionalTargetPath>,
    auto_extract_timestamp: bool,
) -> HecProcessedEvent {
    let mut event = Event::Log(LogEvent::from("hello world"));
    event
        .as_mut_log()
        .insert("event_sourcetype", "test_sourcetype");
    event.as_mut_log().insert("event_source", "test_source");
    event.as_mut_log().insert("event_index", "test_index");
    event.as_mut_log().insert("host_key", "test_host");
    event.as_mut_log().insert("event_field1", "test_value1");
    event.as_mut_log().insert("event_field2", "test_value2");
    event.as_mut_log().insert("key", "value");
    event.as_mut_log().insert("int_val", 123);

    if let Some(OptionalTargetPath {
        path: Some(ts_path),
    }) = &timestamp_key
    {
        if timestamp.is_some() {
            event
                .as_mut_log()
                .insert(&OwnedTargetPath::event(ts_path.path.clone()), timestamp);
        } else {
            event
                .as_mut_log()
                .remove(&OwnedTargetPath::event(ts_path.path.clone()));
        }
    }
    let timestamp_nanos_key = Some(String::from("ts_nanos_key"));

    let timestamp_configuration = TimestampConfiguration {
        timestamp_key: timestamp_key.clone(),
        timestamp_nanos_key,
        preserve_timestamp_key: false,
        format: TimestampFormat::Native
    };


    let sourcetype = Template::try_from("{{ event_sourcetype }}".to_string()).ok();
    let source = Template::try_from("{{ event_source }}".to_string()).ok();
    let index = Template::try_from("{{ event_index }}".to_string()).ok();
    let indexed_fields = vec![
        owned_value_path!("event_field1"),
        owned_value_path!("event_field2"),
    ];


    process_log(
        event,
        &super::sink::HecLogData {
            sourcetype: sourcetype.as_ref(),
            source: source.as_ref(),
            index: index.as_ref(),
            host_key: Some(OptionalTargetPath {
                path: Some(OwnedTargetPath::event(owned_value_path!("host_key"))),
            }),
            indexed_fields: indexed_fields.as_slice(),
            endpoint_target: EndpointTarget::Event,
            auto_extract_timestamp,
            timestamp_configuration: Some(timestamp_configuration),
        },
    )
}

fn get_processed_event() -> HecProcessedEvent {
    get_processed_event_timestamp(
        Some(vrl::value::Value::Timestamp(
            Utc.timestamp_nanos(1638366107111456123),
        )),
        Some(OptionalTargetPath {
            path: Some(OwnedTargetPath::event(owned_value_path!("timestamp"))),
        }),
        false,
    )
}

fn get_event_with_token(msg: &str, token: &str) -> Event {
    let mut event = Event::Log(LogEvent::from(msg));
    event.metadata_mut().set_splunk_hec_token(Arc::from(token));
    event
}

#[test]
fn splunk_process_log_event() {
    let processed_event = get_processed_event();
    let metadata = processed_event.metadata;

    assert_eq!(metadata.sourcetype, Some("test_sourcetype".to_string()));
    assert_eq!(metadata.source, Some("test_source".to_string()));
    assert_eq!(metadata.index, Some("test_index".to_string()));
    assert_eq!(metadata.host, Some(Value::from("test_host")));
    assert!(metadata.fields.contains("event_field1"));
    assert!(metadata.fields.contains("event_field2"));
}

fn hec_encoder(encoding: EncodingConfig) -> HecLogsEncoder {
    let transformer = encoding.transformer();
    let serializer = encoding.build().unwrap();
    let encoder = Encoder::<()>::new(serializer);
    HecLogsEncoder {
        transformer,
        encoder,
        auto_extract_timestamp: false,
    }
}

#[test]
fn splunk_encode_log_event_json() {
    let processed_event = get_processed_event();
    let hec_data =
        get_encoded_event::<HecEventJson>(JsonSerializerConfig::default().into(), processed_event);
    let event = hec_data.event;

    assert_eq!(event.get("key").unwrap(), &serde_json::Value::from("value"));
    assert_eq!(event.get("int_val").unwrap(), &serde_json::Value::from(123));
    assert_eq!(
        event
            .get(&log_schema().message_key().unwrap().to_string())
            .unwrap(),
        &serde_json::Value::from("hello world")
    );
    assert!(!event.contains_key(log_schema().timestamp_key().unwrap().to_string().as_str()));

    assert_eq!(hec_data.source, Some("test_source".to_string()));
    assert_eq!(hec_data.sourcetype, Some("test_sourcetype".to_string()));
    assert_eq!(hec_data.index, Some("test_index".to_string()));
    assert_eq!(hec_data.host, Some("test_host".to_string()));

    assert_eq!(hec_data.fields.get("event_field1").unwrap(), "test_value1");

    assert_eq!(hec_data.time, Some(1638366107.111));
    assert_eq!(
        event.get("ts_nanos_key").unwrap(),
        &serde_json::Value::from(456123)
    );
}

#[test]
fn splunk_encode_log_event_text() {
    let processed_event = get_processed_event();
    let hec_data =
        get_encoded_event::<HecEventText>(TextSerializerConfig::default().into(), processed_event);

    assert_eq!(hec_data.event.as_str(), "hello world");

    assert_eq!(hec_data.source, Some("test_source".to_string()));
    assert_eq!(hec_data.sourcetype, Some("test_sourcetype".to_string()));
    assert_eq!(hec_data.index, Some("test_index".to_string()));
    assert_eq!(hec_data.host, Some("test_host".to_string()));

    assert_eq!(hec_data.fields.get("event_field1").unwrap(), "test_value1");

    assert_eq!(hec_data.time, 1638366107.111);
}

#[tokio::test]
async fn splunk_passthrough_token() {
    let addr = next_addr();
    let config = HecLogsSinkConfig {
        default_token: "token".to_string().into(),
        ignore_stored_token: false,
        endpoint: format!("http://{}", addr),
        host_key: None,
        indexed_fields: Vec::new(),
        index: None,
        sourcetype: None,
        source: None,
        encoding: JsonSerializerConfig::default().into(),
        compression: Compression::None,
        batch: Default::default(),
        batch_headers: Default::default(),
        request: Default::default(),
        tls: None,
        acknowledgements: Default::default(),
        path: None,
        auto_extract_timestamp: None,
        endpoint_target: EndpointTarget::Event,
        timestamp_configuration: None
    };
    let cx = SinkContext::default();

    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let events = vec![
        get_event_with_token("message-1", "passthrough-token-1"),
        get_event_with_token("message-2", "passthrough-token-2"),
        Event::Log(LogEvent::from("default token will be used")),
    ];

    sink.run_events(events).await.unwrap();

    let mut tokens = rx
        .take(3)
        .map(|r| r.0.headers.get("Authorization").unwrap().clone())
        .collect::<Vec<_>>()
        .await;

    tokens.sort();
    assert_eq!(
        tokens,
        vec![
            "Splunk passthrough-token-1",
            "Splunk passthrough-token-2",
            "Splunk token"
        ]
    )
}

#[test]
fn splunk_encode_log_event_json_timestamps() {
    crate::test_util::trace_init();

    fn get_hec_data_for_timestamp_test(
        timestamp: Option<Value>,
        timestamp_path: Option<OptionalTargetPath>,
        auto_extract_timestamp: bool,
    ) -> HecEventJson {
        let processed_event =
            get_processed_event_timestamp(timestamp, timestamp_path, auto_extract_timestamp);
        get_encoded_event::<HecEventJson>(JsonSerializerConfig::default().into(), processed_event)
    }

    let timestamp_key = Some(OptionalTargetPath {
        path: Some(OwnedTargetPath::event(owned_value_path!("timestamp"))),
    });

    let no_timestamp = Some(OptionalTargetPath::none());
    let dont_auto_extract = false;
    let do_auto_extract = true;

    // no timestamp_key is provided
    let mut hec_data = get_hec_data_for_timestamp_test(None, no_timestamp, dont_auto_extract);
    assert_eq!(hec_data.time, None);

    // timestamp_key is provided but timestamp is not valid type
    hec_data = get_hec_data_for_timestamp_test(
        Some(vrl::value::Value::Integer(0)),
        timestamp_key.clone(),
        dont_auto_extract,
    );
    assert_eq!(hec_data.time, None);

    // timestamp_key is provided but no timestamp in the event
    hec_data = get_hec_data_for_timestamp_test(None, timestamp_key.clone(), dont_auto_extract);
    assert_eq!(hec_data.time, None);

    // timestamp_key is provided and timestamp is valid
    hec_data = get_hec_data_for_timestamp_test(
        Some(Value::Timestamp(Utc::now())),
        timestamp_key.clone(),
        dont_auto_extract,
    );
    assert!(hec_data.time.is_some());

    // timestamp_key is provided and timestamp is valid, but auto_extract_timestamp is set
    hec_data = get_hec_data_for_timestamp_test(
        Some(Value::Timestamp(Utc::now())),
        timestamp_key.clone(),
        do_auto_extract,
    );
    assert_eq!(hec_data.time, None);
}

#[test]
fn splunk_encode_log_event_semantic_meanings() {
    let metadata = EventMetadata::default().with_schema_definition(&Arc::new(
        Definition::new_with_default_metadata(Kind::bytes(), [LogNamespace::Vector])
            .with_source_metadata(
                "splunk_hec",
                Some(LegacyKey::InsertIfEmpty(owned_value_path!("hostname"))),
                &owned_value_path!("hostname"),
                Kind::bytes(),
                Some(meaning::HOST),
            )
            .with_source_metadata(
                "splunk_hec",
                Some(LegacyKey::InsertIfEmpty(owned_value_path!("timestamp"))),
                &owned_value_path!("timestamp"),
                Kind::timestamp(),
                Some(meaning::TIMESTAMP),
            ),
    ));

    let mut log = LogEvent::new_with_metadata(metadata);
    log.insert(event_path!("message"), "the_message");

    // insert an arbitrary metadata field such that the log becomes Vector namespaced
    log.insert(metadata_path!("vector", "foo"), "bar");

    let og_time = Utc::now();

    // determine the time we expect to get after encoding
    let expected_time = (og_time.timestamp_millis() as f64) / 1000f64;

    log.insert(metadata_path!("splunk_hec", "hostname"), "roast");
    log.insert(
        metadata_path!("splunk_hec", "timestamp"),
        Value::Timestamp(og_time),
    );

    assert!(log.namespace() == LogNamespace::Vector);

    let event = Event::Log(log);

    let processed_event = process_log(
        event,
        &super::sink::HecLogData {
            sourcetype: None,
            source: None,
            index: None,
            host_key: None,
            indexed_fields: &[],
            endpoint_target: EndpointTarget::Event,
            auto_extract_timestamp: false,
            timestamp_configuration: None,
        },
    );

    let hec_data =
        get_encoded_event::<HecEventJson>(JsonSerializerConfig::default().into(), processed_event);

    assert_eq!(hec_data.time, Some(expected_time));

    assert_eq!(hec_data.host, Some("roast".to_string()));
}

#[test]
fn splunk_encode_log_event_json_no_timestamp_configuration() {
    crate::test_util::trace_init();

    // Vector should default to extracting user logspaced
    // timestamp if no timestamp configuration is provided

    // Build an event similar to `get_processed_event_timestamp` but force Seconds format
    let mut event = create_test_event();

    // timestamp with nanoseconds
    let ts_val = Value::Integer(1638366107983);
    event.as_mut_log().insert(
        &OwnedTargetPath::event(owned_value_path!("time")),
        ts_val
    );

    let sourcetype = Template::try_from("{{ event_sourcetype }}".to_string()).ok();
    let source = Template::try_from("{{ event_source }}".to_string()).ok();
    let index = Template::try_from("{{ event_index }}".to_string()).ok();
    let indexed_fields = vec![
        owned_value_path!("event_field1"),
        owned_value_path!("event_field2"),
    ];


    let processed = process_log(
        event,
        &super::sink::HecLogData {
            sourcetype: sourcetype.as_ref(),
            source: source.as_ref(),
            index: index.as_ref(),
            host_key: Some(OptionalTargetPath {
                path: Some(OwnedTargetPath::event(owned_value_path!("host_key"))),
            }),
            indexed_fields: indexed_fields.as_slice(),
            endpoint_target: EndpointTarget::Event,
            auto_extract_timestamp: false,
            timestamp_configuration: None,
        },
    );

    let hec_data =
        get_encoded_event::<HecEventJson>(JsonSerializerConfig::default().into(), processed);

    // Even though we didn't provide timestamp configuration, it takes user logspaced timestamp and
    // adds that to the metadata, which will be the current time in seconds
    assert_eq!(hec_data.time.is_some(), true);

    // Timestamp key path is not present in event, we expect no ts_nanos_key
    assert_eq!(hec_data.event.get("ts_nanos_key"), None);


    // user_logspaced timestamp should be removed from the event
    assert_eq!(
        hec_data
            .event
            .get("timestamp")
            .is_none(),
        true
    );

    // Basic metadata checks
    assert_eq!(hec_data.source, Some("test_source".to_string()));
    assert_eq!(hec_data.sourcetype, Some("test_sourcetype".to_string()));
    assert_eq!(hec_data.index, Some("test_index".to_string()));
    assert_eq!(hec_data.host, Some("test_host".to_string()));
    assert_eq!(hec_data.fields.get("event_field1").unwrap(), "test_value1");
}

fn create_test_event() -> Event {
    let mut event = Event::Log(LogEvent::from("hello world"));
    let log = event.as_mut_log();
    log.insert("event_sourcetype", "test_sourcetype");
    log.insert("event_source", "test_source");
    log.insert("event_index", "test_index");
    log.insert("host_key", "test_host");
    log.insert("event_field1", "test_value1");
    log.insert("event_field2", "test_value2");
    log.insert("key", "value");
    log.insert("int_val", 123);
    event
}

#[test]
fn test_timestamp_configurations() {
    crate::test_util::trace_init();

    struct TestCase {
        name: &'static str,
        timestamp_value: Value,
        event_timestamp_insertion_path: String,
        config: Option<TimestampConfiguration>,
        expected_time: Option<f64>,
        expected_nanos: Option<i64>,
        time_metadata_should_exist: bool,
        should_preserve_timestamp: bool,
    }

    let test_cases = vec![
        TestCase {
            name: "seconds precision",
            timestamp_value: Value::Integer(1638366107),
            event_timestamp_insertion_path: "time".to_string(),
            config: Some(TimestampConfiguration {
                timestamp_key: Some(OptionalTargetPath {
                    path: Some(OwnedTargetPath::event(owned_value_path!("time"))),
                }),
                timestamp_nanos_key: Some(String::from("ts_nanos_key")),
                preserve_timestamp_key: false,
                format: TimestampFormat::Numeric(TimePrecision::Seconds),
            }),
            expected_time: Some(1638366107.0),
            expected_nanos: Some(0),
            should_preserve_timestamp: false,
            time_metadata_should_exist: true
        },
        TestCase {
            name: "milliseconds precision",
            timestamp_value: Value::Integer(1638366107983),
            event_timestamp_insertion_path: "time".to_string(),
            config: Some(TimestampConfiguration {
                timestamp_key: Some(OptionalTargetPath {
                    path: Some(OwnedTargetPath::event(owned_value_path!("time"))),
                }),
                timestamp_nanos_key: Some(String::from("ts_nanos_key")),
                preserve_timestamp_key: false,
                format: TimestampFormat::Numeric(TimePrecision::Milliseconds),
            }),
            expected_time: Some(1638366107.983),
            expected_nanos: Some(0),
            should_preserve_timestamp: false,
            time_metadata_should_exist: true
        },
        TestCase {
            name: "microseconds precision",
            timestamp_value: Value::Integer(1638366107983874),
            event_timestamp_insertion_path: "time".to_string(),
            config: Some(TimestampConfiguration {
                timestamp_key: Some(OptionalTargetPath {
                    path: Some(OwnedTargetPath::event(owned_value_path!("time"))),
                }),
                timestamp_nanos_key: Some(String::from("ts_nanos_key")),
                preserve_timestamp_key: false,
                format: TimestampFormat::Numeric(TimePrecision::Microseconds),
            }),
            expected_time: Some(1638366107.983),
            expected_nanos: Some(874000),
            should_preserve_timestamp: false,
            time_metadata_should_exist: true
        },
        TestCase {
            name: "nanoseconds precision",
            timestamp_value: Value::Integer(1638366107983874983),
            event_timestamp_insertion_path: "time".to_string(),
            config: Some(TimestampConfiguration {
                timestamp_key: Some(OptionalTargetPath {
                    path: Some(OwnedTargetPath::event(owned_value_path!("time"))),
                }),
                timestamp_nanos_key: Some(String::from("ts_nanos_key")),
                preserve_timestamp_key: false,
                format: TimestampFormat::Numeric(TimePrecision::Nanoseconds),
            }),
            expected_time: Some(1638366107.983),
            expected_nanos: Some(874983),
            should_preserve_timestamp: false,
            time_metadata_should_exist: true
        },
        TestCase {
            name: "seconds precision, with invalid path configuration metadata should not present",
            timestamp_value: Value::Integer(1638366107),
            event_timestamp_insertion_path: "invalid_time_path".to_string(),
            config: Some(TimestampConfiguration {
                timestamp_key: Some(OptionalTargetPath {
                    path: Some(OwnedTargetPath::event(owned_value_path!("time"))),
                }),
                timestamp_nanos_key: Some(String::from("ts_nanos_key")),
                preserve_timestamp_key: false,
                format: TimestampFormat::Numeric(TimePrecision::Seconds),
            }),
            expected_time: None,
            expected_nanos: None,
            should_preserve_timestamp: true,
            time_metadata_should_exist: false
        },
        TestCase {
            name: "regex format with timezone",
            event_timestamp_insertion_path: "time".to_string(),
            timestamp_value: Value::Bytes("1995 Aug 6 12:09:14.274 +0000".into()),
            config: Some(TimestampConfiguration {
                timestamp_key: Some(OptionalTargetPath {
                    path: Some(OwnedTargetPath::event(owned_value_path!("time"))),
                }),
                timestamp_nanos_key: Some(String::from("ts_nanos_key")),
                preserve_timestamp_key: false,
                format: TimestampFormat::Fmtstr("%Y %b %d %H:%M:%S%.3f %z".to_string()), //strftime
            }),
            expected_time: Some(807710954.274),
            expected_nanos: Some(0),
            should_preserve_timestamp: false,
            time_metadata_should_exist: true
        },
        TestCase {
            name: "regex format without zone in format",
            event_timestamp_insertion_path: "time".to_string(),
            timestamp_value: Value::Bytes("1995-08-06T12:34:56.789".into()),
            config: Some(TimestampConfiguration {
                timestamp_key: Some(OptionalTargetPath {
                    path: Some(OwnedTargetPath::event(owned_value_path!("time"))),
                }),
                timestamp_nanos_key: Some(String::from("ts_nanos_key")),
                preserve_timestamp_key: false,
                format: TimestampFormat::Fmtstr("%Y-%m-%dT%H:%M:%S.%f".to_string()),
            }),
            expected_time: Some(807712496.0),
            expected_nanos: Some(789),
            should_preserve_timestamp: false,
            time_metadata_should_exist: true
        },
    ];

    for test_case in test_cases {
        let mut event = create_test_event();
        event.as_mut_log().insert(
            &OwnedTargetPath::event(owned_value_path!(test_case.event_timestamp_insertion_path.as_str())),
            test_case.timestamp_value,
        );

        let sourcetype = Template::try_from("{{ event_sourcetype }}".to_string()).ok();
        let source = Template::try_from("{{ event_source }}".to_string()).ok();
        let index = Template::try_from("{{ event_index }}".to_string()).ok();
        let indexed_fields = vec![
            owned_value_path!("event_field1"),
            owned_value_path!("event_field2"),
        ];

        let processed = process_log(
            event,
            &super::sink::HecLogData {
                sourcetype: sourcetype.as_ref(),
                source: source.as_ref(),
                index: index.as_ref(),
                host_key: Some(OptionalTargetPath {
                    path: Some(OwnedTargetPath::event(owned_value_path!("host_key"))),
                }),
                indexed_fields: indexed_fields.as_slice(),
                endpoint_target: EndpointTarget::Event,
                auto_extract_timestamp: false,
                timestamp_configuration: test_case.config,
            },
        );

        let hec_data = get_encoded_event::<HecEventJson>(JsonSerializerConfig::default().into(), processed);


        if test_case.time_metadata_should_exist {
            assert!(
                hec_data.time.is_some(),
                "Test case '{}' failed: expected time metadata to exist",
                test_case.name
            );
        } else {
            assert!(
                hec_data.time.is_none(),
                "Test case '{}' failed: expected time metadata to not exist",
                test_case.name
            );
        }
        assert_eq!(
            hec_data.time, test_case.expected_time,
            "Test case '{}' failed: unexpected time value", test_case.name
        );
        if test_case.expected_nanos.is_some() {
            assert_eq!(
                hec_data.event.get("ts_nanos_key").unwrap(),
                &serde_json::Value::from(test_case.expected_nanos.unwrap()),
                "Test case '{}' failed: unexpected nanos value", test_case.name
            );
        } else {
            assert_eq!(
                hec_data.event.get("ts_nanos_key"),
                None,
                "Test case '{}' failed: none expected, but present", test_case.name
            );
        }

        if test_case.should_preserve_timestamp {
            assert!(
                hec_data.event.get(test_case.event_timestamp_insertion_path.as_str()).is_some(),
                "Test case '{}' failed: timestamp should be preserved", test_case.name
            );
        } else {
            assert!(
                hec_data.event.get(test_case.event_timestamp_insertion_path.as_str()).is_none(),
                "Test case '{}' failed: timestamp should not be preserved", test_case.name
            );
        }


        // Basic metadata checks
        assert_eq!(hec_data.source, Some("test_source".to_string()));
        assert_eq!(hec_data.sourcetype, Some("test_sourcetype".to_string()));
        assert_eq!(hec_data.index, Some("test_index".to_string()));
        assert_eq!(hec_data.host, Some("test_host".to_string()));
        assert_eq!(hec_data.fields.get("event_field1").unwrap(), "test_value1");
    }
}

// ============================================================================
// Batch Header Tests
// ============================================================================

fn create_batch_headers(headers: Vec<(&str, &str)>) -> BatchHeaders {
    let batch_headers: Vec<BatchHeader> = headers
        .into_iter()
        .map(|(name, path)| BatchHeader {
            name: name.to_string(),
            value: ConfigValuePath::try_from(path.to_string()).unwrap(),
        })
        .collect();
    BatchHeaders::from(batch_headers)
}

fn create_event_with_fields(fields: Vec<(&str, &str)>) -> Event {
    let message = fields
        .iter()
        .find(|(k, _)| *k == "event_id")
        .map(|(_, v)| *v)
        .unwrap_or("test message");
    let mut event = Event::Log(LogEvent::from(message));
    for (key, value) in fields {
        event.as_mut_log().insert(key, value);
    }
    event
}

#[tokio::test]
async fn raw_endpoint_with_metadata_and_batch_headers() {
    let addr = next_addr();
    let config = HecLogsSinkConfig {
        default_token: "token".to_string().into(),
        ignore_stored_token: false,
        endpoint: format!("http://{}", addr),
        host_key: None,
        indexed_fields: Vec::new(),
        index: Some(Template::try_from("{{ idx }}").unwrap()),
        sourcetype: None,
        source: None,
        encoding: TextSerializerConfig::default().into(),
        compression: Compression::None,
        batch: Default::default(),
        batch_headers: create_batch_headers(vec![
            ("X-Header-A", "field_a"),
            ("X-Header-B", "field_b"),
        ]),
        request: Default::default(),
        tls: None,
        acknowledgements: Default::default(),
        path: None,
        auto_extract_timestamp: None,
        endpoint_target: EndpointTarget::Raw,
        timestamp_configuration: None,
    };
    let cx = SinkContext::default();

    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let events = vec![
        create_event_with_fields(vec![("field_a", "val1"), ("field_b", "val2"), ("idx", "idx1"), ("event_id", "evt1")]),
        create_event_with_fields(vec![("field_a", "val1"), ("field_b", "val2"), ("idx", "idx1"), ("event_id", "evt2")]),
        create_event_with_fields(vec![("field_a", "val1"), ("field_b", "val3"), ("idx", "idx1"), ("event_id", "evt3")]),
        create_event_with_fields(vec![("field_a", "val1"), ("field_b", "val2"), ("idx", "idx2"), ("event_id", "evt4")]),
    ];

    sink.run_events(events).await.unwrap();

    let mut requests: Vec<_> = rx.take(3).collect().await;

    requests.sort_by(|a, b| {
        let a_header_b = a.0.headers.get("X-Header-B").map(|v| v.to_str().unwrap_or(""));
        let b_header_b = b.0.headers.get("X-Header-B").map(|v| v.to_str().unwrap_or(""));
        let a_query = a.0.uri.query().unwrap_or("");
        let b_query = b.0.uri.query().unwrap_or("");
        (a_header_b, a_query).cmp(&(b_header_b, b_query))
    });

    // Batch 1: events 1,2 (val2, idx1)
    assert_eq!(requests[0].0.headers.get("X-Header-A").unwrap(), "val1");
    assert_eq!(requests[0].0.headers.get("X-Header-B").unwrap(), "val2");
    assert!(requests[0].0.uri.query().unwrap().contains("index=idx1"));
    let body0 = String::from_utf8_lossy(&requests[0].1);
    assert!(body0.contains("evt1"));
    assert!(body0.contains("evt2"));
    assert!(!body0.contains("evt3"));
    assert!(!body0.contains("evt4"));

    // Batch 2: event 4 (val2, idx2)
    assert_eq!(requests[1].0.headers.get("X-Header-A").unwrap(), "val1");
    assert_eq!(requests[1].0.headers.get("X-Header-B").unwrap(), "val2");
    assert!(requests[1].0.uri.query().unwrap().contains("index=idx2"));
    let body1 = String::from_utf8_lossy(&requests[1].1);
    assert!(body1.contains("evt4"));
    assert!(!body1.contains("evt1"));
    assert!(!body1.contains("evt2"));
    assert!(!body1.contains("evt3"));

    // Batch 3: event 3 (val3, idx1)
    assert_eq!(requests[2].0.headers.get("X-Header-A").unwrap(), "val1");
    assert_eq!(requests[2].0.headers.get("X-Header-B").unwrap(), "val3");
    assert!(requests[2].0.uri.query().unwrap().contains("index=idx1"));
    let body2 = String::from_utf8_lossy(&requests[2].1);
    assert!(body2.contains("evt3"));
    assert!(!body2.contains("evt1"));
    assert!(!body2.contains("evt2"));
    assert!(!body2.contains("evt4"));
}

#[tokio::test]
async fn raw_endpoint_with_only_batch_headers() {
    let addr = next_addr();
    let config = HecLogsSinkConfig {
        default_token: "token".to_string().into(),
        ignore_stored_token: false,
        endpoint: format!("http://{}", addr),
        host_key: None,
        indexed_fields: Vec::new(),
        index: None,
        sourcetype: None,
        source: None,
        encoding: TextSerializerConfig::default().into(),
        compression: Compression::None,
        batch: Default::default(),
        batch_headers: create_batch_headers(vec![("X-Priority", "priority")]),
        request: Default::default(),
        tls: None,
        acknowledgements: Default::default(),
        path: None,
        auto_extract_timestamp: None,
        endpoint_target: EndpointTarget::Raw,
        timestamp_configuration: None,
    };
    let cx = SinkContext::default();

    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let events = vec![
        create_event_with_fields(vec![("priority", "high"), ("event_id", "high-1")]),
        create_event_with_fields(vec![("priority", "high"), ("event_id", "high-2")]),
        create_event_with_fields(vec![("priority", "low"), ("event_id", "low-1")]),
    ];

    sink.run_events(events).await.unwrap();

    let mut requests: Vec<_> = rx.take(2).collect().await;

    requests.sort_by(|a, b| {
        let a_priority = a.0.headers.get("X-Priority").map(|v| v.to_str().unwrap_or(""));
        let b_priority = b.0.headers.get("X-Priority").map(|v| v.to_str().unwrap_or(""));
        a_priority.cmp(&b_priority)
    });

    assert_eq!(requests[0].0.headers.get("X-Priority").unwrap(), "high");
    let query = requests[0].0.uri.query().unwrap_or("");
    assert!(!query.contains("index="));
    let high_body = String::from_utf8_lossy(&requests[0].1);
    assert!(high_body.contains("high-1"));
    assert!(high_body.contains("high-2"));
    assert!(!high_body.contains("low-1"));

    assert_eq!(requests[1].0.headers.get("X-Priority").unwrap(), "low");
    let low_body = String::from_utf8_lossy(&requests[1].1);
    assert!(low_body.contains("low-1"));
    assert!(!low_body.contains("high-1"));
    assert!(!low_body.contains("high-2"));
}

#[tokio::test]
async fn raw_endpoint_without_metadata_or_headers() {
    let addr = next_addr();
    let config = HecLogsSinkConfig {
        default_token: "token".to_string().into(),
        ignore_stored_token: false,
        endpoint: format!("http://{}", addr),
        host_key: None,
        indexed_fields: Vec::new(),
        index: None,
        sourcetype: None,
        source: None,
        encoding: TextSerializerConfig::default().into(),
        compression: Compression::None,
        batch: Default::default(),
        batch_headers: Default::default(),
        request: Default::default(),
        tls: None,
        acknowledgements: Default::default(),
        path: None,
        auto_extract_timestamp: None,
        endpoint_target: EndpointTarget::Raw,
        timestamp_configuration: None,
    };
    let cx = SinkContext::default();

    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let events = vec![
        create_event_with_fields(vec![("event_id", "evt1")]),
        create_event_with_fields(vec![("event_id", "evt2")]),
        create_event_with_fields(vec![("event_id", "evt3")]),
    ];

    sink.run_events(events).await.unwrap();

    let requests: Vec<_> = rx.take(1).collect().await;
    assert_eq!(requests.len(), 1);

    assert!(requests[0].0.headers.get("X-Priority").is_none());
    let query = requests[0].0.uri.query().unwrap_or("");
    assert!(!query.contains("index="));
    let body = String::from_utf8_lossy(&requests[0].1);
    assert!(body.contains("evt1"));
    assert!(body.contains("evt2"));
    assert!(body.contains("evt3"));
}

#[tokio::test]
async fn event_endpoint_with_two_batch_headers() {
    let addr = next_addr();
    let config = HecLogsSinkConfig {
        default_token: "token".to_string().into(),
        ignore_stored_token: false,
        endpoint: format!("http://{}", addr),
        host_key: None,
        indexed_fields: Vec::new(),
        index: None,
        sourcetype: None,
        source: None,
        encoding: JsonSerializerConfig::default().into(),
        compression: Compression::None,
        batch: Default::default(),
        batch_headers: create_batch_headers(vec![
            ("X-Tenant", "tenant"),
            ("X-Region", "region"),
        ]),
        request: Default::default(),
        tls: None,
        acknowledgements: Default::default(),
        path: None,
        auto_extract_timestamp: None,
        endpoint_target: EndpointTarget::Event,
        timestamp_configuration: None,
    };
    let cx = SinkContext::default();

    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let events = vec![
        create_event_with_fields(vec![("tenant", "acme"), ("region", "us"), ("event_id", "acme-us-1")]),
        create_event_with_fields(vec![("tenant", "acme"), ("region", "us"), ("event_id", "acme-us-2")]),
        create_event_with_fields(vec![("tenant", "acme"), ("region", "eu"), ("event_id", "acme-eu-1")]),
        create_event_with_fields(vec![("tenant", "globex"), ("region", "us"), ("event_id", "globex-us-1")]),
    ];

    sink.run_events(events).await.unwrap();

    let mut requests: Vec<_> = rx.take(3).collect().await;

    requests.sort_by(|a, b| {
        let a_tenant = a.0.headers.get("X-Tenant").map(|v| v.to_str().unwrap_or(""));
        let a_region = a.0.headers.get("X-Region").map(|v| v.to_str().unwrap_or(""));
        let b_tenant = b.0.headers.get("X-Tenant").map(|v| v.to_str().unwrap_or(""));
        let b_region = b.0.headers.get("X-Region").map(|v| v.to_str().unwrap_or(""));
        (a_tenant, a_region).cmp(&(b_tenant, b_region))
    });

    assert_eq!(requests[0].0.headers.get("X-Tenant").unwrap(), "acme");
    assert_eq!(requests[0].0.headers.get("X-Region").unwrap(), "eu");
    let body0 = String::from_utf8_lossy(&requests[0].1);
    assert!(body0.contains("acme-eu-1"));
    assert!(!body0.contains("acme-us-1"));
    assert!(!body0.contains("acme-us-2"));
    assert!(!body0.contains("globex-us-1"));

    assert_eq!(requests[1].0.headers.get("X-Tenant").unwrap(), "acme");
    assert_eq!(requests[1].0.headers.get("X-Region").unwrap(), "us");
    let body1 = String::from_utf8_lossy(&requests[1].1);
    assert!(body1.contains("acme-us-1"));
    assert!(body1.contains("acme-us-2"));
    assert!(!body1.contains("acme-eu-1"));
    assert!(!body1.contains("globex-us-1"));

    assert_eq!(requests[2].0.headers.get("X-Tenant").unwrap(), "globex");
    assert_eq!(requests[2].0.headers.get("X-Region").unwrap(), "us");
    let body2 = String::from_utf8_lossy(&requests[2].1);
    assert!(body2.contains("globex-us-1"));
    assert!(!body2.contains("acme-us-1"));
    assert!(!body2.contains("acme-us-2"));
    assert!(!body2.contains("acme-eu-1"));
}

#[tokio::test]
async fn event_endpoint_with_one_batch_header() {
    let addr = next_addr();
    let config = HecLogsSinkConfig {
        default_token: "token".to_string().into(),
        ignore_stored_token: false,
        endpoint: format!("http://{}", addr),
        host_key: None,
        indexed_fields: Vec::new(),
        index: None,
        sourcetype: None,
        source: None,
        encoding: JsonSerializerConfig::default().into(),
        compression: Compression::None,
        batch: Default::default(),
        batch_headers: create_batch_headers(vec![("X-Service", "service")]),
        request: Default::default(),
        tls: None,
        acknowledgements: Default::default(),
        path: None,
        auto_extract_timestamp: None,
        endpoint_target: EndpointTarget::Event,
        timestamp_configuration: None,
    };
    let cx = SinkContext::default();

    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let events = vec![
        create_event_with_fields(vec![("service", "api"), ("event_id", "api-1")]),
        create_event_with_fields(vec![("service", "api"), ("event_id", "api-2")]),
        create_event_with_fields(vec![("service", "web"), ("event_id", "web-1")]),
    ];

    sink.run_events(events).await.unwrap();

    let mut requests: Vec<_> = rx.take(2).collect().await;

    requests.sort_by(|a, b| {
        let a_service = a.0.headers.get("X-Service").map(|v| v.to_str().unwrap_or(""));
        let b_service = b.0.headers.get("X-Service").map(|v| v.to_str().unwrap_or(""));
        a_service.cmp(&b_service)
    });

    assert_eq!(requests[0].0.headers.get("X-Service").unwrap(), "api");
    let api_body = String::from_utf8_lossy(&requests[0].1);
    assert!(api_body.contains("api-1"));
    assert!(api_body.contains("api-2"));
    assert!(!api_body.contains("web-1"));

    assert_eq!(requests[1].0.headers.get("X-Service").unwrap(), "web");
    let web_body = String::from_utf8_lossy(&requests[1].1);
    assert!(web_body.contains("web-1"));
    assert!(!web_body.contains("api-1"));
    assert!(!web_body.contains("api-2"));
}

#[tokio::test]
async fn event_endpoint_no_batching_on_metadata_fields() {
    let addr = next_addr();
    let config = HecLogsSinkConfig {
        default_token: "token".to_string().into(),
        ignore_stored_token: false,
        endpoint: format!("http://{}", addr),
        host_key: None,
        indexed_fields: Vec::new(),
        index: Some(Template::try_from("{{ event_index }}").unwrap()),
        sourcetype: None,
        source: None,
        encoding: JsonSerializerConfig::default().into(),
        compression: Compression::None,
        batch: Default::default(),
        batch_headers: create_batch_headers(vec![("X-Priority", "priority")]),
        request: Default::default(),
        tls: None,
        acknowledgements: Default::default(),
        path: None,
        auto_extract_timestamp: None,
        endpoint_target: EndpointTarget::Event,
        timestamp_configuration: None,
    };
    let cx = SinkContext::default();

    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let events = vec![
        create_event_with_fields(vec![("event_index", "idx1"), ("priority", "high"), ("event_id", "high-idx1")]),
        create_event_with_fields(vec![("event_index", "idx2"), ("priority", "high"), ("event_id", "high-idx2")]),
        create_event_with_fields(vec![("event_index", "idx1"), ("priority", "low"), ("event_id", "low-idx1")]),
    ];

    sink.run_events(events).await.unwrap();

    let mut requests: Vec<_> = rx.take(2).collect().await;

    requests.sort_by(|a, b| {
        let a_priority = a.0.headers.get("X-Priority").map(|v| v.to_str().unwrap_or(""));
        let b_priority = b.0.headers.get("X-Priority").map(|v| v.to_str().unwrap_or(""));
        a_priority.cmp(&b_priority)
    });

    assert_eq!(requests[0].0.headers.get("X-Priority").unwrap(), "high");
    let high_body = String::from_utf8_lossy(&requests[0].1);
    assert!(high_body.contains("high-idx1"));
    assert!(high_body.contains("high-idx2"));
    assert!(!high_body.contains("low-idx1"));

    assert_eq!(requests[1].0.headers.get("X-Priority").unwrap(), "low");
    let low_body = String::from_utf8_lossy(&requests[1].1);
    assert!(low_body.contains("low-idx1"));
    assert!(!low_body.contains("high-idx1"));
    assert!(!low_body.contains("high-idx2"));
}

#[tokio::test]
async fn batch_headers_missing_value_separate_batch() {
    let addr = next_addr();
    let config = HecLogsSinkConfig {
        default_token: "token".to_string().into(),
        ignore_stored_token: false,
        endpoint: format!("http://{}", addr),
        host_key: None,
        indexed_fields: Vec::new(),
        index: None,
        sourcetype: None,
        source: None,
        encoding: JsonSerializerConfig::default().into(),
        compression: Compression::None,
        batch: Default::default(),
        batch_headers: create_batch_headers(vec![("X-Tag", "tag")]),
        request: Default::default(),
        tls: None,
        acknowledgements: Default::default(),
        path: None,
        auto_extract_timestamp: None,
        endpoint_target: EndpointTarget::Event,
        timestamp_configuration: None,
    };
    let cx = SinkContext::default();

    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let events = vec![
        create_event_with_fields(vec![("tag", "important"), ("event_id", "evt-tag-1")]),
        create_event_with_fields(vec![("tag", "important"), ("event_id", "evt-tag-2")]),
        create_event_with_fields(vec![("other_field", "value"), ("event_id", "evt-no-tag")]),
    ];

    sink.run_events(events).await.unwrap();

    let mut requests: Vec<_> = rx.take(2).collect().await;

    requests.sort_by(|a, b| {
        let a_tag = a.0.headers.get("X-Tag").is_some();
        let b_tag = b.0.headers.get("X-Tag").is_some();
        b_tag.cmp(&a_tag)
    });

    assert_eq!(requests[0].0.headers.get("X-Tag").unwrap(), "important");
    let tagged_body = String::from_utf8_lossy(&requests[0].1);
    assert!(tagged_body.contains("evt-tag-1"));
    assert!(tagged_body.contains("evt-tag-2"));
    assert!(!tagged_body.contains("evt-no-tag"));

    assert!(requests[1].0.headers.get("X-Tag").is_none());
    let untagged_body = String::from_utf8_lossy(&requests[1].1);
    assert!(untagged_body.contains("evt-no-tag"));
    assert!(!untagged_body.contains("evt-tag-1"));
    assert!(!untagged_body.contains("evt-tag-2"));
}

#[tokio::test]
async fn batch_headers_static_headers_override() {
    let addr = next_addr();
    let config = HecLogsSinkConfig {
        default_token: "token".to_string().into(),
        ignore_stored_token: false,
        endpoint: format!("http://{}", addr),
        host_key: None,
        indexed_fields: Vec::new(),
        index: None,
        sourcetype: None,
        source: None,
        encoding: JsonSerializerConfig::default().into(),
        compression: Compression::None,
        batch: Default::default(),
        batch_headers: create_batch_headers(vec![("X-Override", "override_field")]),
        request: RequestConfig {
            tower: TowerRequestConfig::default(),
            headers: IndexMap::from_iter([
                ("X-Override".to_owned(), "static-value".to_owned()),
            ]),
        },
        tls: None,
        acknowledgements: Default::default(),
        path: None,
        auto_extract_timestamp: None,
        endpoint_target: EndpointTarget::Event,
        timestamp_configuration: None,
    };
    let cx = SinkContext::default();

    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let events = vec![
        create_event_with_fields(vec![("override_field", "dynamic-value"), ("event_id", "override-evt")]),
    ];

    sink.run_events(events).await.unwrap();

    let requests: Vec<_> = rx.take(1).collect().await;

    assert_eq!(requests[0].0.headers.get("X-Override").unwrap(), "static-value");
    let body = String::from_utf8_lossy(&requests[0].1);
    assert!(body.contains("override-evt"));
    assert!(body.contains("dynamic-value"));
}

#[tokio::test]
async fn batch_header_field_excluded_from_body_raw_endpoint() {
    let addr = next_addr();
    let config_toml = format!(
        r#"
            default_token = "token"
            endpoint = "http://{}"
            endpoint_target = "raw"
            encoding.codec = "json"
            encoding.except_fields = ["tenant"]

            [[batch_headers]]
            name = "X-Tenant"
            value = "tenant"
        "#,
        addr
    );

    let (config, cx) = load_sink::<HecLogsSinkConfig>(&config_toml).unwrap();
    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let mut event = Event::Log(LogEvent::from("test message"));
    event.as_mut_log().insert("tenant", "acme");
    event.as_mut_log().insert("other_field", "keep-me");
    event.as_mut_log().insert("event_id", "evt-raw-transform");

    sink.run_events(vec![event]).await.unwrap();

    let requests: Vec<_> = rx.take(1).collect().await;

    assert_eq!(requests[0].0.headers.get("X-Tenant").unwrap(), "acme");
    let body = String::from_utf8_lossy(&requests[0].1);
    assert!(!body.contains("acme"), "tenant field should be excluded from body");
    assert!(body.contains("other_field"), "other_field should be in body");
    assert!(body.contains("keep-me"), "other_field value should be in body");
}

#[tokio::test]
async fn batch_header_field_excluded_from_body_event_endpoint() {
    let addr = next_addr();
    let config_toml = format!(
        r#"
            default_token = "token"
            endpoint = "http://{}"
            endpoint_target = "event"
            encoding.codec = "json"
            encoding.except_fields = ["priority"]

            [[batch_headers]]
            name = "X-Priority"
            value = "priority"
        "#,
        addr
    );

    let (config, cx) = load_sink::<HecLogsSinkConfig>(&config_toml).unwrap();
    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let mut event = Event::Log(LogEvent::from("test message"));
    event.as_mut_log().insert("priority", "high");
    event.as_mut_log().insert("other_field", "keep-me");
    event.as_mut_log().insert("event_id", "evt-event-transform");

    sink.run_events(vec![event]).await.unwrap();

    let requests: Vec<_> = rx.take(1).collect().await;

    assert_eq!(requests[0].0.headers.get("X-Priority").unwrap(), "high");
    let body = String::from_utf8_lossy(&requests[0].1);
    assert!(!body.contains("high"), "priority field should be excluded from body");
    assert!(body.contains("other_field"), "other_field should be in body");
    assert!(body.contains("keep-me"), "other_field value should be in body");
    assert!(body.contains("evt-event-transform"), "event_id should be in body");
}

async fn run_and_collect_auth_tokens(config_toml: &str, events: Vec<Event>) -> Vec<http::HeaderValue> {
    let addr = next_addr();
    let config_toml = config_toml.replace("{addr}", &addr.to_string());
    let (config, cx) = load_sink::<HecLogsSinkConfig>(&config_toml).unwrap();
    let (sink, _) = config.build(cx).await.unwrap();

    let (rx, _trigger, server) = build_test_server(addr);
    tokio::spawn(server);

    let n = events.len();
    sink.run_events(events).await.unwrap();

    rx.take(n)
        .map(|r| r.0.headers.get("Authorization").unwrap().clone())
        .collect()
        .await
}

#[tokio::test]
async fn splunk_enforce_token_overrides_passthrough() {
    let tokens = run_and_collect_auth_tokens(
        r#"
            default_token = "enforced-token"
            endpoint = "http://{addr}"
            ignore_stored_token = true
            encoding.codec = "json"
        "#,
        vec![
            get_event_with_token("message-with-passthrough", "passthrough-token"),
            Event::Log(LogEvent::from("message-without-passthrough")),
        ],
    )
    .await;

    for token in &tokens {
        assert_eq!(token, "Splunk enforced-token");
    }
}

#[tokio::test]
async fn splunk_enforce_token_without_passthrough() {
    let tokens = run_and_collect_auth_tokens(
        r#"
            default_token = "enforced-token"
            endpoint = "http://{addr}"
            ignore_stored_token = true
            encoding.codec = "json"
        "#,
        vec![Event::Log(LogEvent::from("no-passthrough-event"))],
    )
    .await;

    assert_eq!(tokens[0], "Splunk enforced-token");
}
