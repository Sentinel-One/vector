use std::{fmt::{self, Display}, sync::Arc};

use http::{HeaderName, HeaderValue};

use super::request_builder::HecLogsRequestBuilder;
use crate::{
    internal_events::SplunkEventTimestampInvalidType,
    internal_events::SplunkEventTimestampMissing,
    sinks::{
        prelude::*,
        splunk_hec::common::{
            render_template_string, request::HecRequest, EndpointTarget, INDEX_FIELD,
            SOURCETYPE_FIELD, SOURCE_FIELD,
        },
        util::processed_event::ProcessedEvent,
    },
};
use vector_lib::{
    config::{log_schema, LogNamespace, TimestampFormat, TimestampResolutionError},
    lookup::{event_path, lookup_v2::{ConfigValuePath, OptionalTargetPath}, OwnedValuePath, PathPrefix},
    schema::meaning,
};
use vrl::path::OwnedTargetPath;
use crate::sinks::splunk_hec::logs::config::TimestampConfiguration;

// NOTE: The `OptionalTargetPath`s are wrapped in an `Option` in order to distinguish between a true
//       `None` type and an empty string. This is necessary because `OptionalTargetPath` deserializes an
//       empty string to a `None` path internally.
pub struct HecLogsSink<S> {
    pub service: S,
    pub request_builder: HecLogsRequestBuilder,
    pub batch_settings: BatcherSettings,
    pub sourcetype: Option<Template>,
    pub source: Option<Template>,
    pub index: Option<Template>,
    pub indexed_fields: Vec<OwnedValuePath>,
    pub host_key: Option<OptionalTargetPath>,
    pub endpoint_target: EndpointTarget,
    pub auto_extract_timestamp: bool,
    pub timestamp_configuration: Option<TimestampConfiguration>,
    pub batch_headers: Vec<(HeaderName, ConfigValuePath)>,
}

pub struct HecLogData<'a> {
    pub sourcetype: Option<&'a Template>,
    pub source: Option<&'a Template>,
    pub index: Option<&'a Template>,
    pub indexed_fields: &'a [OwnedValuePath],
    pub host_key: Option<OptionalTargetPath>,
    pub endpoint_target: EndpointTarget,
    pub auto_extract_timestamp: bool,
    pub timestamp_configuration: Option<TimestampConfiguration>,
}

impl<S> HecLogsSink<S>
where
    S: Service<HecRequest> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: DriverResponse + Send + 'static,
    S::Error: fmt::Debug + Into<crate::Error> + Send,
{
    async fn run_inner(self: Box<Self>, input: BoxStream<'_, Event>) -> Result<(), ()> {
        let data = HecLogData {
            sourcetype: self.sourcetype.as_ref(),
            source: self.source.as_ref(),
            index: self.index.as_ref(),
            indexed_fields: self.indexed_fields.as_slice(),
            host_key: self.host_key.clone(),
            endpoint_target: self.endpoint_target,
            auto_extract_timestamp: self.auto_extract_timestamp,
            timestamp_configuration: self.timestamp_configuration.clone(),
        };
        let batch_settings = self.batch_settings;

        let batch_headers = self.batch_headers.clone();
        input
            .map(move |event| process_log(event, &data))
            .batched_partitioned(
                if self.endpoint_target == EndpointTarget::Raw {
                    // We only need to partition by the metadata fields for the raw endpoint since those fields
                    // are sent via query parameters in the request.
                    EventPartitioner::new(
                        self.sourcetype.clone(),
                        self.source.clone(),
                        self.index.clone(),
                        self.host_key.clone(),
                        batch_headers,
                    )
                } else {
                    EventPartitioner::new(None, None, None, None, batch_headers)
                },
                || batch_settings.as_byte_size_config(),
            )
            .request_builder(
                default_request_builder_concurrency_limit(),
                self.request_builder,
            )
            .filter_map(|request| async move {
                match request {
                    Err(e) => {
                        error!("Failed to build HEC Logs request: {:?}.", e);
                        None
                    }
                    Ok(req) => Some(req),
                }
            })
            .into_driver(self.service)
            .run()
            .await
    }
}

#[async_trait]
impl<S> StreamSink<Event> for HecLogsSink<S>
where
    S: Service<HecRequest> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: DriverResponse + Send + 'static,
    S::Error: fmt::Debug + Into<crate::Error> + Send,
{
    async fn run(self: Box<Self>, input: BoxStream<'_, Event>) -> Result<(), ()> {
        self.run_inner(input).await
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub(super) struct Partitioned {
    pub(super) token: Option<Arc<str>>,
    pub(super) source: Option<String>,
    pub(super) sourcetype: Option<String>,
    pub(super) index: Option<String>,
    pub(super) host: Option<String>,
    pub(super) headers: Vec<(HeaderName, Option<HeaderValue>)>,
}

#[derive(Default)]
struct EventPartitioner {
    pub sourcetype: Option<Template>,
    pub source: Option<Template>,
    pub index: Option<Template>,
    pub host_key: Option<OptionalTargetPath>,
    pub headers: Vec<(HeaderName, ConfigValuePath)>,
}

impl EventPartitioner {
    fn new(
        sourcetype: Option<Template>,
        source: Option<Template>,
        index: Option<Template>,
        host_key: Option<OptionalTargetPath>,
        headers: Vec<(HeaderName, ConfigValuePath)>,
    ) -> Self {
        Self {
            sourcetype,
            source,
            index,
            host_key,
            headers,
        }
    }
}

impl Partitioner for EventPartitioner {
    type Item = HecProcessedEvent;
    type Key = Option<Partitioned>;

    fn partition(&self, item: &Self::Item) -> Self::Key {
        let emit_err = |error, field| {
            emit!(TemplateRenderingError {
                error,
                field: Some(field),
                drop_event: false,
            })
        };

        let source = self.source.as_ref().and_then(|source| {
            source
                .render_string(&item.event)
                .map_err(|error| emit_err(error, SOURCE_FIELD))
                .ok()
        });

        let sourcetype = self.sourcetype.as_ref().and_then(|sourcetype| {
            sourcetype
                .render_string(&item.event)
                .map_err(|error| emit_err(error, SOURCETYPE_FIELD))
                .ok()
        });

        let index = self.index.as_ref().and_then(|index| {
            index
                .render_string(&item.event)
                .map_err(|error| emit_err(error, INDEX_FIELD))
                .ok()
        });

        let host = user_or_namespaced_path(
            &item.event,
            self.host_key.as_ref(),
            meaning::HOST,
            log_schema().host_key_target_path(),
        )
        .and_then(|path| item.event.get(&path))
        .and_then(|value| value.as_str().map(|s| s.to_string()));

        let headers = self.headers.iter().map(|(name, path)| {
            let value = item.event.get((PathPrefix::Event, &path.0))
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    HeaderValue::from_str(s.as_ref())
                        .map_err(|_| {
                            emit!(crate::internal_events::SplunkBatchHeaderValueInvalid {
                                header_name: name.as_str(),
                            });
                        })
                        .ok()
                });
            (name.clone(), value)
        }).collect();

        Some(Partitioned {
            token: item.event.metadata().splunk_hec_token(),
            source,
            sourcetype,
            index,
            host,
            headers,
        })
    }
}

#[derive(PartialEq, Default, Clone, Debug)]
pub struct HecLogsProcessedEventMetadata {
    pub sourcetype: Option<String>,
    pub source: Option<String>,
    pub index: Option<String>,
    pub host: Option<Value>,
    pub timestamp: Option<f64>,
    pub fields: LogEvent,
    pub endpoint_target: EndpointTarget,
}

impl ByteSizeOf for HecLogsProcessedEventMetadata {
    fn allocated_bytes(&self) -> usize {
        self.sourcetype.allocated_bytes()
            + self.source.allocated_bytes()
            + self.index.allocated_bytes()
            + self.host.allocated_bytes()
            + self.fields.allocated_bytes()
    }
}

pub type HecProcessedEvent = ProcessedEvent<LogEvent, HecLogsProcessedEventMetadata>;

// determine the path for a field from one of the following use cases:
// 1. user provided a path in the config settings
//     a. If the path provided was an empty string, None is returned
// 2. namespaced path ("default")
//     a. if Legacy namespace, use the provided path from the global log schema
//     b. if Vector namespace, use the semantically defined path
fn user_or_namespaced_path(
    log: &LogEvent,
    user_key: Option<&OptionalTargetPath>,
    semantic: &str,
    legacy_path: Option<&OwnedTargetPath>,
) -> Option<OwnedTargetPath> {
    match user_key {
        Some(maybe_key) => maybe_key.path.clone(),
        None => match log.namespace() {
            LogNamespace::Vector => log.find_key_by_meaning(semantic).cloned(),
            LogNamespace::Legacy => legacy_path.cloned(),
        },
    }
}

fn report_invalid_timestamp<T>(err: impl Display) -> Option<T> {
    error!("Failed to parse timestamp from strftime for Splunk HEC event: {}", err);
    emit!(SplunkEventTimestampInvalidType { r#type: "string" });
    None
}

pub fn process_log(event: Event, data: &HecLogData) -> HecProcessedEvent {
    let mut log = event.into_log();

    let sourcetype = data
        .sourcetype
        .and_then(|sourcetype| render_template_string(sourcetype, &log, SOURCETYPE_FIELD));

    let source = data
        .source
        .and_then(|source| render_template_string(source, &log, SOURCE_FIELD));

    let index = data
        .index
        .and_then(|index| render_template_string(index, &log, INDEX_FIELD));

    let host = user_or_namespaced_path(
        &log,
        data.host_key.as_ref(),
        meaning::HOST,
        log_schema().host_key_target_path(),
    )
    .and_then(|path| log.get(&path))
    .cloned();

    // only extract the timestamp if this is the Event endpoint, and if the setting
    // `auto_extract_timestamp` is false (because that indicates that we should leave
    // the timestamp in the event as-is, and let Splunk do the extraction).
    let timestamp = if EndpointTarget::Event == data.endpoint_target && !data.auto_extract_timestamp
    {

        let timestamp_configuration = data.timestamp_configuration.as_ref();
        let timestamp_key = timestamp_configuration
            .and_then(|config| config.timestamp_key.as_ref());
        let preserve_timestamp_key_in_event = timestamp_configuration
            .map(|config| config.preserve_timestamp_key)
            .unwrap_or(false);
        let timestamp_nanos_key = timestamp_configuration
            .and_then(|config| config.timestamp_nanos_key.as_ref());

        // determine the actual path first
        let timestamp_path_opt = user_or_namespaced_path(
            &log,
            timestamp_key,
            meaning::TIMESTAMP,
            log_schema().timestamp_key_target_path(),
        );


        let (ts, subsec_nanos) = timestamp_path_opt.as_ref().and_then(|timestamp_path| {
            match (log.get(timestamp_path), timestamp_configuration.map(|c| &(c.format))) {
                (None, _) => {
                    emit!(SplunkEventTimestampMissing {});
                    None
                },
                (Some(v), fmt_opt) => match fmt_opt.unwrap_or(&TimestampFormat::Native).resolve(v) {
                    Ok(t) => Some(((t.timestamp_millis() as f64) / 1_000.0, t.timestamp_subsec_nanos() % 1_000_000)),
                    Err(TimestampResolutionError::InvalidUtf8(err)) => {
                            error!("Failed to parse timestamp from strftime for Splunk HEC event: {}", err);
                            emit!(SplunkEventTimestampInvalidType { r#type: "bytes" });
                            None
                    },
                    Err(TimestampResolutionError::InvalidTimestampString(_, err)) => report_invalid_timestamp(err),
                    Err(err@TimestampResolutionError::NoTimestamp) => report_invalid_timestamp(err),
                },
            }
        }).unzip();

        if let Some(nanos) = subsec_nanos {
            if let Some(key) = timestamp_nanos_key {
                log.try_insert(event_path!(key), nanos);
            }
        }

        if !preserve_timestamp_key_in_event && timestamp_path_opt.is_some(){
            let _ = log.remove(timestamp_path_opt.as_ref().unwrap());
        }

        ts
    } else {
        None
    };

    let fields = data
        .indexed_fields
        .iter()
        .filter_map(|field| {
            log.get((PathPrefix::Event, field))
                .map(|value| (field.to_string(), value.clone()))
        })
        .collect::<LogEvent>();

    let metadata = HecLogsProcessedEventMetadata {
        sourcetype,
        source,
        index,
        host,
        timestamp,
        fields,
        endpoint_target: data.endpoint_target,
    };

    ProcessedEvent {
        event: log,
        metadata,
    }
}

impl EventCount for HecProcessedEvent {
    fn event_count(&self) -> usize {
        // A HecProcessedEvent is mapped one-to-one with an event.
        1
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderName, HeaderValue};
    use vector_lib::{event::LogEvent, lookup::lookup_v2::ConfigValuePath};
    use crate::sinks::prelude::Partitioner;

    use super::*;

    fn create_processed_event(fields: Vec<(&str, &str)>) -> HecProcessedEvent {
        let mut log = LogEvent::from("test message");
        for (key, value) in fields {
            log.insert(key, value);
        }
        ProcessedEvent {
            event: log,
            metadata: HecLogsProcessedEventMetadata::default(),
        }
    }

    #[test]
    fn test_event_partitioner_with_headers_same_values() {
        let headers = vec![
            (
                HeaderName::from_static("x-tenant"),
                ConfigValuePath::try_from("tenant".to_string()).unwrap(),
            ),
            (
                HeaderName::from_static("x-region"),
                ConfigValuePath::try_from("region".to_string()).unwrap(),
            ),
        ];

        let partitioner = EventPartitioner::new(None, None, None, None, headers);

        let event1 = create_processed_event(vec![("tenant", "acme"), ("region", "us")]);
        let event2 = create_processed_event(vec![("tenant", "acme"), ("region", "us")]);

        let partition1 = partitioner.partition(&event1);
        let partition2 = partitioner.partition(&event2);

        // Same header values should produce the same partition key
        assert_eq!(partition1, partition2);

        // Check that headers are correctly extracted
        let p = partition1.unwrap();
        assert_eq!(p.headers.len(), 2);
        assert_eq!(
            p.headers[0],
            (HeaderName::from_static("x-tenant"), Some(HeaderValue::from_static("acme")))
        );
        assert_eq!(
            p.headers[1],
            (HeaderName::from_static("x-region"), Some(HeaderValue::from_static("us")))
        );
    }

    #[test]
    fn test_event_partitioner_with_headers_different_values() {
        let headers = vec![(
            HeaderName::from_static("x-tenant"),
            ConfigValuePath::try_from("tenant".to_string()).unwrap(),
        )];

        let partitioner = EventPartitioner::new(None, None, None, None, headers);

        let event1 = create_processed_event(vec![("tenant", "acme")]);
        let event2 = create_processed_event(vec![("tenant", "globex")]);

        let partition1 = partitioner.partition(&event1);
        let partition2 = partitioner.partition(&event2);

        // Different header values should produce different partition keys
        assert_ne!(partition1, partition2);
    }

    #[test]
    fn test_event_partitioner_with_missing_header_value() {
        let headers = vec![(
            HeaderName::from_static("x-tag"),
            ConfigValuePath::try_from("tag".to_string()).unwrap(),
        )];

        let partitioner = EventPartitioner::new(None, None, None, None, headers);

        let event_with_tag = create_processed_event(vec![("tag", "important")]);
        let event_without_tag = create_processed_event(vec![("other_field", "value")]);

        let partition1 = partitioner.partition(&event_with_tag);
        let partition2 = partitioner.partition(&event_without_tag);

        // Events with and without header values should be in different partitions
        assert_ne!(partition1, partition2);

        // Check that the missing value is represented as None
        let p_with = partition1.unwrap();
        assert_eq!(
            p_with.headers[0],
            (HeaderName::from_static("x-tag"), Some(HeaderValue::from_static("important")))
        );

        let p_without = partition2.unwrap();
        assert_eq!(
            p_without.headers[0],
            (HeaderName::from_static("x-tag"), None)
        );
    }

    #[test]
    fn test_event_partitioner_without_headers() {
        let partitioner = EventPartitioner::new(None, None, None, None, vec![]);

        let event1 = create_processed_event(vec![("field1", "value1")]);
        let event2 = create_processed_event(vec![("field2", "value2")]);

        let partition1 = partitioner.partition(&event1);
        let partition2 = partitioner.partition(&event2);

        // Without headers, events should have the same partition
        assert_eq!(partition1, partition2);

        let p = partition1.unwrap();
        assert!(p.headers.is_empty());
    }
}
