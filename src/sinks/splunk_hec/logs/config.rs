use std::sync::Arc;

use http::HeaderName;
use vector_lib::{
    codecs::TextSerializerConfig, config::TimestampFormat, lookup::lookup_v2::{ConfigValuePath, OptionalTargetPath}, sensitive_string::SensitiveString
};
use serde_with::serde_as;
use crate::{
    http::HttpClient,
    sinks::{
        prelude::*,
        splunk_hec::common::{
            acknowledgements::HecClientAcknowledgementsConfig,
            build_healthcheck, build_http_batch_service, create_client,
            service::{HecRejectionContext, HecService, HttpRequestBuilder, Telemetry, Token},
            EndpointTarget, SplunkHecDefaultBatchSettings,
        },
        util::{http::HttpRetryLogic, RejectionReport},
    },
};
use crate::sinks::util::http::{validate_headers, RequestConfig};
use super::{encoder::HecLogsEncoder, request_builder::HecLogsRequestBuilder, sink::HecLogsSink};

/// A batch http-header to be sent to Splunk HEC.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct BatchHeader {
    /// The name of the header.
    #[configurable(metadata(docs::examples = "X-Priority"))]
    pub name: String,

    /// The value of the header.
    #[configurable(metadata(docs::examples = "pri"))]
    pub value: ConfigValuePath,
}

/// A batch header to be sent to Splunk HEC, represented as a key-value pair.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct BatchHeaders(Vec<BatchHeader>);

impl From<Vec<BatchHeader>> for BatchHeaders {
    fn from(headers: Vec<BatchHeader>) -> Self {
        BatchHeaders(headers)
    }
}

impl BatchHeaders {
    /// Validates header names and converts to a vector of (HeaderName, ConfigValuePath) pairs.
    /// Returns an error if any header name is invalid.
    pub fn into_validated(self) -> Result<Vec<(HeaderName, ConfigValuePath)>, crate::Error> {
        self.0
            .into_iter()
            .map(|header| {
                HeaderName::try_from(header.name.as_str())
                    .map(|name| (name, header.value))
                    .map_err(|e| format!("Invalid batch header name '{}': {}", header.name, e).into())
            })
            .collect()
    }
}

/// Configuration for the `splunk_hec_logs` sink.
#[configurable_component(sink(
    "splunk_hec_logs",
    "Deliver log data to Splunk's HTTP Event Collector."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct HecLogsSinkConfig {
    /// Default Splunk HEC token.
    ///
    /// If an event has a token set in its secrets (`splunk_hec_token`), it prevails over the one set here.
    #[serde(alias = "token")]
    pub default_token: SensitiveString,

    /// Ignore stored token (the token in event metadata)
    ///
    /// If set, sink always uses default token (ignoring stored token)
    #[serde(default)]
    pub ignore_stored_token: bool,

    /// The base URL of the Splunk instance.
    ///
    /// The scheme (`http` or `https`) must be specified. No path should be included since the paths defined
    /// by the [`Splunk`][splunk] API are used.
    ///
    /// [splunk]: https://docs.splunk.com/Documentation/Splunk/8.0.0/Data/HECRESTendpoints
    #[configurable(metadata(
        docs::examples = "https://http-inputs-hec.splunkcloud.com",
        docs::examples = "https://hec.splunk.com:8088",
        docs::examples = "http://example.com"
    ))]
    #[configurable(validation(format = "uri"))]
    pub endpoint: String,

    /// Overrides the name of the log field used to retrieve the hostname to send to Splunk HEC.
    ///
    /// By default, the [global `log_schema.host_key` option][global_host_key] is used if log
    /// events are Legacy namespaced, or the semantic meaning of "host" is used, if defined.
    ///
    /// [global_host_key]: https://vector.dev/docs/reference/configuration/global-options/#log_schema.host_key
    // NOTE: The `OptionalTargetPath` is wrapped in an `Option` in order to distinguish between a true
    //       `None` type and an empty string. This is necessary because `OptionalTargetPath` deserializes an
    //       empty string to a `None` path internally.
    #[configurable(metadata(docs::advanced))]
    pub host_key: Option<OptionalTargetPath>,

    /// Fields to be [added to Splunk index][splunk_field_index_docs].
    ///
    /// [splunk_field_index_docs]: https://docs.splunk.com/Documentation/Splunk/8.0.0/Data/IFXandHEC
    #[configurable(metadata(docs::advanced))]
    #[serde(default)]
    #[configurable(metadata(docs::examples = "field1", docs::examples = "field2"))]
    pub indexed_fields: Vec<ConfigValuePath>,

    /// The name of the index to send events to.
    ///
    /// If not specified, the default index defined within Splunk is used.
    #[configurable(metadata(docs::examples = "{{ host }}", docs::examples = "custom_index"))]
    pub index: Option<Template>,

    /// The sourcetype of events sent to this sink.
    ///
    /// If unset, Splunk defaults to `httpevent`.
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(docs::examples = "{{ sourcetype }}", docs::examples = "_json",))]
    pub sourcetype: Option<Template>,

    /// The source of events sent to this sink.
    ///
    /// This is typically the filename the logs originated from.
    ///
    /// If unset, the Splunk collector sets it.
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(
        docs::examples = "{{ file }}",
        docs::examples = "/var/log/syslog",
        docs::examples = "UDP:514"
    ))]
    pub source: Option<Template>,

    #[configurable(derived)]
    pub encoding: EncodingConfig,

    #[configurable(derived)]
    #[serde(default)]
    pub compression: Compression,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: BatchConfig<SplunkHecDefaultBatchSettings>,

    /// Headers to be included in each batch request to Splunk HEC.
    /// Headers in request-config take precedence over these batch headers if there are any conflicts.
    #[configurable(derived)]
    #[serde(default)]
    pub batch_headers: BatchHeaders,

    #[configurable(derived)]
    #[serde(default)]
    pub request: RequestConfig,

    #[configurable(derived)]
    pub tls: Option<TlsConfig>,

    #[configurable(derived)]
    #[serde(default)]
    pub acknowledgements: HecClientAcknowledgementsConfig,

    #[configurable(derived)]
    #[serde(default)]
    pub path: Option<String>,

    /// Passes the `auto_extract_timestamp` option to Splunk.
    ///
    /// This option is only relevant to Splunk v8.x and above, and is only applied when
    /// `endpoint_target` is set to `event`.
    ///
    /// Setting this to `true` causes Splunk to extract the timestamp from the message text
    /// rather than use the timestamp embedded in the event. The timestamp must be in the format
    /// `yyyy-mm-dd hh:mm:ss`.
    #[serde(default)]
    pub auto_extract_timestamp: Option<bool>,

    #[configurable(derived)]
    #[configurable(metadata(docs::advanced))]
    #[serde(default = "default_endpoint_target")]
    pub endpoint_target: EndpointTarget,

    #[configurable(derived)]
    #[serde(default = "default_timestamp_configuration")]
    pub timestamp_configuration: Option<TimestampConfiguration>,

    /// Controls how much detail is logged when Splunk HEC rejects a batch.
    #[serde(default)]
    pub rejection_report: RejectionReport,
}


#[configurable_component]
#[derive(Clone, Debug)]
/// Configuration for timestamp extraction and formatting.
pub struct TimestampConfiguration {
    /// Overrides the name of the log field used to retrieve the timestamp to send to Splunk HEC.
    /// When set to `“”`, a timestamp is not set in the events sent to Splunk HEC.
    ///
    /// By default, either the [global `log_schema.timestamp_key` option][global_timestamp_key] is used
    /// if log events are Legacy namespaced, or the semantic meaning of "timestamp" is used, if defined.
    ///
    /// [global_timestamp_key]: https://vector.dev/docs/reference/configuration/global-options/#log_schema.timestamp_key
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(docs::examples = "timestamp", docs::examples = ""))]
    // NOTE: The `OptionalTargetPath` is wrapped in an `Option` in order to distinguish between a true
    // `None` type and an empty string. This is necessary because `OptionalTargetPath` deserializes an
    // empty string to a `None` path internally.
    pub timestamp_key: Option<OptionalTargetPath>,
    #[configurable(derived)]
    #[serde(default = "default_timestamp_format")]
    pub format: TimestampFormat,
    // This settings is relevant only for the `humio_logs` sink and should be left as `None`
    // everywhere else.
    #[serde(skip)]
    pub timestamp_nanos_key: Option<String>,
    /// Whether to preserve the timestamp field in the event after extraction.
    pub preserve_timestamp_key: bool,
}

const fn default_timestamp_configuration() -> Option<TimestampConfiguration> {
    Some(
        TimestampConfiguration {
            timestamp_key: None,
            format: TimestampFormat::Native,
            timestamp_nanos_key: None,
            preserve_timestamp_key: false
        }
    )
}

const fn default_timestamp_format() -> TimestampFormat {
    TimestampFormat::Native
}

const fn default_endpoint_target() -> EndpointTarget {
    EndpointTarget::Event
}

impl GenerateConfig for HecLogsSinkConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            default_token: "${VECTOR_SPLUNK_HEC_TOKEN}".to_owned().into(),
            ignore_stored_token: false,
            endpoint: "endpoint".to_owned(),
            host_key: None,
            indexed_fields: vec![],
            index: None,
            sourcetype: None,
            source: None,
            encoding: TextSerializerConfig::default().into(),
            compression: Compression::default(),
            batch: BatchConfig::default(),
            batch_headers: BatchHeaders::default(),
            request: RequestConfig::default(),
            tls: None,
            acknowledgements: Default::default(),
            path: None,
            auto_extract_timestamp: None,
            endpoint_target: EndpointTarget::Event,
            timestamp_configuration: None,
            rejection_report: RejectionReport::default(),
        })
        .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "splunk_hec_logs")]
impl SinkConfig for HecLogsSinkConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        if self.auto_extract_timestamp.is_some() && self.endpoint_target == EndpointTarget::Raw {
            return Err("`auto_extract_timestamp` cannot be set for the `raw` endpoint.".into());
        }

        let client = create_client(self.tls.as_ref(), cx.proxy())?;
        let healthcheck = build_healthcheck(
            self.endpoint.clone(),
            self.default_token.inner().to_owned(),
            client.clone(),
        )
        .boxed();
        let sink = self.build_processor(client, cx)?;

        Ok((sink, healthcheck))
    }

    fn input(&self) -> Input {
        Input::new(self.encoding.config().input_type() & DataType::Log)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements.inner
    }
}

impl HecLogsSinkConfig {
    pub fn build_processor(&self, client: HttpClient, cx: SinkContext) -> crate::Result<VectorSink> {
        let ack_client = if self.acknowledgements.indexer_acknowledgements_enabled {
            Some(client.clone())
        } else {
            None
        };

        let transformer = self.encoding.transformer();
        let serializer = self.encoding.build()?;
        let encoder = Encoder::<()>::new(serializer);
        let encoder = HecLogsEncoder {
            transformer,
            encoder,
            auto_extract_timestamp: self.auto_extract_timestamp.unwrap_or_default(),
        };
        let request_builder = HecLogsRequestBuilder {
            encoder,
            compression: self.compression,
        };

        let request_settings = self.request.tower.into_settings();
        let headers = validate_headers(&self.request.headers)?;
        let batch_headers = self.batch_headers.clone().into_validated()?;

        let token_str = self.default_token.inner().to_owned();
        let token = if self.ignore_stored_token {
            Token::Enforced(token_str)
        } else {
            Token::Fallback(token_str)
        };

        let http_request_builder = Arc::new(HttpRequestBuilder::new(
            self.endpoint.clone(),
            self.endpoint_target,
            token,
            self.compression,
            headers,
        ));
        let http_service = ServiceBuilder::new()
            .settings(request_settings, HttpRetryLogic)
            .service(build_http_batch_service(
                client,
                Arc::clone(&http_request_builder),
                self.endpoint_target,
                self.auto_extract_timestamp.unwrap_or_default(),
                self.path.clone()
            ));

        let context = Arc::new(HecRejectionContext {
            rejected: metrics::counter!(
                "hec_rejected",
                "endpoint" => self.endpoint.clone(),
            ),
        });

        let service = HecService::new(
            http_service,
            ack_client,
            http_request_builder,
            self.acknowledgements.clone(),
            self.rejection_report.clone(),
            self.compression,
            context,
        );

        let batch_settings = self.batch.into_batcher_settings()?;

        let sink = HecLogsSink {
            service,
            request_builder,
            batch_settings,
            sourcetype: self.sourcetype.clone(),
            source: self.source.clone(),
            index: self.index.clone(),
            indexed_fields: self
                .indexed_fields
                .iter()
                .map(|config_path| config_path.0.clone())
                .collect(),
            host_key: self.host_key.clone(),
            endpoint_target: self.endpoint_target,
            auto_extract_timestamp: self.auto_extract_timestamp.unwrap_or_default(),
            timestamp_configuration: self.timestamp_configuration.clone(),
            batch_headers,
            shutdown: cx.shutdown.clone(),
        };

        Ok(VectorSink::from_event_streamsink(sink))
    }
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;
    use super::*;
    use crate::components::validation::prelude::*;
    use vector_lib::{
        codecs::{encoding::format::JsonSerializerOptions, JsonSerializerConfig, MetricTagValues},
        config::LogNamespace,
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<HecLogsSinkConfig>();
    }

    #[test]
    fn test_config_serde() {
        let config_toml = r#"
            default_token = "my-token"
            endpoint = "https://hec.example.com:8088"
            host_key = "hostname"
            indexed_fields = ["field1", "field2"]
            index = "{{ index_field }}"
            sourcetype = "{{ sourcetype_field }}"
            source = "/var/log/app.log"
            compression = "gzip"
            endpoint_target = "raw"
            auto_extract_timestamp = true
            path = "/custom/path"

            [encoding]
            codec = "json"
            except_fields = ["secret_field"]

            [batch]
            max_bytes = 1048576
            max_events = 100
            timeout_secs = 5

            [[batch_headers]]
            name = "X-Tenant"
            value = "tenant"

            [[batch_headers]]
            name = "X-Priority"
            value = "priority"

            [request]
            timeout_secs = 30
            retry_attempts = 3

            [request.headers]
            X-Custom = "custom-value"

            [acknowledgements]
            indexer_acknowledgements_enabled = true
            max_pending_acks = 1000

            [timestamp_configuration]
            timestamp_key = "ts"
            format = "native"
            preserve_timestamp_key = true
        "#;

        let config: HecLogsSinkConfig = toml::from_str(config_toml)
            .expect("Failed to parse config");

        assert_eq!(config.default_token.inner(), "my-token");
        assert_eq!(config.endpoint, "https://hec.example.com:8088");
        assert_eq!(config.endpoint_target, EndpointTarget::Raw);
        assert_eq!(config.auto_extract_timestamp, Some(true));
        assert_eq!(config.path, Some("/custom/path".to_string()));
        assert_eq!(config.indexed_fields.len(), 2);
        assert!(config.index.is_some());
        assert!(config.sourcetype.is_some());
        assert_eq!(config.source, Some(crate::template::Template::try_from("/var/log/app.log").unwrap()));
        assert!(config.host_key.is_some());

        let batch_headers = config.batch_headers.into_validated().expect("batch_headers should be valid");
        assert_eq!(batch_headers.len(), 2);
        assert_eq!(batch_headers[0].0.as_str(), "x-tenant");
        assert_eq!(batch_headers[1].0.as_str(), "x-priority");

        assert!(config.acknowledgements.indexer_acknowledgements_enabled);
        assert_eq!(config.acknowledgements.max_pending_acks.get(), 1000);

        let ts_config = config.timestamp_configuration.expect("timestamp_configuration should be set");
        assert!(ts_config.timestamp_key.is_some());
        assert!(ts_config.preserve_timestamp_key);
    }

    fn hec_logs_config_from_toml(toml: &str) -> HecLogsSinkConfig {
        toml::from_str(toml).expect("failed to parse HecLogsSinkConfig from TOML")
    }

    #[test]
    fn test_config_serde_ignore_stored_token_absent() {
        let config = hec_logs_config_from_toml(
            r#"
            default_token = "my-token"
            endpoint = "https://hec.example.com:8088"
            [encoding]
            codec = "json"
            "#,
        );
        assert!(!config.ignore_stored_token);
    }

    #[test]
    fn test_config_serde_ignore_stored_token_present() {
        let config = hec_logs_config_from_toml(
            r#"
            default_token = "my-token"
            endpoint = "https://hec.example.com:8088"
            ignore_stored_token = true
            [encoding]
            codec = "json"
            "#,
        );
        assert!(config.ignore_stored_token);
    }

    impl ValidatableComponent for HecLogsSinkConfig {
        fn validation_configuration() -> ValidationConfiguration {
            let endpoint = "http://127.0.0.1:9001".to_string();

            let mut batch = BatchConfig::default();
            batch.max_events = Some(1);

            let config = Self {
                endpoint: endpoint.clone(),
                default_token: "i_am_an_island".to_string().into(),
                ignore_stored_token: false,
                host_key: None,
                indexed_fields: vec![],
                index: None,
                sourcetype: None,
                source: None,
                encoding: EncodingConfig::new(
                    JsonSerializerConfig::new(
                        MetricTagValues::Full,
                        JsonSerializerOptions::default(),
                    )
                    .into(),
                    Transformer::default(),
                ),
                compression: Compression::default(),
                batch,
                request: RequestConfig {
                    tower: TowerRequestConfig {
                        timeout_secs: 2,
                        retry_attempts: 0,
                        ..Default::default()
                    },
                    headers: IndexMap::<_, _>::from_iter([
                        ("Accept".to_owned(), "text/plain".to_owned()),
                        ("X-Foo".to_owned(), "bar".to_owned()),
                    ])
                },
                tls: None,
                acknowledgements: HecClientAcknowledgementsConfig {
                    indexer_acknowledgements_enabled: false,
                    ..Default::default()
                },
                batch_headers: BatchHeaders::default(),
                path: None,
                auto_extract_timestamp: None,
                endpoint_target: EndpointTarget::Raw,
                timestamp_configuration: None,
                rejection_report: RejectionReport::default(),
            };

            let endpoint = format!("{endpoint}/services/collector/raw");

            let external_resource = ExternalResource::new(
                ResourceDirection::Push,
                HttpResourceConfig::from_parts(
                    http::Uri::try_from(&endpoint).expect("should not fail to parse URI"),
                    None,
                ),
                config.encoding.clone(),
            );

            ValidationConfiguration::from_sink(
                Self::NAME,
                LogNamespace::Legacy,
                vec![ComponentTestCaseConfig::from_sink(
                    config,
                    None,
                    Some(external_resource),
                )],
            )
        }
    }

    register_validatable_component!(HecLogsSinkConfig);
}
