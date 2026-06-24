//! The `vector` source. See [VectorConfig].
use std::net::SocketAddr;

use chrono::Utc;
use futures::TryFutureExt;
use metrics::{counter, histogram, Counter, Histogram};
use tonic::{Request, Response, Status};
use vector_lib::codecs::NativeDeserializerConfig;
use vector_lib::configurable::configurable_component;
use vector_lib::internal_event::{CountByteSize, InternalEventHandle as _};
use vector_lib::{
    config::LogNamespace,
    event::{BatchNotifier, BatchStatus, BatchStatusReceiver, Event},
    EstimatedJsonEncodedSizeOf,
};

use crate::{
    config::{
        DataType, GenerateConfig, Resource, SourceAcknowledgementsConfig, SourceConfig,
        SourceContext, SourceOutput,
    },
    internal_events::{EventsReceived, StreamClosedError},
    proto::vector as proto,
    serde::bool_or_struct,
    sources::{
        util::{
            add_auth_metadata, grpc::run_grpc_server, Auth, AuthConfig, AuthContext, AuthError,
            AuthEventError, EventValidator,
        },
        Source,
    },
    tls::{MaybeTlsSettings, TlsEnableableConfig},
    SourceSender,
};

/// Marker type for version two of the configuration for the `vector` source.
#[configurable_component]
#[derive(Clone, Debug)]
enum VectorConfigVersion {
    /// Marker value for version two.
    #[serde(rename = "2")]
    V2,
}

#[derive(Debug, Clone)]
struct Service {
    pipeline: SourceSender,
    acknowledgements: bool,
    log_namespace: LogNamespace,
    /// Present when auth is enabled.
    auth: Option<Auth>,
    /// Pre-registered metric handles; only built when `auth` is configured.
    auth_metrics: Option<AuthMetrics>,
}

/// Cached metric handles for per-batch auth outcome reporting.
///
/// Built once when the source's `Service` is constructed so the hot path
/// avoids the per-call recorder lookup the `counter!`/`histogram!` macros do.
#[derive(Debug, Clone)]
struct AuthMetrics {
    batch_failed: Counter,
    authorized: Histogram,
    authorization_missing: Histogram,
    forbidden: Histogram,
}

impl AuthMetrics {
    fn new() -> Self {
        Self {
            batch_failed: counter!("source_auth_batch_failed_total"),
            authorized: histogram!("source_auth_events", "outcome" => "authorized"),
            authorization_missing: histogram!(
                "source_auth_events",
                "outcome" => AuthEventError::AuthorizationMissing.label(),
            ),
            forbidden: histogram!(
                "source_auth_events",
                "outcome" => AuthEventError::Forbidden.label(),
            ),
        }
    }

    fn emit(&self, stats: &AuthBatchStats) {
        if stats.any_failed() {
            self.batch_failed.increment(1);
        }
        if stats.authorized > 0 {
            self.authorized.record(stats.authorized as f64);
        }
        if stats.missing_value > 0 {
            self.authorization_missing.record(stats.missing_value as f64);
        }
        if stats.not_allowed > 0 {
            self.forbidden.record(stats.not_allowed as f64);
        }
    }
}

/// Outcome counts for a single batch's per-event auth filtering.
#[derive(Default)]
struct AuthBatchStats {
    authorized: u64,
    missing_value: u64,
    not_allowed: u64,
}

impl AuthBatchStats {
    fn any_failed(&self) -> bool {
        self.missing_value > 0 || self.not_allowed > 0
    }
}

impl Service {
    /// Run request-level JWT validation against an inbound gRPC request.
    ///
    /// Shared between `push_events` and `health_check` so both RPCs honor the
    /// same `require_token` enforcement and reject the same set of bad tokens.
    async fn validate_auth_header<T>(
        &self,
        request: &Request<T>,
    ) -> Result<Option<AuthContext>, Status> {
        let Some(auth) = &self.auth else {
            return Ok(None);
        };
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok());
        auth.authenticate(authorization)
            .await
            .map_err(|AuthError::InvalidToken(msg)| Status::unauthenticated(msg))
    }
}

#[tonic::async_trait]
impl proto::Service for Service {
    async fn push_events(
        &self,
        request: Request<proto::PushEventsRequest>,
    ) -> Result<Response<proto::PushEventsResponse>, Status> {
        // Request-level JWT validation.
        let auth_ctx = self.validate_auth_header(&request).await?;

        // Build the per-event validator once. Present only when auth is configured,
        // a valid token was provided, AND a `value_path` is set for per-event filtering.
        let validator: Option<EventValidator<'_>> = match (&auth_ctx, &self.auth) {
            (Some(ctx), Some(auth)) => auth.value_path().map(|vp| ctx.into_validator(vp)),
            _ => None,
        };

        let proto_events = request.into_inner().events;
        let mut auth_stats = AuthBatchStats::default();

        // Fused: proto → Event conversion + per-event auth filter + metadata stamp,
        // single pass, single Vec.
        let mut events: Vec<Event> = if let Some(validator) = &validator {
            proto_events
                .into_iter()
                .filter_map(|proto_event| {
                    let mut event = Event::from(proto_event);
                    match validator.check(&event) {
                        Ok((name, value)) => {
                            let value = value.into_owned();
                            add_auth_metadata(&mut event, name, &value);
                            Some(event)
                        }
                        Err(AuthEventError::AuthorizationMissing) => {
                            auth_stats.missing_value += 1;
                            error!(
                                message = "Event dropped: authorization field missing",
                                event = ?event,
                                outcome = AuthEventError::AuthorizationMissing.label(),
                                internal_log_rate_limit = true
                            );
                            None
                        }
                        Err(AuthEventError::Forbidden) => {
                            auth_stats.not_allowed += 1;
                            error!(
                                message = "Forbidden event dropped",
                                event = ?event,
                                outcome = AuthEventError::Forbidden.label(),
                                internal_log_rate_limit = true
                            );
                            None
                        }
                    }
                })
                .collect()
        } else {
            proto_events.into_iter().map(Event::from).collect()
        };

        if auth_ctx.is_some() {
            auth_stats.authorized = events.len() as u64;
        }

        // Emit auth outcome metrics when auth is configured.
        if let (Some(metrics), true) = (&self.auth_metrics, auth_ctx.is_some()) {
            metrics.emit(&auth_stats);
            if auth_stats.any_failed() {
                warn!(
                    message = "Batch contained events rejected due to auth failures.",
                    accepted = auth_stats.authorized,
                    authorization_missing = auth_stats.missing_value,
                    forbidden = auth_stats.not_allowed,
                    internal_log_rate_limit = true
                );
            }
        }

        let now = Utc::now();
        for event in &mut events {
            if let Event::Log(ref mut log) = event {
                self.log_namespace.insert_standard_vector_source_metadata(
                    log,
                    VectorConfig::NAME,
                    now,
                );
            }
        }

        let count = events.len();
        let byte_size = events.estimated_json_encoded_size_of();
        let events_received = register!(EventsReceived);
        events_received.emit(CountByteSize(count, byte_size));

        let receiver = BatchNotifier::maybe_apply_to(self.acknowledgements, &mut events);

        self.pipeline
            .clone()
            .send_batch(events)
            .map_err(|error| {
                let message = error.to_string();
                emit!(StreamClosedError { count });
                Status::unavailable(message)
            })
            .and_then(|_| handle_batch_status(receiver))
            .await?;

        if auth_stats.any_failed() {
            return Err(Status::permission_denied(format!(
                "partial auth failure: accepted={} authorization_missing={} forbidden={}",
                auth_stats.authorized, auth_stats.missing_value, auth_stats.not_allowed
            )));
        }

        Ok(Response::new(proto::PushEventsResponse {}))
    }

    // TODO: figure out a way to determine if the current Vector instance is "healthy".
    async fn health_check(
        &self,
        request: Request<proto::HealthCheckRequest>,
    ) -> Result<Response<proto::HealthCheckResponse>, Status> {
        // Apply the same JWT validation as push_events — same auth posture,
        // including `require_token` enforcement when configured.
        self.validate_auth_header(&request).await?;

        let message = proto::HealthCheckResponse {
            status: proto::ServingStatus::Serving.into(),
        };

        Ok(Response::new(message))
    }
}

async fn handle_batch_status(receiver: Option<BatchStatusReceiver>) -> Result<(), Status> {
    let status = match receiver {
        Some(receiver) => receiver.await,
        None => BatchStatus::Delivered,
    };

    match status {
        BatchStatus::Errored => Err(Status::internal("Delivery error")),
        BatchStatus::Rejected => Err(Status::data_loss("Delivery failed")),
        BatchStatus::Delivered => Ok(()),
    }
}

/// Configuration for the `vector` source.
#[configurable_component(source("vector", "Collect observability data from a Vector instance."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct VectorConfig {
    /// Version of the configuration.
    version: Option<VectorConfigVersion>,

    /// The socket address to listen for connections on.
    ///
    /// It _must_ include a port.
    pub address: SocketAddr,

    #[configurable(derived)]
    #[serde(default)]
    tls: Option<TlsEnableableConfig>,

    #[configurable(derived)]
    #[serde(default, deserialize_with = "bool_or_struct")]
    acknowledgements: SourceAcknowledgementsConfig,

    /// The namespace to use for logs. This overrides the global setting.
    #[serde(default)]
    #[configurable(metadata(docs::hidden))]
    pub log_namespace: Option<bool>,

    /// Auth settings.
    ///
    /// When omitted, all incoming requests are accepted without authentication.
    /// When set, the `authorization` header is validated as a Bearer JWT.
    /// If `auth.value_path` is also configured, each event's field is checked
    /// against the token's membership claim and unauthorized events are filtered out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthConfig>,
}

impl VectorConfig {
    /// Creates a `VectorConfig` with the given address.
    pub fn from_address(addr: SocketAddr) -> Self {
        Self {
            address: addr,
            ..Default::default()
        }
    }
}

impl Default for VectorConfig {
    fn default() -> Self {
        Self {
            version: None,
            address: "0.0.0.0:6000".parse().unwrap(),
            tls: None,
            acknowledgements: Default::default(),
            log_namespace: None,
            auth: None,
        }
    }
}

impl GenerateConfig for VectorConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(VectorConfig::default()).unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "vector")]
impl SourceConfig for VectorConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<Source> {
        let tls_settings = MaybeTlsSettings::from_config(self.tls.as_ref(), true)?;
        let acknowledgements = cx.do_acknowledgements(self.acknowledgements);
        let log_namespace = cx.log_namespace(self.log_namespace);

        let auth = match self.auth.as_ref() {
            Some(cfg) => Some(cfg.build().await?),
            None => None,
        };
        let auth_metrics = auth.as_ref().map(|_| AuthMetrics::new());

        let service = proto::Server::new(Service {
            pipeline: cx.out,
            acknowledgements,
            log_namespace,
            auth,
            auth_metrics,
        })
        .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
        // Tonic added a default of 4MB in 0.9. This replaces the old behavior.
        .max_decoding_message_size(usize::MAX);

        let source =
            run_grpc_server(self.address, tls_settings, service, cx.shutdown).map_err(|error| {
                error!(message = "Source future failed.", %error);
            });

        Ok(Box::pin(source))
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = global_log_namespace.merge(self.log_namespace);

        let schema_definition = NativeDeserializerConfig
            .schema_definition(log_namespace)
            .with_standard_vector_source_metadata();

        vec![SourceOutput::new_maybe_logs(
            DataType::all_bits(),
            schema_definition,
        )]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![Resource::tcp(self.address)]
    }

    fn can_acknowledge(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use vector_lib::lookup::owned_value_path;
    use vector_lib::{config::LogNamespace, schema::Definition};
    use vrl::value::{kind::Collection, Kind};

    use crate::config::SourceConfig;

    use super::VectorConfig;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<super::VectorConfig>();
    }

    #[test]
    fn output_schema_definition_vector_namespace() {
        let config = VectorConfig::default();

        let definitions = config
            .outputs(LogNamespace::Vector)
            .remove(0)
            .schema_definition(true);

        let expected_definition =
            Definition::new_with_default_metadata(Kind::any(), [LogNamespace::Vector])
                .with_metadata_field(
                    &owned_value_path!("vector", "source_type"),
                    Kind::bytes(),
                    None,
                )
                .with_metadata_field(
                    &owned_value_path!("vector", "ingest_timestamp"),
                    Kind::timestamp(),
                    None,
                );

        assert_eq!(definitions, Some(expected_definition))
    }

    #[test]
    fn output_schema_definition_legacy_namespace() {
        let config = VectorConfig::default();

        let definitions = config
            .outputs(LogNamespace::Legacy)
            .remove(0)
            .schema_definition(true);

        let expected_definition = Definition::new_with_default_metadata(
            Kind::object(Collection::empty()),
            [LogNamespace::Legacy],
        )
        .with_event_field(&owned_value_path!("source_type"), Kind::bytes(), None)
        .with_event_field(&owned_value_path!("timestamp"), Kind::timestamp(), None);

        assert_eq!(definitions, Some(expected_definition))
    }
}

// ── Per-event auth unit tests ────────────────────────────────────────────────

#[cfg(all(test, feature = "sources-vector"))]
mod auth_unit_tests {
    use vector_lib::event::{LogEvent, Metric, MetricKind, MetricValue, TraceEvent};

    use super::*;
    use crate::sources::util::jwt_auth::{AuthValuePath, CompiledValuePath};
    use crate::sources::util::AuthContext;

    fn make_validator<'a>(
        ctx: &'a AuthContext,
        vp: &'a CompiledValuePath,
    ) -> EventValidator<'a> {
        ctx.into_validator(vp)
    }

    fn make_auth_ctx(values: &[&str]) -> AuthContext {
        AuthContext {
            allowed_values: Some(values.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn compile(vp: AuthValuePath) -> CompiledValuePath {
        CompiledValuePath::try_from(&vp).expect("test value_path should compile")
    }

    fn make_value_path(default: &str) -> CompiledValuePath {
        compile(AuthValuePath {
            default: default.to_owned(),
            log: None,
            metric_tag: None,
            trace: None,
        })
    }

    /// Test-only batch helper. Mirrors the fused `filter_map` loop in
    /// `Service::push_events` so the unit tests can exercise the same shape
    /// without needing the gRPC plumbing.
    fn filter_events_by_auth(
        events: Vec<Event>,
        validator: &EventValidator<'_>,
    ) -> (Vec<Event>, AuthBatchStats) {
        let mut stats = AuthBatchStats::default();
        let out: Vec<Event> = events
            .into_iter()
            .filter_map(|mut event| match validator.check(&event) {
                Ok((name, value)) => {
                    let value = value.into_owned();
                    add_auth_metadata(&mut event, name, &value);
                    Some(event)
                }
                Err(AuthEventError::AuthorizationMissing) => {
                    stats.missing_value += 1;
                    warn!(
                        message = "Event dropped: authorization field missing",
                        event = ?event,
                        outcome = AuthEventError::AuthorizationMissing.label(),
                        internal_log_rate_limit = true
                    );
                    None
                }
                Err(AuthEventError::Forbidden) => {
                    stats.not_allowed += 1;
                    warn!(
                        message = "Forbidden event dropped",
                        event = ?event,
                        outcome = AuthEventError::Forbidden.label(),
                        internal_log_rate_limit = true
                    );
                    None
                }
            })
            .collect();
        stats.authorized = out.len() as u64;
        (out, stats)
    }

    #[test]
    fn authorized_log_event_gets_auth_metadata() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let mut log = LogEvent::default();
        log.insert("tenant_id", "site-123");
        let events = vec![Event::Log(log)];

        let (out, stats) = filter_events_by_auth(events, &validator);

        assert_eq!(stats.authorized, 1);
        assert_eq!(stats.missing_value, 0);
        assert_eq!(stats.not_allowed, 0);
        assert_eq!(out.len(), 1);

        let log = out[0].as_log();
        assert_eq!(log.get("auth_field_name").unwrap().to_string_lossy(), "tenant_id");
        assert_eq!(log.get("auth_field_value").unwrap().to_string_lossy(), "site-123");
    }

    #[test]
    fn log_event_missing_auth_field_is_filtered() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let log = LogEvent::default(); // no tenant_id field
        let events = vec![Event::Log(log)];

        let (out, stats) = filter_events_by_auth(events, &validator);

        assert_eq!(stats.missing_value, 1); // AuthorizationMissing → missing_value counter
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn log_event_with_wrong_value_is_filtered() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let mut log = LogEvent::default();
        log.insert("tenant_id", "site-other");
        let events = vec![Event::Log(log)];

        let (out, stats) = filter_events_by_auth(events, &validator);

        assert_eq!(stats.not_allowed, 1); // Forbidden → not_allowed counter
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn mixed_batch_only_authorized_events_pass() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let mut log_ok = LogEvent::default();
        log_ok.insert("tenant_id", "site-123");

        let mut log_bad = LogEvent::default();
        log_bad.insert("tenant_id", "site-other");

        let log_missing = LogEvent::default();

        let events = vec![
            Event::Log(log_ok),
            Event::Log(log_bad),
            Event::Log(log_missing),
        ];

        let (out, stats) = filter_events_by_auth(events, &validator);

        assert_eq!(stats.authorized, 1);
        assert_eq!(stats.not_allowed, 1);
        assert_eq!(stats.missing_value, 1);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn metric_event_checked_via_tag_key() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = compile(AuthValuePath {
            default: "tenant_id".into(),
            log: None,
            metric_tag: Some("tenant".into()),
            trace: None,
        });
        let validator = make_validator(&ctx, &vp);

        let mut metric = Metric::new(
            "test_metric",
            MetricKind::Incremental,
            MetricValue::Counter { value: 1.0 },
        );
        metric.replace_tag("tenant".to_owned(), "site-123".to_owned());

        let events = vec![Event::Metric(metric)];
        let (out, stats) = filter_events_by_auth(events, &validator);

        assert_eq!(stats.authorized, 1);
        assert_eq!(out.len(), 1);

        // Auth metadata should be set as tags.
        let m = out[0].as_metric();
        assert_eq!(m.tag_value("auth_field_name").as_deref(), Some("tenant"));
        assert_eq!(m.tag_value("auth_field_value").as_deref(), Some("site-123"));
    }

    #[test]
    fn metric_event_missing_tag_is_filtered() {
        // The `AuthorizationMissing` branch for metrics: the configured tag
        // key isn't present, so the event must be dropped and counted
        // against `missing_value`.
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = compile(AuthValuePath {
            default: "tenant_id".into(),
            log: None,
            metric_tag: Some("tenant".into()),
            trace: None,
        });
        let validator = make_validator(&ctx, &vp);

        let metric = Metric::new(
            "test_metric",
            MetricKind::Incremental,
            MetricValue::Counter { value: 1.0 },
        );
        // No `tenant` tag set.

        let events = vec![Event::Metric(metric)];
        let (out, stats) = filter_events_by_auth(events, &validator);

        assert_eq!(stats.missing_value, 1);
        assert_eq!(stats.authorized, 0);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn trace_event_authorized_via_default_path() {
        // Exercises both `EventValidator::check`'s `Event::Trace` arm and
        // `add_auth_metadata`'s trace branch — neither is covered by the
        // log/metric tests.
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let mut trace = TraceEvent::default();
        trace.insert("tenant_id", "site-123");
        let events = vec![Event::Trace(trace)];

        let (out, stats) = filter_events_by_auth(events, &validator);

        assert_eq!(stats.authorized, 1);
        assert_eq!(out.len(), 1);

        let t = out[0].as_trace();
        assert_eq!(t.get("auth_field_name").and_then(|v| v.as_str()).as_deref(), Some("tenant_id"));
        assert_eq!(t.get("auth_field_value").and_then(|v| v.as_str()).as_deref(), Some("site-123"));
    }

    #[test]
    fn trace_event_missing_field_is_filtered() {
        // `AuthorizationMissing` branch for traces.
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let trace = TraceEvent::default(); // no tenant_id field
        let events = vec![Event::Trace(trace)];

        let (out, stats) = filter_events_by_auth(events, &validator);

        assert_eq!(stats.missing_value, 1);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn type_specific_log_override_is_used() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = compile(AuthValuePath {
            default: "default_field".into(),
            log: Some("log_field".into()),
            metric_tag: None,
            trace: None,
        });
        let validator = make_validator(&ctx, &vp);

        let mut log = LogEvent::default();
        log.insert("log_field", "site-123");
        // default_field is absent — would fail if default was used.

        let events = vec![Event::Log(log)];
        let (out, stats) = filter_events_by_auth(events, &validator);

        assert_eq!(stats.authorized, 1);
        assert_eq!(out.len(), 1);
    }

    // ── EventValidator::check unit tests ────────────────────────────────────

    #[test]
    fn validator_check_returns_field_name_and_value_on_success() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let mut log = LogEvent::default();
        log.insert("tenant_id", "site-123");
        let event = Event::Log(log);

        let (name, value) = validator.check(&event).expect("event should authorize");
        assert_eq!(name, "tenant_id");
        assert_eq!(value, "site-123");
    }

    #[test]
    fn validator_check_returns_authorization_missing_for_missing_field() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let event = Event::Log(LogEvent::default());
        assert_eq!(validator.check(&event), Err(AuthEventError::AuthorizationMissing));
    }

    #[test]
    fn validator_check_returns_forbidden_for_wrong_value() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let mut log = LogEvent::default();
        log.insert("tenant_id", "site-not-allowed");
        let event = Event::Log(log);

        assert_eq!(validator.check(&event), Err(AuthEventError::Forbidden));
    }

    // ── AuthBatchStats::any_failed unit tests ────────────────────────────────

    #[test]
    fn any_failed_is_false_when_all_authorized() {
        let stats = AuthBatchStats { authorized: 5, missing_value: 0, not_allowed: 0 };
        assert!(!stats.any_failed());
    }

    #[test]
    fn any_failed_is_true_when_missing_value() {
        let stats = AuthBatchStats { authorized: 3, missing_value: 2, not_allowed: 0 };
        assert!(stats.any_failed());
    }

    #[test]
    fn any_failed_is_true_when_not_allowed() {
        let stats = AuthBatchStats { authorized: 3, missing_value: 0, not_allowed: 1 };
        assert!(stats.any_failed());
    }

    #[test]
    fn any_failed_is_true_when_both_failure_kinds_present() {
        let stats = AuthBatchStats { authorized: 1, missing_value: 1, not_allowed: 1 };
        assert!(stats.any_failed());
    }

    #[test]
    fn empty_batch_filter_returns_default_stats() {
        let ctx = make_auth_ctx(&["site-123"]);
        let vp = make_value_path("tenant_id");
        let validator = make_validator(&ctx, &vp);

        let (out, stats) = filter_events_by_auth(vec![], &validator);
        assert!(out.is_empty());
        assert!(!stats.any_failed());
        assert_eq!(stats.authorized, 0);
        assert_eq!(stats.missing_value, 0);
        assert_eq!(stats.not_allowed, 0);
    }
}

#[cfg(feature = "sinks-vector")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{SinkConfig as _, SinkContext},
        sinks::vector::VectorConfig as SinkConfig,
        test_util, SourceSender,
    };
    use vector_lib::assert_event_data_eq;
    use vector_lib::config::log_schema;

    async fn run_test(vector_source_config_str: &str, addr: SocketAddr) {
        let config = format!(r#"address = "{}""#, addr);
        let source: VectorConfig = toml::from_str(&config).unwrap();

        let (tx, rx) = SourceSender::new_test();
        let server = source
            .build(SourceContext::new_test(tx, None))
            .await
            .unwrap();
        tokio::spawn(server);
        test_util::wait_for_tcp(addr).await;

        // Ideally, this would be a fully custom agent to send the data,
        // but the sink side already does such a test and this is good
        // to ensure interoperability.
        let sink: SinkConfig = toml::from_str(vector_source_config_str).unwrap();
        let cx = SinkContext::default();
        let (sink, _) = sink.build(cx).await.unwrap();

        let (mut events, stream) = test_util::random_events_with_stream(100, 100, None);
        sink.run(stream).await.unwrap();

        for event in &mut events {
            event.as_mut_log().insert(
                log_schema().source_type_key_target_path().unwrap(),
                "vector",
            );
        }

        let output = test_util::collect_ready(rx).await;
        assert_event_data_eq!(events, output);
    }

    #[tokio::test]
    async fn receive_message() {
        let addr = test_util::next_addr();

        let config = format!(r#"address = "{}""#, addr);
        run_test(&config, addr).await;
    }

    #[tokio::test]
    async fn receive_compressed_message() {
        let addr = test_util::next_addr();

        let config = format!(
            r#"address = "{}"
            compression=true"#,
            addr
        );
        run_test(&config, addr).await;
    }

    // ── Auth integration tests ───────────────────────────────────────────────
    //
    // These tests require `sources-vector` (for jsonwebtoken) in addition to the
    // `sinks-vector` feature already guarding this module.

    #[cfg(feature = "sources-vector")]
    mod auth_tests {
        use std::collections::HashMap;

        use vector_lib::event::{BatchNotifier, BatchStatus};

        use super::*;
        use crate::test_util::jwt_auth::{make_token, TEST_CERT, TEST_PUBLIC_KEY};

        /// Run a source+sink pair and return the final `BatchStatus`.
        async fn run_auth_pair(source_auth_toml: &str, sink_auth_toml: &str) -> BatchStatus {
            let addr = test_util::next_addr();

            let source: VectorConfig = toml::from_str(&format!(
                "address = \"{addr}\"\n{source_auth_toml}"
            ))
            .unwrap();

            let (tx, _rx) = SourceSender::new_test();
            let server = source
                .build(SourceContext::new_test(tx, None))
                .await
                .unwrap();
            tokio::spawn(server);
            test_util::wait_for_tcp(addr).await;

            let sink_toml = format!("address = \"http://{addr}/\"\n{sink_auth_toml}");
            let sink_cfg: SinkConfig = toml::from_str(&sink_toml).unwrap();
            let (sink, _) = sink_cfg.build(SinkContext::default()).await.unwrap();

            let (batch, receiver) = BatchNotifier::new_with_receiver();
            let (_, stream) = test_util::random_lines_with_stream(8, 5, Some(batch));
            sink.run(stream).await.unwrap();

            receiver.await
        }

        #[tokio::test]
        async fn valid_token_delivers() {
            let token = make_token(HashMap::new());
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            let sink_auth = format!(
                r#"[auth]
[auth.token]
type  = "inline"
value = "{token}""#
            );
            assert_eq!(
                run_auth_pair(&source_auth, &sink_auth).await,
                BatchStatus::Delivered
            );
        }

        #[tokio::test]
        async fn valid_token_delivers_with_tls_cert_authority() {
            // End-to-end exercise of the tls_cert variant at the source/sink
            // boundary: the inline X.509 cert in the source config must yield a
            // verifier that accepts a token signed by the matching test key.
            let token = make_token(HashMap::new());
            let source_auth = format!(
                r#"[auth]
tls_cert.type  = "inline"
tls_cert.value = "{}"
membership_claim = "site_ids""#,
                TEST_CERT.replace('\n', "\\n")
            );
            let sink_auth = format!(
                r#"[auth]
[auth.token]
type  = "inline"
value = "{token}""#
            );
            assert_eq!(
                run_auth_pair(&source_auth, &sink_auth).await,
                BatchStatus::Delivered
            );
        }

        #[tokio::test]
        async fn legacy_sink_without_auth_is_accepted() {
            // Source has auth configured with require_token=false (legacy mode);
            // sink sends no token → request allowed through.
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids"
require_token    = false"#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            assert_eq!(
                run_auth_pair(&source_auth, "").await,
                BatchStatus::Delivered
            );
        }

        #[tokio::test]
        async fn invalid_token_is_rejected() {
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            let sink_auth = r#"[auth]
[auth.token]
type  = "inline"
value = "not.a.valid.jwt""#;
            assert_eq!(
                run_auth_pair(&source_auth, sink_auth).await,
                BatchStatus::Rejected
            );
        }

        #[tokio::test]
        async fn source_without_auth_accepts_all_requests() {
            // Source has no auth config; any sink (with or without a token) is accepted.
            assert_eq!(run_auth_pair("", "").await, BatchStatus::Delivered);
        }

        #[tokio::test]
        async fn events_failing_value_path_check_rejects_batch() {
            // Valid JWT, but events don't carry the required tenant_id field.
            // Source should send PermissionDenied (non-retriable) → BatchStatus::Rejected.
            let token = make_token(HashMap::new());
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids"
[auth.value_path]
default = "tenant_id""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            let sink_auth = format!(
                r#"[auth]
[auth.token]
type  = "inline"
value = "{token}""#
            );
            // random_lines_with_stream creates log events without a `tenant_id` field;
            // every event fails the AuthorizationMissing check.
            assert_eq!(
                run_auth_pair(&source_auth, &sink_auth).await,
                BatchStatus::Rejected
            );
        }

        #[tokio::test]
        async fn legacy_sink_with_value_path_configured_is_accepted() {
            // Source has value_path with require_token=false (legacy mode); sink sends
            // no token → per-event filtering is skipped entirely, all events pass through.
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids"
require_token    = false
[auth.value_path]
default = "tenant_id""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            assert_eq!(
                run_auth_pair(&source_auth, "").await,
                BatchStatus::Delivered
            );
        }

        // ── require_token + healthcheck integration ──────────────────────────

        /// Build a source+sink pair and return the result of the sink's healthcheck.
        async fn run_healthcheck_pair(
            source_auth_toml: &str,
            sink_auth_toml: &str,
        ) -> crate::Result<()> {
            let addr = test_util::next_addr();

            let source: VectorConfig = toml::from_str(&format!(
                "address = \"{addr}\"\n{source_auth_toml}"
            ))
            .unwrap();

            let (tx, _rx) = SourceSender::new_test();
            let server = source
                .build(SourceContext::new_test(tx, None))
                .await
                .unwrap();
            tokio::spawn(server);
            test_util::wait_for_tcp(addr).await;

            let sink_toml = format!("address = \"http://{addr}/\"\n{sink_auth_toml}");
            let sink_cfg: SinkConfig = toml::from_str(&sink_toml).unwrap();
            let (_, healthcheck) = sink_cfg.build(SinkContext::default()).await.unwrap();
            healthcheck.await
        }

        #[tokio::test]
        async fn require_token_source_rejects_unauthenticated_push() {
            // Source: require_token = true (explicit); sink: no auth → rejected.
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids"
require_token    = true"#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            assert_eq!(
                run_auth_pair(&source_auth, "").await,
                BatchStatus::Rejected
            );
        }

        #[tokio::test]
        async fn require_token_source_accepts_authenticated_push() {
            // Source: require_token = true (explicit); sink: valid token → delivered.
            let token = make_token(HashMap::new());
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids"
require_token    = true"#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            let sink_auth = format!(
                r#"[auth]
[auth.token]
type  = "inline"
value = "{token}""#
            );
            assert_eq!(
                run_auth_pair(&source_auth, &sink_auth).await,
                BatchStatus::Delivered
            );
        }

        #[tokio::test]
        async fn default_require_token_rejects_request_without_token() {
            // Source TOML omits `require_token` — the default is `true`,
            // so a sink with no token must be rejected.
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            assert_eq!(
                run_auth_pair(&source_auth, "").await,
                BatchStatus::Rejected
            );
        }

        #[tokio::test]
        async fn default_require_token_accepts_request_with_token() {
            // Source TOML omits `require_token` — default `true`. Sink sends
            // a valid token; request flows through.
            let token = make_token(HashMap::new());
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            let sink_auth = format!(
                r#"[auth]
[auth.token]
type  = "inline"
value = "{token}""#
            );
            assert_eq!(
                run_auth_pair(&source_auth, &sink_auth).await,
                BatchStatus::Delivered
            );
        }

        #[tokio::test]
        async fn healthcheck_succeeds_when_sink_sends_token_to_require_token_source() {
            let token = make_token(HashMap::new());
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids"
require_token    = true"#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            let sink_auth = format!(
                r#"[auth]
[auth.token]
type  = "inline"
value = "{token}""#
            );
            assert!(run_healthcheck_pair(&source_auth, &sink_auth).await.is_ok());
        }

        #[tokio::test]
        async fn healthcheck_fails_when_sink_omits_token_to_require_token_source() {
            let source_auth = format!(
                r#"[auth]
pub_key.type  = "inline"
pub_key.value = "{}"
membership_claim = "site_ids"
require_token    = true"#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            assert!(run_healthcheck_pair(&source_auth, "").await.is_err());
        }

        #[tokio::test]
        async fn healthcheck_succeeds_when_neither_side_has_auth() {
            assert!(run_healthcheck_pair("", "").await.is_ok());
        }
    }
}
