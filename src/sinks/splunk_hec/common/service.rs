use std::{
    fmt,
    sync::Arc,
    task::{ready, Context, Poll},
};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{HeaderName, Request, HeaderValue};
use indexmap::IndexMap;
use metrics::Counter;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::PollSemaphore;
use tower::Service;
use uuid::Uuid;
use vector_lib::event::EventStatus;
use vector_lib::request_metadata::MetaDescriptive;

use super::{
    acknowledgements::{run_acknowledgements, HecClientAcknowledgementsConfig},
    EndpointTarget,
};
use crate::{
    http::HttpClient,
    internal_events::{SplunkIndexerAcknowledgementUnavailableError, SplunkResponseParseError},
    sinks::{
        splunk_hec::common::{build_uri, request::HecRequest, response::HecResponse},
        util::{emit_rejection_error, sink::Response, Compression, RejectionContext, RejectionReport},
        UriParseSnafu,
    },
};

pub struct HecRejectionContext {
    pub rejected: Counter,
}

#[derive(serde::Deserialize)]
struct SplunkErrorBody {
    text: Option<String>,
}

impl RejectionContext for HecRejectionContext {
    fn error_message(&self, status: u16, body: &Bytes) -> String {
        let splunk_text = serde_json::from_slice::<SplunkErrorBody>(body)
            .ok()
            .and_then(|b| b.text);
        match splunk_text {
            Some(text) => format!("Request rejected (status: {status}): {text}."),
            None => format!("Request rejected (status: {status})."),
        }
    }

    fn record_rejection(&self, _status: u16, _body: &Bytes) {
        self.rejected.increment(1);
    }
}

pub struct HecService<S> {
    pub inner: S,
    ack_finalizer_tx: Option<mpsc::Sender<(u64, oneshot::Sender<EventStatus>)>>,
    ack_slots: PollSemaphore,
    current_ack_slot: Option<OwnedSemaphorePermit>,
    rej_rpt: RejectionReport,
    compression: Compression,
    rej_ctx: Arc<HecRejectionContext>,
}

#[derive(Deserialize, Serialize, Debug)]
struct HecAckResponseBody {
    #[serde(alias = "ackId")]
    ack_id: Option<u64>,
}

impl<S> HecService<S>
where
    S: Service<HecRequest> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Response + ResponseExt + Send + 'static,
    S::Error: fmt::Debug + Into<crate::Error> + Send,
{
    pub fn new(
        inner: S,
        ack_client: Option<HttpClient>,
        http_request_builder: Arc<HttpRequestBuilder>,
        indexer_acknowledgements: HecClientAcknowledgementsConfig,
        rej_rpt: RejectionReport,
        compression: Compression,
        rej_ctx: Arc<HecRejectionContext>,
    ) -> Self {
        let max_pending_acks = indexer_acknowledgements.max_pending_acks.get();
        let tx = if let Some(ack_client) = ack_client {
            let (tx, rx) = mpsc::channel(128);
            tokio::spawn(run_acknowledgements(
                rx,
                ack_client,
                Arc::clone(&http_request_builder),
                indexer_acknowledgements,
            ));
            Some(tx)
        } else {
            None
        };

        let ack_slots = PollSemaphore::new(Arc::new(Semaphore::new(max_pending_acks as usize)));
        Self {
            inner,
            ack_finalizer_tx: tx,
            ack_slots,
            current_ack_slot: None,
            rej_rpt,
            compression,
            rej_ctx,
        }
    }
}

impl<S> Service<HecRequest> for HecService<S>
where
    S: Service<HecRequest> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Response + ResponseExt + Send + 'static,
    S::Error: fmt::Debug + Into<crate::Error> + Send,
{
    type Response = HecResponse;
    type Error = crate::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context) -> std::task::Poll<Result<(), Self::Error>> {
        // Ready if indexer acknowledgements is disabled or there is room for
        // additional pending acks. Otherwise, wait until there is room.
        if self.ack_finalizer_tx.is_none() || self.current_ack_slot.is_some() {
            self.inner.poll_ready(cx).map_err(Into::into)
        } else {
            match ready!(self.ack_slots.poll_acquire(cx)) {
                Some(permit) => {
                    self.current_ack_slot.replace(permit);
                    self.inner.poll_ready(cx).map_err(Into::into)
                }
                None => Poll::Ready(Err(
                    "Indexer acknowledgements semaphore unexpectedly closed".into(),
                )),
            }
        }
    }

    fn call(&mut self, mut req: HecRequest) -> Self::Future {
        let ack_finalizer_tx = self.ack_finalizer_tx.clone();
        let ack_slot = self.current_ack_slot.take();
        let rej_rpt = self.rej_rpt.clone();
        let compression = self.compression;
        let rej_ctx = Arc::clone(&self.rej_ctx);
        let req_for_rpt = if rej_rpt.needs_request() {
            Some((req.body.clone(), compression))
        } else {
            None
        };

        let metadata = std::mem::take(req.metadata_mut());
        let events_count = metadata.event_count();
        let events_byte_size = metadata.into_events_estimated_json_encoded_byte_size();
        let response = self.inner.call(req);

        Box::pin(async move {
            let response = response.await.map_err(Into::into)?;
            let event_status = if response.is_successful() {
                if let Some(ack_finalizer_tx) = ack_finalizer_tx {
                    let _ack_slot = ack_slot.expect("poll_ready not called before invoking call");
                    let body = serde_json::from_slice::<HecAckResponseBody>(response.body());
                    match body {
                        Ok(body) => {
                            if let Some(ack_id) = body.ack_id {
                                let (tx, rx) = oneshot::channel();
                                match ack_finalizer_tx.send((ack_id, tx)).await {
                                    Ok(_) => rx.await.unwrap_or(EventStatus::Rejected),
                                    // If we cannot send ack ids to the ack client, fall back to default behavior
                                    Err(error) => {
                                        emit!(SplunkIndexerAcknowledgementUnavailableError {
                                            error
                                        });
                                        EventStatus::Delivered
                                    }
                                }
                            } else {
                                // Default behavior if indexer acknowledgements is disabled on the Splunk server
                                EventStatus::Delivered
                            }
                        }
                        Err(error) => {
                            // This may occur if Splunk changes the response format in future versions.
                            emit!(SplunkResponseParseError { error });
                            EventStatus::Delivered
                        }
                    }
                } else {
                    // Default behavior if indexer acknowledgements is disabled by configuration
                    EventStatus::Delivered
                }
            } else if response.is_transient() {
                let mode = if rej_rpt == RejectionReport::RequestResponse {
                    RejectionReport::Response
                } else {
                    rej_rpt
                };
                emit_rejection_error(rej_ctx.as_ref(), response.status_code(), response.body(), None, mode);
                EventStatus::Errored
            } else {
                emit_rejection_error(rej_ctx.as_ref(), response.status_code(), response.body(), req_for_rpt, rej_rpt);
                EventStatus::Rejected
            };

            Ok(HecResponse {
                event_status,
                events_count,
                events_byte_size,
            })
        })
    }
}

pub trait ResponseExt {
    fn body(&self) -> &Bytes;
    fn status_code(&self) -> u16;
}

impl ResponseExt for http::Response<Bytes> {
    fn body(&self) -> &Bytes {
        self.body()
    }

    fn status_code(&self) -> u16 {
        self.status().as_u16()
    }
}

pub enum Token {
    Fallback(String),

    Enforced(String),
}

impl Token {
    fn authz_header(&self, passthru: Option<Arc<str>>) -> String {
        let t = match self {
            Token::Fallback(t) => passthru.unwrap_or_else(|| t.as_str().into()),
            Token::Enforced(t) => t.as_str().into(),
        };
        format!("Splunk {t}")
    }
}

pub struct HttpRequestBuilder {
    pub endpoint_target: EndpointTarget,
    pub endpoint: String,
    pub token: Token,
    pub compression: Compression,
    // A Splunk channel must be a GUID/UUID formatted value
    // https://docs.splunk.com/Documentation/Splunk/8.2.3/Data/AboutHECIDXAck#About_channels_and_sending_data
    pub channel: String,
    pub headers: IndexMap<HeaderName, HeaderValue>,
}

#[derive(Default)]
pub(super) struct MetadataFields {
    pub(super) source: Option<String>,
    pub(super) sourcetype: Option<String>,
    pub(super) index: Option<String>,
    pub(super) host: Option<String>,
}

impl HttpRequestBuilder {
    pub fn new(
        endpoint: String,
        endpoint_target: EndpointTarget,
        token: Token,
        compression: Compression,
        headers: IndexMap<HeaderName, HeaderValue>,
    ) -> Self {
        let channel = Uuid::new_v4().hyphenated().to_string();
        Self {
            endpoint,
            endpoint_target,
            token,
            compression,
            channel,
            headers,
        }
    }

    pub(super) fn build_request(
        &self,
        body: Bytes,
        path: &str,
        passthrough_token: Option<Arc<str>>,
        metadata_fields: MetadataFields,
        auto_extract_timestamp: bool,
        dyn_headers: Vec<(HeaderName, HeaderValue)>,
    ) -> Result<Request<Bytes>, crate::Error> {
        let uri = match self.endpoint_target {
            EndpointTarget::Raw => {
                // `auto_extract_timestamp` doesn't apply to the raw endpoint since the raw endpoint
                // always does this anyway.
                let metadata = [
                    (super::SOURCE_FIELD, metadata_fields.source),
                    (super::SOURCETYPE_FIELD, metadata_fields.sourcetype),
                    (super::INDEX_FIELD, metadata_fields.index),
                    (super::HOST_FIELD, metadata_fields.host),
                ]
                .into_iter()
                .filter_map(|(key, value)| value.map(|value| (key, value)));
                build_uri(self.endpoint.as_str(), path, metadata).context(UriParseSnafu)?
            }
            EndpointTarget::Event => build_uri(
                self.endpoint.as_str(),
                path,
                if auto_extract_timestamp {
                    Some((super::AUTO_EXTRACT_TIMESTAMP_FIELD, "true".to_string()))
                } else {
                    None
                },
            )
            .context(UriParseSnafu)?,
        };

        let mut builder = Request::post(uri)
            .header("Content-Type", "application/json")
            .header("Authorization", self.token.authz_header(passthrough_token))
            .header("X-Splunk-Request-Channel", self.channel.as_str());

        let headers = builder
            .headers_mut()
            .ok_or_else(|| {
                crate::Error::from("Failed to access headers in http::Request builder")
            })?;

        for (header, value) in dyn_headers {
            headers.insert(header, value);
        }

        // Static headers from request config take precedence over dynamic headers
        for (header, value) in self.headers.iter() {
            headers.insert(header, value.clone());
        }

        if let Some(ce) = self.compression.content_encoding() {
            builder = builder.header("Content-Encoding", ce);
        }

        builder.body(body).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        future::poll_fn,
        num::{NonZeroU64, NonZeroU8, NonZeroUsize},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        task::Poll,
    };

    use bytes::Bytes;
    use futures_util::{poll, stream::FuturesUnordered, StreamExt};
    use http::{HeaderName, HeaderValue};
    use indexmap::IndexMap;
    use tower::{util::BoxService, Service, ServiceExt};
    use vector_lib::internal_event::CountByteSize;
    use vector_lib::{
        config::proxy::ProxyConfig,
        event::{EventFinalizers, EventStatus},
    };
    use wiremock::{
        matchers::{header, header_exists, method, path},
        Mock, MockServer, Request, Respond, ResponseTemplate,
    };

    use crate::{
        http::HttpClient,
        sinks::{
            splunk_hec::common::{
                acknowledgements::{
                    HecAckStatusRequest, HecAckStatusResponse, HecClientAcknowledgementsConfig,
                },
                build_http_batch_service,
                request::HecRequest,
                service::{HecAckResponseBody, HecRejectionContext, HecService, HttpRequestBuilder,Token},
                EndpointTarget,
            },
            util::{metadata::RequestMetadataBuilder, Compression, RejectionContext, RejectionReport},
        },
    };

    fn get_hec_service_with_rejection_report(
        endpoint: String,
        rej_rpt: RejectionReport,
        acknowledgements_config: HecClientAcknowledgementsConfig,
    ) -> HecService<BoxService<HecRequest, http::Response<Bytes>, crate::Error>> {
        let app_info = crate::app_info();
        let client = HttpClient::new(None, &ProxyConfig::default(), &app_info).unwrap();
        let http_request_builder = Arc::new(HttpRequestBuilder::new(
            endpoint,
            EndpointTarget::default(),
            Token::Fallback(String::from(TOKEN)),
            Compression::default(),
            IndexMap::default(),
        ));
        let http_service = build_http_batch_service(
            client.clone(),
            Arc::clone(&http_request_builder),
            EndpointTarget::Event,
            false,
            None,
        );
        HecService::new(
            BoxService::new(http_service),
            None,
            http_request_builder,
            acknowledgements_config,
            rej_rpt,
            Compression::default(),
            test_context(),
        )
    }

    const TOKEN: &str = "token";
    static ACK_ID: AtomicU64 = AtomicU64::new(0);

    fn test_context() -> Arc<HecRejectionContext> {
        Arc::new(HecRejectionContext {
            rejected: metrics::counter!("hec_rejected_test"),
        })
    }

    #[test]
    fn error_message_extracts_splunk_text_field() {
        let ctx = HecRejectionContext { rejected: metrics::counter!("_test") };
        assert_eq!(
            ctx.error_message(400, &Bytes::from(r#"{"text":"Invalid token","code":4}"#)),
            "Request rejected (status: 400): Invalid token."
        );
    }

    #[test]
    fn error_message_falls_back_to_status_when_no_text_field() {
        let ctx = HecRejectionContext { rejected: metrics::counter!("_test") };
        assert_eq!(
            ctx.error_message(503, &Bytes::from("Service Unavailable")),
            "Request rejected (status: 503)."
        );
    }

    fn get_hec_service(
        endpoint: String,
        acknowledgements_config: HecClientAcknowledgementsConfig,
    ) -> HecService<BoxService<HecRequest, http::Response<Bytes>, crate::Error>> {
        let app_info = crate::app_info();
        let client = HttpClient::new(None, &ProxyConfig::default(), &app_info).unwrap();
        let http_request_builder = Arc::new(HttpRequestBuilder::new(
            endpoint,
            EndpointTarget::default(),
            Token::Fallback(String::from(TOKEN)),
            Compression::default(),
            IndexMap::default()
        ));
        let http_service = build_http_batch_service(
            client.clone(),
            Arc::clone(&http_request_builder),
            EndpointTarget::Event,
            false,
            None
        );
        HecService::new(
            BoxService::new(http_service),
            Some(client),
            http_request_builder,
            acknowledgements_config,
            RejectionReport::default(),
            Compression::default(),
            test_context(),
        )
    }

    fn get_hec_request() -> HecRequest {
        let body = Bytes::from("test-message");
        let events_byte_size = body.len();

        let builder = RequestMetadataBuilder::new(
            1,
            events_byte_size,
            CountByteSize(1, events_byte_size.into()).into(),
        );
        let bytes_len =
            NonZeroUsize::new(events_byte_size).expect("payload should never be zero length");
        let metadata = builder.with_request_size(bytes_len);

        HecRequest {
            body,
            metadata,
            finalizers: EventFinalizers::default(),
            passthrough_token: None,
            index: None,
            source: None,
            sourcetype: None,
            host: None,
            headers: vec![],
        }
    }

    async fn get_hec_mock_server<R>(acknowledgements_enabled: bool, ack_response: R) -> MockServer
    where
        R: Respond + 'static,
    {
        // Authorization tokens and channels are required
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .and(header(
                "Authorization",
                format!("Splunk {}", TOKEN).as_str(),
            ))
            .and(header_exists("X-Splunk-Request-Channel"))
            .respond_with(move |_: &Request| {
                let ack_id =
                    acknowledgements_enabled.then(|| ACK_ID.fetch_add(1, Ordering::Relaxed));
                ResponseTemplate::new(200).set_body_json(HecAckResponseBody { ack_id })
            })
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/services/collector/ack"))
            .and(header(
                "Authorization",
                format!("Splunk {}", TOKEN).as_str(),
            ))
            .and(header_exists("X-Splunk-Request-Channel"))
            .respond_with(ack_response)
            .mount(&mock_server)
            .await;

        mock_server
    }

    fn ack_response_always_succeed(req: &Request) -> ResponseTemplate {
        let req = serde_json::from_slice::<HecAckStatusRequest>(req.body.as_slice()).unwrap();
        ResponseTemplate::new(200).set_body_json(HecAckStatusResponse {
            acks: req
                .acks
                .into_iter()
                .map(|ack_id| (ack_id, true))
                .collect::<HashMap<_, _>>(),
        })
    }

    fn ack_response_always_fail(req: &Request) -> ResponseTemplate {
        let req = serde_json::from_slice::<HecAckStatusRequest>(req.body.as_slice()).unwrap();
        ResponseTemplate::new(200).set_body_json(HecAckStatusResponse {
            acks: req
                .acks
                .into_iter()
                .map(|ack_id| (ack_id, false))
                .collect::<HashMap<_, _>>(),
        })
    }

    #[tokio::test]
    async fn acknowledgements_disabled_in_config() {
        let mock_server = get_hec_mock_server(true, ack_response_always_succeed).await;

        let acknowledgements_config = HecClientAcknowledgementsConfig {
            indexer_acknowledgements_enabled: false,
            ..Default::default()
        };
        let mut service = get_hec_service(mock_server.uri(), acknowledgements_config);

        let request = get_hec_request();
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(EventStatus::Delivered, response.event_status)
    }

    #[tokio::test]
    async fn acknowledgements_enabled_on_server() {
        let mock_server = get_hec_mock_server(true, ack_response_always_succeed).await;

        let acknowledgements_config = HecClientAcknowledgementsConfig {
            query_interval: NonZeroU8::new(1).unwrap(),
            ..Default::default()
        };
        let mut service = get_hec_service(mock_server.uri(), acknowledgements_config);

        let mut responses = FuturesUnordered::new();
        responses.push(service.ready().await.unwrap().call(get_hec_request()));
        responses.push(service.ready().await.unwrap().call(get_hec_request()));
        responses.push(service.ready().await.unwrap().call(get_hec_request()));
        while let Some(response) = responses.next().await {
            assert_eq!(EventStatus::Delivered, response.unwrap().event_status)
        }
    }

    #[tokio::test]
    async fn acknowledgements_disabled_on_server() {
        let ack_response = |_: &Request| ResponseTemplate::new(400);
        let mock_server = get_hec_mock_server(false, ack_response).await;

        let acknowledgements_config = HecClientAcknowledgementsConfig {
            query_interval: NonZeroU8::new(1).unwrap(),
            ..Default::default()
        };
        let mut service = get_hec_service(mock_server.uri(), acknowledgements_config);

        let request = get_hec_request();
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(EventStatus::Delivered, response.event_status)
    }

    #[tokio::test]
    async fn acknowledgements_enabled_on_server_retry_limit_exceeded() {
        let mock_server = get_hec_mock_server(true, ack_response_always_fail).await;

        let acknowledgements_config = HecClientAcknowledgementsConfig {
            query_interval: NonZeroU8::new(1).unwrap(),
            retry_limit: NonZeroU8::new(1).unwrap(),
            ..Default::default()
        };
        let mut service = get_hec_service(mock_server.uri(), acknowledgements_config);

        let request = get_hec_request();
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(EventStatus::Rejected, response.event_status)
    }

    #[tokio::test]
    async fn acknowledgements_server_changed_ack_response_format() {
        let ack_response = |_: &Request| {
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!(r#"{ "new": "a new response body" }"#))
        };
        let mock_server = get_hec_mock_server(true, ack_response).await;

        let acknowledgements_config = HecClientAcknowledgementsConfig {
            query_interval: NonZeroU8::new(1).unwrap(),
            retry_limit: NonZeroU8::new(3).unwrap(),
            ..Default::default()
        };
        let mut service = get_hec_service(mock_server.uri(), acknowledgements_config);

        let request = get_hec_request();
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(EventStatus::Delivered, response.event_status)
    }

    #[tokio::test]
    async fn acknowledgements_enabled_on_server_ack_endpoint_failing() {
        let ack_response = |_: &Request| ResponseTemplate::new(503);
        let mock_server = get_hec_mock_server(true, ack_response).await;

        let acknowledgements_config = HecClientAcknowledgementsConfig {
            query_interval: NonZeroU8::new(1).unwrap(),
            retry_limit: NonZeroU8::new(3).unwrap(),
            ..Default::default()
        };
        let mut service = get_hec_service(mock_server.uri(), acknowledgements_config);

        let request = get_hec_request();
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(EventStatus::Errored, response.event_status)
    }

    #[tokio::test]
    async fn acknowledgements_server_changed_event_response_format() {
        let mock_server = get_hec_mock_server(true, ack_response_always_succeed).await;
        // Override the usual event endpoint
        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .and(header(
                "Authorization",
                format!("Splunk {}", TOKEN).as_str(),
            ))
            .and(header_exists("X-Splunk-Request-Channel"))
            .respond_with(move |_: &Request| {
                ResponseTemplate::new(200).set_body_json(r#"{ "new": "a new response body" }"#)
            })
            .mount(&mock_server)
            .await;

        let acknowledgements_config = HecClientAcknowledgementsConfig {
            query_interval: NonZeroU8::new(1).unwrap(),
            retry_limit: NonZeroU8::new(1).unwrap(),
            ..Default::default()
        };
        let mut service = get_hec_service(mock_server.uri(), acknowledgements_config);

        let request = get_hec_request();
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(EventStatus::Delivered, response.event_status)
    }

    #[tokio::test]
    async fn service_poll_ready_multiple_times() {
        let mock_server = get_hec_mock_server(true, ack_response_always_fail).await;
        let mut service = get_hec_service(mock_server.uri(), Default::default());

        assert!(service.ready().await.is_ok());
        // Consecutive poll_ready returns OK since an ack slot has been granted
        // but has not been used (call has not been invoked)
        assert!(service.ready().await.is_ok());
    }

    #[tokio::test]
    #[should_panic]
    async fn service_call_without_poll_ready() {
        let mock_server = get_hec_mock_server(true, ack_response_always_fail).await;
        let mut service = get_hec_service(mock_server.uri(), Default::default());

        _ = service.call(get_hec_request()).await;
    }

    #[tokio::test]
    async fn acknowledgements_max_pending_acks_reached() {
        let mock_server = get_hec_mock_server(true, ack_response_always_fail).await;

        let acknowledgements_config = HecClientAcknowledgementsConfig {
            query_interval: NonZeroU8::new(1).unwrap(),
            retry_limit: NonZeroU8::new(5).unwrap(),
            // Allow a single pending ack
            max_pending_acks: NonZeroU64::new(1).unwrap(),
            ..Default::default()
        };
        let mut service = get_hec_service(mock_server.uri(), acknowledgements_config);

        // Grab the one available ack slot
        let pending_call = service.ready().await.unwrap().call(get_hec_request());
        // The service should return pending for additional requests
        assert!(matches!(
            poll!(poll_fn(|cx| service.poll_ready(cx))),
            Poll::Pending
        ));
        // Complete the call to free up the slot
        let response = pending_call.await.unwrap();
        assert_eq!(EventStatus::Rejected, response.event_status);
        // The service should now be ready for additional requests
        assert!(matches!(
            poll!(poll_fn(|cx| service.poll_ready(cx))),
            Poll::Ready(Ok(_))
        ));
    }

    #[tokio::test]
    async fn hec_service_with_custom_headers() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .and(header("X-Service-Header", "service-value"))
            .respond_with(ResponseTemplate::new(200).set_body_json(HecAckResponseBody {
                ack_id: Some(123),
            }))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/services/collector/ack"))
            .respond_with(ack_response_always_succeed)
            .mount(&mock_server)
            .await;

        let mut custom_headers = IndexMap::new();
        custom_headers.insert(
            HeaderName::from_static("x-service-header"),
            HeaderValue::from_static("service-value"),
        );

        let acknowledgements_config = HecClientAcknowledgementsConfig {
            query_interval: NonZeroU8::new(1).unwrap(),
            ..Default::default()
        };

        let app_info = crate::app_info();
        let client = HttpClient::new(None, &ProxyConfig::default(), &app_info).unwrap();
        let http_request_builder = Arc::new(HttpRequestBuilder::new(
            mock_server.uri(),
            EndpointTarget::default(),
            Token::Fallback(String::from(TOKEN)),
            Compression::default(),
            custom_headers,
        ));

        let http_service = build_http_batch_service(
            client.clone(),
            Arc::clone(&http_request_builder),
            EndpointTarget::Event,
            false,
            None,
        );

        let mut service = HecService::new(
            BoxService::new(http_service),
            Some(client),
            http_request_builder,
            acknowledgements_config,
            RejectionReport::default(),
            Compression::default(),
            test_context(),
        );

        let request = get_hec_request();
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(EventStatus::Delivered, response.event_status);
    }

    #[tokio::test]
    async fn empty_headers() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .respond_with(ResponseTemplate::new(200).set_body_json(HecAckResponseBody {
                ack_id: None,
            }))
            .mount(&mock_server)
            .await;

        let custom_headers = IndexMap::default();

        let app_info = crate::app_info();
        let client = HttpClient::new(None, &ProxyConfig::default(), &app_info).unwrap();
        let http_request_builder = Arc::new(HttpRequestBuilder::new(
            mock_server.uri(),
            EndpointTarget::Event,
            Token::Fallback(String::from(TOKEN)),
            Compression::default(),
            custom_headers,
        ));

        let http_service = build_http_batch_service(
            client.clone(),
            Arc::clone(&http_request_builder),
            EndpointTarget::Event,
            false,
            None,
        );

        let mut service = HecService::new(
            BoxService::new(http_service),
            None, // No ack client needed for this test
            http_request_builder,
            HecClientAcknowledgementsConfig {
                indexer_acknowledgements_enabled: false,
                ..Default::default()
            },
            RejectionReport::default(),
            Compression::default(),
            test_context(),
        );

        let request = get_hec_request();
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(EventStatus::Delivered, response.event_status);
    }

    #[tokio::test]
    async fn multiple_headers_with_various_values() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .and(header("X-Special-Chars", "value-with-dashes_and_underscores"))
            .and(header("X-Numeric", "12345"))
            .respond_with(ResponseTemplate::new(200).set_body_json(HecAckResponseBody {
                ack_id: None,
            }))
            .expect(1) // Verify the mock was actually called
            .mount(&mock_server)
            .await;

        let custom_headers: IndexMap<HeaderName, HeaderValue> = [
            (
                HeaderName::from_static("x-special-chars"),
                HeaderValue::from_str("value-with-dashes_and_underscores").unwrap(),
            ),
            (
                HeaderName::from_static("x-numeric"),
                HeaderValue::from_str("12345").unwrap(),
            ),
        ].into();

        let app_info = crate::app_info();
        let client = HttpClient::new(None, &ProxyConfig::default(), &app_info).unwrap();
        let http_request_builder = Arc::new(HttpRequestBuilder::new(
            mock_server.uri(),
            EndpointTarget::Event,
            Token::Fallback(String::from(TOKEN)),
            Compression::default(),
            custom_headers,
        ));

        let http_service = build_http_batch_service(
            client.clone(),
            Arc::clone(&http_request_builder),
            EndpointTarget::Event,
            false,
            None,
        );

        let mut service = HecService::new(
            BoxService::new(http_service),
            None,
            http_request_builder,
            HecClientAcknowledgementsConfig {
                indexer_acknowledgements_enabled: false,
                ..Default::default()
            },
            RejectionReport::default(),
            Compression::default(),
            test_context(),
        );

        let request = get_hec_request();
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(EventStatus::Delivered, response.event_status);
    }

    fn no_ack_config() -> HecClientAcknowledgementsConfig {
        HecClientAcknowledgementsConfig {
            indexer_acknowledgements_enabled: false,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn hec_service_4xx_returns_rejected() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"text":"Invalid token","code":4}"#))
            .mount(&mock_server)
            .await;

        let mut service = get_hec_service_with_rejection_report(
            mock_server.uri(),
            RejectionReport::Stats,
            no_ack_config(),
        );
        let response = service.ready().await.unwrap().call(get_hec_request()).await.unwrap();
        assert_eq!(EventStatus::Rejected, response.event_status);
    }

    #[tokio::test]
    async fn hec_service_5xx_returns_errored() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .mount(&mock_server)
            .await;

        let mut service = get_hec_service_with_rejection_report(
            mock_server.uri(),
            RejectionReport::Stats,
            no_ack_config(),
        );
        let response = service.ready().await.unwrap().call(get_hec_request()).await.unwrap();
        assert_eq!(EventStatus::Errored, response.event_status);
    }

    #[tokio::test]
    async fn hec_service_5xx_with_request_response_mode_still_errored() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let mut service = get_hec_service_with_rejection_report(
            mock_server.uri(),
            RejectionReport::RequestResponse,
            no_ack_config(),
        );
        let response = service.ready().await.unwrap().call(get_hec_request()).await.unwrap();
        assert_eq!(EventStatus::Errored, response.event_status);
    }

    #[tokio::test]
    async fn hec_service_4xx_with_request_response_mode_returns_rejected() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string(r#"{"text":"Forbidden","code":6}"#))
            .mount(&mock_server)
            .await;

        let mut service = get_hec_service_with_rejection_report(
            mock_server.uri(),
            RejectionReport::RequestResponse,
            no_ack_config(),
        );
        let response = service.ready().await.unwrap().call(get_hec_request()).await.unwrap();
        assert_eq!(EventStatus::Rejected, response.event_status);
    }
}


