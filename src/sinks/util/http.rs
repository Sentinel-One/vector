use std::{
    fmt,
    future::Future,
    hash::Hash,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
    time::Duration,
};

use bytes::{Buf, Bytes};
use futures::{future::BoxFuture, Sink};
use headers::HeaderName;
use http::{header, HeaderValue, Request, Response, StatusCode};
use hyper::{body, Body};
use indexmap::IndexMap;
use pin_project::pin_project;
use snafu::{ResultExt, Snafu};
use tower::{Service, ServiceBuilder};
use tower_http::decompression::DecompressionLayer;
use vector_lib::configurable::configurable_component;
use vector_lib::internal_event::{ByteSize, BytesSent, InternalEventHandle as _, Registered};
use vector_lib::stream::batcher::limiter::ItemBatchSize;
use vector_lib::{ByteSizeOf, EstimatedJsonEncodedSizeOf};

use super::{
    retries::{RetryAction, RetryLogic},
    sink::{self, Response as _},
    Batch, EncodedEvent, Partition, TowerBatchedSink, TowerPartitionSink, TowerRequestConfig,
    TowerRequestSettings,
};
use crate::{
    event::Event,
    http::{HttpClient, HttpError},
    internal_events::SinkRequestBuildError,
    sinks::prelude::*,
};

pub use vector_lib::sink::http::HttpEventEncoder;
pub use vector_lib::sink::http::HttpSink;

/// Provides a simple wrapper around internal tower and
/// batching sinks for http.
///
/// This type wraps some `HttpSink` and some `Batch` type
/// and will apply request, batch and tls settings. Internally,
/// it holds an Arc reference to the `HttpSink`. It then exposes
/// a `Sink` interface that can be returned from `SinkConfig`.
///
/// Implementation details we require to buffer a single item due
/// to how `Sink` works. This is because we must "encode" the type
/// to be able to send it to the inner batch type and sink. Because of
/// this we must provide a single buffer slot. To ensure the buffer is
/// fully flushed make sure `poll_flush` returns ready.
///
/// Note: This has been deprecated, please do not use when creating new Sinks.
#[pin_project]
pub struct BatchedHttpSink<T, B, RL = HttpRetryLogic>
where
    B: Batch,
    B::Output: ByteSizeOf + Clone + Send + 'static,
    T: HttpSink<Input = B::Input, Output = B::Output>,
    RL: RetryLogic<Response = http::Response<Bytes>> + Send + 'static,
{
    sink: Arc<T>,
    #[pin]
    inner: TowerBatchedSink<
        HttpBatchService<BoxFuture<'static, crate::Result<hyper::Request<Bytes>>>, B::Output>,
        B,
        RL,
    >,
    encoder: T::Encoder,
    // An empty slot is needed to buffer an item where we encoded it but
    // the inner sink is applying back pressure. This trick is used in the `WithFlatMap`
    // sink combinator. https://docs.rs/futures/0.1.29/src/futures/sink/with_flat_map.rs.html#20
    slot: Option<EncodedEvent<B::Input>>,
}

impl<T, B> BatchedHttpSink<T, B>
where
    B: Batch,
    B::Output: ByteSizeOf + Clone + Send + 'static,
    T: HttpSink<Input = B::Input, Output = B::Output>,
{
    pub fn new(
        sink: T,
        batch: B,
        request_settings: TowerRequestSettings,
        batch_timeout: Duration,
        client: HttpClient,
        bytes_sent: Registered<BytesSent>,
    ) -> Self {
        Self::with_logic(
            sink,
            batch,
            HttpRetryLogic,
            request_settings,
            batch_timeout,
            client,
            bytes_sent,
        )
    }
}

impl<T, B, RL> BatchedHttpSink<T, B, RL>
where
    B: Batch,
    B::Output: ByteSizeOf + Clone + Send + 'static,
    RL: RetryLogic<Response = http::Response<Bytes>, Error = HttpError> + Send + 'static,
    T: HttpSink<Input = B::Input, Output = B::Output>,
{
    pub fn with_logic(
        sink: T,
        batch: B,
        retry_logic: RL,
        request_settings: TowerRequestSettings,
        batch_timeout: Duration,
        client: HttpClient,
        bytes_sent: Registered<BytesSent>,
    ) -> Self {
        let sink = Arc::new(sink);

        let sink1 = Arc::clone(&sink);
        let request_builder = move |b| -> BoxFuture<'static, crate::Result<http::Request<Bytes>>> {
            let sink = Arc::clone(&sink1);
            Box::pin(async move { sink.build_request(b).await })
        };

        let svc = HttpBatchService::new(client, request_builder, bytes_sent);
        let inner = request_settings.batch_sink(retry_logic, svc, batch, batch_timeout);
        let encoder = sink.build_encoder();

        Self {
            sink,
            inner,
            encoder,
            slot: None,
        }
    }
}

impl<T, B, RL> Sink<Event> for BatchedHttpSink<T, B, RL>
where
    B: Batch,
    B::Output: ByteSizeOf + Clone + Send + 'static,
    T: HttpSink<Input = B::Input, Output = B::Output>,
    RL: RetryLogic<Response = http::Response<Bytes>> + Send + 'static,
{
    type Error = crate::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.slot.is_some() {
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    if self.slot.is_some() {
                        return Poll::Pending;
                    }
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, mut event: Event) -> Result<(), Self::Error> {
        let byte_size = event.size_of();
        let json_byte_size = event.estimated_json_encoded_size_of();
        let finalizers = event.metadata_mut().take_finalizers();
        if let Some(item) = self.encoder.encode_event(event) {
            *self.project().slot = Some(EncodedEvent {
                item,
                finalizers,
                byte_size,
                json_byte_size,
            });
        }

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        if this.slot.is_some() {
            ready!(this.inner.as_mut().poll_ready(cx))?;
            this.inner.as_mut().start_send(this.slot.take().unwrap())?;
        }

        this.inner.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        self.project().inner.poll_close(cx)
    }
}

/// Note: This has been deprecated, please do not use when creating new Sinks.
#[pin_project]
pub struct PartitionHttpSink<T, B, K, RL = HttpRetryLogic>
where
    B: Batch,
    B::Output: ByteSizeOf + Clone + Send + 'static,
    B::Input: Partition<K>,
    K: Hash + Eq + Clone + Send + 'static,
    T: HttpSink<Input = B::Input, Output = B::Output>,
    RL: RetryLogic<Response = http::Response<Bytes>> + Send + 'static,
{
    sink: Arc<T>,
    #[pin]
    inner: TowerPartitionSink<
        HttpBatchService<BoxFuture<'static, crate::Result<hyper::Request<Bytes>>>, B::Output>,
        B,
        RL,
        K,
    >,
    encoder: T::Encoder,
    slot: Option<EncodedEvent<B::Input>>,
}

impl<T, B, K> PartitionHttpSink<T, B, K, HttpRetryLogic>
where
    B: Batch,
    B::Output: ByteSizeOf + Clone + Send + 'static,
    B::Input: Partition<K>,
    K: Hash + Eq + Clone + Send + 'static,
    T: HttpSink<Input = B::Input, Output = B::Output>,
{
    pub fn new(
        sink: T,
        batch: B,
        request_settings: TowerRequestSettings,
        batch_timeout: Duration,
        client: HttpClient,
        bytes_sent: Registered<BytesSent>,
    ) -> Self {
        Self::with_retry_logic(
            sink,
            batch,
            HttpRetryLogic,
            request_settings,
            batch_timeout,
            client,
            bytes_sent,
        )
    }
}

impl<T, B, K, RL> PartitionHttpSink<T, B, K, RL>
where
    B: Batch,
    B::Output: ByteSizeOf + Clone + Send + 'static,
    B::Input: Partition<K>,
    K: Hash + Eq + Clone + Send + 'static,
    T: HttpSink<Input = B::Input, Output = B::Output>,
    RL: RetryLogic<Response = http::Response<Bytes>, Error = HttpError> + Send + 'static,
{
    pub fn with_retry_logic(
        sink: T,
        batch: B,
        retry_logic: RL,
        request_settings: TowerRequestSettings,
        batch_timeout: Duration,
        client: HttpClient,
        bytes_sent: Registered<BytesSent>,
    ) -> Self {
        let sink = Arc::new(sink);

        let sink1 = Arc::clone(&sink);
        let request_builder = move |b| -> BoxFuture<'static, crate::Result<http::Request<Bytes>>> {
            let sink = Arc::clone(&sink1);
            Box::pin(async move { sink.build_request(b).await })
        };

        let svc = HttpBatchService::new(client, request_builder, bytes_sent);
        let inner = request_settings.partition_sink(retry_logic, svc, batch, batch_timeout);
        let encoder = sink.build_encoder();

        Self {
            sink,
            inner,
            encoder,
            slot: None,
        }
    }

    /// Enforces per partition ordering of request.
    pub fn ordered(mut self) -> Self {
        self.inner.ordered();
        self
    }
}

impl<T, B, K, RL> Sink<Event> for PartitionHttpSink<T, B, K, RL>
where
    B: Batch,
    B::Output: ByteSizeOf + Clone + Send + 'static,
    B::Input: Partition<K>,
    K: Hash + Eq + Clone + Send + 'static,
    T: HttpSink<Input = B::Input, Output = B::Output>,
    RL: RetryLogic<Response = http::Response<Bytes>> + Send + 'static,
{
    type Error = crate::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.slot.is_some() {
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    if self.slot.is_some() {
                        return Poll::Pending;
                    }
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, mut event: Event) -> Result<(), Self::Error> {
        let finalizers = event.metadata_mut().take_finalizers();
        let byte_size = event.size_of();
        let json_byte_size = event.estimated_json_encoded_size_of();

        if let Some(item) = self.encoder.encode_event(event) {
            *self.project().slot = Some(EncodedEvent {
                item,
                finalizers,
                byte_size,
                json_byte_size,
            });
        }

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        if this.slot.is_some() {
            ready!(this.inner.as_mut().poll_ready(cx))?;
            this.inner.as_mut().start_send(this.slot.take().unwrap())?;
        }

        this.inner.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        self.project().inner.poll_close(cx)
    }
}

/// @struct HttpBatchService
///
/// NOTE: This has been deprecated, please do not use directly when creating new sinks.
///       The `HttpService` currently wraps this structure. Eventually all sinks currently using the
///       HttpBatchService directly should be updated to use `HttpService`. At which time we can
///       remove this struct and inline the functionality into the `HttpService` directly.
pub struct HttpBatchService<F, B = Bytes> {
    inner: HttpClient<Body>,
    request_builder: Arc<dyn Fn(B) -> F + Send + Sync>,
    /// Counts `component_sent_bytes_total`. The sink gets it from `SinkContext::bytes_sent()` in
    /// `build()` and passes it in; the service holds it for its whole life, which keeps the series
    /// present from startup and stops it expiring while the sink is idle.
    ///
    /// Do not also call `.protocol(..)` on the driver of a sink that sends through this service when
    /// its response returns `Some` from `bytes_sent()`: the bytes would be counted twice.
    bytes_sent: Registered<BytesSent>,
}

impl<F, B> HttpBatchService<F, B> {
    pub fn new(
        inner: HttpClient,
        request_builder: impl Fn(B) -> F + Send + Sync + 'static,
        bytes_sent: Registered<BytesSent>,
    ) -> Self {
        HttpBatchService {
            inner,
            request_builder: Arc::new(Box::new(request_builder)),
            bytes_sent,
        }
    }
}

impl<F, B> Service<B> for HttpBatchService<F, B>
where
    F: Future<Output = crate::Result<hyper::Request<Bytes>>> + Send + 'static,
    B: ByteSizeOf + Send + 'static,
{
    type Response = http::Response<Bytes>;
    type Error = crate::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, body: B) -> Self::Future {
        let request_builder = Arc::clone(&self.request_builder);
        let http_client = self.inner.clone();
        let bytes_sent = self.bytes_sent.clone();

        Box::pin(async move {
            let request = request_builder(body).await.inspect_err(|error| {
                emit!(SinkRequestBuildError { error });
            })?;
            let byte_size = request.body().len();
            let request = request.map(Body::from);

            let mut decompression_service = ServiceBuilder::new()
                .layer(DecompressionLayer::new())
                .service(http_client);

            // Any errors raised in `http_client.call` results in a `GotHttpWarning` event being emitted
            // in `HttpClient::send`. This does not result in incrementing `component_errors_total` however,
            // because that is incremented by the driver when retries have been exhausted.
            let response = decompression_service.call(request).await?;

            if response.status().is_success() {
                bytes_sent.emit(ByteSize(byte_size));
            }

            let (parts, body) = response.into_parts();
            let mut body = body::aggregate(body).await?;
            Ok(hyper::Response::from_parts(
                parts,
                body.copy_to_bytes(body.remaining()),
            ))
        })
    }
}

impl<F, B> Clone for HttpBatchService<F, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            request_builder: Arc::clone(&self.request_builder),
            bytes_sent: self.bytes_sent.clone(),
        }
    }
}

impl<T: fmt::Debug> sink::Response for http::Response<T> {
    fn is_successful(&self) -> bool {
        self.status().is_success()
    }

    fn is_transient(&self) -> bool {
        self.status().is_server_error()
    }
}

#[derive(Debug, Default, Clone)]
pub struct HttpRetryLogic;

impl RetryLogic for HttpRetryLogic {
    type Error = HttpError;
    type Response = hyper::Response<Bytes>;

    fn is_retriable_error(&self, _error: &Self::Error) -> bool {
        true
    }

    fn should_retry_response(&self, response: &Self::Response) -> RetryAction {
        let status = response.status();

        match status {
            StatusCode::TOO_MANY_REQUESTS => RetryAction::Retry("too many requests".into()),
            StatusCode::REQUEST_TIMEOUT => RetryAction::Retry("request timeout".into()),
            StatusCode::NOT_IMPLEMENTED => {
                RetryAction::DontRetry("endpoint not implemented".into())
            }
            _ if status.is_server_error() => RetryAction::Retry(
                format!("{}: {}", status, String::from_utf8_lossy(response.body())).into(),
            ),
            _ if status.is_success() => RetryAction::Successful,
            _ => RetryAction::DontRetry(format!("response status: {}", status).into()),
        }
    }
}

/// A more generic version of `HttpRetryLogic` that accepts anything that can be converted
/// to a status code
#[derive(Debug)]
pub struct HttpStatusRetryLogic<F, T> {
    func: F,
    request: PhantomData<T>,
}

impl<F, T> HttpStatusRetryLogic<F, T>
where
    F: Fn(&T) -> StatusCode + Clone + Send + Sync + 'static,
    T: Send + Sync + 'static,
{
    pub const fn new(func: F) -> HttpStatusRetryLogic<F, T> {
        HttpStatusRetryLogic {
            func,
            request: PhantomData,
        }
    }
}

impl<F, T> RetryLogic for HttpStatusRetryLogic<F, T>
where
    F: Fn(&T) -> StatusCode + Clone + Send + Sync + 'static,
    T: Send + Sync + 'static,
{
    type Error = HttpError;
    type Response = T;

    fn is_retriable_error(&self, _error: &Self::Error) -> bool {
        true
    }

    fn should_retry_response(&self, response: &T) -> RetryAction {
        let status = (self.func)(response);

        match status {
            StatusCode::TOO_MANY_REQUESTS => RetryAction::Retry("too many requests".into()),
            StatusCode::REQUEST_TIMEOUT => RetryAction::Retry("request timeout".into()),
            StatusCode::NOT_IMPLEMENTED => {
                RetryAction::DontRetry("endpoint not implemented".into())
            }
            _ if status.is_server_error() => {
                RetryAction::Retry(format!("Http Status: {}", status).into())
            }
            _ if status.is_success() => RetryAction::Successful,
            _ => RetryAction::DontRetry(format!("Http status: {}", status).into()),
        }
    }
}

impl<F, T> Clone for HttpStatusRetryLogic<F, T>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            func: self.func.clone(),
            request: PhantomData,
        }
    }
}

/// Outbound HTTP request settings.
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub struct RequestConfig {
    #[serde(flatten)]
    pub tower: TowerRequestConfig,

    /// Additional HTTP headers to add to every HTTP request.
    #[serde(default)]
    #[configurable(metadata(
        docs::additional_props_description = "An HTTP request header and it's value."
    ))]
    #[configurable(metadata(docs::examples = "headers_examples()"))]
    pub headers: IndexMap<String, String>,
}

fn headers_examples() -> IndexMap<String, String> {
    IndexMap::<_, _>::from_iter([
        ("Accept".to_owned(), "text/plain".to_owned()),
        ("X-My-Custom-Header".to_owned(), "A-Value".to_owned()),
    ])
}

impl RequestConfig {
    pub fn add_old_option(&mut self, headers: Option<IndexMap<String, String>>) {
        if let Some(headers) = headers {
            warn!("Option `headers` has been deprecated. Use `request.headers` instead.");
            self.headers.extend(headers);
        }
    }
}

#[derive(Debug, Snafu)]
pub enum HeaderValidationError {
    #[snafu(display("{}: {}", source, name))]
    InvalidHeaderName {
        name: String,
        source: header::InvalidHeaderName,
    },
    #[snafu(display("{}: {}", source, value))]
    InvalidHeaderValue {
        value: String,
        source: header::InvalidHeaderValue,
    },
}

pub fn validate_headers(
    headers: &IndexMap<String, String>,
) -> crate::Result<IndexMap<HeaderName, HeaderValue>> {
    let mut validated_headers = IndexMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|_| InvalidHeaderNameSnafu { name })?;
        let value = HeaderValue::from_bytes(value.as_bytes())
            .with_context(|_| InvalidHeaderValueSnafu { value })?;

        validated_headers.insert(name, value);
    }

    Ok(validated_headers)
}

/// Request type for use in the `Service` implementation of HTTP stream sinks.
#[derive(Clone)]
pub struct HttpRequest<T: Send> {
    payload: Bytes,
    finalizers: EventFinalizers,
    request_metadata: RequestMetadata,
    additional_metadata: T,
}

impl<T: Send> HttpRequest<T> {
    /// Creates a new `HttpRequest`.
    pub const fn new(
        payload: Bytes,
        finalizers: EventFinalizers,
        request_metadata: RequestMetadata,
        additional_metadata: T,
    ) -> Self {
        Self {
            payload,
            finalizers,
            request_metadata,
            additional_metadata,
        }
    }

    pub const fn get_additional_metadata(&self) -> &T {
        &self.additional_metadata
    }

    pub fn take_payload(&mut self) -> Bytes {
        std::mem::take(&mut self.payload)
    }
}

impl<T: Send> Finalizable for HttpRequest<T> {
    fn take_finalizers(&mut self) -> EventFinalizers {
        self.finalizers.take_finalizers()
    }
}

impl<T: Send> MetaDescriptive for HttpRequest<T> {
    fn get_metadata(&self) -> &RequestMetadata {
        &self.request_metadata
    }

    fn metadata_mut(&mut self) -> &mut RequestMetadata {
        &mut self.request_metadata
    }
}

impl<T: Send> ByteSizeOf for HttpRequest<T> {
    fn allocated_bytes(&self) -> usize {
        self.payload.allocated_bytes() + self.finalizers.allocated_bytes()
    }
}

/// Response type for use in the `Service` implementation of HTTP stream sinks.
pub struct HttpResponse {
    pub http_response: Response<Bytes>,
    pub events_byte_size: GroupedCountByteSize,
    pub raw_byte_size: usize,
}

impl DriverResponse for HttpResponse {
    fn event_status(&self) -> EventStatus {
        if self.http_response.is_successful() {
            EventStatus::Delivered
        } else if self.http_response.is_transient() {
            EventStatus::Errored
        } else {
            EventStatus::Rejected
        }
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        &self.events_byte_size
    }

    fn bytes_sent(&self) -> Option<usize> {
        Some(self.raw_byte_size)
    }
}

/// Creates a `RetryLogic` for use with `HttpResponse`.
pub fn http_response_retry_logic() -> HttpStatusRetryLogic<
    impl Fn(&HttpResponse) -> StatusCode + Clone + Send + Sync + 'static,
    HttpResponse,
> {
    HttpStatusRetryLogic::new(|req: &HttpResponse| req.http_response.status())
}

/// Uses the estimated json encoded size to determine batch sizing.
#[derive(Default)]
pub struct HttpJsonBatchSizer;

impl ItemBatchSize<Event> for HttpJsonBatchSizer {
    fn size(&self, item: &Event) -> usize {
        item.estimated_json_encoded_size_of().get()
    }
}

/// HTTP request builder for HTTP stream sinks using the generic `HttpService`
pub trait HttpServiceRequestBuilder<T: Send> {
    fn build(&self, request: HttpRequest<T>) -> Result<Request<Bytes>, crate::Error>;
}

/// Generic 'Service' implementation for HTTP stream sinks.
#[derive(Clone)]
pub struct HttpService<B, T: Send> {
    batch_service:
        HttpBatchService<BoxFuture<'static, Result<Request<Bytes>, crate::Error>>, HttpRequest<T>>,
    _phantom: PhantomData<B>,
}

impl<B, T: Send + 'static> HttpService<B, T>
where
    B: HttpServiceRequestBuilder<T> + std::marker::Sync + std::marker::Send + 'static,
{
    pub fn new(
        http_client: HttpClient<Body>,
        http_request_builder: B,
        bytes_sent: Registered<BytesSent>,
    ) -> Self {
        let http_request_builder = Arc::new(http_request_builder);

        let batch_service = HttpBatchService::new(
            http_client,
            move |req: HttpRequest<T>| {
                let request_builder = Arc::clone(&http_request_builder);

                let fut: BoxFuture<'static, Result<http::Request<Bytes>, crate::Error>> =
                    Box::pin(async move { request_builder.build(req) });

                fut
            },
            bytes_sent,
        );
        Self {
            batch_service,
            _phantom: PhantomData,
        }
    }
}

impl<B, T: Send + 'static> Service<HttpRequest<T>> for HttpService<B, T>
where
    B: HttpServiceRequestBuilder<T> + std::marker::Sync + std::marker::Send + 'static,
{
    type Response = HttpResponse;
    type Error = crate::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: HttpRequest<T>) -> Self::Future {
        let mut http_service = self.batch_service.clone();

        // NOTE: By taking the metadata here, when passing the request to `call()` below,
        //       that function does not have access to the metadata anymore.
        let metadata = std::mem::take(request.metadata_mut());
        let raw_byte_size = metadata.request_encoded_size();
        let events_byte_size = metadata.into_events_estimated_json_encoded_byte_size();

        Box::pin(async move {
            let http_response = http_service.call(request).await?;

            Ok(HttpResponse {
                http_response,
                events_byte_size,
                raw_byte_size,
            })
        })
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::print_stderr)] //tests

    use futures::{future::ready, StreamExt};
    use hyper::{
        service::{make_service_fn, service_fn},
        Response, Server, Uri,
    };

    use super::*;
    use crate::{config::ProxyConfig, test_util::next_addr};

    #[test]
    fn util_http_retry_logic() {
        let logic = HttpRetryLogic;

        let response_408 = Response::builder().status(408).body(Bytes::new()).unwrap();
        let response_429 = Response::builder().status(429).body(Bytes::new()).unwrap();
        let response_500 = Response::builder().status(500).body(Bytes::new()).unwrap();
        let response_400 = Response::builder().status(400).body(Bytes::new()).unwrap();
        let response_501 = Response::builder().status(501).body(Bytes::new()).unwrap();
        assert!(logic.should_retry_response(&response_429).is_retryable());
        assert!(logic.should_retry_response(&response_500).is_retryable());
        assert!(logic.should_retry_response(&response_408).is_retryable());
        assert!(logic
            .should_retry_response(&response_400)
            .is_not_retryable());
        assert!(logic
            .should_retry_response(&response_501)
            .is_not_retryable());
    }

    #[tokio::test]
    async fn util_http_it_makes_http_requests() {
        let addr = next_addr();

        let uri = format!("http://{}:{}/", addr.ip(), addr.port())
            .parse::<Uri>()
            .unwrap();

        let request = Bytes::from("hello");
        let proxy = ProxyConfig::default();
        let app_info = crate::app_info();
        let client = HttpClient::new(None, &proxy, &app_info).unwrap();
        let mut service = HttpBatchService::new(
            client,
            move |body: Bytes| {
                Box::pin(ready(
                    http::Request::post(&uri).body(body).map_err(Into::into),
                ))
            },
            SinkContext::default().bytes_sent(),
        );

        let (tx, rx) = futures::channel::mpsc::channel(10);

        let new_service = make_service_fn(move |_| {
            let tx = tx.clone();

            let svc = service_fn(move |req| {
                let mut tx = tx.clone();

                async move {
                    let mut body = hyper::body::aggregate(req.into_body())
                        .await
                        .map_err(|error| format!("error: {}", error))?;
                    let string = String::from_utf8(body.copy_to_bytes(body.remaining()).to_vec())
                        .map_err(|_| "Wasn't UTF-8".to_string())?;
                    tx.try_send(string).map_err(|_| "Send error".to_string())?;

                    Ok::<_, crate::Error>(Response::new(Body::from("")))
                }
            });

            async move { Ok::<_, std::convert::Infallible>(svc) }
        });

        tokio::spawn(async move {
            if let Err(error) = Server::bind(&addr).serve(new_service).await {
                eprintln!("Server error: {}", error);
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        service.call(request).await.unwrap();

        let (body, _rest) = rx.into_future().await;
        assert_eq!(body.unwrap(), "hello");
    }

    /// Value of `component_sent_bytes_total` in this test's registry, and whether it has a
    /// `protocol` tag. `None` if the series does not exist.
    fn sent_bytes_total() -> Option<(f64, bool)> {
        let controller = vector_lib::metrics::Controller::get().expect("metrics are initialized");
        controller
            .capture_metrics()
            .into_iter()
            .find(|metric| metric.name() == "component_sent_bytes_total")
            .map(|metric| {
                let value = match metric.value() {
                    vector_lib::event::MetricValue::Counter { value } => *value,
                    other => panic!("unexpected metric value {other:?}"),
                };
                (value, metric.tag_value("protocol").is_some())
            })
    }

    fn test_batch_service(
        uri: Uri,
    ) -> HttpBatchService<futures::future::Ready<Result<http::Request<Bytes>, crate::Error>>> {
        let client = HttpClient::new(None, &ProxyConfig::default(), &crate::app_info()).unwrap();
        HttpBatchService::new(
            client,
            move |body: Bytes| ready(http::Request::post(&uri).body(body).map_err(Into::into)),
            SinkContext::default().bytes_sent(),
        )
    }

    /// Starts a server that answers 500 to a body starting with `fail` and 200 otherwise.
    async fn start_status_server() -> Uri {
        let addr = next_addr();
        let new_service = make_service_fn(|_| async {
            Ok::<_, std::convert::Infallible>(service_fn(|req: hyper::Request<Body>| async move {
                let body = hyper::body::to_bytes(req.into_body()).await.unwrap();
                let status = if body.starts_with(b"fail") { 500 } else { 200 };
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(status)
                        .body(Body::from(""))
                        .unwrap(),
                )
            }))
        });
        tokio::spawn(async move {
            if let Err(error) = Server::bind(&addr).serve(new_service).await {
                eprintln!("Server error: {}", error);
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        format!("http://{}:{}/", addr.ip(), addr.port())
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn sent_bytes_series_exists_before_any_request() {
        crate::test_util::components::init_test();

        let uri = "http://127.0.0.1:1/".parse::<Uri>().unwrap();
        let _service = test_batch_service(uri);

        // The series is there, at zero, as soon as the service is built.
        assert_eq!(sent_bytes_total(), Some((0.0, false)));
    }

    #[tokio::test]
    async fn sent_bytes_counts_only_successful_requests() {
        crate::test_util::components::init_test();

        let mut service = test_batch_service(start_status_server().await);

        service.call(Bytes::from("hello")).await.unwrap();
        assert_eq!(sent_bytes_total(), Some((5.0, false)));

        // A 500 response is returned to the caller but adds nothing to the counter.
        let response = service.call(Bytes::from("fail!!")).await.unwrap();
        assert_eq!(response.status(), 500);
        assert_eq!(sent_bytes_total(), Some((5.0, false)));

        service.call(Bytes::from("again")).await.unwrap();
        assert_eq!(sent_bytes_total(), Some((10.0, false)));
    }
}
