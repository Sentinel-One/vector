use std::sync::Arc;
use std::task::{Context, Poll};

use futures::{future::BoxFuture, TryFutureExt};
use http::Uri;
use hyper::client::HttpConnector;
use hyper_openssl::HttpsConnector;
use hyper_proxy::ProxyConnector;
use prost::Message;
use tonic::{body::BoxBody, IntoRequest};
use tower::Service;
use tracing::warn;
use vector_lib::internal_event::{ByteSize, BytesSent, InternalEventHandle as _, Registered};
use vector_lib::request_metadata::{GroupedCountByteSize, MetaDescriptive, RequestMetadata};
use vector_lib::stream::DriverResponse;

use super::{config::VectorSinkAuthConfig, VectorSinkError};
use crate::{
    event::{EventFinalizers, EventStatus, Finalizable},
    proto::vector as proto_vector,
    sinks::util::AuthState,
    Error,
};

#[derive(Clone)]
pub struct VectorService {
    pub client: proto_vector::Client<HyperSvc>,
    auth: Option<Arc<AuthState>>,
    /// Counts `component_sent_bytes_total`; held for the life of the service.
    bytes_sent: Registered<BytesSent>,
}

pub struct VectorResponse {
    events_byte_size: GroupedCountByteSize,
}

impl DriverResponse for VectorResponse {
    fn event_status(&self) -> EventStatus {
        EventStatus::Delivered
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        &self.events_byte_size
    }
}

#[derive(Clone, Default)]
pub struct VectorRequest {
    pub finalizers: EventFinalizers,
    pub metadata: RequestMetadata,
    pub request: proto_vector::PushEventsRequest,
}

impl Finalizable for VectorRequest {
    fn take_finalizers(&mut self) -> EventFinalizers {
        self.finalizers.take_finalizers()
    }
}

impl MetaDescriptive for VectorRequest {
    fn get_metadata(&self) -> &RequestMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut RequestMetadata {
        &mut self.metadata
    }
}

impl VectorService {
    pub fn new(
        hyper_client: hyper::Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody>,
        uri: Uri,
        compression: bool,
        auth: Option<VectorSinkAuthConfig>,
        bytes_sent: Registered<BytesSent>,
    ) -> crate::Result<Self> {
        let mut proto_client = proto_vector::Client::new(HyperSvc {
            uri,
            client: hyper_client,
        });

        if compression {
            proto_client = proto_client.send_compressed(tonic::codec::CompressionEncoding::Gzip);
        }

        let auth = auth
            .map(|cfg| {
                AuthState::from_config(cfg.token)
                    .map(|state| Arc::new(state))
                    .map_err(|e| -> Error { e.into() })
            })
            .transpose()?;

        Ok(Self {
            client: proto_client,
            auth,
            bytes_sent,
        })
    }

    /// Pre-parsed auth state, if any. Used by the healthcheck path to inject
    /// the same `authorization` header that `Service::call` injects for
    /// `push_events`.
    pub(super) fn auth(&self) -> Option<&Arc<AuthState>> {
        self.auth.as_ref()
    }
}

impl Service<VectorRequest> for VectorService {
    type Response = VectorResponse;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    // Emission of an internal event in case of errors is handled upstream by the caller.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Readiness check of the client is done through the `push_events()`
        // call happening inside `call()`. That check blocks until the client is
        // ready to perform another request.
        //
        // See: <https://docs.rs/tonic/0.4.2/tonic/client/struct.Grpc.html#method.ready>
        Poll::Ready(Ok(()))
    }

    // Emission of internal events for errors and dropped events is handled upstream by the caller.
    fn call(&mut self, mut list: VectorRequest) -> Self::Future {
        let mut service = self.clone();
        let bytes_sent = self.bytes_sent.clone();
        let byte_size = list.request.encoded_len();
        let metadata = std::mem::take(list.metadata_mut());
        let events_byte_size = metadata.into_events_estimated_json_encoded_byte_size();

        let future = async move {
            let mut request = list.request.into_request();

            // Inject auth token on every call so a rotated token is always used.
            if let Some(auth) = &service.auth {
                let bearer = auth.bearer_token().map_err(|message| {
                    VectorSinkError::AuthTokenUnavailable { message }
                })?;
                request.metadata_mut().insert("authorization", bearer);
            }

            service
                .client
                .push_events(request)
                .map_ok(|_response| {
                    bytes_sent.emit(ByteSize(byte_size));

                    VectorResponse { events_byte_size }
                })
                .map_err(|source: tonic::Status| {
                    if source.code() == tonic::Code::PermissionDenied {
                        warn!(
                            message = "Vector source dropped events due to auth failures.",
                            details = %source.message(),
                            internal_log_rate_limit = true
                        );
                    }
                    Into::<crate::Error>::into(VectorSinkError::Request { source })
                })
                .await
        };

        Box::pin(future)
    }
}

#[derive(Clone, Debug)]
pub struct HyperSvc {
    uri: Uri,
    client: hyper::Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody>,
}

impl Service<hyper::Request<BoxBody>> for HyperSvc {
    type Response = hyper::Response<hyper::Body>;
    type Error = hyper::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    // Emission of an internal event in case of errors is handled upstream by the caller.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    // Emission of internal events for errors and dropped events is handled upstream by the caller.
    fn call(&mut self, mut req: hyper::Request<BoxBody>) -> Self::Future {
        let uri = Uri::builder()
            .scheme(self.uri.scheme().unwrap().clone())
            .authority(self.uri.authority().unwrap().clone())
            .path_and_query(req.uri().path_and_query().unwrap().clone())
            .build()
            .unwrap();

        *req.uri_mut() = uri;

        Box::pin(self.client.request(req))
    }
}
