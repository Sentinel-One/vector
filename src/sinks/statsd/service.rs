use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use tower::Service;
use vector_lib::internal_event::{ByteSize, BytesSent, InternalEventHandle as _, Registered};
use vector_lib::stream::DriverResponse;
use vector_lib::{
    finalization::{EventFinalizers, EventStatus, Finalizable},
    request_metadata::{GroupedCountByteSize, MetaDescriptive, RequestMetadata},
};

/// Generalized request for sending metrics to a StatsD endpoint.
#[derive(Clone, Debug)]
pub struct StatsdRequest {
    pub payload: Vec<u8>,
    pub finalizers: EventFinalizers,
    pub metadata: RequestMetadata,
}

impl Finalizable for StatsdRequest {
    fn take_finalizers(&mut self) -> EventFinalizers {
        std::mem::take(&mut self.finalizers)
    }
}

impl MetaDescriptive for StatsdRequest {
    fn get_metadata(&self) -> &RequestMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut RequestMetadata {
        &mut self.metadata
    }
}

// Placeholder response to shuttle request metadata for StatsD requests.
//
// As StatsD sends no response back to a caller, there's no success/failure to report except for raw
// I/O errors when sending the request. Primarily, this type shuttles the metadata around the
// request -- events sent, bytes sent, etc -- that is required by `Driver`.
#[derive(Debug)]
pub struct StatsdResponse {
    metadata: RequestMetadata,
}

impl DriverResponse for StatsdResponse {
    fn event_status(&self) -> EventStatus {
        // If we generated a response, that implies our send concluded without any I/O errors, so we
        // assume things were delivered.
        EventStatus::Delivered
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        self.metadata.events_estimated_json_encoded_byte_size()
    }
}

#[derive(Clone)]
pub struct StatsdService<T> {
    transport: T,
    /// Counts `component_sent_bytes_total`; held for the life of the service.
    bytes_sent: Registered<BytesSent>,
}

impl<T> StatsdService<T> {
    /// Creates a new `StatsdService` with the given `transport` service.
    ///
    /// The `transport` service is responsible for sending the actual encoded requests to the downstream
    /// endpoint.
    pub fn from_transport(transport: T, bytes_sent: Registered<BytesSent>) -> Self {
        Self {
            transport,
            bytes_sent,
        }
    }
}

impl<T> Service<StatsdRequest> for StatsdService<T>
where
    T: Service<Vec<u8>>,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T::Future: Send + 'static,
{
    type Response = StatsdResponse;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.transport.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: StatsdRequest) -> Self::Future {
        let StatsdRequest {
            payload,
            finalizers: _,
            metadata,
        } = request;

        let byte_size = metadata.request_encoded_size();
        let bytes_sent = self.bytes_sent.clone();
        let send_future = self.transport.call(payload);

        Box::pin(async move {
            send_future
                .await
                .map(|_| {
                    bytes_sent.emit(ByteSize(byte_size));
                    StatsdResponse { metadata }
                })
                .map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use futures_util::future::ready;
    use tower::service_fn;
    use vector_lib::request_metadata::GroupedCountByteSize;

    use super::*;
    use crate::{
        config::SinkContext,
        test_util::components::{init_test, sent_bytes_total},
    };

    fn request(encoded_size: usize) -> StatsdRequest {
        StatsdRequest {
            payload: vec![0; encoded_size],
            finalizers: EventFinalizers::default(),
            metadata: RequestMetadata::new(
                1,
                encoded_size,
                encoded_size,
                encoded_size,
                GroupedCountByteSize::new_untagged(),
            ),
        }
    }

    #[tokio::test]
    async fn sent_bytes_series_exists_before_any_request() {
        init_test();

        let transport = service_fn(|_payload: Vec<u8>| ready(Ok::<(), io::Error>(())));
        let _service = StatsdService::from_transport(transport, SinkContext::default().bytes_sent());

        assert_eq!(sent_bytes_total(), Some(0.0));
    }

    #[tokio::test]
    async fn sent_bytes_counts_only_successful_sends() {
        init_test();

        let handle = SinkContext::default().bytes_sent();

        // A transport that fails adds nothing to the counter.
        let failing = service_fn(|_payload: Vec<u8>| {
            ready(Err::<(), io::Error>(io::Error::other("connection refused")))
        });
        let mut service = StatsdService::from_transport(failing, handle.clone());
        assert!(service.call(request(7)).await.is_err());
        assert_eq!(sent_bytes_total(), Some(0.0));

        // A transport that succeeds counts exactly the request's encoded size.
        let working = service_fn(|_payload: Vec<u8>| ready(Ok::<(), io::Error>(())));
        let mut service = StatsdService::from_transport(working, handle);
        service.call(request(7)).await.unwrap();
        assert_eq!(sent_bytes_total(), Some(7.0));
        service.call(request(5)).await.unwrap();
        assert_eq!(sent_bytes_total(), Some(12.0));
    }
}
