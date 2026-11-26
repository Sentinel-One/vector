use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::TryFutureExt;
use vector_lib::internal_event::{ByteSize, BytesSent, InternalEventHandle as _, Registered};

use crate::sinks::prelude::*;

use super::{config::NatsPublisher, request_builder::NatsRequest, NatsError};

#[derive(Clone)]
pub(super) struct NatsService {
    pub(super) publisher: Arc<NatsPublisher>,
    /// Counts `component_sent_bytes_total`; held for the life of the service.
    pub(super) bytes_sent: Registered<BytesSent>,
}

pub(super) struct NatsResponse {
    metadata: RequestMetadata,
}

impl DriverResponse for NatsResponse {
    fn event_status(&self) -> EventStatus {
        EventStatus::Delivered
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        self.metadata.events_estimated_json_encoded_byte_size()
    }
}

impl Service<NatsRequest> for NatsService {
    type Response = NatsResponse;

    type Error = NatsError;

    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: NatsRequest) -> Self::Future {
        let publisher = Arc::clone(&self.publisher);
        let bytes_sent = self.bytes_sent.clone();
        let byte_size = req.metadata.request_encoded_size();

        Box::pin(async move {
            match publisher
                .publish(req.subject, req.bytes)
                .map_err(async_nats::Error::from)
                .await
            {
                Err(error) => Err(NatsError::ServerError { source: error }),
                Ok(_) => {
                    bytes_sent.emit(ByteSize(byte_size));
                    Ok(NatsResponse {
                        metadata: req.metadata,
                    })
                }
            }
        })
    }
}
