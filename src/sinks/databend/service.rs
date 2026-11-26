use std::collections::BTreeMap;
use std::io::Cursor;
use std::task::{Context, Poll};

use bytes::Bytes;
use chrono::Utc;
use databend_client::error::Error as DatabendError;
use databend_client::APIClient as DatabendAPIClient;
use futures::future::BoxFuture;
use rand::{thread_rng, Rng};
use rand_distr::Alphanumeric;
use snafu::Snafu;
use tower::Service;
use vector_lib::finalization::{EventFinalizers, EventStatus, Finalizable};
use vector_lib::request_metadata::{GroupedCountByteSize, MetaDescriptive, RequestMetadata};
use vector_lib::stream::DriverResponse;

use vector_lib::internal_event::{ByteSize, BytesSent, InternalEventHandle as _, Registered};

use crate::sinks::util::retries::RetryLogic;

#[derive(Clone)]
pub struct DatabendRetryLogic;

impl RetryLogic for DatabendRetryLogic {
    type Error = DatabendError;
    type Response = DatabendResponse;

    fn is_retriable_error(&self, error: &Self::Error) -> bool {
        match error {
            DatabendError::InvalidResponse(qe) => match qe.code {
                429 => true,
                // general server error
                500 => true,
                // storage doesn't support presign operation
                3902 => false,
                // fail to parse stage attachment
                1046 => false,
                _ => false,
            },
            DatabendError::IO(_) => true,
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct DatabendService {
    client: DatabendAPIClient,
    table: String,
    file_format_options: BTreeMap<&'static str, &'static str>,
    copy_options: BTreeMap<&'static str, &'static str>,
    /// Counts `component_sent_bytes_total`; held for the life of the service.
    bytes_sent: Registered<BytesSent>,
}

#[derive(Clone)]
pub struct DatabendRequest {
    pub data: Bytes,
    pub finalizers: EventFinalizers,
    pub metadata: RequestMetadata,
}

impl Finalizable for DatabendRequest {
    fn take_finalizers(&mut self) -> EventFinalizers {
        self.finalizers.take_finalizers()
    }
}

impl MetaDescriptive for DatabendRequest {
    fn get_metadata(&self) -> &RequestMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut RequestMetadata {
        &mut self.metadata
    }
}

#[derive(Debug, Snafu)]
pub struct DatabendResponse {
    metadata: RequestMetadata,
}

impl DriverResponse for DatabendResponse {
    fn event_status(&self) -> EventStatus {
        EventStatus::Delivered
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        self.metadata.events_estimated_json_encoded_byte_size()
    }
}

impl DatabendService {
    pub(super) fn new(
        client: DatabendAPIClient,
        table: String,
        file_format_options: BTreeMap<&'static str, &'static str>,
        copy_options: BTreeMap<&'static str, &'static str>,
        bytes_sent: Registered<BytesSent>,
    ) -> Result<Self, DatabendError> {
        if table.is_empty() {
            return Err(DatabendError::BadArgument("table is required".to_string()));
        }
        Ok(Self {
            client,
            table,
            file_format_options,
            copy_options,
            bytes_sent,
        })
    }

    async fn new_stage_location(&self) -> String {
        let now = Utc::now().timestamp();
        let database = self
            .client
            .current_database()
            .await
            .unwrap_or("default".to_string());
        let suffix = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect::<String>();
        format!("@~/vector/{}/{}/{}-{}", database, self.table, now, suffix,)
    }

    pub(crate) async fn insert_with_stage(&self, data: Bytes) -> Result<(), DatabendError> {
        let stage = self.new_stage_location().await;
        let size = data.len() as u64;
        let reader = Box::new(Cursor::new(data));
        self.client.upload_to_stage(&stage, reader, size).await?;
        let sql = format!("INSERT INTO `{}` VALUES", self.table);
        let _ = self
            .client
            .insert_with_stage(
                &sql,
                &stage,
                self.file_format_options.clone(),
                self.copy_options.clone(),
            )
            .await?;
        Ok(())
    }
}

impl Service<DatabendRequest> for DatabendService {
    type Response = DatabendResponse;
    type Error = DatabendError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: DatabendRequest) -> Self::Future {
        let service = self.clone();

        let future = async move {
            let metadata = request.get_metadata().clone();
            let byte_size = request.data.len();
            service.insert_with_stage(request.data).await?;
            service.bytes_sent.emit(ByteSize(byte_size));
            Ok(DatabendResponse { metadata })
        };
        Box::pin(future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SinkContext;

    #[tokio::test]
    async fn sent_bytes_series_exists_before_any_request() {
        crate::test_util::components::init_test();

        // Nothing listens on this port, and no request is sent.
        let client = DatabendAPIClient::new("databend://localhost:1/default?sslmode=disable", None)
            .await
            .unwrap();
        let _service = DatabendService::new(
            client,
            "table".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            SinkContext::default().bytes_sent(),
        )
        .unwrap();

        // The series is there, at zero, as soon as the service is built.
        assert_eq!(crate::test_util::components::sent_bytes_total(), Some(0.0));
    }
}
