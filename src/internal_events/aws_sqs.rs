use metrics::counter;
#[cfg(feature = "sources-aws_s3")]
pub use s3::*;
use vector_lib::internal_event::InternalEvent;
#[cfg(any(feature = "sources-aws_s3", feature = "sources-aws_sqs"))]
use vector_lib::internal_event::{error_stage, error_type};

#[cfg(feature = "sources-aws_s3")]
mod s3 {
    use aws_sdk_sqs::types::{
        BatchResultErrorEntry, DeleteMessageBatchRequestEntry, DeleteMessageBatchResultEntry,
    };

    use super::*;
    use crate::sources::aws_s3::sqs::ProcessingError;

    #[derive(Debug)]
    pub struct SqsMessageProcessingError<'a> {
        pub message_id: &'a str,
        pub error: &'a ProcessingError,
    }

    impl InternalEvent for SqsMessageProcessingError<'_> {
        fn emit(self) {
            error!(
                message = "Failed to process SQS message.",
                message_id = %self.message_id,
                error = %self.error,
                error_code = "failed_processing_sqs_message",
                error_type = error_type::PARSER_FAILED,
                stage = error_stage::PROCESSING,
                internal_log_rate_limit = true,
            );
            counter!(
                "component_errors_total",
                "error_code" => "failed_processing_sqs_message",
                "error_type" => error_type::PARSER_FAILED,
                "stage" => error_stage::PROCESSING,
            )
            .increment(1);
        }
    }

    /// A non-resumable decoding error stopped an object part-way; nothing after it was ingested,
    /// yet the object still counts as processed, so it is not retried.
    #[derive(Debug)]
    pub struct SqsS3ObjectDecodingAborted<'a> {
        pub bucket: &'a str,
        pub key: &'a str,
        pub region: &'a str,
        pub content_length: Option<i64>,
        pub content_type: Option<&'a str>,
        pub content_encoding: Option<&'a str>,
        pub last_modified: Option<chrono::DateTime<chrono::Utc>>,
        pub bytes_read: u64,
        pub error: &'a str,
    }

    impl InternalEvent for SqsS3ObjectDecodingAborted<'_> {
        fn emit(self) {
            error!(
                message = "Stopped decoding S3 object at a non-resumable error; the rest of the object was not ingested.",
                bucket = %self.bucket,
                key = %self.key,
                region = %self.region,
                content_length = ?self.content_length,
                content_type = ?self.content_type,
                content_encoding = ?self.content_encoding,
                last_modified = ?self.last_modified,
                bytes_read = self.bytes_read,
                error = %self.error,
                error_code = "object_decoding_aborted",
                error_type = error_type::PARSER_FAILED,
                stage = error_stage::PROCESSING,
            );
            counter!(
                "component_errors_total",
                "error_code" => "object_decoding_aborted",
                "error_type" => error_type::PARSER_FAILED,
                "stage" => error_stage::PROCESSING,
            )
            .increment(1);
        }
    }

    #[derive(Debug)]
    pub struct SqsMessageDeleteSucceeded {
        pub message_ids: Vec<DeleteMessageBatchResultEntry>,
    }

    impl InternalEvent for SqsMessageDeleteSucceeded {
        fn emit(self) {
            trace!(message = "Deleted SQS message(s).",
            message_ids = %self.message_ids.iter()
                .map(|x| x.id.as_str())
                .collect::<Vec<_>>()
                .join(", "));
            counter!("sqs_message_delete_succeeded_total").increment(self.message_ids.len() as u64);
        }
    }

    #[derive(Debug)]
    pub struct SqsMessageDeletePartialError {
        pub entries: Vec<BatchResultErrorEntry>,
    }

    impl InternalEvent for SqsMessageDeletePartialError {
        fn emit(self) {
            error!(
                message = "Deletion of SQS message(s) failed.",
                message_ids = %self.entries.iter()
                    .map(|x| format!("{}/{}", x.id, x.code))
                    .collect::<Vec<_>>()
                    .join(", "),
                error_code = "failed_deleting_some_sqs_messages",
                error_type = error_type::ACKNOWLEDGMENT_FAILED,
                stage = error_stage::PROCESSING,
                internal_log_rate_limit = true,
            );
            counter!(
                "component_errors_total",
                "error_code" => "failed_deleting_some_sqs_messages",
                "error_type" => error_type::ACKNOWLEDGMENT_FAILED,
                "stage" => error_stage::PROCESSING,
            )
            .increment(1);
        }
    }

    #[derive(Debug)]
    pub struct SqsMessageDeleteBatchError<E> {
        pub entries: Vec<DeleteMessageBatchRequestEntry>,
        pub error: E,
    }

    impl<E: std::fmt::Display> InternalEvent for SqsMessageDeleteBatchError<E> {
        fn emit(self) {
            error!(
                message = "Deletion of SQS message(s) failed.",
                message_ids = %self.entries.iter()
                    .map(|x| x.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                error = %self.error,
                error_code = "failed_deleting_all_sqs_messages",
                error_type = error_type::ACKNOWLEDGMENT_FAILED,
                stage = error_stage::PROCESSING,
                internal_log_rate_limit = true,
            );
            counter!(
                "component_errors_total",
                "error_code" => "failed_deleting_all_sqs_messages",
                "error_type" => error_type::ACKNOWLEDGMENT_FAILED,
                "stage" => error_stage::PROCESSING,
            )
            .increment(1);
        }
    }
}

#[derive(Debug)]
pub struct SqsMessageReceiveError<'a, E> {
    pub error: &'a E,
    pub aws_error_code: Option<&'a str>,
    pub aws_error_message: Option<&'a str>,
}

impl<E: std::fmt::Display> InternalEvent for SqsMessageReceiveError<'_, E> {
    fn emit(self) {
        let message = self.aws_error_message
            .map(|msg| format!("Failed to fetch SQS events: {}", msg))
            .unwrap_or_else(|| "Failed to fetch SQS events.".to_string());

        error!(
            message = %message,
            error = %self.error,
            aws_error_code = self.aws_error_code,
            error_code = "failed_fetching_sqs_events",
            error_type = error_type::REQUEST_FAILED,
            stage = error_stage::RECEIVING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => "failed_fetching_sqs_events",
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::RECEIVING,
        )
        .increment(1);
    }
}

#[derive(Debug)]
pub struct SqsMessageReceiveSucceeded {
    pub count: usize,
}

impl InternalEvent for SqsMessageReceiveSucceeded {
    fn emit(self) {
        trace!(message = "Received SQS messages.", count = %self.count);
        counter!("sqs_message_receive_succeeded_total").increment(1);
        counter!("sqs_message_received_messages_total").increment(self.count as u64);
    }
}

#[derive(Debug)]
pub struct SqsMessageProcessingSucceeded<'a> {
    pub message_id: &'a str,
}

impl InternalEvent for SqsMessageProcessingSucceeded<'_> {
    fn emit(self) {
        trace!(message = "Processed SQS message successfully.", message_id = %self.message_id);
        counter!("sqs_message_processing_succeeded_total").increment(1);
    }
}

// AWS SQS source

#[cfg(feature = "sources-aws_sqs")]
#[derive(Debug)]
pub struct SqsMessageDeleteError<'a, E> {
    pub error: &'a E,
}

#[cfg(feature = "sources-aws_sqs")]
impl<E: std::fmt::Display> InternalEvent for SqsMessageDeleteError<'_, E> {
    fn emit(self) {
        error!(
            message = "Failed to delete SQS events.",
            error = %self.error,
            error_type = error_type::WRITER_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_type" => error_type::WRITER_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}

// AWS s3 source

#[derive(Debug)]
pub struct SqsS3EventRecordInvalidEventIgnored<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub kind: &'a str,
    pub name: &'a str,
}

impl InternalEvent for SqsS3EventRecordInvalidEventIgnored<'_> {
    fn emit(self) {
        warn!(message = "Ignored S3 record in SQS message for an event that was not ObjectCreated.",
            bucket = %self.bucket, key = %self.key, kind = %self.kind, name = %self.name);
        counter!("sqs_s3_event_record_ignored_total", "ignore_type" => "invalid_event_kind")
            .increment(1);
    }
}
