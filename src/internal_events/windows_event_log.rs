use metrics::counter;
use tracing::error;
use vector_lib::internal_event::{InternalEvent, error_stage, error_type};

#[derive(Debug)]
pub struct WindowsEventLogParseError {
    pub error: String,
    pub channel: String,
    pub event_id: Option<u32>,
}

impl InternalEvent for WindowsEventLogParseError {
    fn name(&self) -> Option<&'static str> {
        Some("WindowsEventLogParseError")
    }

    fn emit(self) {
        error!(
            message = "Failed to parse Windows Event Log event.",
            error = %self.error,
            channel = %self.channel,
            event_id = ?self.event_id,
            error_code = "parse_failed",
            error_type = error_type::PARSER_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => "parse_failed",
            "error_type" => error_type::PARSER_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}

#[derive(Debug)]
pub struct WindowsEventLogQueryError {
    pub channel: String,
    pub query: Option<String>,
    pub error: String,
}

impl InternalEvent for WindowsEventLogQueryError {
    fn name(&self) -> Option<&'static str> {
        Some("WindowsEventLogQueryError")
    }

    fn emit(self) {
        error!(
            message = "Failed to query Windows Event Log.",
            channel = %self.channel,
            query = ?self.query,
            error = %self.error,
            error_code = "query_failed",
            error_type = error_type::REQUEST_FAILED,
            stage = error_stage::RECEIVING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => "query_failed",
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::RECEIVING,
        )
        .increment(1);
    }
}

#[derive(Debug)]
pub struct WindowsEventLogBookmarkError {
    pub channel: String,
    pub error: String,
}

impl InternalEvent for WindowsEventLogBookmarkError {
    fn name(&self) -> Option<&'static str> {
        Some("WindowsEventLogBookmarkError")
    }

    fn emit(self) {
        error!(
            message = "Failed to save bookmark for Windows Event Log channel.",
            channel = %self.channel,
            error = %self.error,
            error_code = "bookmark_failed",
            error_type = error_type::REQUEST_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => "bookmark_failed",
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error() {
        let event = WindowsEventLogParseError {
            error: "Test error".to_string(),
            channel: "System".to_string(),
            event_id: Some(1000),
        };
        event.emit();
    }

    #[test]
    fn test_query_error() {
        let event = WindowsEventLogQueryError {
            channel: "System".to_string(),
            query: Some("*[System]".to_string()),
            error: "Operation timed out".to_string(),
        };
        event.emit();
    }

    #[test]
    fn test_bookmark_error() {
        let event = WindowsEventLogBookmarkError {
            channel: "System".to_string(),
            error: "Failed to save bookmark".to_string(),
        };
        event.emit();
    }
}
