use metrics::counter;
use vector_lib::internal_event::{error_stage, error_type, InternalEvent};

/// How a `bsp` control stream to control-agent failed.
#[derive(Debug, Clone, Copy)]
pub enum BspControlFailure {
    /// The RPC could not be opened.
    Open,
    /// Control-agent ended the stream without a `Stop`.
    Ended,
    /// The stream failed with an error status.
    Failed,
    /// Control-agent rejected the token. Capture stays off until the next reload.
    Unauthenticated,
    /// The token file could not be read. Retried with backoff.
    Token,
}

impl BspControlFailure {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Ended => "ended",
            Self::Failed => "failed",
            Self::Unauthenticated => "unauthenticated",
            Self::Token => "token",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Open => "Failed to open control stream.",
            Self::Ended => "Control stream ended.",
            Self::Failed => "Control stream failed.",
            Self::Unauthenticated => "Control-agent rejected the capture token.",
            Self::Token => "Failed to read the capture token.",
        }
    }
}

#[derive(Debug)]
pub struct BspControlStreamError<'a, E> {
    pub failure: BspControlFailure,
    pub error: &'a E,
}

impl<E: std::fmt::Display> InternalEvent for BspControlStreamError<'_, E> {
    fn emit(self) {
        let reason = self.failure.as_str();
        error!(
            message = self.failure.message(),
            error = %self.error,
            error_code = "control_stream_failed",
            error_type = error_type::CONNECTION_FAILED,
            stage = error_stage::SENDING,
            %reason,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => "control_stream_failed",
            "error_type" => error_type::CONNECTION_FAILED,
            "stage" => error_stage::SENDING,
            "reason" => reason,
        )
        .increment(1);
        counter!("bsp_control_stream_failures_total", "reason" => reason).increment(1);
    }
}

#[derive(Debug)]
pub struct BspCaptureSessionError<'a> {
    pub status: &'a tonic::Status,
}

impl InternalEvent for BspCaptureSessionError<'_> {
    fn emit(self) {
        error!(
            message = "Capture session failed.",
            error = %self.status,
            error_code = "capture_session_failed",
            error_type = error_type::REQUEST_FAILED,
            stage = error_stage::SENDING,
            internal_log_rate_limit = true,
        );
        counter!(
            "component_errors_total",
            "error_code" => "capture_session_failed",
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::SENDING,
        )
        .increment(1);
        counter!("bsp_capture_sessions_failed_total").increment(1);
    }
}
