use bytes::Bytes;
use vector_lib::configurable::configurable_component;

use super::{Compression, Decompressor};

/// Controls how much detail is logged when a sink's HTTP request is rejected.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RejectionReport {
    /// Increment counters only; do not log request or response bodies.
    #[serde(alias = "normal")]
    Stats,

    /// Log the HTTP response body on rejection.
    Response,

    /// Log both the request payload and the HTTP response body (may be large;
    /// use smaller batch sizes when debugging with this mode).
    RequestResponse,
}

impl Default for RejectionReport {
    fn default() -> Self {
        Self::Stats
    }
}

impl RejectionReport {
    /// `true` only for `RequestResponse` — the caller must clone request bytes before the send.
    pub fn needs_request(&self) -> bool {
        matches!(self, Self::RequestResponse)
    }
}

/// Sink-specific behaviour plugged into `emit_rejection_error`.
///
/// Each sink implements this to provide its own counters, response parsing,
/// and log category. The generic `emit_rejection_error` handles the three
/// `RejectionReport` mode branches.
pub trait RejectionContext: Send + Sync {
    /// Short category label emitted as a structured log field
    /// (e.g. `"es_rej_rpt"`, `"hec_rej_rpt"`).
    fn log_category(&self) -> &'static str;

    /// Human-readable error code string (default: `"http_response_<N>"`).
    fn error_code(&self, status: u16) -> String {
        format!("http_response_{status}")
    }

    /// Human-readable message describing the rejection.
    fn error_message(&self, status: u16, body: &Bytes) -> String;

    /// Update sink-specific counters. Called once per rejection before logging.
    fn record_rejection(&self, status: u16, body: &Bytes);
}

/// Emit a structured error log for a rejected or errored HTTP response.
///
/// Handles all three `RejectionReport` modes. `request` must be
/// `Some((compressed_body, compression))` when `mode` is `RequestResponse`;
/// pass `None` otherwise (or when the request body is unavailable, e.g. 5xx).
pub fn emit_rejection_error<C: RejectionContext>(
    context: &C,
    status: u16,
    response_body: &Bytes,
    request: Option<(Bytes, Compression)>,
    mode: RejectionReport,
) {
    context.record_rejection(status, response_body);
    let error_code = context.error_code(status);
    let message = context.error_message(status, response_body);
    let category = context.log_category();
    let response_body_str = String::from_utf8_lossy(response_body);

    match (mode, request) {
        (RejectionReport::RequestResponse, Some((body, comp))) => {
            let decomp = Decompressor::from(comp);
            let req_data = match decomp.decompress(body) {
                Ok(data) => data,
                Err(err) => format!("- decompression failed({comp}): '{err}' -").into(),
            };
            error!(
                category = category,
                message = message,
                error_code = error_code,
                response_status = status,
                response_body = %response_body_str,
                request = %String::from_utf8_lossy(&req_data),
            );
        }
        (RejectionReport::Stats, _) => {
            error!(
                category = category,
                message = message,
                error_code = error_code,
            );
        }
        _ => {
            // Covers `Response` mode and `RequestResponse` without a body
            // (e.g. 5xx where the request payload is suppressed).
            error!(
                category = category,
                message = message,
                error_code = error_code,
                response_status = status,
                response_body = %response_body_str,
            );
        }
    }
}
