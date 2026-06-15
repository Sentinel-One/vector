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

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    use super::*;

    // --- RejectionReport enum behaviour ---

    #[test]
    fn default_is_stats() {
        assert_eq!(RejectionReport::default(), RejectionReport::Stats);
    }

    #[test]
    fn needs_request_is_true_only_for_request_response() {
        assert!(!RejectionReport::Stats.needs_request());
        assert!(!RejectionReport::Response.needs_request());
        assert!(RejectionReport::RequestResponse.needs_request());
    }

    #[test]
    fn serde_roundtrip() {
        let cases: &[(&str, RejectionReport)] = &[
            (r#""stats""#, RejectionReport::Stats),
            (r#""normal""#, RejectionReport::Stats),    // alias
            (r#""response""#, RejectionReport::Response),
            (r#""request_response""#, RejectionReport::RequestResponse),
        ];
        for (input, expected) in cases {
            let parsed: RejectionReport = serde_json::from_str(input)
                .unwrap_or_else(|_| panic!("failed to parse {input}"));
            assert_eq!(&parsed, expected, "input={input}");
        }
        // Serialize → Deserialize round-trip
        for variant in [RejectionReport::Stats, RejectionReport::Response, RejectionReport::RequestResponse] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: RejectionReport = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    // --- emit_rejection_error via mock context ---

    struct MockContext {
        call_count: Arc<AtomicU64>,
    }

    impl RejectionContext for MockContext {
        fn log_category(&self) -> &'static str {
            "test_cat"
        }

        fn error_message(&self, status: u16, _body: &Bytes) -> String {
            format!("test error {status}")
        }

        fn record_rejection(&self, _status: u16, _body: &Bytes) {
            self.call_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn make_ctx() -> (MockContext, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        let ctx = MockContext { call_count: Arc::clone(&count) };
        (ctx, count)
    }

    #[test]
    fn record_rejection_called_once_per_invocation_for_every_mode() {
        let body = Bytes::from("error body");

        let (ctx, count) = make_ctx();
        emit_rejection_error(&ctx, 400, &body, None, RejectionReport::Stats);
        assert_eq!(count.load(Ordering::Relaxed), 1);

        let (ctx, count) = make_ctx();
        emit_rejection_error(&ctx, 400, &body, None, RejectionReport::Response);
        assert_eq!(count.load(Ordering::Relaxed), 1);

        let (ctx, count) = make_ctx();
        // RequestResponse without a request body falls back to response-only logging.
        emit_rejection_error(&ctx, 400, &body, None, RejectionReport::RequestResponse);
        assert_eq!(count.load(Ordering::Relaxed), 1);

        let (ctx, count) = make_ctx();
        let req = Bytes::from("request body");
        emit_rejection_error(&ctx, 400, &body, Some((req, Compression::None)), RejectionReport::RequestResponse);
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn request_response_mode_decompresses_uncompressed_body_without_panic() {
        let (ctx, _) = make_ctx();
        let response_body = Bytes::from("response body");
        let request_body = Bytes::from("request payload");
        // Should complete without panicking; decompressor pass-through for Compression::None.
        emit_rejection_error(
            &ctx,
            400,
            &response_body,
            Some((request_body, Compression::None)),
            RejectionReport::RequestResponse,
        );
    }

    #[test]
    fn error_code_default_impl_formats_status() {
        let (ctx, _) = make_ctx();
        assert_eq!(ctx.error_code(400), "http_response_400");
        assert_eq!(ctx.error_code(503), "http_response_503");
    }
}
