use std::borrow::Cow;

use metrics::counter;
use vector_lib::internal_event::InternalEvent;
use vector_lib::internal_event::{error_stage, error_type};

/// A request-level JWT rejection. `emit()` logs (rate-limited) and increments
/// the generic `component_errors_total` plus `component_jwt_auth_errors_total`,
/// the latter tagged by `reason` and the membership claim.
#[derive(Debug)]
pub struct JwtAuthError<'a> {
    /// Rejection reason; metric tag, so a small fixed set of `&'static str`s.
    pub reason: &'static str,
    /// Short message, in step with the returned error string.
    pub message: &'static str,
    /// Underlying detail (error kind, `kid`, algorithm), if any.
    pub error: Option<Cow<'a, str>>,
    /// Configured membership claim name.
    pub claim_field: Option<Cow<'a, str>>,
    /// Extracted membership value, when the token parses.
    pub claim_value: Option<Cow<'a, str>>,
    /// Decoded header + claims; never the raw token.
    pub decoded_token: &'a str,
}

impl InternalEvent for JwtAuthError<'_> {
    fn emit(self) {
        warn!(
            message = self.message,
            reason = self.reason,
            error = self.error.as_deref().unwrap_or(""),
            claim_field = self.claim_field.as_deref().unwrap_or(""),
            claim_value = self.claim_value.as_deref().unwrap_or(""),
            decoded_token = self.decoded_token,
            error_type = error_type::REQUEST_FAILED,
            stage = error_stage::RECEIVING,
            internal_log_rate_limit = true,
        );
        // Generic component error metric (matches other sources for rollup),
        // tagged with the auth reason.
        counter!(
            "component_errors_total",
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::RECEIVING,
            "reason" => self.reason,
        )
        .increment(1);
        // JWT-specific metric with the full reason/claim breakdown.
        counter!(
            "component_jwt_auth_errors_total",
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::RECEIVING,
            "reason" => self.reason,
            "claim_field" => self.claim_field.map(Cow::into_owned).unwrap_or_default(),
            "claim_value" => self.claim_value.map(Cow::into_owned).unwrap_or_default(),
        )
        .increment(1);
    }

    fn name(&self) -> Option<&'static str> {
        Some("JwtAuthError")
    }
}

/// A request-level JWT acceptance. Increments `component_jwt_auth_success_total`,
/// tagged by the membership claim, for an auth success rate alongside the errors.
#[derive(Debug)]
pub struct JwtAuthSuccess<'a> {
    /// Configured membership claim name.
    pub claim_field: Option<Cow<'a, str>>,
    /// Extracted membership value (verified).
    pub claim_value: Option<Cow<'a, str>>,
}

impl InternalEvent for JwtAuthSuccess<'_> {
    fn emit(self) {
        counter!(
            "component_jwt_auth_success_total",
            "claim_field" => self.claim_field.map(Cow::into_owned).unwrap_or_default(),
            "claim_value" => self.claim_value.map(Cow::into_owned).unwrap_or_default(),
        )
        .increment(1);
    }

    fn name(&self) -> Option<&'static str> {
        Some("JwtAuthSuccess")
    }
}
