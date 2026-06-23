use std::borrow::Cow;

use metrics::counter;
use vector_lib::internal_event::InternalEvent;
use vector_lib::internal_event::{error_stage, error_type};

/// Fixed set of JWT rejection reasons; each maps to a log/error `message` and a
/// snake_case metric `tag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwtRejection {
    /// `require_token` is set but no `authorization` header was present.
    MissingToken,
    /// The `authorization` header was not a `Bearer` scheme.
    InvalidScheme,
    /// The token header could not be decoded.
    MalformedHeader,
    /// The token header carried no `kid` (required for JWKS lookup).
    MissingKid,
    /// The token's algorithm is not served by the configured keys.
    UnsupportedAlgorithm,
    /// No JWKS key matched the token's `kid`, even after a refresh.
    UnknownKey,
    /// The token is past its `exp`.
    Expired,
    /// The token is not yet valid (`nbf` in the future).
    Immature,
    /// The signature did not verify.
    InvalidSignature,
    /// The `iss` claim did not match.
    InvalidIssuer,
    /// The `aud` claim did not match.
    InvalidAudience,
    /// The `sub` claim did not match.
    InvalidSubject,
    /// Any other decode/validation failure.
    InvalidToken,
}

impl JwtRejection {
    /// Human-readable message; the log message and the returned `AuthError` string.
    pub const fn message(self) -> &'static str {
        match self {
            Self::MissingToken => "missing authorization header",
            Self::InvalidScheme => "expected bearer scheme",
            Self::MalformedHeader => "invalid token header",
            Self::MissingKid => "missing kid header",
            Self::UnsupportedAlgorithm => "unsupported algorithm",
            Self::UnknownKey => "unknown signing key",
            Self::Expired => "token has expired",
            Self::Immature => "token is not yet valid",
            Self::InvalidSignature => "invalid token signature",
            Self::InvalidIssuer => "invalid token issuer",
            Self::InvalidAudience => "invalid token audience",
            Self::InvalidSubject => "invalid token subject",
            Self::InvalidToken => "invalid or expired token",
        }
    }

    /// Low-cardinality snake_case metric label.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::MissingToken => "missing_token",
            Self::InvalidScheme => "invalid_scheme",
            Self::MalformedHeader => "malformed_header",
            Self::MissingKid => "missing_kid",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::UnknownKey => "unknown_key",
            Self::Expired => "expired",
            Self::Immature => "immature",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidAudience => "invalid_audience",
            Self::InvalidSubject => "invalid_subject",
            Self::InvalidToken => "invalid_token",
        }
    }
}

/// A request-level JWT rejection. `emit()` logs (rate-limited) and increments
/// the generic `component_errors_total` plus `jwt_auth_errors_total`,
/// the latter tagged by `reason` and the membership claim.
#[derive(Debug)]
pub struct JwtAuthError<'a> {
    /// Rejection reason; supplies both the metric tag and the log message.
    pub reason: JwtRejection,
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
            message = self.reason.message(),
            reason = self.reason.tag(),
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
            "reason" => self.reason.tag(),
        )
        .increment(1);
        // JWT-specific metric with the full reason/claim breakdown.
        counter!(
            "jwt_auth_errors_total",
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::RECEIVING,
            "reason" => self.reason.tag(),
            "claim_field" => self.claim_field.map(Cow::into_owned).unwrap_or_default(),
            "claim_value" => self.claim_value.map(Cow::into_owned).unwrap_or_default(),
        )
        .increment(1);
    }

    fn name(&self) -> Option<&'static str> {
        Some("JwtAuthError")
    }
}

/// A request-level JWT acceptance. Increments `jwt_auth_success_total`,
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
            "jwt_auth_success_total",
            "claim_field" => self.claim_field.map(Cow::into_owned).unwrap_or_default(),
            "claim_value" => self.claim_value.map(Cow::into_owned).unwrap_or_default(),
        )
        .increment(1);
    }

    fn name(&self) -> Option<&'static str> {
        Some("JwtAuthSuccess")
    }
}
