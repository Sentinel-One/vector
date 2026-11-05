//! Classification of HTTP 409 responses from Thanos Receive.
//!
//! Thanos Receive stores the valid samples of a request and answers 409 for the whole request
//! when some of its samples conflict. The body names each rejection once per receiving replica,
//! for example `... desc = add 3 samples: out of order sample; ...`.

use http::StatusCode;

use crate::{
    http::HttpError,
    internal_events::{
        PrometheusRemoteWriteRejectedSamples, PrometheusRemoteWriteUnclassifiedConflict,
    },
    sinks::util::{
        http::{http_response_retry_logic, HttpResponse},
        retries::{RetryAction, RetryLogic},
    },
};

/// The rejection reason Thanos Receive gives for a sample older than the newest stored one.
pub(super) const OUT_OF_ORDER: &str = "out of order sample";

/// Retry logic for remote write.
///
/// A 409 whose every rejection is `out of order sample` counts as delivered: the receiver stored
/// the other samples, and resending cannot store the rejected ones. Any other 409, including one
/// with an unrecognised body, is handled like the shared HTTP retry logic handles it: not retried
/// and counted as dropped.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct RemoteWriteRetryLogic;

impl RetryLogic for RemoteWriteRetryLogic {
    type Error = HttpError;
    type Response = HttpResponse;

    fn is_retriable_error(&self, error: &Self::Error) -> bool {
        http_response_retry_logic().is_retriable_error(error)
    }

    fn should_retry_response(&self, response: &Self::Response) -> RetryAction {
        if response.http_response.status() != StatusCode::CONFLICT {
            return http_response_retry_logic().should_retry_response(response);
        }

        let body = String::from_utf8_lossy(response.http_response.body());
        let rejections = parse_rejections(&body);
        for (reason, count) in &rejections {
            emit!(PrometheusRemoteWriteRejectedSamples {
                reason,
                count: *count,
            });
        }

        if !rejections.is_empty() && rejections.iter().all(|(reason, _)| reason == OUT_OF_ORDER) {
            RetryAction::Successful
        } else {
            emit!(PrometheusRemoteWriteUnclassifiedConflict {
                body: logged_body(&body),
            });
            http_response_retry_logic().should_retry_response(response)
        }
    }
}

/// Longest part of a 409 body that is logged, in bytes.
pub(super) const LOGGED_BODY_LIMIT: usize = 2048;

/// The start of `body`, at most `LOGGED_BODY_LIMIT` bytes, cut on a character boundary.
pub(super) fn logged_body(body: &str) -> &str {
    if body.len() <= LOGGED_BODY_LIMIT {
        return body;
    }
    let mut end = LOGGED_BODY_LIMIT;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}

/// Parses the `add <count> samples: <reason>` entries of a Thanos Receive 409 body.
///
/// Returns each reason once, with the largest count reported for it. Every replica reports the
/// same rejections, so the largest count is the request's count when all its series went to one
/// set of replicas, and a lower bound otherwise.
pub(super) fn parse_rejections(body: &str) -> Vec<(String, u64)> {
    let mut rejections: Vec<(String, u64)> = Vec::new();
    for entry in body.split("add ").skip(1) {
        let Some((count, rest)) = entry.split_once(" samples: ") else {
            continue;
        };
        let Ok(count) = count.trim().parse::<u64>() else {
            continue;
        };
        let reason = rest.split(';').next().unwrap_or_default().trim();
        if reason.is_empty() {
            continue;
        }
        match rejections.iter_mut().find(|(known, _)| known == reason) {
            Some((_, largest)) => *largest = (*largest).max(count),
            None => rejections.push((reason.to_string(), count)),
        }
    }
    rejections
}
