use bytes::Bytes;
use http::StatusCode;
use vector_lib::request_metadata::GroupedCountByteSize;

use super::conflict::{parse_rejections, RemoteWriteRetryLogic};
use crate::sinks::util::{
    http::HttpResponse,
    retries::{RetryAction, RetryLogic},
};

// A real Thanos Receive 409 body: one entry per receiving replica.
const OUT_OF_ORDER_BODY: &str = "2 errors: forwarding request to endpoint {receiver-az1-0:10901 receiver-az1-0:19391 az1}: rpc error: code = AlreadyExists desc = add 3 samples: out of order sample; forwarding request to endpoint {receiver-az2-0:10901 receiver-az2-0:19391 az2}: rpc error: code = AlreadyExists desc = add 3 samples: out of order sample";

const DUPLICATE_BODY: &str = "2 errors: forwarding request to endpoint {receiver-az1-0:10901 receiver-az1-0:19391 az1}: rpc error: code = AlreadyExists desc = add 1 samples: duplicate sample for timestamp; forwarding request to endpoint {receiver-az2-0:10901 receiver-az2-0:19391 az2}: rpc error: code = AlreadyExists desc = add 1 samples: duplicate sample for timestamp";

const MIXED_BODY: &str = "2 errors: forwarding request to endpoint {receiver-az1-0:10901 az1}: rpc error: code = AlreadyExists desc = add 2 samples: out of order sample; forwarding request to endpoint {receiver-az2-0:10901 az2}: rpc error: code = AlreadyExists desc = add 1 samples: out of bounds";

fn response(status: StatusCode, body: &str) -> HttpResponse {
    HttpResponse {
        http_response: http::Response::builder()
            .status(status)
            .body(Bytes::from(body.to_string()))
            .unwrap(),
        events_byte_size: GroupedCountByteSize::new_untagged(),
        raw_byte_size: 0,
    }
}

#[test]
fn parses_out_of_order_rejections_once_per_request() {
    let rejections = parse_rejections(OUT_OF_ORDER_BODY);

    assert_eq!(rejections, vec![("out of order sample".to_string(), 3)]);
}

#[test]
fn parses_each_rejection_reason() {
    let rejections = parse_rejections(MIXED_BODY);

    assert_eq!(
        rejections,
        vec![
            ("out of order sample".to_string(), 2),
            ("out of bounds".to_string(), 1),
        ]
    );
}

#[test]
fn parses_nothing_from_an_unrecognised_body() {
    assert!(parse_rejections("").is_empty());
    assert!(parse_rejections("conflict").is_empty());
    assert!(parse_rejections("add x samples: out of order sample").is_empty());
}

#[test]
fn treats_out_of_order_conflict_as_delivered() {
    let action = RemoteWriteRetryLogic
        .should_retry_response(&response(StatusCode::CONFLICT, OUT_OF_ORDER_BODY));

    assert!(matches!(action, RetryAction::Successful));
}

#[test]
fn drops_duplicate_conflict() {
    let action = RemoteWriteRetryLogic
        .should_retry_response(&response(StatusCode::CONFLICT, DUPLICATE_BODY));

    assert!(matches!(action, RetryAction::DontRetry(_)));
}

#[test]
fn drops_conflict_with_any_other_reason() {
    let action =
        RemoteWriteRetryLogic.should_retry_response(&response(StatusCode::CONFLICT, MIXED_BODY));

    assert!(matches!(action, RetryAction::DontRetry(_)));
}

#[test]
fn drops_conflict_with_unrecognised_body() {
    let action =
        RemoteWriteRetryLogic.should_retry_response(&response(StatusCode::CONFLICT, "conflict"));

    assert!(matches!(action, RetryAction::DontRetry(_)));
}

#[test]
fn keeps_other_statuses_unchanged() {
    let logic = RemoteWriteRetryLogic;

    assert!(matches!(
        logic.should_retry_response(&response(StatusCode::OK, "")),
        RetryAction::Successful
    ));
    assert!(matches!(
        logic.should_retry_response(&response(StatusCode::INTERNAL_SERVER_ERROR, "")),
        RetryAction::Retry(_)
    ));
    assert!(matches!(
        logic.should_retry_response(&response(StatusCode::BAD_REQUEST, OUT_OF_ORDER_BODY)),
        RetryAction::DontRetry(_)
    ));
}
