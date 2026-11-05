use snafu::Snafu;

use vector_lib::configurable::configurable_component;

mod config;
mod service;
mod sink;

pub use config::VectorConfig;

/// Marker type for the version two of the configuration for the `vector` sink.
#[configurable_component]
#[derive(Clone, Debug)]
enum VectorConfigVersion {
    /// Marker value for version two.
    #[serde(rename = "2")]
    V2,
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum VectorSinkError {
    #[snafu(display("Request failed: {}", source))]
    Request { source: tonic::Status },

    #[snafu(display("Vector source unhealthy: {:?}", status))]
    Health { status: Option<&'static str> },

    #[snafu(display("URL has no host."))]
    NoHost,

    #[snafu(display("Auth token unavailable: {}", message))]
    AuthTokenUnavailable { message: String },
}

#[cfg(test)]
mod test {
    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<super::VectorConfig>();
    }
}

#[cfg(test)]
mod retry_logic_tests {
    use super::config::VectorGrpcRetryLogic;
    use super::VectorSinkError;
    use crate::sinks::util::retries::RetryLogic;

    fn logic() -> VectorGrpcRetryLogic {
        VectorGrpcRetryLogic
    }

    #[test]
    fn permission_denied_is_not_retriable() {
        // Source returns PermissionDenied when events fail auth → must not retry.
        let err = VectorSinkError::Request {
            source: tonic::Status::permission_denied(
                "partial auth failure: accepted=0 unauthenticated=5 forbidden=0",
            ),
        };
        assert!(!logic().is_retriable_error(&err));
    }

    #[test]
    fn auth_token_unavailable_is_not_retriable() {
        // Missing token file is a config error; retrying will never help.
        let err = VectorSinkError::AuthTokenUnavailable {
            message: "No such file or directory".into(),
        };
        assert!(!logic().is_retriable_error(&err));
    }

    #[test]
    fn unauthenticated_is_not_retriable() {
        let err = VectorSinkError::Request {
            source: tonic::Status::unauthenticated("invalid token"),
        };
        assert!(!logic().is_retriable_error(&err));
    }

    #[test]
    fn unavailable_is_retriable() {
        // Transient network failure → should retry.
        let err = VectorSinkError::Request {
            source: tonic::Status::unavailable("connection reset"),
        };
        assert!(logic().is_retriable_error(&err));
    }

    #[test]
    fn internal_error_is_retriable() {
        let err = VectorSinkError::Request {
            source: tonic::Status::internal("internal server error"),
        };
        assert!(logic().is_retriable_error(&err));
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, Bytes, BytesMut};
    use futures::{channel::mpsc, StreamExt};
    use http::request::Parts;
    use hyper::Method;
    use prost::Message;
    use vector_lib::{
        config::{init_telemetry, Tags, Telemetry},
        event::{BatchNotifier, BatchStatus},
    };

    use super::config::with_default_scheme;
    use super::*;
    use crate::{
        config::{SinkConfig as _, SinkContext},
        event::Event,
        proto::vector as proto,
        sinks::util::test::build_test_server_generic,
        test_util::{
            components::{
                run_and_assert_data_volume_sink_compliance, run_and_assert_sink_compliance,
                DATA_VOLUME_SINK_TAGS, HTTP_SINK_TAGS,
            },
            next_addr, random_lines_with_stream,
        },
    };

    // one byte for the compression flag plus four bytes for the length
    const GRPC_HEADER_SIZE: usize = 5;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<VectorConfig>();
    }

    enum TestType {
        Normal,
        DataVolume,
    }

    async fn run_sink_test(test_type: TestType) {
        let num_lines = 10;

        let in_addr = next_addr();

        let config = format!(r#"address = "http://{}/""#, in_addr);
        let config: VectorConfig = toml::from_str(&config).unwrap();

        let cx = SinkContext::default();

        let (sink, _) = config.build(cx).await.unwrap();
        let (rx, trigger, server) = build_test_server_generic(in_addr, move || {
            hyper::Response::builder()
                .header("grpc-status", "0") // OK
                .header("content-type", "application/grpc")
                .body(hyper::Body::from(encode_body(proto::PushEventsResponse {})))
                .unwrap()
        });

        tokio::spawn(server);

        let (batch, mut receiver) = BatchNotifier::new_with_receiver();
        let (input_lines, events) = random_lines_with_stream(8, num_lines, Some(batch));

        match test_type {
            TestType::Normal => run_and_assert_sink_compliance(sink, events, &HTTP_SINK_TAGS).await,

            TestType::DataVolume => {
                run_and_assert_data_volume_sink_compliance(sink, events, &DATA_VOLUME_SINK_TAGS)
                    .await
            }
        }

        drop(trigger);

        assert_eq!(receiver.try_recv(), Ok(BatchStatus::Delivered));

        let output_lines = get_received(rx, |parts| {
            assert_eq!(Method::POST, parts.method);
            assert_eq!("/vector.Vector/PushEvents", parts.uri.path());
            assert_eq!(
                "application/grpc",
                parts.headers.get("content-type").unwrap().to_str().unwrap()
            );
        })
        .await;

        assert_eq!(num_lines, output_lines.len());
        assert_eq!(input_lines, output_lines);
    }

    #[tokio::test]
    async fn deliver_message() {
        run_sink_test(TestType::Normal).await;
    }

    #[tokio::test]
    async fn data_volume_tags() {
        init_telemetry(
            Telemetry {
                tags: Tags {
                    emit_service: true,
                    emit_source: true,
                },
            },
            true,
        );

        run_sink_test(TestType::DataVolume).await;
    }

    #[tokio::test]
    async fn acknowledges_error() {
        let num_lines = 10;

        let in_addr = next_addr();

        let config = format!(r#"address = "http://{}/""#, in_addr);
        let config: VectorConfig = toml::from_str(&config).unwrap();

        let cx = SinkContext::default();

        let (sink, _) = config.build(cx).await.unwrap();
        let (_rx, trigger, server) = build_test_server_generic(in_addr, move || {
            hyper::Response::builder()
                .header("grpc-status", "7") // permission denied
                .header("content-type", "application/grpc")
                .body(tonic::body::empty_body())
                .unwrap()
        });

        tokio::spawn(server);

        let (batch, mut receiver) = BatchNotifier::new_with_receiver();
        let (_, events) = random_lines_with_stream(8, num_lines, Some(batch));

        sink.run(events).await.expect("Running sink failed");

        drop(trigger);
        assert_eq!(receiver.try_recv(), Ok(BatchStatus::Rejected));
    }

    #[test]
    fn test_with_default_scheme() {
        assert_eq!(
            with_default_scheme("0.0.0.0", false).unwrap().to_string(),
            "http://0.0.0.0/"
        );
        assert_eq!(
            with_default_scheme("0.0.0.0", true).unwrap().to_string(),
            "https://0.0.0.0/"
        );
    }

    async fn get_received(
        rx: mpsc::Receiver<(Parts, Bytes)>,
        assert_parts: impl Fn(Parts),
    ) -> Vec<String> {
        rx.map(|(parts, body)| {
            assert_parts(parts);

            let proto_body = body.slice(GRPC_HEADER_SIZE..);

            let req = proto::PushEventsRequest::decode(proto_body).unwrap();

            let mut events = Vec::with_capacity(req.events.len());
            for event in req.events {
                let event: Event = event.into();
                let string = event
                    .as_log()
                    .get("message")
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                events.push(string)
            }

            events
        })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .map(Into::into)
        .collect()
    }

    // -- JWT auth integration tests --

    fn make_ok_responder(
    ) -> impl Fn() -> hyper::Response<hyper::Body> + Clone + Send + Sync + 'static {
        move || {
            hyper::Response::builder()
                .header("grpc-status", "0")
                .header("content-type", "application/grpc")
                .body(hyper::Body::from(encode_body(proto::PushEventsResponse {})))
                .unwrap()
        }
    }

    async fn run_auth_sink(
        config: VectorConfig,
        in_addr: std::net::SocketAddr,
    ) -> http::request::Parts {
        let cx = SinkContext::default();
        let (sink, _) = config.build(cx).await.expect("sink should build");

        let (rx, trigger, server) = build_test_server_generic(in_addr, make_ok_responder());
        tokio::spawn(server);

        let (_, events) = random_lines_with_stream(8, 1, None);
        sink.run(events).await.expect("sink run failed");
        drop(trigger);

        let mut parts_list: Vec<_> = rx.collect().await;
        assert_eq!(parts_list.len(), 1, "expected exactly one request");
        parts_list.remove(0).0
    }

    #[tokio::test]
    async fn auth_inline_sends_authorization_header() {
        let in_addr = next_addr();
        let config: VectorConfig = toml::from_str(&format!(
            r#"
            address = "http://{}/"
            [auth]
            [auth.token]
            type  = "inline"
            value = "my-auth-token"
            "#,
            in_addr
        ))
        .unwrap();

        let parts = run_auth_sink(config, in_addr).await;

        assert_eq!(
            parts
                .headers
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer my-auth-token"
        );
        assert!(
            parts.headers.get("x-site-id").is_none(),
            "x-site-id header must not be sent"
        );
    }

    #[tokio::test]
    async fn sends_configured_headers() {
        let in_addr = next_addr();
        let config: VectorConfig = toml::from_str(&format!(
            r#"
            address = "http://{}/"
            [headers]
            x-observo-host = "data-plane-14477-dev-95d856588-4f4x5"
            "#,
            in_addr
        ))
        .unwrap();

        let parts = run_auth_sink(config, in_addr).await;

        assert_eq!(
            parts
                .headers
                .get("x-observo-host")
                .unwrap()
                .to_str()
                .unwrap(),
            "data-plane-14477-dev-95d856588-4f4x5"
        );
    }

    #[tokio::test]
    async fn rejects_invalid_header_name() {
        let config: VectorConfig = toml::from_str(
            r#"
            address = "http://localhost:6000/"
            [headers]
            "not a header" = "x"
            "#,
        )
        .unwrap();

        assert!(config.build(SinkContext::default()).await.is_err());
    }

    #[tokio::test]
    async fn auth_file_sends_authorization_header() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, b"file-token").unwrap();

        let in_addr = next_addr();
        let config: VectorConfig = toml::from_str(&format!(
            r#"
            address = "http://{}/"
            [auth]
            [auth.token]
            type = "file"
            path = "{}"
            "#,
            in_addr,
            f.path().display()
        ))
        .unwrap();

        let parts = run_auth_sink(config, in_addr).await;

        assert_eq!(
            parts
                .headers
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer file-token"
        );
    }

    #[tokio::test]
    async fn no_auth_sends_no_auth_headers() {
        let in_addr = next_addr();
        let config: VectorConfig =
            toml::from_str(&format!(r#"address = "http://{}/""#, in_addr)).unwrap();

        let parts = run_auth_sink(config, in_addr).await;

        assert!(
            parts.headers.get("authorization").is_none(),
            "no authorization header expected"
        );
        assert!(
            parts.headers.get("x-site-id").is_none(),
            "no x-site-id header expected"
        );
    }

    #[tokio::test]
    async fn auth_file_missing_token_file_fails_batch() {
        let in_addr = next_addr();
        let config: VectorConfig = toml::from_str(&format!(
            r#"
            address = "http://{}/"
            [auth]
            [auth.token]
            type = "file"
            path = "/nonexistent/path/to/token"
            "#,
            in_addr
        ))
        .unwrap();

        let cx = SinkContext::default();
        let (sink, _) = config.build(cx).await.unwrap();

        let (_rx, _trigger, server) = build_test_server_generic(in_addr, make_ok_responder());
        tokio::spawn(server);

        let (batch, mut receiver) = BatchNotifier::new_with_receiver();
        let (_, events) = random_lines_with_stream(8, 1, Some(batch));

        sink.run(events).await.expect("run itself should not error");
        assert_eq!(
            receiver.try_recv(),
            Ok(BatchStatus::Rejected),
            "batch should be rejected when token file is missing"
        );
    }

    #[tokio::test]
    async fn build_rejects_invalid_inline_token() {
        let in_addr = next_addr();

        let mut config: VectorConfig = toml::from_str(&format!(
            r#"
            address = "http://{}/"
            [auth]
            [auth.token]
            type  = "inline"
            value = "token"
            "#,
            in_addr
        ))
        .unwrap();

        use crate::sinks::util::AuthTokenConfig;
        config.auth.as_mut().unwrap().token = AuthTokenConfig::Inline {
            value: "bad\0token".to_string().into(),
        };

        let cx = SinkContext::default();
        assert!(
            config.build(cx).await.is_err(),
            "build should fail for inline token with invalid characters"
        );
    }

    // taken from <https://github.com/hyperium/tonic/blob/5aa8ae1fec27377cd4c2a41d309945d7e38087d0/examples/src/grpc-web/client.rs#L45-L75>
    fn encode_body<T>(msg: T) -> Bytes
    where
        T: prost::Message,
    {
        let mut buf = BytesMut::with_capacity(1024);

        // first skip past the header
        // cannot write it yet since we don't know the size of the
        // encoded message
        buf.reserve(GRPC_HEADER_SIZE);
        unsafe {
            buf.advance_mut(GRPC_HEADER_SIZE);
        }

        // write the message
        msg.encode(&mut buf).unwrap();

        // now we know the size of encoded message and can write the
        // header
        let len = buf.len() - GRPC_HEADER_SIZE;
        {
            let mut buf = &mut buf[..GRPC_HEADER_SIZE];

            // compression flag, 0 means "no compression"
            buf.put_u8(0);

            buf.put_u32(len as u32);
        }

        buf.split_to(len + GRPC_HEADER_SIZE).freeze()
    }
}
