use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use futures::Stream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status, Streaming};

use super::{
    config::{
        BspConfig, CaptureAuth, CaptureConfig, CaptureLimits, CaptureSampling, InputConfig,
        ReconnectBackoff, TcpInput, TcpUpstream, UdpInput, UdpUpstream, UnixStreamInput,
        UnixStreamUpstream, UpstreamCapture,
    },
    tee::Unit,
};
use crate::{
    config::{SourceConfig, SourceContext},
    proto::beam::{
        beam_server::{Beam, BeamServer},
        control_request, control_response, session_request, session_response, ControlRequest,
        ControlResponse, HalfClose, Mode, Ready as BeamReady, Reply, SessionRequest,
        SessionResponse, Stop,
    },
    sinks::util::AuthTokenConfig,
    test_util::{next_addr, temp_dir},
    tls::{self, TlsConfig, TlsEnableableConfig, TlsSourceConfig},
    SourceSender,
};

const WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
enum OnHello {
    Ready,
    Stop,
    Hold,
}

#[derive(Clone, Copy)]
enum OnSession {
    Record,
    /// New mode: every `Data` comes back as a `Reply`; `HalfClose` is answered and ends the stream.
    Echo,
    Fail,
    /// Waits before reading anything, so the client side backs up.
    Stall(Duration),
}

#[derive(Default)]
struct Recorded {
    control: Vec<ControlRequest>,
    sessions: Vec<Arc<Mutex<Vec<SessionRequest>>>>,
    authorization: Vec<String>,
}

#[derive(Clone)]
struct FakeBeam {
    on_hello: OnHello,
    on_session: OnSession,
    recorded: Arc<Mutex<Recorded>>,
    stop: watch::Receiver<bool>,
}

impl FakeBeam {
    fn record_auth<T>(&self, request: &Request<T>) {
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        self.recorded
            .lock()
            .unwrap()
            .authorization
            .push(authorization);
    }
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

fn control_msg(msg: control_response::Msg) -> ControlResponse {
    ControlResponse { msg: Some(msg) }
}

fn session_msg(msg: session_response::Msg) -> SessionResponse {
    SessionResponse { msg: Some(msg) }
}

#[tonic::async_trait]
impl Beam for FakeBeam {
    type ControlStream = BoxStream<ControlResponse>;
    type SessionStream = BoxStream<SessionResponse>;

    async fn control(
        &self,
        request: Request<Streaming<ControlRequest>>,
    ) -> Result<Response<Self::ControlStream>, Status> {
        self.record_auth(&request);
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(8);
        let this = self.clone();
        tokio::spawn(async move {
            let mut stop = this.stop.clone();
            loop {
                tokio::select! {
                    message = inbound.message() => match message {
                        Ok(Some(message)) => {
                            let hello = matches!(message.msg, Some(control_request::Msg::Hello(_)));
                            this.recorded.lock().unwrap().control.push(message);
                            let reply = match (hello, this.on_hello) {
                                (true, OnHello::Ready) => Some(control_response::Msg::Ready(BeamReady {})),
                                (true, OnHello::Stop) => Some(control_response::Msg::Stop(Stop {
                                    reason: "not admitted".into(),
                                })),
                                (true, OnHello::Hold) | (false, _) => None,
                            };
                            if let Some(reply) = reply {
                                _ = tx.send(Ok(control_msg(reply))).await;
                            }
                        }
                        Ok(None) | Err(_) => break,
                    },
                    Ok(()) = stop.changed() => {
                        _ = tx
                            .send(Ok(control_msg(control_response::Msg::Stop(Stop {
                                reason: "run finished".into(),
                            }))))
                            .await;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn session(
        &self,
        request: Request<Streaming<SessionRequest>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        self.record_auth(&request);
        let messages = Arc::new(Mutex::new(Vec::new()));
        self.recorded
            .lock()
            .unwrap()
            .sessions
            .push(Arc::clone(&messages));
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(8);
        let on_session = self.on_session;
        match on_session {
            OnSession::Fail => Err(Status::internal("injected session failure")),
            OnSession::Record | OnSession::Echo | OnSession::Stall(_) => {
                tokio::spawn(async move {
                    if let OnSession::Stall(delay) = on_session {
                        tokio::time::sleep(delay).await;
                    }
                    while let Ok(Some(message)) = inbound.message().await {
                        let reply = match (&message.msg, on_session) {
                            (Some(session_request::Msg::Data(data)), OnSession::Echo) => {
                                Some(session_response::Msg::Reply(Reply {
                                    payload: data.payload.clone(),
                                }))
                            }
                            (Some(session_request::Msg::HalfClose(_)), OnSession::Echo) => {
                                Some(session_response::Msg::HalfClose(HalfClose {}))
                            }
                            _ => None,
                        };
                        let half_close = matches!(reply, Some(session_response::Msg::HalfClose(_)));
                        messages.lock().unwrap().push(message);
                        if let Some(reply) = reply {
                            _ = tx.send(Ok(session_msg(reply))).await;
                        }
                        if half_close {
                            break;
                        }
                    }
                });
                Ok(Response::new(
                    Box::pin(ReceiverStream::new(rx)) as Self::SessionStream
                ))
            }
        }
    }
}

struct Harness {
    endpoint: String,
    recorded: Arc<Mutex<Recorded>>,
    stop: watch::Sender<bool>,
}

impl Harness {
    async fn start(on_hello: OnHello, on_session: OnSession) -> Self {
        let (stop, stop_rx) = watch::channel(false);
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let beam = FakeBeam {
            on_hello,
            on_session,
            recorded: Arc::clone(&recorded),
            stop: stop_rx,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(BeamServer::new(beam))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        Self {
            endpoint,
            recorded,
            stop,
        }
    }

    fn capture(&self) -> CaptureConfig {
        CaptureConfig {
            endpoint: self.endpoint.clone(),
            run_id: "run-1".into(),
            auth: CaptureAuth {
                token: AuthTokenConfig::Inline {
                    value: "test-token".to_owned().into(),
                },
            },
            tls: None,
            connect_timeout: Duration::from_secs(2),
            reconnect_backoff: ReconnectBackoff {
                initial: Duration::from_millis(50),
                max: Duration::from_millis(200),
            },
            limits: CaptureLimits::default(),
        }
    }

    fn stop_run(&self) {
        self.stop.send_replace(true);
    }

    /// Polls until `check` yields a value; panics after [`WAIT`].
    async fn wait<T>(&self, check: impl Fn(&Recorded) -> Option<T>) -> T {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            if let Some(value) = check(&self.recorded.lock().unwrap()) {
                break value;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for the fake control-agent"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Waits for session `index` to end with a `HalfClose`, then returns its messages.
    async fn half_closed_session(&self, index: usize) -> Vec<SessionRequest> {
        self.wait(|recorded| {
            recorded.sessions.get(index).and_then(|session| {
                let session = session.lock().unwrap();
                session
                    .iter()
                    .any(|m| matches!(m.msg, Some(session_request::Msg::HalfClose(_))))
                    .then(|| session.clone())
            })
        })
        .await
    }
}

#[derive(Debug, Default, PartialEq)]
struct Captured {
    bytes: Vec<u8>,
    /// `(offset, len)` of each `Data`.
    chunks: Vec<(u64, usize)>,
    gaps: Vec<(u64, u64)>,
    half_closed: bool,
}

fn captured(messages: &[SessionRequest]) -> Captured {
    messages
        .iter()
        .fold(Captured::default(), |mut captured, message| {
            match &message.msg {
                Some(session_request::Msg::Data(data)) => {
                    captured.chunks.push((data.offset, data.payload.len()));
                    captured.bytes.extend_from_slice(&data.payload);
                }
                Some(session_request::Msg::Gap(gap)) => {
                    captured.gaps.push((gap.offset, gap.length))
                }
                Some(session_request::Msg::HalfClose(_)) => captured.half_closed = true,
                Some(session_request::Msg::Open(_)) | None => {}
            }
            captured
        })
}

async fn start_bsp(input: InputConfig, capture: CaptureConfig) -> JoinHandle<Result<(), ()>> {
    let config = BspConfig { input, capture };
    let (tx, _rx) = SourceSender::new_test();
    let source = config
        .build(SourceContext::new_test(tx, None))
        .await
        .unwrap();
    tokio::spawn(source)
}

/// Upstream that reads one connection to EOF, replies `ack:<len>` and hands back what it read.
async fn upstream_tcp() -> (SocketAddr, oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        stream
            .write_all(format!("ack:{}", received.len()).as_bytes())
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        _ = tx.send(received);
    });
    (addr, rx)
}

async fn connect_tcp(addr: SocketAddr) -> TcpStream {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => break stream,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "bsp never listened: {error}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

async fn exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    stream.write_all(payload).await?;
    stream.shutdown().await?;
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await?;
    Ok(reply)
}

fn tcp_input(address: SocketAddr, upstream: Option<TcpUpstream>) -> TcpInput {
    TcpInput {
        address: address.into(),
        keepalive: None,
        tls: None,
        permit_origin: None,
        receive_buffer_bytes: None,
        connection_limit: None,
        max_connection_duration: None,
        shutdown_timeout: Duration::from_secs(1),
        max_chunk_bytes: 1024 * 1024,
        upstream,
    }
}

fn tcp_upstream(address: SocketAddr) -> TcpUpstream {
    TcpUpstream {
        address,
        connect_timeout: Duration::from_secs(2),
        capture: UpstreamCapture::default(),
    }
}

fn hello_mode(recorded: &Recorded) -> Option<i32> {
    recorded
        .control
        .iter()
        .find_map(|message| match &message.msg {
            Some(control_request::Msg::Hello(hello)) => Some(hello.mode),
            _ => None,
        })
}

#[test]
fn generate_config() {
    crate::test_util::test_generate_config::<BspConfig>();
}

#[test]
fn test_config_yaml_without_upstream_parses_as_new_mode() {
    let config: BspConfig = serde_yaml::from_str(
        r#"
        input:
          mode: udp
          address: 0.0.0.0:5514
          session_idle_timeout_secs: 60
        capture:
          endpoint: https://control-agent:9443
          run_id: run-1
          auth:
            token: { type: file, path: /etc/observo/auth/site_token }
          limits:
            max_bytes: 1073741824
        "#,
    )
    .unwrap();
    assert_eq!(config.input.mode(), Mode::New);
    assert_eq!(config.capture.limits.max_bytes, 1073741824);
}

#[test]
fn test_config_yaml_with_upstream_parses_as_update_mode_with_sampling() {
    let config: BspConfig = serde_yaml::from_str(
        r#"
        input:
          mode: tcp
          address: 0.0.0.0:8088
          upstream:
            address: 127.0.0.1:65101
            capture:
              sampling: { rate: 0.5 }
        capture:
          endpoint: https://control-agent:9443
          run_id: run-1
          auth:
            token: { type: file, path: /etc/observo/auth/site_token }
        "#,
    )
    .unwrap();
    assert_eq!(config.input.mode(), Mode::Update);
    assert_eq!(
        config.input.sampling().map(|sampling| sampling.rate),
        Some(0.5)
    );
}

#[test]
fn test_config_rejects_unix_upstream_on_tcp_input() {
    let error = serde_yaml::from_str::<BspConfig>(
        r#"
        input:
          mode: tcp
          address: 0.0.0.0:8088
          upstream:
            path: /run/observo/bsp/65102.sock
        capture:
          endpoint: https://control-agent:9443
          run_id: run-1
          auth:
            token: { type: file, path: /etc/observo/auth/site_token }
        "#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("path"), "{error}");
}

#[test]
fn test_config_rejects_sampling_on_new_mode_input() {
    let error = serde_yaml::from_str::<BspConfig>(
        r#"
        input:
          mode: tcp
          address: 0.0.0.0:8088
          capture:
            sampling: { rate: 0.5 }
        capture:
          endpoint: https://control-agent:9443
          run_id: run-1
          auth:
            token: { type: file, path: /etc/observo/auth/site_token }
        "#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("capture"), "{error}");
}

#[tokio::test]
async fn test_build_rejects_tls_client_metadata_key() {
    let mut config: BspConfig = serde_yaml::from_str(
        r#"
        input:
          mode: tcp
          address: 0.0.0.0:8088
          tls:
            enabled: true
            client_metadata_key: tls_peer
        capture:
          endpoint: https://control-agent:9443
          run_id: run-1
          auth:
            token: { type: file, path: /etc/observo/auth/site_token }
        "#,
    )
    .unwrap();
    config.capture = Harness::start(OnHello::Ready, OnSession::Record)
        .await
        .capture();
    let (tx, _rx) = SourceSender::new_test();
    let error = config
        .build(SourceContext::new_test(tx, None))
        .await
        .err()
        .expect("build should fail");
    assert!(error.to_string().contains("client_metadata_key"), "{error}");
}

#[tokio::test]
async fn test_build_rejects_sampling_rate_above_one() {
    let mut upstream = tcp_upstream(next_addr());
    upstream.capture.sampling = CaptureSampling { rate: 1.5 };
    let config = BspConfig {
        input: InputConfig::Tcp(tcp_input(next_addr(), Some(upstream))),
        capture: Harness::start(OnHello::Ready, OnSession::Record)
            .await
            .capture(),
    };
    let (tx, _rx) = SourceSender::new_test();
    let error = config
        .build(SourceContext::new_test(tx, None))
        .await
        .err()
        .expect("build should fail");
    assert!(error.to_string().contains("sampling.rate"), "{error}");
}

#[test]
fn test_unit_bytes_chunks_split_at_max_chunk_with_contiguous_offsets() {
    let chunks = Unit::Bytes { max_chunk: 4 }.chunks(10, Bytes::from_static(b"abcdefghij"));
    assert_eq!(
        chunks,
        vec![
            (10, Bytes::from_static(b"abcd")),
            (14, Bytes::from_static(b"efgh")),
            (18, Bytes::from_static(b"ij")),
        ]
    );
}

#[tokio::test]
async fn test_update_tcp_proxies_to_upstream_and_captures_exact_bytes() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let (upstream, received) = upstream_tcp().await;
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(addr, Some(tcp_upstream(upstream)))),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let reply = exchange(connect_tcp(addr).await, b"hello world")
        .await
        .unwrap();

    assert_eq!(reply, b"ack:11");
    assert_eq!(received.await.unwrap(), b"hello world");
    let session = beam.half_closed_session(0).await;
    let Some(session_request::Msg::Open(open)) = &session[0].msg else {
        panic!("first session message is not Open: {:?}", session[0]);
    };
    assert_eq!(open.run_id, "run-1");
    let captured = captured(&session);
    assert_eq!(captured.bytes, b"hello world");
    assert_eq!(captured.gaps, vec![]);
    let recorded = beam.recorded.lock().unwrap();
    assert_eq!(hello_mode(&recorded), Some(Mode::Update as i32));
    assert!(recorded
        .authorization
        .iter()
        .all(|value| value == "Bearer test-token"));
}

#[tokio::test]
async fn test_update_tcp_splits_capture_at_max_chunk_bytes() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let (upstream, received) = upstream_tcp().await;
    let addr = next_addr();
    let mut input = tcp_input(addr, Some(tcp_upstream(upstream)));
    input.max_chunk_bytes = 1024;
    let _bsp = start_bsp(InputConfig::Tcp(input), beam.capture()).await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();

    exchange(connect_tcp(addr).await, &payload).await.unwrap();

    assert_eq!(received.await.unwrap(), payload);
    let captured = captured(&beam.half_closed_session(0).await);
    assert_eq!(captured.bytes, payload);
    assert!(captured.chunks.iter().all(|(_, len)| *len <= 1024));
    let contiguous = captured
        .chunks
        .windows(2)
        .all(|pair| pair[0].0 + pair[0].1 as u64 == pair[1].0);
    assert!(contiguous, "offsets not contiguous: {:?}", captured.chunks);
}

#[tokio::test]
async fn test_update_tcp_reports_gap_when_capture_stalls_and_upstream_gets_every_byte() {
    let beam = Harness::start(OnHello::Ready, OnSession::Stall(Duration::from_secs(2))).await;
    let (upstream, received) = upstream_tcp().await;
    let addr = next_addr();
    let mut upstream_config = tcp_upstream(upstream);
    upstream_config.capture.buffer_bytes = 64 * 1024;
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(addr, Some(upstream_config))),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let payload = vec![7u8; 8 * 1024 * 1024];

    exchange(connect_tcp(addr).await, &payload).await.unwrap();

    assert_eq!(received.await.unwrap().len(), payload.len());
    let captured = captured(&beam.half_closed_session(0).await);
    assert!(!captured.gaps.is_empty(), "expected a gap");
    let gap_bytes: u64 = captured.gaps.iter().map(|(_, len)| len).sum();
    assert_eq!(
        captured.bytes.len() as u64 + gap_bytes,
        payload.len() as u64
    );
}

#[tokio::test]
async fn test_update_tcp_proxies_without_capture_when_hello_is_answered_with_stop() {
    let beam = Harness::start(OnHello::Stop, OnSession::Record).await;
    let (upstream, received) = upstream_tcp().await;
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(addr, Some(tcp_upstream(upstream)))),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let reply = exchange(connect_tcp(addr).await, b"payload").await.unwrap();

    assert_eq!(reply, b"ack:7");
    assert_eq!(received.await.unwrap(), b"payload");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let recorded = beam.recorded.lock().unwrap();
    assert_eq!(recorded.sessions.len(), 0);
    assert_eq!(
        recorded.control.len(),
        1,
        "a stopped instance must not reconnect"
    );
}

#[tokio::test]
async fn test_update_tcp_keeps_proxying_when_session_rpc_fails() {
    let beam = Harness::start(OnHello::Ready, OnSession::Fail).await;
    let (upstream, received) = upstream_tcp().await;
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(addr, Some(tcp_upstream(upstream)))),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let reply = exchange(connect_tcp(addr).await, b"still delivered")
        .await
        .unwrap();

    assert_eq!(reply, b"ack:15");
    assert_eq!(received.await.unwrap(), b"still delivered");
}

#[tokio::test]
async fn test_update_tcp_resets_client_when_upstream_is_down() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(addr, Some(tcp_upstream(next_addr())))),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;

    let mut client = connect_tcp(addr).await;
    let mut buf = [0u8; 16];
    let read = client.read(&mut buf).await;

    assert!(
        matches!(&read, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "{read:?}"
    );
}

#[tokio::test]
async fn test_update_tcp_reports_budget_exhausted_status_once_max_bytes_is_spent() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let (upstream, _received) = upstream_tcp().await;
    let addr = next_addr();
    let mut capture = beam.capture();
    capture.limits.max_bytes = 10;
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(addr, Some(tcp_upstream(upstream)))),
        capture,
    )
    .await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    exchange(connect_tcp(addr).await, &[1u8; 100])
        .await
        .unwrap();

    beam.wait(|recorded| {
        recorded
            .control
            .iter()
            .any(|message| {
                matches!(
                    &message.msg,
                    Some(control_request::Msg::Status(status)) if status.budget_exhausted
                )
            })
            .then_some(())
    })
    .await;
}

#[tokio::test]
async fn test_update_tcp_terminates_tls_and_upstream_receives_plaintext() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let (upstream, received) = upstream_tcp().await;
    let addr = next_addr();
    let mut input = tcp_input(addr, Some(tcp_upstream(upstream)));
    input.tls = Some(TlsSourceConfig {
        client_metadata_key: None,
        tls_config: TlsEnableableConfig {
            enabled: Some(true),
            options: TlsConfig {
                crt_file: Some(tls::TEST_PEM_CRT_PATH.into()),
                key_file: Some(tls::TEST_PEM_KEY_PATH.into()),
                ..Default::default()
            },
        },
    });
    let _bsp = start_bsp(InputConfig::Tcp(input), beam.capture()).await;
    beam.wait(hello_mode).await;
    connect_tcp(addr).await;

    crate::test_util::send_lines_tls(
        addr,
        "localhost".into(),
        vec!["secret line".to_owned()].into_iter(),
        Path::new(tls::TEST_PEM_CA_PATH),
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!(received.await.unwrap(), b"secret line\n");
    assert_eq!(
        captured(&beam.half_closed_session(0).await).bytes,
        b"secret line\n"
    );
}

#[tokio::test]
async fn test_update_tcp_rejects_client_outside_permit_origin_without_dialing_upstream() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let (upstream, mut received) = upstream_tcp().await;
    let addr = next_addr();
    let mut input = tcp_input(addr, Some(tcp_upstream(upstream)));
    input.permit_origin = Some(serde_json::from_str(r#"["10.0.0.0/8"]"#).unwrap());
    let _bsp = start_bsp(InputConfig::Tcp(input), beam.capture()).await;
    beam.wait(hello_mode).await;

    let reply = exchange(connect_tcp(addr).await, b"nope").await;

    assert!(
        !matches!(&reply, Ok(reply) if !reply.is_empty()),
        "{reply:?}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(received.try_recv().is_err());
    assert_eq!(beam.recorded.lock().unwrap().sessions.len(), 0);
}

#[tokio::test]
async fn test_new_tcp_relays_control_agent_replies_to_client() {
    let beam = Harness::start(OnHello::Ready, OnSession::Echo).await;
    let addr = next_addr();
    let _bsp = start_bsp(InputConfig::Tcp(tcp_input(addr, None)), beam.capture()).await;

    let reply = exchange(connect_tcp(addr).await, b"ping").await.unwrap();

    assert_eq!(reply, b"ping");
    assert_eq!(captured(&beam.half_closed_session(0).await).bytes, b"ping");
    assert_eq!(
        hello_mode(&beam.recorded.lock().unwrap()),
        Some(Mode::New as i32)
    );
}

#[tokio::test]
async fn test_new_tcp_does_not_bind_until_control_agent_sends_ready() {
    let beam = Harness::start(OnHello::Hold, OnSession::Echo).await;
    let addr = next_addr();
    let _bsp = start_bsp(InputConfig::Tcp(tcp_input(addr, None)), beam.capture()).await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let connected = TcpStream::connect(addr).await;

    assert!(
        matches!(&connected, Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused),
        "{connected:?}"
    );
}

#[tokio::test]
async fn test_new_tcp_drops_listener_after_control_stop() {
    let beam = Harness::start(OnHello::Ready, OnSession::Echo).await;
    let addr = next_addr();
    let _bsp = start_bsp(InputConfig::Tcp(tcp_input(addr, None)), beam.capture()).await;
    assert_eq!(
        exchange(connect_tcp(addr).await, b"one").await.unwrap(),
        b"one"
    );

    beam.stop_run();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let connected = TcpStream::connect(addr).await;

    assert!(
        matches!(&connected, Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused),
        "{connected:?}"
    );
}

#[tokio::test]
async fn test_new_tcp_resets_client_when_session_rpc_fails() {
    let beam = Harness::start(OnHello::Ready, OnSession::Fail).await;
    let addr = next_addr();
    let _bsp = start_bsp(InputConfig::Tcp(tcp_input(addr, None)), beam.capture()).await;

    let mut client = connect_tcp(addr).await;
    client.write_all(b"data").await.unwrap();
    let mut buf = [0u8; 16];
    let read = client.read(&mut buf).await;

    assert!(
        matches!(&read, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "{read:?}"
    );
}

/// Upstream UDP socket that answers every datagram with `re:<datagram>`.
async fn upstream_udp() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let reply = [b"re:".as_slice(), &buf[..len]].concat();
            _ = socket.send_to(&reply, peer).await;
        }
    });
    addr
}

fn udp_input(address: SocketAddr, upstream: Option<UdpUpstream>) -> UdpInput {
    UdpInput {
        address: address.into(),
        max_length: 65535,
        receive_buffer_bytes: None,
        permit_origin: None,
        session_idle_timeout: Duration::from_secs(60),
        upstream,
    }
}

async fn udp_roundtrip(client: &UdpSocket, addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 2048];
    loop {
        client.send_to(payload, addr).await.unwrap();
        if let Ok(Ok(len)) =
            tokio::time::timeout(Duration::from_millis(200), client.recv(&mut buf)).await
        {
            break buf[..len].to_vec();
        }
    }
}

#[tokio::test]
async fn test_update_udp_forwards_datagrams_relays_replies_and_captures_indexes() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let upstream = upstream_udp().await;
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Udp(udp_input(
            addr,
            Some(UdpUpstream {
                address: upstream,
                capture: UpstreamCapture::default(),
            }),
        )),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let first = udp_roundtrip(&client, addr, b"a").await;
    let second = udp_roundtrip(&client, addr, b"b").await;

    assert_eq!(first, b"re:a");
    assert_eq!(second, b"re:b");
    let captured = beam
        .wait(|recorded| {
            recorded.sessions.first().and_then(|session| {
                let captured = captured(&session.lock().unwrap());
                captured.bytes.ends_with(b"b").then_some(captured)
            })
        })
        .await;
    let offsets: Vec<u64> = captured.chunks.iter().map(|(offset, _)| *offset).collect();
    assert_eq!(offsets, (0..offsets.len() as u64).collect::<Vec<_>>());
}

#[tokio::test]
async fn test_new_udp_relays_control_agent_reply_datagrams() {
    let beam = Harness::start(OnHello::Ready, OnSession::Echo).await;
    let addr = next_addr();
    let _bsp = start_bsp(InputConfig::Udp(udp_input(addr, None)), beam.capture()).await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let reply = udp_roundtrip(&client, addr, b"syslog line").await;

    assert_eq!(reply, b"syslog line");
}

fn socket_path(name: &str) -> PathBuf {
    let dir = temp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[tokio::test]
async fn test_update_unix_stream_proxies_to_upstream_and_captures_bytes() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let upstream_path = socket_path("upstream.sock");
    let upstream = UnixListener::bind(&upstream_path).unwrap();
    let (received_tx, received) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        stream.write_all(b"ok").await.unwrap();
        stream.shutdown().await.unwrap();
        _ = received_tx.send(buf);
    });
    let path = socket_path("bsp.sock");
    let _bsp = start_bsp(
        InputConfig::UnixStream(UnixStreamInput {
            path: path.clone(),
            socket_file_mode: None,
            connection_limit: None,
            shutdown_timeout: Duration::from_secs(1),
            max_chunk_bytes: 1024 * 1024,
            upstream: Some(UnixStreamUpstream {
                path: upstream_path,
                connect_timeout: Duration::from_secs(2),
                capture: UpstreamCapture::default(),
            }),
        }),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;
    let client = loop {
        match UnixStream::connect(&path).await {
            Ok(client) => break client,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    tokio::time::sleep(Duration::from_millis(100)).await;

    let reply = exchange(client, b"<13>local message").await.unwrap();

    assert_eq!(reply, b"ok");
    assert_eq!(received.await.unwrap(), b"<13>local message");
    assert_eq!(
        captured(&beam.half_closed_session(0).await).bytes,
        b"<13>local message"
    );
}
