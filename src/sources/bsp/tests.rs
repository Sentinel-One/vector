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
use vector_lib::event::MetricValue;

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
    /// Ends the control stream right after `Hello`, without `Ready` or `Stop`.
    End,
    /// Rejects the control RPC as `UNAUTHENTICATED`.
    Reject,
}

#[derive(Clone, Copy)]
enum OnSession {
    Record,
    /// New mode: every `Data` comes back as a `Reply`; `HalfClose` is answered and ends the stream.
    Echo,
    Fail,
    /// Waits before reading anything, so the client side backs up.
    Stall(Duration),
    /// Like `Record`, but keeps the response stream open this long after the requests end.
    Linger(Duration),
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

    /// Answers `Hello` according to `on_hello`, and sends `Stop` once `stop` flips.
    fn serve_control(
        &self,
        mut inbound: Streaming<ControlRequest>,
    ) -> Response<BoxStream<ControlResponse>> {
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
                                (true, OnHello::Hold | OnHello::End | OnHello::Reject) | (false, _) => None,
                            };
                            if let Some(reply) = reply {
                                _ = tx.send(Ok(control_msg(reply))).await;
                            }
                            if hello && matches!(this.on_hello, OnHello::End) {
                                break;
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
        Response::new(Box::pin(ReceiverStream::new(rx)))
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
        match self.on_hello {
            OnHello::Reject => Err(Status::unauthenticated("bad token")),
            OnHello::Ready | OnHello::Stop | OnHello::Hold | OnHello::End => {
                Ok(self.serve_control(request.into_inner()))
            }
        }
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
            OnSession::Record | OnSession::Echo | OnSession::Stall(_) | OnSession::Linger(_) => {
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
                    if let OnSession::Linger(linger) = on_session {
                        tokio::time::sleep(linger).await;
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
        handshake_timeout: Duration::from_secs(10),
        max_chunk_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
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
        config
            .input
            .upstream_capture()
            .map(|capture| capture.sampling.rate),
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
    input.max_chunk_bytes = NonZeroUsize::new(1024).unwrap();
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
        max_length: NonZeroUsize::new(65535).unwrap(),
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
                max_peers: NonZeroUsize::new(16384).unwrap(),
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
            max_chunk_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
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

/// Sum of a counter across series whose tags include `tags`, from this test thread's registry.
fn counter_total(name: &str, tags: &[(&str, &str)]) -> f64 {
    vector_lib::metrics::Controller::get()
        .unwrap()
        .capture_metrics()
        .into_iter()
        .filter(|metric| {
            metric.name() == name
                && tags
                    .iter()
                    .all(|(tag, value)| metric.tag_matches(tag, value))
        })
        .map(|metric| match metric.value() {
            MetricValue::Counter { value } => *value,
            _ => 0.0,
        })
        .sum()
}

/// Polls until the counter reaches `at_least`; panics after [`WAIT`].
async fn wait_for_counter(name: &str, tags: &[(&str, &str)], at_least: f64) -> f64 {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let total = counter_total(name, tags);
        if total >= at_least {
            break total;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {name} {tags:?} to reach {at_least}, at {total}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn tls_tcp_input(address: SocketAddr, upstream: SocketAddr) -> TcpInput {
    let mut input = tcp_input(address, Some(tcp_upstream(upstream)));
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
    input
}

#[tokio::test]
async fn test_update_tcp_counts_tls_handshake_failure_from_plaintext_client() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let (upstream, mut received) = upstream_tcp().await;
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Tcp(tls_tcp_input(addr, upstream)),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;

    _ = exchange(connect_tcp(addr).await, b"GET / HTTP/1.1\r\n\r\n").await;

    let failures = wait_for_counter(
        "component_errors_total",
        &[("error_code", "connection_failed")],
        1.0,
    )
    .await;
    assert_eq!(failures, 1.0);
    assert!(received.try_recv().is_err());
}

#[tokio::test]
async fn test_update_tcp_does_not_count_bare_connect_as_tls_handshake_failure() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let (upstream, _received) = upstream_tcp().await;
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Tcp(tls_tcp_input(addr, upstream)),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;

    // A load-balancer health check: connect, then close without a ClientHello.
    drop(connect_tcp(addr).await);
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        counter_total(
            "component_errors_total",
            &[("error_code", "connection_failed")]
        ),
        0.0
    );
}

#[tokio::test]
async fn test_update_udp_counts_datagram_from_peer_outside_permit_origin_and_does_not_forward() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let upstream = upstream_udp().await;
    let addr = next_addr();
    let mut input = udp_input(
        addr,
        Some(UdpUpstream {
            address: upstream,
            max_peers: NonZeroUsize::new(16384).unwrap(),
            capture: UpstreamCapture::default(),
        }),
    );
    input.permit_origin = Some(serde_json::from_str(r#"["10.0.0.0/8"]"#).unwrap());
    let _bsp = start_bsp(InputConfig::Udp(input), beam.capture()).await;
    beam.wait(hello_mode).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    client.send_to(b"denied", addr).await.unwrap();

    let denied =
        wait_for_counter("component_errors_total", &[("error_code", "bad_peer")], 1.0).await;
    assert_eq!(denied, 1.0);
    let mut buf = [0u8; 64];
    let reply = tokio::time::timeout(Duration::from_millis(300), client.recv(&mut buf)).await;
    assert!(reply.is_err(), "no reply expected, got {reply:?}");
    assert_eq!(beam.recorded.lock().unwrap().sessions.len(), 0);
}

#[tokio::test]
async fn test_update_tcp_counts_capture_session_failure_and_keeps_proxying() {
    vector_lib::metrics::init_test();
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

    let reply = exchange(connect_tcp(addr).await, b"payload").await.unwrap();

    assert_eq!(reply, b"ack:7");
    assert_eq!(received.await.unwrap(), b"payload");
    let failures = wait_for_counter("bsp_capture_sessions_failed_total", &[], 1.0).await;
    assert_eq!(failures, 1.0);
    assert_eq!(
        counter_total(
            "component_errors_total",
            &[("error_code", "capture_session_failed")]
        ),
        1.0
    );
}

#[tokio::test]
async fn test_new_tcp_counts_capture_session_failure_when_resetting_client() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Ready, OnSession::Fail).await;
    let addr = next_addr();
    let _bsp = start_bsp(InputConfig::Tcp(tcp_input(addr, None)), beam.capture()).await;
    beam.wait(hello_mode).await;

    _ = exchange(connect_tcp(addr).await, b"payload").await;

    let failures = wait_for_counter("bsp_capture_sessions_failed_total", &[], 1.0).await;
    assert_eq!(failures, 1.0);
}

#[tokio::test]
async fn test_control_stream_counts_each_end_without_stop_while_reconnecting() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::End, OnSession::Record).await;
    let (upstream, _received) = upstream_tcp().await;
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(next_addr(), Some(tcp_upstream(upstream)))),
        beam.capture(),
    )
    .await;

    wait_for_counter(
        "bsp_control_stream_failures_total",
        &[("reason", "ended")],
        2.0,
    )
    .await;

    let hellos = beam.recorded.lock().unwrap().control.len();
    assert!(hellos >= 2, "expected reconnects, saw {hellos} Hello(s)");
}

#[tokio::test]
async fn test_control_stream_counts_rejected_token_once_and_stops_reconnecting() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Reject, OnSession::Record).await;
    let (upstream, _received) = upstream_tcp().await;
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(next_addr(), Some(tcp_upstream(upstream)))),
        beam.capture(),
    )
    .await;

    wait_for_counter(
        "bsp_control_stream_failures_total",
        &[("reason", "unauthenticated")],
        1.0,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        counter_total(
            "bsp_control_stream_failures_total",
            &[("reason", "unauthenticated")]
        ),
        1.0
    );
    assert_eq!(beam.recorded.lock().unwrap().authorization.len(), 1);
}

use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::atomic::{AtomicBool, Ordering},
};

use tracing::Instrument;
use tracing_subscriber::layer::SubscriberExt;
use tracing_test::traced_test;

use super::{
    capture::{Capture, ControlLoop, Phase},
    config::{UnixDatagramInput, UnixDatagramUpstream},
    tee::Tee,
};
use crate::proto::beam::Transport;

/// Upstream that accepts any number of connections, reads each to EOF and replies `ack`.
async fn upstream_tcp_many() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut received = Vec::new();
                _ = stream.read_to_end(&mut received).await;
                _ = stream.write_all(b"ack").await;
                _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// UDP upstream that answers every datagram with `reply`.
async fn upstream_udp_replying(reply: Vec<u8>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((_, peer)) = socket.recv_from(&mut buf).await {
            _ = socket.send_to(&reply, peer).await;
        }
    });
    addr
}

fn udp_update_input(address: SocketAddr, upstream: SocketAddr, max_peers: usize) -> UdpInput {
    let mut input = udp_input(address, None);
    input.upstream = Some(UdpUpstream {
        address: upstream,
        max_peers: NonZeroUsize::new(max_peers).unwrap(),
        capture: UpstreamCapture::default(),
    });
    input
}

fn unix_stream_input(path: PathBuf) -> UnixStreamInput {
    UnixStreamInput {
        path,
        socket_file_mode: None,
        connection_limit: None,
        shutdown_timeout: Duration::from_secs(1),
        max_chunk_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
        upstream: None,
    }
}

fn unix_datagram_input(path: PathBuf, upstream: Option<UnixDatagramUpstream>) -> UnixDatagramInput {
    UnixDatagramInput {
        path,
        socket_file_mode: None,
        max_length: NonZeroUsize::new(65535).unwrap(),
        session_idle_timeout: Duration::from_secs(60),
        upstream,
    }
}

async fn build_error(config: BspConfig) -> String {
    let (tx, _rx) = SourceSender::new_test();
    config
        .build(SourceContext::new_test(tx, None))
        .await
        .err()
        .expect("build should fail")
        .to_string()
}

fn yaml_error(input: &str, limits: &str) -> String {
    serde_yaml::from_str::<BspConfig>(&format!(
        r#"
        input:
          {input}
        capture:
          endpoint: https://control-agent:9443
          run_id: run-1
          auth:
            token: {{ type: file, path: /etc/observo/auth/site_token }}
          limits: {{ {limits} }}
        "#
    ))
    .unwrap_err()
    .to_string()
}

fn session_messages(recorded: &Recorded, index: usize) -> Option<Vec<SessionRequest>> {
    recorded
        .sessions
        .get(index)
        .map(|session| session.lock().unwrap().clone())
}

/// Polls until `path` exists or not, as `present` says; panics after [`WAIT`].
async fn wait_for_path(path: &Path, present: bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while path.exists() != present {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {} to be present: {present}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct ReadBuffer {
    bytes: Vec<u8>,
    released: Arc<AtomicBool>,
}

impl AsRef<[u8]> for ReadBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ReadBuffer {
    fn drop(&mut self) {
        self.released.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn test_tee_queues_a_copy_so_a_stalled_session_does_not_keep_the_read_buffer_alive() {
    let beam = Harness::start(OnHello::Ready, OnSession::Stall(Duration::from_secs(30))).await;
    let (capture, control) =
        Capture::new(&beam.capture(), Mode::Update, Transport::Tcp, "bsp".into()).unwrap();
    tokio::spawn(control.run());
    assert_eq!(capture.settled().await, Phase::Ready);
    let mut tee = Tee::open(
        &capture,
        capture.admit().unwrap(),
        "client".into(),
        "local".into(),
        1024 * 1024,
        Unit::Bytes { max_chunk: 1024 },
        0,
    );
    let released = Arc::new(AtomicBool::new(false));
    let read_buffer = Bytes::from_owner(ReadBuffer {
        bytes: vec![7; 64 * 1024],
        released: Arc::clone(&released),
    });

    tee.push(&read_buffer.slice(..10));
    drop(read_buffer);

    assert!(released.load(Ordering::SeqCst));
}

#[tokio::test]
async fn test_update_udp_resumes_replies_after_upstream_was_down_and_restarts() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let upstream = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Udp(udp_update_input(addr, upstream, 16)),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"while down", addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let restarted = UdpSocket::bind(upstream).await.unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((len, peer)) = restarted.recv_from(&mut buf).await {
            let reply = [b"re:".as_slice(), &buf[..len]].concat();
            _ = restarted.send_to(&reply, peer).await;
        }
    });
    let reply = tokio::time::timeout(WAIT, udp_roundtrip(&client, addr, b"back")).await;

    assert_eq!(reply.unwrap(), b"re:back");
}

#[tokio::test]
async fn test_control_stream_retries_unreadable_token_file_and_connects_once_it_appears() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let token_path = socket_path("late_token");
    let mut capture = beam.capture();
    capture.auth.token = AuthTokenConfig::File {
        path: token_path.display().to_string(),
        reload_interval: Duration::from_millis(10),
    };
    let upstream = upstream_tcp_many().await;
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(next_addr(), Some(tcp_upstream(upstream)))),
        capture,
    )
    .await;
    wait_for_counter(
        "bsp_control_stream_failures_total",
        &[("reason", "token")],
        2.0,
    )
    .await;

    std::fs::write(&token_path, "late-token").unwrap();

    beam.wait(|recorded| {
        recorded
            .authorization
            .iter()
            .any(|authorization| authorization.contains("late-token"))
            .then_some(())
    })
    .await;
    assert_eq!(
        counter_total(
            "bsp_control_stream_failures_total",
            &[("reason", "unauthenticated")]
        ),
        0.0
    );
}

#[tokio::test]
async fn test_update_tcp_keeps_capture_slot_until_the_finished_session_rpc_ends() {
    let beam = Harness::start(
        OnHello::Ready,
        OnSession::Linger(Duration::from_millis(1500)),
    )
    .await;
    let mut capture = beam.capture();
    capture.limits.max_sessions = NonZeroUsize::new(1).unwrap();
    let upstream = upstream_tcp_many().await;
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(addr, Some(tcp_upstream(upstream)))),
        capture,
    )
    .await;
    beam.wait(hello_mode).await;
    exchange(connect_tcp(addr).await, b"one").await.unwrap();
    beam.half_closed_session(0).await;

    exchange(connect_tcp(addr).await, b"two").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(beam.recorded.lock().unwrap().sessions.len(), 1);

    tokio::time::sleep(Duration::from_millis(1500)).await;
    exchange(connect_tcp(addr).await, b"three").await.unwrap();
    assert_eq!(captured(&beam.half_closed_session(1).await).bytes, b"three");
}

#[tokio::test]
async fn test_capture_session_failure_is_counted_with_the_component_id_of_the_source() {
    vector_lib::metrics::init_test();
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(metrics_tracing_context::MetricsLayer::new()),
    );
    let beam = Harness::start(OnHello::Ready, OnSession::Fail).await;
    let upstream = upstream_tcp_many().await;
    let addr = next_addr();
    let config = BspConfig {
        input: InputConfig::Tcp(tcp_input(addr, Some(tcp_upstream(upstream)))),
        capture: beam.capture(),
    };
    let span = error_span!(
        "source",
        component_kind = "source",
        component_id = "bsp_under_test",
        component_type = "bsp",
    );
    let (tx, _rx) = SourceSender::new_test();
    let source = config
        .build(SourceContext::new_test(tx, None))
        .instrument(span.clone())
        .await
        .unwrap();
    let _bsp = tokio::spawn(source.instrument(span));
    beam.wait(hello_mode).await;

    exchange(connect_tcp(addr).await, b"payload").await.unwrap();

    wait_for_counter(
        "component_errors_total",
        &[
            ("error_code", "capture_session_failed"),
            ("component_id", "bsp_under_test"),
        ],
        1.0,
    )
    .await;
}

#[test]
fn test_config_rejects_zero_max_chunk_bytes() {
    let error = yaml_error(
        "{ mode: tcp, address: 0.0.0.0:9000, max_chunk_bytes: 0 }",
        "",
    );
    assert!(error.contains("nonzero"), "{error}");
}

#[test]
fn test_config_rejects_zero_max_length() {
    let error = yaml_error("{ mode: udp, address: 0.0.0.0:9000, max_length: 0 }", "");
    assert!(error.contains("nonzero"), "{error}");
}

#[test]
fn test_config_rejects_zero_max_peers() {
    let error = yaml_error(
        "{ mode: udp, address: 0.0.0.0:9000, upstream: { address: 127.0.0.1:9001, max_peers: 0 } }",
        "",
    );
    assert!(error.contains("nonzero"), "{error}");
}

#[test]
fn test_config_rejects_zero_max_sessions() {
    let error = yaml_error("{ mode: tcp, address: 0.0.0.0:9000 }", "max_sessions: 0");
    assert!(error.contains("nonzero"), "{error}");
}

#[test]
fn test_config_rejects_zero_max_bytes_per_sec() {
    let error = yaml_error(
        "{ mode: tcp, address: 0.0.0.0:9000 }",
        "max_bytes_per_sec: 0",
    );
    assert!(error.contains("nonzero"), "{error}");
}

#[tokio::test]
async fn test_build_rejects_zero_reconnect_backoff_initial() {
    let mut capture = Harness::start(OnHello::Ready, OnSession::Record)
        .await
        .capture();
    capture.reconnect_backoff.initial = Duration::ZERO;
    let error = build_error(BspConfig {
        input: InputConfig::Tcp(tcp_input(next_addr(), None)),
        capture,
    })
    .await;
    assert!(error.contains("reconnect_backoff.initial"), "{error}");
}

#[tokio::test]
async fn test_build_rejects_reconnect_backoff_initial_above_max() {
    let mut capture = Harness::start(OnHello::Ready, OnSession::Record)
        .await
        .capture();
    capture.reconnect_backoff = ReconnectBackoff {
        initial: Duration::from_secs(5),
        max: Duration::from_secs(1),
    };
    let error = build_error(BspConfig {
        input: InputConfig::Tcp(tcp_input(next_addr(), None)),
        capture,
    })
    .await;
    assert!(error.contains("reconnect_backoff.initial"), "{error}");
}

#[test]
fn test_reconnect_delay_jitter_shortens_by_at_most_twenty_percent() {
    let delay = Duration::from_secs(1);
    for _ in 0..1000 {
        let jittered = ControlLoop::jittered(delay);
        assert!(
            jittered >= Duration::from_millis(800) && jittered <= delay,
            "{jittered:?}"
        );
    }
}

#[tokio::test]
async fn test_control_stream_keeps_backing_off_when_control_agent_ends_it_before_ready() {
    let beam = Harness::start(OnHello::End, OnSession::Record).await;
    let mut capture = beam.capture();
    capture.reconnect_backoff = ReconnectBackoff {
        initial: Duration::from_millis(100),
        max: Duration::from_secs(10),
    };
    let upstream = upstream_tcp_many().await;
    let _bsp = start_bsp(
        InputConfig::Tcp(tcp_input(next_addr(), Some(tcp_upstream(upstream)))),
        capture,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(1600)).await;

    // 100, 200, 400 and 800 ms apart, less up to 20% jitter: at most 5 attempts. Resetting the
    // backoff after every stream would make about 15.
    let hellos = beam.recorded.lock().unwrap().authorization.len();
    assert!((3..=6).contains(&hellos), "{hellos} attempts");
}

#[tokio::test]
async fn test_build_rejects_unix_stream_path_that_is_a_regular_file_and_leaves_it_alone() {
    let path = socket_path("not_a_socket");
    std::fs::write(&path, "keep me").unwrap();
    let error = build_error(BspConfig {
        input: InputConfig::UnixStream(unix_stream_input(path.clone())),
        capture: Harness::start(OnHello::Ready, OnSession::Record)
            .await
            .capture(),
    })
    .await;

    assert!(error.contains("not a socket"), "{error}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me");
}

#[tokio::test]
async fn test_build_rejects_unix_datagram_path_that_is_a_regular_file_and_leaves_it_alone() {
    let path = socket_path("not_a_socket");
    std::fs::write(&path, "keep me").unwrap();
    let error = build_error(BspConfig {
        input: InputConfig::UnixDatagram(unix_datagram_input(path.clone(), None)),
        capture: Harness::start(OnHello::Ready, OnSession::Record)
            .await
            .capture(),
    })
    .await;

    assert!(error.contains("not a socket"), "{error}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me");
}

#[tokio::test]
async fn test_new_unix_stream_replaces_stale_socket_left_by_a_previous_run() {
    let beam = Harness::start(OnHello::Ready, OnSession::Echo).await;
    let path = socket_path("bsp.sock");
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    assert!(path.exists());
    let _bsp = start_bsp(
        InputConfig::UnixStream(unix_stream_input(path.clone())),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;

    let deadline = tokio::time::Instant::now() + WAIT;
    let client = loop {
        match UnixStream::connect(&path).await {
            Ok(client) => break client,
            Err(error) => {
                assert!(tokio::time::Instant::now() < deadline, "{error}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };

    assert_eq!(exchange(client, b"ping").await.unwrap(), b"ping");
}

#[tokio::test]
async fn test_new_unix_stream_removes_its_socket_file_when_control_agent_stops_the_run() {
    let beam = Harness::start(OnHello::Ready, OnSession::Echo).await;
    let path = socket_path("bsp.sock");
    let _bsp = start_bsp(
        InputConfig::UnixStream(unix_stream_input(path.clone())),
        beam.capture(),
    )
    .await;
    wait_for_path(&path, true).await;

    beam.stop_run();

    wait_for_path(&path, false).await;
}

#[tokio::test]
async fn test_new_unix_datagram_removes_its_socket_file_when_control_agent_stops_the_run() {
    let beam = Harness::start(OnHello::Ready, OnSession::Echo).await;
    let path = socket_path("bsp_dgram.sock");
    let _bsp = start_bsp(
        InputConfig::UnixDatagram(unix_datagram_input(path.clone(), None)),
        beam.capture(),
    )
    .await;
    wait_for_path(&path, true).await;

    beam.stop_run();

    wait_for_path(&path, false).await;
}

#[tokio::test]
#[traced_test]
async fn test_build_warns_when_capture_endpoint_is_plaintext_http() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    assert!(beam.endpoint.starts_with("http://"));
    let config = BspConfig {
        input: InputConfig::Tcp(tcp_input(next_addr(), None)),
        capture: beam.capture(),
    };
    let (tx, _rx) = SourceSender::new_test();

    let _source = config
        .build(SourceContext::new_test(tx, None))
        .await
        .unwrap();

    assert!(logs_contain("plaintext HTTP"));
}

#[tokio::test]
#[traced_test]
async fn test_build_does_not_warn_when_capture_endpoint_is_https() {
    let mut capture = Harness::start(OnHello::Ready, OnSession::Record)
        .await
        .capture();
    capture.endpoint = "https://control-agent:9443".into();
    let config = BspConfig {
        input: InputConfig::Tcp(tcp_input(next_addr(), None)),
        capture,
    };
    let (tx, _rx) = SourceSender::new_test();

    let _source = config
        .build(SourceContext::new_test(tx, None))
        .await
        .unwrap();

    assert!(!logs_contain("plaintext HTTP"));
}

#[tokio::test]
async fn test_new_udp_drops_rate_limited_datagrams_without_stalling_other_peers() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Ready, OnSession::Echo).await;
    let mut capture = beam.capture();
    capture.limits.max_bytes_per_sec = NonZeroU64::new(1000).unwrap();
    let addr = next_addr();
    let _bsp = start_bsp(InputConfig::Udp(udp_input(addr, None)), capture).await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let flooding = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..20 {
        flooding.send_to(&[1; 500], addr).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let reply =
        tokio::time::timeout(Duration::from_secs(1), udp_roundtrip(&other, addr, b"hi")).await;

    assert_eq!(reply.unwrap(), b"hi");
    wait_for_counter(
        "bsp_capture_bytes_dropped_total",
        &[("reason", "rate_limited")],
        500.0,
    )
    .await;
}

#[tokio::test]
async fn test_new_udp_drops_and_counts_datagrams_when_session_queue_is_full() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Ready, OnSession::Stall(Duration::from_secs(30))).await;
    let addr = next_addr();
    let _bsp = start_bsp(InputConfig::Udp(udp_input(addr, None)), beam.capture()).await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sent = 3000;

    for _ in 0..sent {
        _ = client.send_to(&[1; 1000], addr).await;
        tokio::task::yield_now().await;
    }

    wait_for_counter(
        "bsp_capture_bytes_dropped_total",
        &[("reason", "buffer_full")],
        1000.0,
    )
    .await;
    assert!(counter_total("bsp_capture_bytes_total", &[]) < (sent * 1000) as f64);
}

#[tokio::test]
async fn test_update_udp_refuses_new_peer_beyond_max_peers_and_keeps_serving_existing_one() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let upstream = upstream_udp().await;
    let addr = next_addr();
    let _bsp = start_bsp(
        InputConfig::Udp(udp_update_input(addr, upstream, 1)),
        beam.capture(),
    )
    .await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(udp_roundtrip(&first, addr, b"a").await, b"re:a");

    second.send_to(b"b", addr).await.unwrap();
    let mut buf = [0u8; 64];
    let refused = tokio::time::timeout(Duration::from_millis(500), second.recv(&mut buf)).await;

    assert!(refused.is_err(), "the second peer got a reply");
    assert_eq!(
        counter_total("bsp_sessions_total", &[("outcome", "peer_limited")]),
        1.0
    );
    assert_eq!(udp_roundtrip(&first, addr, b"c").await, b"re:c");
}

#[tokio::test]
async fn test_update_udp_truncates_upstream_reply_to_max_length() {
    vector_lib::metrics::init_test();
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let upstream = upstream_udp_replying(vec![b'x'; 100]).await;
    let addr = next_addr();
    let mut input = udp_update_input(addr, upstream, 16);
    input.max_length = NonZeroUsize::new(16).unwrap();
    let _bsp = start_bsp(InputConfig::Udp(input), beam.capture()).await;
    beam.wait(hello_mode).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let reply = udp_roundtrip(&client, addr, b"hi").await;

    assert_eq!(reply, vec![b'x'; 16]);
    assert!(counter_total("bsp_datagrams_truncated_total", &[]) >= 1.0);
}

#[tokio::test]
async fn test_update_tcp_drops_client_that_never_completes_tls_handshake() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let upstream = upstream_tcp_many().await;
    let addr = next_addr();
    let mut input = tls_tcp_input(addr, upstream);
    input.handshake_timeout = Duration::from_millis(300);
    let _bsp = start_bsp(InputConfig::Tcp(input), beam.capture()).await;
    beam.wait(hello_mode).await;
    let mut idle = connect_tcp(addr).await;

    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(3), idle.read(&mut buf)).await;

    assert!(
        matches!(&read, Ok(Ok(0)))
            || matches!(&read, Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "{read:?}"
    );
}

#[tokio::test]
async fn test_new_tcp_handshake_timeout_frees_the_capture_slot_for_the_next_client() {
    let beam = Harness::start(OnHello::Ready, OnSession::Echo).await;
    let mut capture = beam.capture();
    capture.limits.max_sessions = NonZeroUsize::new(1).unwrap();
    let addr = next_addr();
    let mut input = tls_tcp_input(addr, next_addr());
    input.upstream = None;
    input.handshake_timeout = Duration::from_millis(300);
    let _bsp = start_bsp(InputConfig::Tcp(input), capture).await;
    let _idle = connect_tcp(addr).await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    crate::test_util::send_lines_tls(
        addr,
        "localhost".into(),
        vec!["after timeout".to_owned()].into_iter(),
        Path::new(tls::TEST_PEM_CA_PATH),
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        captured(&beam.half_closed_session(0).await).bytes,
        b"after timeout\n"
    );
}

#[tokio::test]
async fn test_update_tcp_max_connection_duration_ends_capture_but_keeps_client_connected_to_upstream(
) {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let upstream = upstream_tcp_many().await;
    let addr = next_addr();
    let mut input = tcp_input(addr, Some(tcp_upstream(upstream)));
    input.max_connection_duration = Some(Duration::from_millis(500));
    let _bsp = start_bsp(InputConfig::Tcp(input), beam.capture()).await;
    beam.wait(hello_mode).await;
    let mut client = connect_tcp(addr).await;
    client.write_all(b"hello").await.unwrap();

    beam.wait(|recorded| {
        session_messages(recorded, 0)
            .map(|messages| captured(&messages))
            .filter(|captured| captured.bytes == b"hello")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    client.write_all(b" after the cut").await.unwrap();
    client.shutdown().await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(WAIT, client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(reply, b"ack");
    let messages = beam.wait(|recorded| session_messages(recorded, 0)).await;
    assert_eq!(captured(&messages).bytes, b"hello");
}

#[tokio::test]
async fn test_new_tcp_max_connection_duration_closes_client() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let addr = next_addr();
    let mut input = tcp_input(addr, None);
    input.max_connection_duration = Some(Duration::from_millis(500));
    let _bsp = start_bsp(InputConfig::Tcp(input), beam.capture()).await;
    let mut client = connect_tcp(addr).await;
    client.write_all(b"hello").await.unwrap();

    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .unwrap();

    assert!(matches!(read, Ok(0)), "client should see a FIN: {read:?}");
    let messages = beam.wait(|recorded| session_messages(recorded, 0)).await;
    assert_eq!(captured(&messages).bytes, b"hello");
}

async fn start_bsp_with_shutdown(
    input: InputConfig,
    capture: CaptureConfig,
) -> (
    JoinHandle<Result<(), ()>>,
    crate::shutdown::SourceShutdownCoordinator,
) {
    let config = BspConfig { input, capture };
    let (tx, _rx) = SourceSender::new_test();
    let (cx, shutdown) = SourceContext::new_shutdown(&crate::config::ComponentKey::from("bsp"), tx);
    let source = config.build(cx).await.unwrap();
    (tokio::spawn(source), shutdown)
}

#[tokio::test]
async fn test_new_tcp_shutdown_returns_at_once_and_closes_open_client_after_shutdown_timeout() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let addr = next_addr();
    let mut input = tcp_input(addr, None);
    input.shutdown_timeout = Duration::from_secs(1);
    let (bsp, mut shutdown) =
        start_bsp_with_shutdown(InputConfig::Tcp(input), beam.capture()).await;
    let mut client = connect_tcp(addr).await;
    client.write_all(b"hello").await.unwrap();
    beam.wait(|recorded| {
        session_messages(recorded, 0)
            .map(|messages| captured(&messages))
            .filter(|captured| captured.bytes == b"hello")
    })
    .await;

    let began = std::time::Instant::now();
    let completed = shutdown.shutdown_source(
        &crate::config::ComponentKey::from("bsp"),
        tokio::time::Instant::now() + WAIT,
    );
    assert!(completed.await, "source should finish before the deadline");
    assert_eq!(bsp.await.unwrap(), Ok(()));
    let returned = began.elapsed();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .unwrap();

    assert!(
        returned < Duration::from_millis(500),
        "returned after {returned:?}"
    );
    assert!(matches!(read, Ok(0)), "client should see a FIN: {read:?}");
    assert!(began.elapsed() >= Duration::from_secs(1));
}

#[tokio::test]
async fn test_update_tcp_shutdown_returns_at_once_and_keeps_proxying_until_shutdown_timeout() {
    let beam = Harness::start(OnHello::Ready, OnSession::Record).await;
    let upstream = upstream_tcp_many().await;
    let addr = next_addr();
    let mut input = tcp_input(addr, Some(tcp_upstream(upstream)));
    input.shutdown_timeout = Duration::from_secs(1);
    let (bsp, mut shutdown) =
        start_bsp_with_shutdown(InputConfig::Tcp(input), beam.capture()).await;
    beam.wait(hello_mode).await;
    let mut finishing = connect_tcp(addr).await;
    finishing.write_all(b"hello").await.unwrap();
    beam.wait(|recorded| session_messages(recorded, 0)).await;
    let mut holding = connect_tcp(addr).await;
    holding.write_all(b"held").await.unwrap();
    beam.wait(|recorded| {
        session_messages(recorded, 1)
            .map(|messages| captured(&messages))
            .filter(|captured| captured.bytes == b"held")
    })
    .await;

    let began = std::time::Instant::now();
    let completed = shutdown.shutdown_source(
        &crate::config::ComponentKey::from("bsp"),
        tokio::time::Instant::now() + WAIT,
    );
    assert!(completed.await, "source should finish before the deadline");
    assert_eq!(bsp.await.unwrap(), Ok(()));
    let returned = began.elapsed();
    finishing.write_all(b" after shutdown").await.unwrap();
    finishing.shutdown().await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(WAIT, finishing.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(WAIT, holding.read(&mut buf))
        .await
        .unwrap();

    assert!(
        returned < Duration::from_millis(500),
        "returned after {returned:?}"
    );
    assert_eq!(reply, b"ack");
    assert!(
        matches!(read, Ok(0)),
        "held client should see a FIN: {read:?}"
    );
    assert!(began.elapsed() >= Duration::from_secs(1));
    let finished = beam.half_closed_session(0).await;
    assert_eq!(captured(&finished).bytes, b"hello after shutdown");
}
