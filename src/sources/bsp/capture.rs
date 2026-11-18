use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::future::BoxFuture;
use http::Uri;
use hyper::client::HttpConnector;
use hyper_openssl::HttpsConnector;
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tonic::body::BoxBody;
use tower::Service;

use super::{
    config::{CaptureConfig, CaptureLimits, ReconnectBackoff},
    metrics::Metrics,
};
use crate::{
    internal_events::{BspCaptureSessionError, BspControlFailure, BspControlStreamError},
    proto::beam::{
        beam_client::BeamClient, control_request, control_response, session_request,
        ControlRequest, ControlResponse, Data, Gap, HalfClose, Hello, Mode, Open, SessionRequest,
        SessionResponse, Status, Transport,
    },
    sinks::util::AuthState,
    tls::{tls_connector_builder, MaybeTlsSettings},
};

const SESSION_QUEUE: usize = 16;
const SESSION_FINISH_GRACE: Duration = Duration::from_secs(30);
const HTTP2_KEEPALIVE: Duration = Duration::from_secs(30);

/// Where the instance stands with control-agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    /// Not connected, or connected and waiting for `Ready`.
    Pending,
    Ready,
    /// Latched until the source is rebuilt.
    Stopped,
}

#[derive(Clone)]
pub(super) struct BeamSvc {
    uri: Uri,
    client: hyper::Client<HttpsConnector<HttpConnector>, BoxBody>,
}

impl Service<hyper::Request<BoxBody>> for BeamSvc {
    type Response = hyper::Response<hyper::Body>;
    type Error = hyper::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: hyper::Request<BoxBody>) -> Self::Future {
        let mut parts = self.uri.clone().into_parts();
        parts.path_and_query = req.uri().path_and_query().cloned();
        if let Ok(uri) = Uri::from_parts(parts) {
            *req.uri_mut() = uri;
        }
        Box::pin(self.client.request(req))
    }
}

impl BeamSvc {
    fn new(config: &CaptureConfig) -> crate::Result<Self> {
        let uri: Uri = config.endpoint.parse()?;
        let uri = if uri.scheme().is_some() && uri.authority().is_some() {
            Ok(uri)
        } else {
            Err(format!(
                "capture.endpoint `{}` must include a scheme and a host",
                config.endpoint
            ))
        }?;
        let tls = MaybeTlsSettings::from_config(config.tls.as_ref(), false)?;

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        http.set_connect_timeout(Some(config.connect_timeout));

        let mut https = HttpsConnector::with_connector(http, tls_connector_builder(&tls)?)?;
        let settings = tls.tls().cloned();
        https.set_callback(move |connection, _uri| match &settings {
            Some(settings) => settings.apply_connect_configuration(connection),
            None => Ok(()),
        });

        let client = hyper::Client::builder()
            .http2_only(true)
            .http2_keep_alive_interval(HTTP2_KEEPALIVE)
            .http2_keep_alive_while_idle(true)
            .build(https);
        Ok(Self { uri, client })
    }
}

/// Ticket to open one captured session: holds a `max_sessions` slot for the session's lifetime.
pub(super) struct Admission {
    permit: OwnedSemaphorePermit,
    seq: u64,
}

/// Token bucket shared by all sessions of an instance.
struct RateLimit {
    per_sec: f64,
    state: Mutex<(f64, Instant)>,
}

impl RateLimit {
    fn new(per_sec: u64) -> Self {
        let per_sec = per_sec as f64;
        Self {
            per_sec,
            state: Mutex::new((per_sec, Instant::now())),
        }
    }

    /// Takes `n` tokens if available, or returns how long until they are. A request larger than
    /// the bucket only needs a full bucket, so it can't wait forever.
    fn take_or_wait(&self, n: usize) -> Option<Duration> {
        let mut state = self.state.lock().expect("rate limit lock poisoned");
        let (tokens, at) = &mut *state;
        let now = Instant::now();
        *tokens =
            (*tokens + now.duration_since(*at).as_secs_f64() * self.per_sec).min(self.per_sec);
        *at = now;
        let needed = (n as f64).min(self.per_sec);
        if *tokens >= needed {
            *tokens -= n as f64;
            None
        } else {
            Some(Duration::from_secs_f64((needed - *tokens) / self.per_sec))
        }
    }
}

/// Capture client shared by every session of one BSP instance.
pub(super) struct Capture {
    client: BeamClient<BeamSvc>,
    auth: AuthState,
    run_id: String,
    instance_id: String,
    mode: Mode,
    transport: Transport,
    phase: watch::Receiver<Phase>,
    exhausted: watch::Sender<bool>,
    sessions: Arc<Semaphore>,
    spent: AtomicU64,
    limits: CaptureLimits,
    rate: RateLimit,
    seq: AtomicU64,
    pub(super) metrics: Metrics,
}

/// Owns the `Control` stream for the lifetime of the instance.
pub(super) struct ControlLoop {
    capture: Arc<Capture>,
    phase: watch::Sender<Phase>,
    component_id: String,
    backoff: ReconnectBackoff,
}

impl Capture {
    pub(super) fn new(
        config: &CaptureConfig,
        mode: Mode,
        transport: Transport,
        component_id: String,
    ) -> crate::Result<(Arc<Self>, ControlLoop)> {
        let auth = AuthState::from_config(config.auth.token.clone())?;
        let svc = BeamSvc::new(config)?;
        let (phase_tx, phase_rx) = watch::channel(Phase::Pending);
        let capture = Arc::new(Self {
            client: BeamClient::new(svc),
            auth,
            run_id: config.run_id.clone(),
            instance_id: uuid::Uuid::new_v4().to_string(),
            mode,
            transport,
            phase: phase_rx,
            exhausted: watch::Sender::new(false),
            sessions: Arc::new(Semaphore::new(config.limits.max_sessions)),
            spent: AtomicU64::new(0),
            limits: config.limits.clone(),
            rate: RateLimit::new(config.limits.max_bytes_per_sec),
            seq: AtomicU64::new(0),
            metrics: Metrics::new(),
        });
        let control = ControlLoop {
            capture: Arc::clone(&capture),
            phase: phase_tx,
            component_id,
            backoff: config.reconnect_backoff.clone(),
        };
        Ok((capture, control))
    }

    pub(super) fn phase(&self) -> Phase {
        *self.phase.borrow()
    }

    /// Resolves once control-agent has answered: `Ready` or `Stopped`.
    pub(super) async fn settled(&self) -> Phase {
        let mut phase = self.phase.clone();
        phase
            .wait_for(|phase| *phase != Phase::Pending)
            .await
            .map(|phase| *phase)
            .unwrap_or(Phase::Stopped)
    }

    pub(super) async fn stopped(&self) {
        let mut phase = self.phase.clone();
        _ = phase.wait_for(|phase| *phase == Phase::Stopped).await;
    }

    pub(super) fn budget_exhausted(&self) -> bool {
        *self.exhausted.borrow()
    }

    pub(super) const fn max_session_bytes(&self) -> u64 {
        self.limits.max_session_bytes
    }

    /// A slot for a new captured session, if capture is armed, the budget isn't spent and
    /// `max_sessions` isn't reached.
    pub(super) fn admit(&self) -> Option<Admission> {
        if self.phase() == Phase::Ready && !self.budget_exhausted() {
            Arc::clone(&self.sessions)
                .try_acquire_owned()
                .ok()
                .map(|permit| Admission {
                    permit,
                    seq: self.seq.fetch_add(1, Ordering::Relaxed),
                })
        } else {
            None
        }
    }

    /// Counts captured bytes against `max_bytes`.
    pub(super) fn charge(&self, bytes: usize) {
        let bytes = bytes as u64;
        self.metrics.capture_bytes.increment(bytes);
        let spent = self.spent.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if spent >= self.limits.max_bytes && !self.exhausted.send_replace(true) {
            self.metrics.capture_budget_exhausted.set(1.0);
            info!(
                message = "Capture budget exhausted.",
                max_bytes = self.limits.max_bytes
            );
        }
    }

    pub(super) fn try_rate(&self, bytes: usize) -> bool {
        self.rate.take_or_wait(bytes).is_none()
    }

    pub(super) async fn rate(&self, bytes: usize) {
        while let Some(wait) = self.rate.take_or_wait(bytes) {
            tokio::time::sleep(wait).await;
        }
    }

    fn bearer(&self) -> Result<tonic::metadata::MetadataValue<tonic::metadata::Ascii>, String> {
        self.auth.bearer_token()
    }

    /// Opens a `Session` RPC. Failures to open arrive as the first item on
    /// [`SessionStream::rx`].
    pub(super) fn open(
        self: &Arc<Self>,
        admission: Admission,
        client_addr: String,
        local_addr: String,
    ) -> SessionStream {
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        let open = Open {
            run_id: self.run_id.clone(),
            instance_id: self.instance_id.clone(),
            session_seq: admission.seq,
            transport: self.transport as i32,
            client_addr,
            local_addr,
            opened_at: Some(now()),
        };
        _ = tx.try_send(SessionRequest {
            msg: Some(session_request::Msg::Open(open)),
        });

        let (resp_tx, resp_rx) = mpsc::channel(SESSION_QUEUE);
        let capture = Arc::clone(self);
        let task = tokio::spawn(async move {
            let result = async {
                let mut request = tonic::Request::new(ReceiverStream::new(rx));
                request.metadata_mut().insert(
                    "authorization",
                    capture.bearer().map_err(tonic::Status::unauthenticated)?,
                );
                let mut responses = capture.client.clone().session(request).await?.into_inner();
                let mut forwarding = true;
                // Keep reading after the session side is gone: dropping the response stream early
                // would cancel the RPC instead of letting it end normally.
                while let Some(response) = responses.message().await? {
                    if forwarding {
                        forwarding = resp_tx.send(Ok(response)).await.is_ok();
                    }
                }
                Ok::<(), tonic::Status>(())
            }
            .await;
            if let Err(status) = result {
                emit!(BspCaptureSessionError { status: &status });
                _ = resp_tx.send(Err(status)).await;
            }
        });

        SessionStream {
            tx: SessionTx(Some(tx)),
            rx: resp_rx,
            guard: SessionGuard {
                task: Some(task),
                _permit: admission.permit,
            },
        }
    }
}

impl ControlLoop {
    pub(super) async fn run(self) {
        let mut delay = self.backoff.initial;
        loop {
            match self.connect_once().await {
                ControlOutcome::Stopped => break,
                ControlOutcome::Connected => delay = self.backoff.initial,
                ControlOutcome::Failed => {}
            }
            self.phase.send_if_modified(|phase| {
                let reset = *phase == Phase::Ready;
                if reset {
                    *phase = Phase::Pending;
                }
                reset
            });
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(self.backoff.max);
        }
    }

    fn stop(&self, reason: &str) -> ControlOutcome {
        info!(message = "Capture stopped by control-agent.", %reason);
        self.phase.send_replace(Phase::Stopped);
        self.capture.metrics.capture_stopped.set(1.0);
        ControlOutcome::Stopped
    }

    async fn connect_once(&self) -> ControlOutcome {
        let capture = &self.capture;
        let (tx, rx) = mpsc::channel(4);
        let hello = Hello {
            run_id: capture.run_id.clone(),
            instance_id: capture.instance_id.clone(),
            mode: capture.mode as i32,
            transport: capture.transport as i32,
            component_id: self.component_id.clone(),
            host: crate::get_hostname().unwrap_or_default(),
        };
        _ = tx.try_send(ControlRequest {
            msg: Some(control_request::Msg::Hello(hello)),
        });
        let mut exhausted = capture.exhausted.subscribe();
        if *exhausted.borrow_and_update() {
            _ = tx.try_send(status_exhausted());
        }

        let request = capture.bearer().map(|bearer| {
            let mut request = tonic::Request::new(ReceiverStream::new(rx));
            request.metadata_mut().insert("authorization", bearer);
            request
        });
        let response = match request {
            Ok(request) => capture.client.clone().control(request).await,
            Err(message) => Err(tonic::Status::unauthenticated(message)),
        };
        match response {
            Ok(response) => {
                capture.metrics.control_stream_connected.set(1.0);
                let outcome = self.drive(response.into_inner(), tx, exhausted).await;
                capture.metrics.control_stream_connected.set(0.0);
                outcome
            }
            Err(status) if status.code() == tonic::Code::Unauthenticated => {
                emit!(BspControlStreamError {
                    failure: BspControlFailure::Unauthenticated,
                    error: &status,
                });
                self.stop("unauthenticated")
            }
            Err(status) => {
                emit!(BspControlStreamError {
                    failure: BspControlFailure::Open,
                    error: &status,
                });
                ControlOutcome::Failed
            }
        }
    }

    async fn drive(
        &self,
        mut responses: tonic::Streaming<ControlResponse>,
        tx: mpsc::Sender<ControlRequest>,
        mut exhausted: watch::Receiver<bool>,
    ) -> ControlOutcome {
        loop {
            tokio::select! {
                message = responses.message() => match message {
                    Ok(Some(ControlResponse { msg: Some(control_response::Msg::Ready(_)) })) => {
                        debug!(message = "Capture ready.");
                        self.phase.send_replace(Phase::Ready);
                    }
                    Ok(Some(ControlResponse { msg: Some(control_response::Msg::Stop(stop)) })) => {
                        break self.stop(&stop.reason);
                    }
                    Ok(Some(_)) => self.capture.metrics.ignored_responses.increment(1),
                    Ok(None) => {
                        emit!(BspControlStreamError {
                            failure: BspControlFailure::Ended,
                            error: &"control-agent ended the stream without a Stop",
                        });
                        break ControlOutcome::Connected;
                    }
                    Err(status) if status.code() == tonic::Code::Unauthenticated => {
                        emit!(BspControlStreamError {
                            failure: BspControlFailure::Unauthenticated,
                            error: &status,
                        });
                        break self.stop("unauthenticated");
                    }
                    Err(status) => {
                        emit!(BspControlStreamError {
                            failure: BspControlFailure::Failed,
                            error: &status,
                        });
                        break ControlOutcome::Connected;
                    }
                },
                Ok(()) = exhausted.changed() => {
                    if *exhausted.borrow_and_update() {
                        _ = tx.send(status_exhausted()).await;
                    }
                }
            }
        }
    }
}

enum ControlOutcome {
    Stopped,
    /// The stream was up and then ended, so the backoff starts over.
    Connected,
    Failed,
}

const fn status_exhausted() -> ControlRequest {
    ControlRequest {
        msg: Some(control_request::Msg::Status(Status {
            budget_exhausted: true,
        })),
    }
}

pub(super) fn now() -> prost_types::Timestamp {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    prost_types::Timestamp {
        seconds: since_epoch.as_secs() as i64,
        nanos: since_epoch.subsec_nanos() as i32,
    }
}

/// Sending half of a `Session` RPC.
pub(super) struct SessionTx(Option<mpsc::Sender<SessionRequest>>);

impl SessionTx {
    /// Fails once the RPC is gone.
    async fn send(&self, msg: session_request::Msg) -> Result<(), ()> {
        match &self.0 {
            Some(tx) => tx
                .send(SessionRequest { msg: Some(msg) })
                .await
                .map_err(|_| ()),
            None => Err(()),
        }
    }

    pub(super) async fn data(
        &self,
        offset: u64,
        received_at: prost_types::Timestamp,
        payload: bytes::Bytes,
    ) -> Result<(), ()> {
        self.send(session_request::Msg::Data(Data {
            offset,
            received_at: Some(received_at),
            payload,
        }))
        .await
    }

    pub(super) async fn gap(&self, offset: u64, length: u64) -> Result<(), ()> {
        self.send(session_request::Msg::Gap(Gap { offset, length }))
            .await
    }

    pub(super) async fn half_close(&self) -> Result<(), ()> {
        self.send(session_request::Msg::HalfClose(HalfClose {}))
            .await
    }
}

/// One `Session` RPC.
///
/// Dropping it without [`SessionStream::finish`] cancels the RPC, which tells control-agent the
/// session was reset.
pub(super) struct SessionStream {
    pub(super) tx: SessionTx,
    /// Ends (`None`) once the RPC has ended normally; a failure to open arrives as the first item.
    pub(super) rx: mpsc::Receiver<Result<SessionResponse, tonic::Status>>,
    pub(super) guard: SessionGuard,
}

impl SessionStream {
    /// Ends the RPC normally.
    pub(super) fn finish(self) {
        let Self { tx, rx, guard } = self;
        drop((tx, rx));
        guard.finish();
    }
}

/// Keeps the RPC and its `max_sessions` slot alive; cancels the RPC when dropped.
pub(super) struct SessionGuard {
    task: Option<tokio::task::JoinHandle<()>>,
    _permit: OwnedSemaphorePermit,
}

impl SessionGuard {
    /// Lets the RPC end normally once the sending half is dropped.
    pub(super) fn finish(mut self) {
        if let Some(task) = self.task.take() {
            let abort = task.abort_handle();
            tokio::spawn(async move {
                if tokio::time::timeout(SESSION_FINISH_GRACE, task)
                    .await
                    .is_err()
                {
                    abort.abort();
                }
            });
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
