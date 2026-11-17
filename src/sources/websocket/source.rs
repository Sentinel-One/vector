use crate::vector_lib::codecs::StreamDecodingError;
use crate::{
    codecs::{DecoderFactory, Stream as StreamScope},
    common::{
        backoff::ExponentialBackoff,
        websocket::{is_closed, PingInterval, WebSocketConnector},
    },
    config::SourceContext,
    internal_events::{
        ConnectionOpen, OpenGauge, WebSocketBytesReceived, WebSocketConnectionFailedError,
        WebSocketConnectionShutdown, WebSocketKind, WebSocketMessageReceived,
        WebSocketReceiveError, WebSocketSendError, PROTOCOL,
    },
    sources::websocket::config::WebSocketConfig,
    SourceSender,
};
use chrono::Utc;
use futures::{pin_mut, sink::SinkExt, Sink, Stream, StreamExt};
use snafu::Snafu;
use std::pin::Pin;
use std::time::Instant;
use tokio::time;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{error::Error as TungsteniteError, Message};
use tokio_util::codec::FramedRead;
use vector_lib::internal_event::{CountByteSize, EventsReceived, InternalEventHandle as _};
use vector_lib::{
    config::LogNamespace,
    event::{Event, LogEvent},
    EstimatedJsonEncodedSizeOf,
};

macro_rules! fail_with_event {
    ($context:expr) => {{
        emit!(WebSocketConnectionFailedError {
            error: Box::new($context.build())
        });
        return $context.fail();
    }};
}

type WebSocketSink = Pin<Box<dyn Sink<Message, Error = TungsteniteError> + Send>>;
type WebSocketStream = Pin<Box<dyn Stream<Item = Result<Message, TungsteniteError>> + Send>>;

pub(crate) struct WebSocketSourceParams {
    pub connector: WebSocketConnector,
    pub decoder: DecoderFactory<StreamScope>,
    pub log_namespace: LogNamespace,
}

pub(crate) struct WebSocketSource {
    config: WebSocketConfig,
    params: WebSocketSourceParams,
}

#[derive(Debug, Snafu)]
pub enum WebSocketSourceError {
    #[snafu(display("Connection attempt timed out"))]
    ConnectTimeout,

    #[snafu(display("Server did not respond to the initial message in time"))]
    InitialMessageTimeout,

    #[snafu(display(
        "The connection was closed after sending the initial message, but before a response."
    ))]
    ConnectionClosedPrematurely,

    #[snafu(display("Connection closed by server with code '{}' and reason: '{}'", frame.code, frame.reason))]
    RemoteClosed { frame: CloseFrame<'static> },

    #[snafu(display("Connection closed by server without a close frame"))]
    RemoteClosedEmpty,

    #[snafu(display("Connection timed out while waiting for a pong response"))]
    PongTimeout,

    #[snafu(display("A WebSocket error occurred: {}", source))]
    Tungstenite { source: TungsteniteError },
}

impl WebSocketSource {
    pub const fn new(config: WebSocketConfig, params: WebSocketSourceParams) -> Self {
        Self { config, params }
    }

    pub async fn run(self, cx: SourceContext) -> Result<(), WebSocketSourceError> {
        let _open_token = OpenGauge::new().open(|count| emit!(ConnectionOpen { count }));
        let mut ping_manager = PingManager::new(&self.config);

        let mut out = cx.out;

        let connect_start = Instant::now();
        let (ws_sink, ws_source) = self.connect(&mut out).await?;
        let connect_duration_ms = connect_start.elapsed().as_millis() as u64;

        pin_mut!(ws_sink, ws_source);

        info!(
            message = "WebSocket source started.",
            uri = %self.config.common.uri,
            ping_interval = ?self.config.common.ping_interval.map(|v| format!("{}s", v)),
            ping_message = ?self.config.ping_message,
            connect_duration_ms,
        );

        loop {
            let result = tokio::select! {
                _ = cx.shutdown.clone() => {
                    info!("Received shutdown signal.");
                    break;
                },

                res = ping_manager.tick(&mut ws_sink) => res,

                Some(msg_result) = ws_source.next() => {
                    match msg_result {
                        Ok(msg) => self.handle_message(msg, &mut ping_manager, &mut out).await,
                        Err(error) => {
                            emit!(WebSocketReceiveError { error: &error });
                            Err(WebSocketSourceError::Tungstenite { source: error })
                        }
                    }
                }
            };

            if let Err(error) = result {
                match error {
                    WebSocketSourceError::RemoteClosed { frame } => {
                        info!(
                            message = "Connection closed by server.",
                            code = %frame.code,
                            reason = %frame.reason
                        );
                        // Flush tungstenite's auto-queued close response to complete the close handshake.
                        // See: https://docs.rs/tungstenite/0.20.1/tungstenite/protocol/struct.WebSocket.html#method.read
                        let _ = ws_sink.flush().await;
                        emit!(WebSocketConnectionShutdown);
                    }
                    WebSocketSourceError::RemoteClosedEmpty => {
                        info!("Connection closed by server without a close frame.");
                        let _ = ws_sink.flush().await;
                        emit!(WebSocketConnectionShutdown);
                    }
                    WebSocketSourceError::PongTimeout => {
                        info!(
                            message = "Pong timeout — connection appears dead, will reconnect.",
                            uri = %self.config.common.uri,
                        );
                        emit!(WebSocketReceiveError {
                            error: &TungsteniteError::Io(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "Pong timeout"
                            ))
                        });
                        emit!(WebSocketConnectionShutdown);
                    }
                    WebSocketSourceError::Tungstenite { source: ws_err } => {
                        if is_closed(&ws_err) {
                            emit!(WebSocketConnectionShutdown);
                        }
                        error!(
                            message = "WebSocket error.",
                            error = %ws_err,
                            uri = %self.config.common.uri,
                            is_closed = is_closed(&ws_err),
                        );
                    }
                    // These errors should only happen during `connect` or `reconnect`,
                    // not in the main loop's result.
                    WebSocketSourceError::ConnectTimeout
                    | WebSocketSourceError::InitialMessageTimeout
                    | WebSocketSourceError::ConnectionClosedPrematurely => {
                        unreachable!(
                            "Encountered a connection-time error during runtime: {:?}",
                            error
                        );
                    }
                }
                // Retry indefinitely with exponential backoff
                let mut backoff = ExponentialBackoff::from_millis(100)
                    .factor(1000)
                    .max_delay(std::time::Duration::from_secs(30));

                loop {
                    match self
                        .reconnect(&mut out, &mut ws_sink, &mut ws_source)
                        .await
                    {
                        Ok(()) => {
                            backoff.reset();
                            ping_manager.reset();
                            info!("Ping manager reset after reconnect.");
                            break;
                        }
                        Err(err) => {
                            let delay = backoff.next().unwrap_or(std::time::Duration::from_secs(30));
                            info!(
                                message = "Reconnection failed, retrying after delay.",
                                error = ?err,
                                delay_ms = delay.as_millis()
                            );
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_message(
        &self,
        msg: Message,
        ping_manager: &mut PingManager,
        out: &mut SourceSender,
    ) -> Result<(), WebSocketSourceError> {
        match msg {
            Message::Pong(_) => {
                info!("Received pong response.");
                ping_manager.record_pong();
                Ok(())
            }
            Message::Text(msg_txt) => {
                if self.is_custom_pong(&msg_txt) {
                    ping_manager.record_pong();
                    info!("Received custom pong response.");
                } else {
                    self.process_message(&msg_txt, WebSocketKind::Text, out)
                        .await;
                }
                Ok(())
            }
            Message::Binary(msg_bytes) => {
                self.process_message(&msg_bytes, WebSocketKind::Binary, out)
                    .await;
                Ok(())
            }
            Message::Ping(_) => {
                info!("Received ping from server (tungstenite auto-pongs).");
                Ok(())
            }
            Message::Close(frame) => self.handle_close_frame(frame),
            Message::Frame(_) => {
                info!("Unsupported message type received: frame.");
                Ok(())
            }
        }
    }

    async fn process_message<T>(&self, payload: &T, kind: WebSocketKind, out: &mut SourceSender)
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let payload_bytes = payload.as_ref();

        emit!(WebSocketBytesReceived {
            byte_size: payload_bytes.len(),
            url: &self.config.common.uri,
            protocol: PROTOCOL,
            kind,
        });
        let mut stream = FramedRead::new(payload_bytes, self.params.decoder.build());

        while let Some(result) = stream.next().await {
            match result {
                Ok((events, _)) => {
                    if events.is_empty() {
                        continue;
                    }

                    let event_count = events.len();
                    let byte_size = events.estimated_json_encoded_size_of();

                    register!(EventsReceived).emit(CountByteSize(event_count, byte_size));
                    emit!(WebSocketMessageReceived {
                        count: event_count,
                        byte_size,
                        url: &self.config.common.uri,
                        protocol: PROTOCOL,
                        kind,
                    });

                    let events_with_meta = events.into_iter().map(|mut event| {
                        if let Event::Log(event) = &mut event {
                            self.add_metadata(event);
                        }
                        event
                    });

                    if let Err(error) = out.send_batch(events_with_meta).await {
                        error!(message = "Error sending events.", %error);
                    }
                }
                Err(error) => {
                    if !error.can_continue() {
                        error!(message = "Fatal decoder error, stopping message processing.", %error);
                        break;
                    }
                }
            }
        }
    }

    fn add_metadata(&self, event: &mut LogEvent) {
        self.params
            .log_namespace
            .insert_standard_vector_source_metadata(event, WebSocketConfig::NAME, Utc::now());
    }

    async fn reconnect(
        &self,
        out: &mut SourceSender,
        ws_sink: &mut WebSocketSink,
        ws_source: &mut WebSocketStream,
    ) -> Result<(), WebSocketSourceError> {
        info!(
            message = "Reconnecting to WebSocket...",
            uri = %self.config.common.uri,
        );

        let reconnect_start = Instant::now();
        let (new_sink, new_source) = self.connect(out).await?;
        let connect_duration_ms = reconnect_start.elapsed().as_millis() as u64;

        *ws_sink = new_sink;
        *ws_source = new_source;

        info!(
            message = "Reconnected successfully.",
            uri = %self.config.common.uri,
            connect_duration_ms,
        );

        Ok(())
    }

    async fn connect(
        &self,
        out: &mut SourceSender,
    ) -> Result<(WebSocketSink, WebSocketStream), WebSocketSourceError> {
        let (mut ws_sink, mut ws_source) = self.try_create_sink_and_stream().await?;

        if self.config.initial_message.is_some() {
            self.send_initial_message(&mut ws_sink, &mut ws_source, out)
                .await?;
        }

        Ok((ws_sink, ws_source))
    }

    async fn try_create_sink_and_stream(
        &self,
    ) -> Result<(WebSocketSink, WebSocketStream), WebSocketSourceError> {
        // connect_backoff now handles timeouts per-attempt internally and retries indefinitely
        // for retriable errors.
        let ws_stream = self
            .params
            .connector
            .connect_backoff(self.config.connect_timeout_secs)
            .await;

        let (sink, stream) = ws_stream.split();

        Ok((Box::pin(sink), Box::pin(stream)))
    }

    async fn send_initial_message(
        &self,
        ws_sink: &mut WebSocketSink,
        ws_source: &mut WebSocketStream,
        out: &mut SourceSender,
    ) -> Result<(), WebSocketSourceError> {
        let initial_message = self.config.initial_message.as_ref().unwrap();
        ws_sink
            .send(Message::Text(initial_message.clone()))
            .await
            .map_err(|error| {
                emit!(WebSocketSendError { error: &error });
                WebSocketSourceError::Tungstenite { source: error }
            })?;

        debug!("Sent initial message, awaiting response from server.");

        let response =
            match time::timeout(self.config.initial_message_timeout_secs, ws_source.next()).await {
                Ok(Some(msg)) => msg,
                Ok(None) => fail_with_event!(ConnectionClosedPrematurelySnafu),
                Err(_) => fail_with_event!(InitialMessageTimeoutSnafu),
            };

        let message = response.map_err(|source| {
            emit!(WebSocketReceiveError { error: &source });
            WebSocketSourceError::Tungstenite { source }
        })?;

        match message {
            Message::Text(txt) => {
                self.process_message(&txt, WebSocketKind::Text, out).await;
                Ok(())
            }
            Message::Binary(bin) => {
                self.process_message(&bin, WebSocketKind::Binary, out).await;
                Ok(())
            }
            Message::Close(frame) => self.handle_close_frame(frame),
            _ => Ok(()),
        }
    }

    fn handle_close_frame(
        &self,
        frame: Option<CloseFrame<'_>>,
    ) -> Result<(), WebSocketSourceError> {
        let (error_message, specific_error) = match frame {
            Some(frame) => {
                let msg = format!(
                    "Connection closed by server with code '{}' and reason: '{}'",
                    frame.code, frame.reason
                );
                let err = WebSocketSourceError::RemoteClosed {
                    frame: frame.into_owned(),
                };
                (msg, err)
            }
            None => (
                "Connection closed by server without a close frame".to_string(),
                WebSocketSourceError::RemoteClosedEmpty,
            ),
        };

        let error = TungsteniteError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            error_message,
        ));
        emit!(WebSocketReceiveError { error: &error });

        Err(specific_error)
    }

    fn is_custom_pong(&self, msg_txt: &str) -> bool {
        match self.config.pong_message.as_ref() {
            Some(config) => config.matches(msg_txt),
            None => false,
        }
    }
}

struct PingManager {
    interval: PingInterval,
    waiting_for_pong: bool,
    message: Message,
    last_ping_sent: Option<Instant>,
}

impl PingManager {
    fn new(config: &WebSocketConfig) -> Self {
        let ping_message = if let Some(ping_msg) = &config.ping_message {
            Message::Text(ping_msg.clone())
        } else {
            Message::Ping(vec![])
        };

        Self {
            interval: PingInterval::new(config.common.ping_interval.map(u64::from)),
            waiting_for_pong: false,
            message: ping_message,
            last_ping_sent: None,
        }
    }

    fn record_pong(&mut self) {
        self.reset();
    }

    fn reset(&mut self) {
        self.waiting_for_pong = false;
        self.last_ping_sent = None;
    }

    async fn tick(&mut self, ws_sink: &mut WebSocketSink) -> Result<(), WebSocketSourceError> {
        self.interval.tick().await;

        if self.waiting_for_pong {
            let elapsed_since_ping_ms = self
                .last_ping_sent
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(0);
            info!(
                message = "Pong not received before next ping interval — declaring connection dead.",
                elapsed_since_ping_ms,
            );
            return Err(WebSocketSourceError::PongTimeout);
        }

        info!("Sending ping.");
        ws_sink.send(self.message.clone()).await.map_err(|error| {
            emit!(WebSocketSendError { error: &error });
            WebSocketSourceError::Tungstenite { source: error }
        })?;

        self.last_ping_sent = Some(Instant::now());
        self.waiting_for_pong = true;
        Ok(())
    }
}

#[cfg(feature = "websocket-integration-tests")]
#[cfg(test)]
mod integration_test {
    use crate::{
        common::websocket::WebSocketCommonConfig,
        sources::websocket::config::PongMessage,
        sources::websocket::config::WebSocketConfig,
        test_util::{
            components::{run_and_assert_source_compliance, SOURCE_TAGS},
            next_addr,
        },
    };
    use futures::{sink::SinkExt, StreamExt};
    use std::num::NonZeroU64;
    use tokio::{net::TcpListener, time::Duration};
    use tokio_tungstenite::{accept_async, tungstenite::Message};
    use url::Url;
    use vector_lib::codecs::decoding::DeserializerConfig;

    fn make_config(uri: &str) -> WebSocketConfig {
        WebSocketConfig {
            common: WebSocketCommonConfig {
                uri: Url::parse(uri).unwrap().to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Starts a WebSocket server that pushes a binary message to the first client.
    async fn start_binary_push_server() -> String {
        let addr = next_addr();
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
        let server_addr = format!("ws://{}", listener.local_addr().unwrap());

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.expect("Failed to accept");

            let binary_payload = br#"{"message": "binary data"}"#.to_vec();
            websocket
                .send(Message::Binary(binary_payload))
                .await
                .unwrap();
        });

        server_addr
    }

    /// Starts a WebSocket server that pushes a message to the first client that connects.
    async fn start_push_server() -> String {
        let addr = next_addr();
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
        let server_addr = format!("ws://{}", listener.local_addr().unwrap());

        tokio::spawn(async move {
            // Accept one connection
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.expect("Failed to accept");

            // Immediately send a message to the connected client (which will be our source)
            websocket
                .send(Message::Text("message from server".to_string()))
                .await
                .unwrap();
        });

        server_addr
    }

    /// Starts a WebSocket server that waits for an initial message from the client,
    /// and upon receiving it, sends a confirmation message back.
    async fn start_subscribe_server(initial_message: String, response_message: String) -> String {
        let addr = next_addr();
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
        let server_addr = format!("ws://{}", listener.local_addr().unwrap());

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.expect("Failed to accept");

            // Wait for the initial message from the client
            if let Some(Ok(Message::Text(msg))) = websocket.next().await {
                if msg == initial_message {
                    // Received correct initial message, send response
                    websocket
                        .send(Message::Text(response_message))
                        .await
                        .unwrap();
                }
            }
        });

        server_addr
    }

    async fn start_reconnect_server() -> String {
        let addr = next_addr();
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
        let server_addr = format!("ws://{}", listener.local_addr().unwrap());

        tokio::spawn(async move {
            // First connection
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.expect("Failed to accept");
            websocket
                .send(Message::Text("first message".to_string()))
                .await
                .unwrap();
            // Close the connection to force a reconnect from the client
            websocket.close(None).await.unwrap();

            // Second connection
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.expect("Failed to accept");
            websocket
                .send(Message::Text("second message".to_string()))
                .await
                .unwrap();
        });

        server_addr
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn websocket_source_reconnects_after_disconnect() {
        let server_addr = start_reconnect_server().await;
        let config = make_config(&server_addr);

        // Run for a longer duration to allow for reconnection
        let events =
            run_and_assert_source_compliance(config, Duration::from_secs(5), &SOURCE_TAGS).await;

        assert_eq!(
            events.len(),
            2,
            "Should have received messages from both connections"
        );

        let event = events[0].as_log();
        assert_eq!(event["message"], "first message".into());

        let event = events[1].as_log();
        assert_eq!(event["message"], "second message".into());
    }

    /// Starts a server that sends a message on the first connection, holds it open
    /// without responding (simulating a dead peer / network partition), then accepts
    /// a second connection and sends another message.
    ///
    /// If `consume_messages` is true, the first connection drains reads silently —
    /// used when the client sends text-based ping messages that the server must read
    /// but not reply to. If false, the connection just sleeps without reading.
    async fn start_silent_then_recover_server(consume_messages: bool) -> String {
        let addr = next_addr();
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
        let server_addr = format!("ws://{}", listener.local_addr().unwrap());

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.expect("Failed to accept");
            websocket
                .send(Message::Text("before silence".to_string()))
                .await
                .unwrap();
            // Spawn so the listener can accept the second connection while the
            // first is still alive (the client's reconnect creates the new
            // connection before dropping the old one).
            tokio::spawn(async move {
                if consume_messages {
                    while websocket.next().await.is_some() {}
                } else {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(websocket);
                }
            });

            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.expect("Failed to accept");
            websocket
                .send(Message::Text("after reconnect".to_string()))
                .await
                .unwrap();
        });

        server_addr
    }

    /// When the server goes silent, the source should detect the dead connection via
    /// pong timeout, reconnect, and continue receiving data — NOT exit permanently.
    #[tokio::test(flavor = "multi_thread")]
    async fn websocket_source_reconnects_after_pong_timeout() {
        let server_addr = start_silent_then_recover_server(false).await;

        let mut config = make_config(&server_addr);
        config.common.ping_interval = NonZeroU64::new(1);

        let events =
            run_and_assert_source_compliance(config, Duration::from_secs(5), &SOURCE_TAGS).await;

        assert_eq!(
            events.len(),
            2,
            "Should reconnect after pong timeout and receive messages from both connections"
        );
        assert_eq!(events[0].as_log()["message"], "before silence".into());
        assert_eq!(events[1].as_log()["message"], "after reconnect".into());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn websocket_source_consume_binary_event() {
        let server_addr = start_binary_push_server().await;
        let mut config = make_config(&server_addr);
        let decoding = DeserializerConfig::Json(Default::default());
        config.decoding = decoding;

        let events =
            run_and_assert_source_compliance(config, Duration::from_secs(2), &SOURCE_TAGS).await;

        assert!(!events.is_empty(), "No events received from source");
        let event = events[0].as_log();
        assert_eq!(event["message"], "binary data".into());
        assert_eq!(*event.get_source_type().unwrap(), "websocket".into());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn websocket_source_consume_event() {
        let server_addr = start_push_server().await;
        let config = make_config(&server_addr);

        // Run the source, which will connect to the server and receive the pushed message.
        let events =
            run_and_assert_source_compliance(config, Duration::from_secs(2), &SOURCE_TAGS).await;

        // Now assert that the event was received and is correct.
        assert!(!events.is_empty(), "No events received from source");
        let event = events[0].as_log();
        assert_eq!(event["message"], "message from server".into());
        assert_eq!(*event.get_source_type().unwrap(), "websocket".into());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn websocket_source_sends_initial_message() {
        let initial_msg = "{\"action\":\"subscribe\",\"topic\":\"test\"}".to_string();
        let response_msg = "{\"status\":\"subscribed\",\"topic\":\"test\"}".to_string();
        let server_addr = start_subscribe_server(initial_msg.clone(), response_msg.clone()).await;

        let mut config = make_config(&server_addr);
        config.initial_message = Some(initial_msg);

        let events =
            run_and_assert_source_compliance(config, Duration::from_secs(2), &SOURCE_TAGS).await;

        assert!(!events.is_empty(), "No events received from source");
        let event = events[0].as_log();
        assert_eq!(event["message"], response_msg.into());
        assert_eq!(*event.get_source_type().unwrap(), "websocket".into());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn websocket_source_retries_on_connection_failures() {
        let addr = next_addr();
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
        let server_addr = format!("ws://{}", listener.local_addr().unwrap());

        // Server that fails once then succeeds
        tokio::spawn(async move {
            // First connection: close immediately
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }

            // Second connection: succeed
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.unwrap();
            websocket
                .send(Message::Text("retry success".to_string()))
                .await
                .unwrap();
        });

        let config = make_config(&server_addr);
        let events =
            run_and_assert_source_compliance(config, Duration::from_secs(5), &SOURCE_TAGS).await;

        assert!(!events.is_empty());
        assert_eq!(events[0].as_log()["message"], "retry success".into());
    }

    async fn start_close_handshake_server() -> String {
        let addr = next_addr();
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
        let server_addr = format!("ws://{}", listener.local_addr().unwrap());

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.expect("Failed to accept");
            websocket
                .send(Message::Text("before close".to_string()))
                .await
                .unwrap();

            websocket.send(Message::Close(None)).await.unwrap();

            // Wait for the client's close response before accepting a new connection
            let handshake_ok = loop {
                match websocket.next().await {
                    None => break true,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break false,
                }
            };

            if !handshake_ok {
                return;
            }

            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.expect("Failed to accept");
            websocket
                .send(Message::Text("after close".to_string()))
                .await
                .unwrap();
        });

        server_addr
    }

    #[tokio::test(flavor = "current_thread")]
    async fn websocket_source_completes_close_handshake() {
        let server_addr = start_close_handshake_server().await;
        let config = make_config(&server_addr);

        let events =
            run_and_assert_source_compliance(config, Duration::from_secs(5), &SOURCE_TAGS).await;

        assert_eq!(
            events.len(),
            2,
            "Should receive messages from both connections (close handshake must complete)"
        );
        assert_eq!(events[0].as_log()["message"], "before close".into());
        assert_eq!(events[1].as_log()["message"], "after close".into());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn websocket_source_reconnects_on_pong_timeout() {
        let server_addr = start_silent_then_recover_server(true).await;

        let mut config = make_config(&server_addr);
        config.common.ping_interval = NonZeroU64::new(1);
        config.ping_message = Some("ping".to_string());
        config.pong_message = Some(PongMessage::Simple("pong".to_string()));

        let events =
            run_and_assert_source_compliance(config, Duration::from_secs(8), &SOURCE_TAGS).await;

        assert_eq!(
            events.len(),
            2,
            "Should reconnect after pong timeout and receive messages from both connections"
        );
        assert_eq!(events[0].as_log()["message"], "before silence".into());
        assert_eq!(events[1].as_log()["message"], "after reconnect".into());
    }

}
