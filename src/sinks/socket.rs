use vector_lib::codecs::{
    encoding::{Framer, FramingConfig},
    TextSerializerConfig,
};
use vector_lib::configurable::configurable_component;

#[cfg(unix)]
use crate::sinks::util::unix::UnixSinkConfig;
use crate::{
    codecs::{Encoder, EncodingConfig, EncodingConfigWithFraming, SinkType},
    config::{AcknowledgementsConfig, GenerateConfig, Input, SinkConfig, SinkContext},
    sinks::util::{tcp::TcpSinkConfig, udp::UdpSinkConfig},
};

/// Configuration for the `socket` sink.
#[configurable_component(sink("socket", "Deliver logs to a remote socket endpoint."))]
#[derive(Clone, Debug)]
pub struct SocketSinkConfig {
    #[serde(flatten)]
    pub mode: Mode,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub acknowledgements: AcknowledgementsConfig,
}

/// Socket mode.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[configurable(metadata(docs::enum_tag_description = "The type of socket to use."))]
pub enum Mode {
    /// Send over TCP.
    Tcp(TcpMode),

    /// Send over UDP.
    Udp(UdpMode),

    /// Send over a Unix domain socket (UDS), in stream mode.
    #[cfg(unix)]
    #[serde(alias = "unix")]
    UnixStream(UnixMode),

    /// Send over a Unix domain socket (UDS), in datagram mode.
    /// Unavailable on macOS, due to send(2)'s apparent non-blocking behavior,
    /// resulting in ENOBUFS errors which we currently don't handle.
    #[cfg(unix)]
    #[cfg_attr(target_os = "macos", serde(skip))]
    UnixDatagram(UnixMode),
}

/// TCP configuration.
#[configurable_component]
#[derive(Clone, Debug)]
pub struct TcpMode {
    #[serde(flatten)]
    config: TcpSinkConfig,

    #[serde(flatten)]
    encoding: EncodingConfigWithFraming,
}

/// UDP configuration.
#[configurable_component]
#[derive(Clone, Debug)]
pub struct UdpMode {
    #[serde(flatten)]
    config: UdpSinkConfig,

    #[configurable(derived)]
    encoding: EncodingConfig,
}

/// Unix Domain Socket configuration.
#[cfg(unix)]
#[configurable_component]
#[derive(Clone, Debug)]
pub struct UnixMode {
    #[serde(flatten)]
    config: UnixSinkConfig,

    #[serde(flatten)]
    encoding: EncodingConfigWithFraming,
}

impl GenerateConfig for SocketSinkConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(
            r#"address = "92.12.333.224:5000"
            mode = "tcp"
            encoding.codec = "json""#,
        )
        .unwrap()
    }
}

impl SocketSinkConfig {
    pub const fn new(mode: Mode, acknowledgements: AcknowledgementsConfig) -> Self {
        SocketSinkConfig {
            mode,
            acknowledgements,
        }
    }

    pub fn make_basic_tcp_config(
        address: String,
        acknowledgements: AcknowledgementsConfig,
    ) -> Self {
        Self::new(
            Mode::Tcp(TcpMode {
                config: TcpSinkConfig::from_address(address),
                encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            }),
            acknowledgements,
        )
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "socket")]
impl SinkConfig for SocketSinkConfig {
    async fn build(
        &self,
        cx: SinkContext,
    ) -> crate::Result<(super::VectorSink, super::Healthcheck)> {
        match &self.mode {
            Mode::Tcp(TcpMode { config, encoding }) => {
                let transformer = encoding.transformer();
                let (framer, serializer) = encoding.build(SinkType::StreamBased)?;
                let encoder = Encoder::<Framer>::new(framer, serializer);
                config.build(transformer, encoder, cx.bytes_sent())
            }
            Mode::Udp(UdpMode { config, encoding }) => {
                let transformer = encoding.transformer();
                let serializer = encoding.build()?;
                let encoder = Encoder::<()>::new(serializer);
                config.build(transformer, encoder)
            }
            #[cfg(unix)]
            Mode::UnixStream(UnixMode { config, encoding }) => {
                let transformer = encoding.transformer();
                let (framer, serializer) = encoding.build(SinkType::StreamBased)?;
                let encoder = Encoder::<Framer>::new(framer, serializer);
                config.build(
                    transformer,
                    encoder,
                    super::util::service::net::UnixMode::Stream,
                    cx.bytes_sent(),
                )
            }
            #[cfg(unix)]
            Mode::UnixDatagram(UnixMode { config, encoding }) => {
                let transformer = encoding.transformer();
                let (framer, serializer) = encoding.build(SinkType::StreamBased)?;
                let encoder = Encoder::<Framer>::new(framer, serializer);
                config.build(
                    transformer,
                    encoder,
                    super::util::service::net::UnixMode::Datagram,
                    cx.bytes_sent(),
                )
            }
        }
    }

    fn input(&self) -> Input {
        let encoder_input_type = match &self.mode {
            Mode::Tcp(TcpMode { encoding, .. }) => encoding.config().1.input_type(),
            Mode::Udp(UdpMode { encoding, .. }) => encoding.config().input_type(),
            #[cfg(unix)]
            Mode::UnixStream(UnixMode { encoding, .. }) => encoding.config().1.input_type(),
            #[cfg(unix)]
            Mode::UnixDatagram(UnixMode { encoding, .. }) => encoding.config().1.input_type(),
        };
        Input::new(encoder_input_type)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::BTreeMap, future::ready, net::{SocketAddr, UdpSocket}
    };
    #[cfg(unix)]
    use std::{os::unix::net::UnixDatagram, path::PathBuf};

    use assert_matches::assert_matches;
    use futures::stream::StreamExt;
    use futures_util::stream;
    use serde_json::Value;
    use tokio::{
        net::TcpListener,
        time::{sleep, timeout, Duration},
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tokio_util::codec::{FramedRead, LinesCodec};
    use vector_lib::{codecs::{actions::Transformer, encoding::{format::{SyslogFormat, SyslogSerializerConfig}, Rfc5424, SerializerConfig, SyslogTimeRes, Truncation}, JsonSerializerConfig}, config::{TimePrecision, TimestampFormat}};
    #[cfg(unix)]
    use vector_lib::codecs::NativeJsonSerializerConfig;

    use super::*;
    #[cfg(unix)]
    use crate::test_util::random_metrics_with_stream;
    use crate::{
        config::SinkContext,
        event::{Event, LogEvent},
        test_util::{
            components::{
                assert_sink_compliance, build_run_and_assert_sink_compliance, SINK_TAGS,
            },
            next_addr, next_addr_v6, random_lines_with_stream, trace_init, CountReceiver,
        },
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<SocketSinkConfig>();
    }

    enum DatagramSocket {
        Udp(UdpSocket),
        #[cfg(unix)]
        Unix(UnixDatagram),
    }

    enum DatagramSocketAddr {
        Udp(SocketAddr),
        #[cfg(unix)]
        Unix(PathBuf),
    }

    async fn test_datagram(datagram_addr: DatagramSocketAddr) {
        let receiver = match &datagram_addr {
            DatagramSocketAddr::Udp(addr) => DatagramSocket::Udp(UdpSocket::bind(addr).unwrap()),
            #[cfg(unix)]
            DatagramSocketAddr::Unix(path) => {
                DatagramSocket::Unix(UnixDatagram::bind(path).unwrap())
            }
        };

        let config = SocketSinkConfig {
            mode: match &datagram_addr {
                DatagramSocketAddr::Udp(addr) => Mode::Udp(UdpMode {
                    config: UdpSinkConfig::from_address(addr.to_string()),
                    encoding: JsonSerializerConfig::default().into(),
                }),
                #[cfg(unix)]
                DatagramSocketAddr::Unix(path) => Mode::UnixDatagram(UnixMode {
                    config: UnixSinkConfig::new(path.to_path_buf()),
                    encoding: (None::<FramingConfig>, JsonSerializerConfig::default()).into(),
                }),
            },
            acknowledgements: Default::default(),
        };

        let context = SinkContext::default();
        assert_sink_compliance(&SINK_TAGS, async move {
            let (sink, _healthcheck) = config.build(context).await.unwrap();

            let event = Event::Log(LogEvent::from("raw log line"));
            sink.run(stream::once(ready(event.into()))).await
        })
        .await
        .expect("Running sink failed");

        let mut buf = [0; 256];
        let size = match &receiver {
            DatagramSocket::Udp(sock) => {
                sock.recv_from(&mut buf).expect("Did not receive message").0
            }
            #[cfg(unix)]
            DatagramSocket::Unix(sock) => sock.recv(&mut buf).expect("Did not receive message"),
        };

        let packet = String::from_utf8(buf[..size].to_vec()).expect("Invalid data received");
        let data = serde_json::from_str::<Value>(&packet).expect("Invalid JSON received");
        let data = data.as_object().expect("Not a JSON object");
        assert!(data.get("timestamp").is_some());
        let message = data.get("message").expect("No message in JSON");
        assert_eq!(message, &Value::String("raw log line".into()));
    }

    #[tokio::test]
    async fn udp_ipv4() {
        trace_init();

        test_datagram(DatagramSocketAddr::Udp(next_addr())).await;
    }

    #[tokio::test]
    async fn udp_ipv6() {
        trace_init();

        test_datagram(DatagramSocketAddr::Udp(next_addr_v6())).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_datagram() {
        trace_init();

        test_datagram(DatagramSocketAddr::Unix(temp_uds_path(
            "unix_datagram_socket_test",
        )))
        .await;
    }

    #[tokio::test]
    async fn sent_bytes_series_exists_after_build_tcp() {
        let config = SocketSinkConfig::make_basic_tcp_config("127.0.0.1:1".to_string(), Default::default());
        crate::test_util::components::assert_sent_bytes_series_after_build(config).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sent_bytes_series_exists_after_build_unix_stream() {
        let config = SocketSinkConfig {
            mode: Mode::UnixStream(UnixMode {
                config: UnixSinkConfig::new(temp_uds_path("sent_bytes_series_unix_stream")),
                encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            }),
            acknowledgements: Default::default(),
        };
        crate::test_util::components::assert_sent_bytes_series_after_build(config).await;
    }

    #[tokio::test]
    async fn tcp_stream_counts_the_bytes_it_sends() {
        trace_init();

        let addr = next_addr();
        let config = SocketSinkConfig {
            mode: Mode::Tcp(TcpMode {
                config: TcpSinkConfig::from_address(addr.to_string()),
                encoding: (None::<FramingConfig>, JsonSerializerConfig::default()).into(),
            }),
            acknowledgements: Default::default(),
        };

        let mut receiver = CountReceiver::receive_lines(addr);
        let (_lines, events) = random_lines_with_stream(10, 100, None);

        assert_sink_compliance(&SINK_TAGS, async move {
            let context = SinkContext::default();
            let (sink, _healthcheck) = config.build(context).await.unwrap();

            sink.run(events).await
        })
        .await
        .expect("Running sink failed");

        receiver.connected().await;
        let output = receiver.await;

        // Each event is one line plus the newline that frames it. The counter has no
        // `protocol` tag and equals the bytes the receiver got.
        let received_bytes: usize = output.iter().map(|line| line.len() + 1).sum();
        assert!(received_bytes > 0);
        assert_eq!(
            crate::test_util::components::sent_bytes_total(),
            Some(received_bytes as f64)
        );
    }

    #[tokio::test]
    async fn tcp_stream() {
        trace_init();

        let addr = next_addr();
        let config = SocketSinkConfig {
            mode: Mode::Tcp(TcpMode {
                config: TcpSinkConfig::from_address(addr.to_string()),
                encoding: (None::<FramingConfig>, JsonSerializerConfig::default()).into(),
            }),
            acknowledgements: Default::default(),
        };

        let mut receiver = CountReceiver::receive_lines(addr);

        let (lines, events) = random_lines_with_stream(10, 100, None);

        assert_sink_compliance(&SINK_TAGS, async move {
            let context = SinkContext::default();
            let (sink, _healthcheck) = config.build(context).await.unwrap();

            sink.run(events).await
        })
        .await
        .expect("Running sink failed");

        // Wait for output to connect
        receiver.connected().await;

        let output = receiver.await;
        assert_eq!(lines.len(), output.len());
        for (source, received) in lines.iter().zip(output) {
            let json = serde_json::from_str::<Value>(&received).expect("Invalid JSON");
            let received = json.get("message").unwrap().as_str().unwrap();
            assert_eq!(source, received);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn metrics_socket() {
        trace_init();

        let out_path = temp_uds_path("unix_socket_test");
        let mut receiver = CountReceiver::receive_lines_unix(out_path.clone());

        let config = SocketSinkConfig {
            mode: Mode::UnixStream(UnixMode {
                config: UnixSinkConfig::new(out_path),
                encoding: (None::<FramingConfig>, NativeJsonSerializerConfig).into(),
            }),
            acknowledgements: Default::default(),
        };

        let (expected, events) = random_metrics_with_stream(10, None, None);

        assert_sink_compliance(&SINK_TAGS, async move {
            let context = SinkContext::default();
            let (sink, _healthcheck) = config.build(context).await.unwrap();

            sink.run(events).await
        })
        .await
        .expect("Running sink failed");

        // Wait for output to connect
        receiver.connected().await;

        let output = receiver.await;
        assert_eq!(expected.len(), output.len());
        for (source, received) in expected.iter().zip(output) {
            let json = serde_json::from_str::<Value>(&received).expect("Invalid JSON");
            let received = json.get("metric").unwrap();
            let received_name = received.get("name").unwrap().as_str().unwrap();
            assert_eq!(source.as_metric().name(), received_name);
        }
    }

    // This is a test that checks that we properly receive all events in the
    // case of a proper server side write side shutdown.
    //
    // This test basically sends 10 events, shuts down the server and forces a
    // reconnect. It then forces another 10 events through and we should get a
    // total of 20 events.
    //
    // If this test hangs that means somewhere we are not collecting the correct
    // events.
    #[tokio::test]
    async fn tcp_stream_detects_disconnect() {
        use std::{
            pin::Pin,
            sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            },
            task::Poll,
        };

        use futures::{channel::mpsc, FutureExt, SinkExt, StreamExt};
        use tokio::{
            io::{AsyncRead, AsyncWriteExt, ReadBuf},
            net::TcpStream,
            task::yield_now,
            time::{interval, Duration},
        };
        use tokio_stream::wrappers::IntervalStream;

        use crate::event::EventArray;
        use crate::tls::{
            self, MaybeTlsIncomingStream, MaybeTlsSettings, TlsConfig, TlsEnableableConfig,
        };

        trace_init();

        let addr = next_addr();
        let config = SocketSinkConfig {
            mode: Mode::Tcp(TcpMode {
                config: TcpSinkConfig::new(
                    addr.to_string(),
                    None,
                    Some(TlsEnableableConfig {
                        enabled: Some(true),
                        options: TlsConfig {
                            verify_certificate: Some(false),
                            verify_hostname: Some(false),
                            ca_file: Some(tls::TEST_PEM_CRT_PATH.into()),
                            ..Default::default()
                        },
                    }),
                    None,
                ),
                encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            }),
            acknowledgements: Default::default(),
        };
        let sink_future = async move { config.build(SinkContext::default()).await.unwrap().0 };
        let (mut sender, receiver) = mpsc::channel::<Option<EventArray>>(0);
        let jh1 = tokio::spawn(async move {
            let stream = receiver
                .take_while(|event| ready(event.is_some()))
                .map(|event| event.unwrap())
                .boxed();
            build_run_and_assert_sink_compliance(sink_future, stream, &SINK_TAGS).await
        });

        let msg_counter = Arc::new(AtomicUsize::new(0));
        let msg_counter1 = Arc::clone(&msg_counter);
        let conn_counter = Arc::new(AtomicUsize::new(0));
        let conn_counter1 = Arc::clone(&conn_counter);

        let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
        let mut close_rx = Some(close_rx.map(|x| x.unwrap()));

        let config = Some(TlsEnableableConfig::test_config());

        // Only accept two connections.
        let jh2 = tokio::spawn(async move {
            let tls = MaybeTlsSettings::from_config(config.as_ref(), true).unwrap();
            let listener = tls.bind(&addr).await.unwrap();
            listener
                .accept_stream()
                .take(2)
                .for_each(|connection| {
                    let mut close_rx = close_rx.take();

                    conn_counter1.fetch_add(1, Ordering::SeqCst);
                    let msg_counter1 = Arc::clone(&msg_counter1);

                    let mut stream: MaybeTlsIncomingStream<TcpStream> = connection.unwrap();

                    std::future::poll_fn(move |cx| loop {
                        if let Some(fut) = close_rx.as_mut() {
                            if let Poll::Ready(()) = fut.poll_unpin(cx) {
                                stream
                                    .get_mut()
                                    .unwrap()
                                    .shutdown()
                                    .now_or_never()
                                    .unwrap()
                                    .unwrap();
                                close_rx = None;
                            }
                        }

                        let mut buf = [0u8; 11];
                        let mut buf = ReadBuf::new(&mut buf);
                        return match Pin::new(&mut stream).poll_read(cx, &mut buf) {
                            Poll::Ready(Ok(())) => {
                                if buf.filled().is_empty() {
                                    Poll::Ready(())
                                } else {
                                    msg_counter1.fetch_add(1, Ordering::SeqCst);
                                    continue;
                                }
                            }
                            Poll::Ready(Err(error)) => panic!("{}", error),
                            Poll::Pending => Poll::Pending,
                        };
                    })
                })
                .await;
        });

        let (_, mut events) = random_lines_with_stream(10, 10, None);
        while let Some(event) = events.next().await {
            sender.send(Some(event)).await.unwrap();
        }

        // Loop and check for 10 events, we should always get 10 events. Once,
        // we have 10 events we can tell the server to shutdown to simulate the
        // remote shutting down on an idle connection.
        IntervalStream::new(interval(Duration::from_millis(100)))
            .take(500)
            .take_while(|_| ready(msg_counter.load(Ordering::SeqCst) != 10))
            .for_each(|_| ready(()))
            .await;
        close_tx.send(()).unwrap();

        // Close connection in spawned future
        yield_now().await;

        assert_eq!(msg_counter.load(Ordering::SeqCst), 10);
        assert_eq!(conn_counter.load(Ordering::SeqCst), 1);

        // Send another 10 events
        let (_, mut events) = random_lines_with_stream(10, 10, None);
        while let Some(event) = events.next().await {
            sender.send(Some(event)).await.unwrap();
        }

        // Wait for server task to be complete.
        sender.send(None).await.unwrap();
        jh1.await.unwrap();
        jh2.await.unwrap();

        // Check that there are exactly 20 events.
        assert_eq!(msg_counter.load(Ordering::SeqCst), 20);
        assert_eq!(conn_counter.load(Ordering::SeqCst), 2);
    }

    /// Tests whether socket recovers from a hard disconnect.
    #[tokio::test]
    async fn reconnect() {
        trace_init();

        let addr = next_addr();
        let config = SocketSinkConfig {
            mode: Mode::Tcp(TcpMode {
                config: TcpSinkConfig::from_address(addr.to_string()),
                encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            }),
            acknowledgements: Default::default(),
        };

        let sink_future = async move { config.build(SinkContext::default()).await.unwrap().0 };

        let (_, events) = random_lines_with_stream(1000, 10000, None);
        let sink_handle = tokio::spawn(build_run_and_assert_sink_compliance(
            sink_future,
            events,
            &SINK_TAGS,
        ));

        // First listener
        let mut count = 20usize;
        TcpListenerStream::new(TcpListener::bind(addr).await.unwrap())
            .next()
            .await
            .unwrap()
            .map(|socket| FramedRead::new(socket, LinesCodec::new()))
            .unwrap()
            .map(|x| x.unwrap())
            .take_while(|_| {
                ready(if count > 0 {
                    count -= 1;
                    true
                } else {
                    false
                })
            })
            .collect::<Vec<_>>()
            .await;

        // Disconnect
        if cfg!(windows) {
            // Gives Windows time to release the addr port.
            sleep(Duration::from_secs(1)).await;
        }

        // Second listener
        // If this doesn't succeed then the sink hanged.
        assert!(timeout(
            Duration::from_secs(5),
            CountReceiver::receive_lines(addr).connected()
        )
        .await
        .is_ok());

        sink_handle.await.unwrap();
    }

    #[cfg(unix)]
    fn temp_uds_path(name: &str) -> PathBuf {
        tempfile::tempdir().unwrap().into_path().join(name)
    }

    #[test]
    fn test_tcp_syslog_5424_config() {
        let toml = r#"
        mode = "tcp"
        address = "127.0.0.1:514"
        [framing]
        method = "octet_counted"
        [encoding]
        codec = "syslog"
        [encoding.format]
        rfc = "rfc5424"
        bom = true
        res = "millis"
        [encoding.ts_format.native]
        "#;

        let config: SocketSinkConfig = toml::from_str(toml).expect("Couldn't build RFC5424 config");

        assert_matches!(
            config,
            SocketSinkConfig { mode: Mode::Tcp(
                TcpMode{
                    config: TcpSinkConfig{address, ..},
                    encoding: EncodingConfigWithFraming {
                        framing: Some(framing),
                        encoding: EncodingConfig{
                            encoding: SerializerConfig::Syslog(syslog),
                            transformer,
                        },
                    }}), .. } => {
                assert_eq!(framing, FramingConfig::OctetCounted);
                assert_eq!(syslog, SyslogSerializerConfig::new(
                    SyslogFormat::Rfc5424(Rfc5424::new(SyslogTimeRes::Milliseconds, true, true)),
                    TimestampFormat::Native,
                    None));
                assert_eq!(transformer, Transformer::new(None, None, None, BTreeMap::new()).unwrap());
                assert_eq!(address.as_str(), "127.0.0.1:514");
            });
    }

    #[test]
    fn test_tcp_syslog_5424_config_with_non_transparent_framing() {
        let toml = r#"
        mode = "tcp"
        address = "127.0.0.1:514"
        [framing]
        method = "newline_delimited"
        [encoding]
        codec = "syslog"
        [encoding.format]
        rfc = "rfc5424"
        bom = true
        res = "millis"
        [encoding.ts_format]
        numeric = "us"
        "#;

        let config: SocketSinkConfig = toml::from_str(toml).expect("Couldn't build RFC5424 config");

        assert_matches!(
            config,
            SocketSinkConfig { mode: Mode::Tcp(
                TcpMode{
                    config: TcpSinkConfig{address, ..},
                    encoding: EncodingConfigWithFraming {
                        framing: Some(framing),
                        encoding: EncodingConfig{
                            encoding: SerializerConfig::Syslog(syslog),
                            transformer,
                        },
                    }}), .. } => {
                assert_eq!(framing, FramingConfig::NewlineDelimited);
                assert_eq!(syslog, SyslogSerializerConfig::new(
                    SyslogFormat::Rfc5424(Rfc5424::new(SyslogTimeRes::Milliseconds, true, true)),
                    TimestampFormat::Numeric(TimePrecision::Microseconds),
                    None));
                assert_eq!(transformer, Transformer::new(None, None, None, BTreeMap::new()).unwrap());
                assert_eq!(address.as_str(), "127.0.0.1:514");
            });
    }

    #[test]
    fn test_udp_syslog_5424_config() {
        let toml = r#"
        mode = "udp"
        address = "127.0.0.1:514"
        [encoding]
        codec = "syslog"
        [encoding.rename]
        host = ["sender", "peer"]
        timestamp = ["ts"]
        [encoding.format]
        rfc = "rfc5424"
        res = "s"
        [encoding.ts_format]
        str = "%Y-%m-%dT%H:%M:%S.%f"
        [encoding.trunc]
        max_len = 1472
        elipsis = "..."
        "#;

        let config: SocketSinkConfig = toml::from_str(toml).expect("Couldn't build RFC5424 config");

        assert_matches!(
            config,
            SocketSinkConfig { mode: Mode::Udp(
                UdpMode {
                    config: UdpSinkConfig{address, ..},
                    encoding: EncodingConfig{
                        encoding: SerializerConfig::Syslog(syslog),
                        transformer,
                    },
                }),
                ..
            } => {
                assert_eq!(syslog, SyslogSerializerConfig::new(
                    SyslogFormat::Rfc5424(Rfc5424::new(SyslogTimeRes::Seconds, true, false)),
                    TimestampFormat::Fmtstr("%Y-%m-%dT%H:%M:%S.%f".into()),
                    Some(Truncation::new(1472, Some("...".into()))))); // eg. mtu = 1500
                assert_eq!(
                    transformer,
                    Transformer::new(
                        None,
                        None,
                        None,
                        [("host", &["sender", "peer"][..]), ("timestamp", &["ts"][..])]
                            .into_iter()
                            .map(|(k, v)| (k.into(), v.into_iter().map(|v| (*v).into()).collect()))
                            .collect())
                    .unwrap());
                assert_eq!(address.as_str(), "127.0.0.1:514");
            });
    }

    #[test]
    fn test_udp_syslog_3164_config() {
        let toml = r#"
        mode = "udp"
        address = "127.0.0.1:514"
        [encoding]
        codec = "syslog"
        [encoding.rename]
        host = ["sender", "peer"]
        timestamp = ["ts"]
        [encoding.format]
        rfc = "3164"
        [encoding.ts_format]
        str = "%Y-%m-%dT%H:%M:%S.%f"
        [encoding.trunc]
        max_len = 1472
        "#;

        let config: SocketSinkConfig = toml::from_str(toml).expect("Couldn't build RFC3164 config");

        assert_matches!(
            config,
            SocketSinkConfig { mode: Mode::Udp(
                UdpMode {
                    config: UdpSinkConfig{address, ..},
                    encoding: EncodingConfig{
                        encoding: SerializerConfig::Syslog(syslog),
                        transformer,
                    },
                }),
                ..
            } => {
                assert_eq!(syslog, SyslogSerializerConfig::new(
                    SyslogFormat::Rfc3164,
                    TimestampFormat::Fmtstr("%Y-%m-%dT%H:%M:%S.%f".into()),
                    Some(Truncation::new(1472, None)))); // eg. mtu = 1500
                assert_eq!(
                    transformer,
                    Transformer::new(
                        None,
                        None,
                        None,
                        [("host", &["sender", "peer"][..]), ("timestamp", &["ts"][..])]
                            .into_iter()
                            .map(|(k, v)| (k.into(), v.into_iter().map(|v| (*v).into()).collect()))
                            .collect())
                    .unwrap());
                assert_eq!(address.as_str(), "127.0.0.1:514");
            });
    }

    #[test]
    fn test_pre_encoded_syslog_config() {
        let toml = r#"
        mode = "udp"
        address = "127.0.0.1:514"
        [encoding]
        codec = "raw_message"
        "#;

        let config: SocketSinkConfig = toml::from_str(toml).expect("Couldn't build RFC3164 config");

        assert_matches!(
            config,
            SocketSinkConfig { mode: Mode::Udp(
                UdpMode {
                    config: UdpSinkConfig{address, ..},
                    encoding: EncodingConfig{
                        encoding: SerializerConfig::RawMessage,
                        ..
                    },
                }),
                ..
            } if address.as_str() == "127.0.0.1:514");
    }
}
