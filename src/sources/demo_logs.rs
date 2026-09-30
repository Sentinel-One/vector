use std::fmt;
use chrono::Utc;
use fakedata::logs::*;
use futures::StreamExt;
use rand::seq::SliceRandom;
use serde_with::serde_as;
use snafu::Snafu;
use std::task::Poll;
use tokio::time::{self, Duration};
use tokio_util::codec::FramedRead;
use vector_lib::codecs::{
    decoding::{DeserializerConfig, FramingConfig},
    StreamDecodingError,
};
use vector_lib::configurable::configurable_component;
use vector_lib::internal_event::{
    ByteSize, BytesReceived, CountByteSize, InternalEventHandle as _, Protocol,
};
use vector_lib::lookup::{owned_value_path, path};
use vector_lib::{
    config::{LegacyKey, LogNamespace},
    EstimatedJsonEncodedSizeOf,
};
use vrl::value::Kind;

use crate::{
    codecs::{Decoder, DecodingConfig},
    config::{SourceConfig, SourceContext, SourceOutput},
    internal_events::{DemoLogsEventProcessed,  EventsReceived, StreamClosedError},
    serde::{default_decoding, default_framing_message_based},
    shutdown::ShutdownSignal,
    SourceSender,
};
use chrono::Local;
use csv::ReaderBuilder;
use std::fs::File;

/// Configuration for the `demo_logs` source.
#[serde_as]
#[configurable_component(source(
    "demo_logs",
    "Generate fake log events, which can be useful for testing and demos."
))]
#[derive(Clone, Debug, Derivative)]
#[derivative(Default)]
pub struct DemoLogsConfig {
    /// The amount of time, in seconds, to pause between each batch of output lines.
    ///
    /// The default is one batch per second. To remove the delay and output batches as quickly as possible, set
    /// `interval` to `0.0`.
    #[serde(alias = "batch_interval")]
    #[derivative(Default(value = "default_interval()"))]
    #[serde(default = "default_interval")]
    #[configurable(metadata(docs::examples = 1.0, docs::examples = 0.1, docs::examples = 0.01,))]
    #[serde_as(as = "serde_with::DurationSecondsWithFrac<f64>")]
    pub interval: Duration,

    /// The total number of lines to output.
    ///
    /// By default, the source continuously prints logs (infinitely).
    #[derivative(Default(value = "default_count()"))]
    #[serde(default = "default_count")]
    pub count: usize,

    #[serde(flatten)]
    #[configurable(metadata(
        docs::enum_tag_description = "The format of the randomly generated output."
    ))]
    pub format: OutputFormat,

    #[configurable(derived)]
    #[derivative(Default(value = "default_framing_message_based()"))]
    #[serde(default = "default_framing_message_based")]
    pub framing: FramingConfig,

    #[configurable(derived)]
    #[derivative(Default(value = "default_decoding()"))]
    #[serde(default = "default_decoding")]
    pub decoding: DeserializerConfig,

    /// The namespace to use for logs. This overrides the global setting.
    #[serde(default)]
    #[configurable(metadata(docs::hidden))]
    pub log_namespace: Option<bool>,
}

const fn default_interval() -> Duration {
    Duration::from_secs(1)
}

const fn default_count() -> usize {
    isize::MAX as usize
}

#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum DemoLogsConfigError {
    #[snafu(display("A non-empty list of lines is required for the shuffle format"))]
    ShuffleDemoLogsItemsEmpty,
    #[snafu(display("A non-empty sample log file is required for sample file format"))]
    SampleFileDemoLogsEmpty,
    #[snafu(display("A non-empty time format is required for sample file format"))]
    SampleFileTimeFormatEmpty,
    #[snafu(display("time format provided is invalid for sample file format"))]
    SampleFileTimeFormatInvalid,
    #[snafu(display("Could not open sample file"))]
    SampleFileOpenFailed {
        message: String,
    },
    #[snafu(display("Could not read sample file"))]
    SampleFileReadFailed {
        message: String,
    },
    #[snafu(display("Not implemented"))]
    NotImplemented,
}

#[derive(Clone, Debug, Derivative)]
enum GenCtx {
    TimeJoin {
        data: Vec<(String, String)>,
    },
    None,
}

/// Output format configuration.
#[configurable_component]
#[derive(Clone, Debug, Derivative)]
#[derivative(Default)]
#[serde(tag = "format", rename_all = "snake_case")]
#[configurable(metadata(
    docs::enum_tag_description = "The format of the randomly generated output."
))]
pub enum OutputFormat {
    /// Lines are chosen in round robin fashion from file (at path)
    SampleFile {
        /// File path to read lines from.
        /// File must be a two column csv with time_prefix and time_suffix
        #[configurable(metadata(docs::examples = "path_example()"))]
        path: String,
        /// Format of timestamp to inject.
        #[configurable(metadata(docs::examples = "time_format_example()"))]
        time_format: String,
    },

    /// Lines are chosen at random from the list specified using `lines`.
    Shuffle {
        /// If `true`, each output line starts with an increasing sequence number, beginning with 0.
        #[serde(default)]
        sequence: bool,
        /// The list of lines to output.
        #[configurable(metadata(docs::examples = "lines_example()"))]
        lines: Vec<String>,
    },

    /// Randomly generated logs in [Apache common][apache_common] format.
    ///
    /// [apache_common]: https://httpd.apache.org/docs/current/logs.html#common
    ApacheCommon,

    /// Randomly generated logs in [Apache error][apache_error] format.
    ///
    /// [apache_error]: https://httpd.apache.org/docs/current/logs.html#errorlog
    ApacheError,

    /// Randomly generated logs in Syslog format ([RFC 5424][syslog_5424]).
    ///
    /// [syslog_5424]: https://tools.ietf.org/html/rfc5424
    #[serde(alias = "rfc5424")]
    Syslog,

    /// Randomly generated logs in Syslog format ([RFC 3164][syslog_3164]).
    ///
    /// [syslog_3164]: https://tools.ietf.org/html/rfc3164
    #[serde(alias = "rfc3164")]
    BsdSyslog,

    /// Randomly generated HTTP server logs in [JSON][json] format.
    ///
    /// [json]: https://en.wikipedia.org/wiki/JSON
    #[derivative(Default)]
    Json,
}

const fn lines_example() -> [&'static str; 2] {
    ["line1", "line2"]
}

const fn path_example() -> &'static str {
    "/foo/bar/foobar.log"
}

const fn time_format_example() -> &'static str {
    "%Y-%m-%d %H:%M:%S"
}

impl OutputFormat {
    fn build_gen_ctx(&self) -> Result<GenCtx, DemoLogsConfigError> {
        match self {
            Self::SampleFile { path, .. } => {
                let file = File::open(path)
                    .map_err(|e| DemoLogsConfigError::SampleFileOpenFailed { message: e.to_string() })?;
                let mut rdr = ReaderBuilder::new().from_reader(file);

                let mut csv_lines = Vec::<(String, String)>::new();
                for result in rdr.records() {
                    let record = result
                        .map_err(|e| DemoLogsConfigError::SampleFileReadFailed { message: e.to_string() })?;
                    csv_lines.push((
                        record.get(0).unwrap_or("").to_string(),
                        record.get(1).unwrap_or("").to_string()));
                }
                if csv_lines.len() == 0 {
                    return Err(DemoLogsConfigError::SampleFileDemoLogsEmpty);
                }

                Ok(GenCtx::TimeJoin { data: csv_lines })
            },
            _ => Ok(GenCtx::None),
        }
    }

    fn generate_line(&self, n: usize, gen_ctx: &GenCtx) -> String {
        emit!(DemoLogsEventProcessed);

        match self {
            Self::SampleFile { time_format, .. } => {
                match gen_ctx {
                    GenCtx::TimeJoin { data } => {
                        let (time_prefix, time_suffix) = &data[n % data.len()];
                        let now = Local::now();

                        let timestamp = match try_format_timestamp(&now, time_format) {
                            Some(ts) => ts,
                            None => {
                                warn!("Failed to format timestamp with provided time_format, falling back to RFC3339");
                                now.to_rfc3339()
                            }
                        };
                        format!("{}{}{}", time_prefix, timestamp, time_suffix)
                    }
                    GenCtx::None => {
                        panic!("Sample-file format requires TimeJoin generator-context")
                    }
                }
            },
            Self::Shuffle {
                sequence,
                ref lines,
            } => Self::shuffle_generate(*sequence, lines, n),
            Self::ApacheCommon => apache_common_log_line(),
            Self::ApacheError => apache_error_log_line(),
            Self::Syslog => syslog_5424_log_line(),
            Self::BsdSyslog => syslog_3164_log_line(),
            Self::Json => json_log_line(),
        }
    }

    fn shuffle_generate(sequence: bool, lines: &[String], n: usize) -> String {
        // unwrap can be called here because `lines` can't be empty
        let line = lines.choose(&mut rand::thread_rng()).unwrap();

        if sequence {
            format!("{} {}", n, line)
        } else {
            line.into()
        }
    }

    // Ensures that the `lines` list is non-empty if `Shuffle` is chosen
    pub(self) fn validate(&self) -> Result<(), DemoLogsConfigError> {
        match self {
            Self::Shuffle { lines, .. } => {
                if lines.is_empty() {
                    Err(DemoLogsConfigError::ShuffleDemoLogsItemsEmpty)
                } else {
                    Ok(())
                }
            }
            Self::SampleFile {path, time_format} => {
                if path.is_empty() {
                    return Err(DemoLogsConfigError::SampleFileDemoLogsEmpty);
                } else if time_format.is_empty() {
                    return Err(DemoLogsConfigError::SampleFileTimeFormatEmpty);
                }

                match try_format_timestamp(&Local::now(), time_format) {
                    Some(_) => Ok(()),
                    None => Err(DemoLogsConfigError::SampleFileTimeFormatInvalid),
                }
            }
            _ => Ok(()),
        }
    }
}

fn try_format_timestamp(time: &chrono::DateTime<Local>, time_format: &str) -> Option<String> {
    let fmt_obj = time.format(time_format); // bind formatter so it outlives use
    let mut buf = String::new();
    if fmt::write(&mut buf, format_args!("{}", fmt_obj)).is_ok() {
        Some(buf)
    } else {
        None
    }
}

impl DemoLogsConfig {
    #[cfg(test)]
    pub fn repeat(
        lines: Vec<String>,
        count: usize,
        interval: Duration,
        log_namespace: Option<bool>,
    ) -> Self {
        Self {
            count,
            interval,
            format: OutputFormat::Shuffle {
                lines,
                sequence: false,
            },
            framing: default_framing_message_based(),
            decoding: default_decoding(),
            log_namespace,
        }
    }
}

async fn demo_logs_source(
    interval: Duration,
    count: usize,
    format: OutputFormat,
    decoder: Decoder,
    mut shutdown: ShutdownSignal,
    mut out: SourceSender,
    log_namespace: LogNamespace,
    gen_ctx : GenCtx,
) -> Result<(), ()> {
    let interval: Option<Duration> = (interval != Duration::ZERO).then_some(interval);
    let mut interval = interval.map(time::interval);

    let bytes_received = register!(BytesReceived::from(Protocol::NONE));
    let events_received = register!(EventsReceived);

    for n in 0..count {
        if matches!(futures::poll!(&mut shutdown), Poll::Ready(_)) {
            break;
        }

        if let Some(interval) = &mut interval {
            interval.tick().await;
        }
        bytes_received.emit(ByteSize(0));

        let line = format.generate_line(n, &gen_ctx);

        let mut stream = FramedRead::new(line.as_bytes(), decoder.clone());
        while let Some(next) = stream.next().await {
            match next {
                Ok((events, _byte_size)) => {
                    let count = events.len();
                    let byte_size = events.estimated_json_encoded_size_of();
                    events_received.emit(CountByteSize(count, byte_size));
                    let now = Utc::now();

                    let events = events.into_iter().map(|mut event| {
                        let log = event.as_mut_log();
                        log_namespace.insert_standard_vector_source_metadata(
                            log,
                            "observo_sample_logs",
                            now,
                        );
                        log_namespace.insert_source_metadata(
                            DemoLogsConfig::NAME,
                            log,
                            Some(LegacyKey::InsertIfEmpty(path!("service"))),
                            path!("service"),
                            "observo.ai",
                        );
                        log_namespace.insert_source_metadata(
                            DemoLogsConfig::NAME,
                            log,
                            Some(LegacyKey::InsertIfEmpty(path!("host"))),
                            path!("host"),
                            "localhost",
                        );

                        event
                    });
                    out.send_batch(events).await.map_err(|_| {
                        emit!(StreamClosedError { count });
                    })?;
                }
                Err(error) => {
                    // Error is logged by `crate::codecs::Decoder`, no further
                    // handling is needed here.
                    if !error.can_continue() {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

impl_generate_config_from_default!(DemoLogsConfig);

#[async_trait::async_trait]
#[typetag::serde(name = "demo_logs")]
impl SourceConfig for DemoLogsConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<super::Source> {
        let log_namespace = cx.log_namespace(self.log_namespace);

        self.format.validate()?;
        let decoder =
            DecodingConfig::new(self.framing.clone(), self.decoding.clone(), log_namespace, cx.globals.ops_limits)
                .build()?;

        let gen_ctx = self.format.build_gen_ctx()?;

        let src = demo_logs_source(
            self.interval,
            self.count,
            self.format.clone(),
            decoder,
            cx.shutdown,
            cx.out,
            log_namespace,
            gen_ctx);

        Ok(Box::pin(src))
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        // There is a global and per-source `log_namespace` config. The source config overrides the global setting,
        // and is merged here.
        let log_namespace = global_log_namespace.merge(self.log_namespace);

        let schema_definition = self
            .decoding
            .schema_definition(log_namespace)
            .with_standard_vector_source_metadata()
            .with_source_metadata(
                DemoLogsConfig::NAME,
                Some(LegacyKey::InsertIfEmpty(owned_value_path!("service"))),
                &owned_value_path!("service"),
                Kind::bytes(),
                Some("service"),
            );

        vec![SourceOutput::new_maybe_logs(
            self.decoding.output_type(),
            schema_definition,
        )]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use futures::{poll, Stream, StreamExt};
    use tempfile::NamedTempFile;
    use serde_json;
    use chrono::NaiveDateTime;
    use csv::WriterBuilder;
    use std::mem;

    use super::*;
    use crate::{
        config::log_schema,
        event::Event,
        shutdown::ShutdownSignal,
        test_util::components::{assert_source_compliance, SOURCE_TAGS},
        SourceSender,
    };

    fn validate_log_line_with_timestamp(pattern: &str, actual: &str) {
        match NaiveDateTime::parse_from_str(actual, pattern) {
            Ok(_) => {},  // Successfully parsed
            Err(_) => {
                // println!("actual: {}, expected_pattern: {}", actual, pattern);
                panic!("actual log differs from expected pattern")
            }
        }
    }

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<DemoLogsConfig>();
    }

    async fn runit(config: &str) -> impl Stream<Item = Event> {
        assert_source_compliance(&SOURCE_TAGS, async {
            let (tx, rx) = SourceSender::new_test();
            let config: DemoLogsConfig = toml::from_str(config).unwrap();
            let decoder = DecodingConfig::new(
                default_framing_message_based(),
                default_decoding(),
                LogNamespace::Legacy,
                Default::default(),
            )
            .build()
            .unwrap();
            let gen_ctx = config.format.build_gen_ctx().unwrap();
            demo_logs_source(
                config.interval,
                config.count,
                config.format,
                decoder,
                ShutdownSignal::noop(),
                tx,
                LogNamespace::Legacy,
                gen_ctx)
            .await
            .unwrap();

            rx
        })
        .await
    }

    #[tokio::test]
    async fn test_sample_file_generate_reads_syslog_lines_correctly() {
        let mut tempfile = NamedTempFile::new().unwrap();
        let mut wtr = WriterBuilder::new()
            .has_headers(true)
            .flexible(false)
            .quote_style(csv::QuoteStyle::NonNumeric)
            .from_writer(&mut tempfile);

        let syslog_lines= vec![
            // prefix empty
            ("", " myhost sshd[1234]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2"),
            // suffix empty
            ("myhost sshd[1234]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2 time: ", ""),
            // both prefix and suffix empty
            ("", ""),
            ("Timestamp: ", " myhost systemd[1]: Started Session 42 of user root."),
            ("Time: ", " myhost kernel: [123456.789012] eth0: link up, 1000 Mbps, full-duplex"),
        ];
        let expected_log_patterns = [
            "%d/%b/%Y:%H:%M:%S myhost sshd[1234]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2",
            "myhost sshd[1234]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2 time: %d/%b/%Y:%H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
            "Timestamp: %d/%b/%Y:%H:%M:%S myhost systemd[1]: Started Session 42 of user root.",
            "Time:%d/%b/%Y:%H:%M:%S myhost kernel: [123456.789012] eth0: link up, 1000 Mbps, full-duplex",
        ];

        wtr.write_record(&["prefix", "suffix"]).unwrap();
        for (prefix, suffix) in &syslog_lines {
            wtr.write_record(&[prefix, suffix]).unwrap();
        }
        wtr.flush().unwrap();
        mem::drop(wtr);

        let path = tempfile.path().to_string_lossy();
        let pattern = "%d/%b/%Y:%H:%M:%S";
        let message_key = log_schema().message_key().unwrap().to_string();
        let demo_log_config = DemoLogsConfig {
            format: OutputFormat::SampleFile {
                path: (&path).to_string(),
                time_format: pattern.to_string(),
            },
            count: 8,
            ..DemoLogsConfig::default()
        };
        let toml_string = toml::to_string(&demo_log_config).unwrap();

        let mut rx = runit(toml_string.as_str()).await;

        let length = expected_log_patterns.len();
        for num in 0..5 {
            let event = match poll!(rx.next()) {
                Poll::Ready(event) => event.unwrap(),
                _ => unreachable!(),
            };
            let log = event.as_log();
            let message = log[&message_key].to_string_lossy();
            let expected_log_pattern = expected_log_patterns[num%length];
            validate_log_line_with_timestamp(expected_log_pattern, &&*message);
        }
    }

    #[tokio::test]
    async fn test_sample_file_generate_reads_syslog_lines_fallback() {
        let mut tempfile = NamedTempFile::new().unwrap();
        let mut wtr = WriterBuilder::new()
            .has_headers(true)
            .flexible(false)
            .quote_style(csv::QuoteStyle::NonNumeric)
            .from_writer(&mut tempfile);

        let syslog_lines= vec![
            // prefix empty
            ("", " myhost sshd[1234]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2"),
            // suffix empty
            ("myhost sshd[1234]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2 time: ", ""),
            // both prefix and suffix empty
            ("", ""),
            ("Timestamp: ", " myhost systemd[1]: Started Session 42 of user root."),
            ("Time: ", " myhost kernel: [123456.789012] eth0: link up, 1000 Mbps, full-duplex"),
        ];
        let expected_log_patterns = [
            "%Y-%m-%dT%H:%M:%S%.f%:z myhost sshd[1234]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2",
            "myhost sshd[1234]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2 time: %Y-%m-%dT%H:%M:%S%.f%:z",
            "%Y-%m-%dT%H:%M:%S%.f%:z",
            "Timestamp: %Y-%m-%dT%H:%M:%S%.f%:z myhost systemd[1]: Started Session 42 of user root.",
            "Time: %Y-%m-%dT%H:%M:%S%.f%:z myhost kernel: [123456.789012] eth0: link up, 1000 Mbps, full-duplex",
        ];

        wtr.write_record(&["prefix", "suffix"]).unwrap();
        for (prefix, suffix) in &syslog_lines {
            wtr.write_record(&[prefix, suffix]).unwrap();
        }
        wtr.flush().unwrap();
        mem::drop(wtr);

        let path = tempfile.path().to_string_lossy();
        let pattern = "%s.%3N";
        let message_key = log_schema().message_key().unwrap().to_string();
        let demo_log_config = DemoLogsConfig {
            format: OutputFormat::SampleFile {
                path: (&path).to_string(),
                time_format: pattern.to_string(),
            },
            count: 8,
            ..DemoLogsConfig::default()
        };
        let toml_string = toml::to_string(&demo_log_config).unwrap();

        let mut rx = runit(toml_string.as_str()).await;

        let length = expected_log_patterns.len();
        for num in 0..5 {
            let event = match poll!(rx.next()) {
                Poll::Ready(event) => event.unwrap(),
                _ => unreachable!(),
            };
            let log = event.as_log();
            let message = log[&message_key].to_string_lossy();
            let expected_log_pattern = expected_log_patterns[num%length];
            validate_log_line_with_timestamp(expected_log_pattern, &&*message);
        }
    }

    #[test]
    fn config_sample_file_generate_empty_file() {
        let temp_file = NamedTempFile::new().expect("failed to create temp file");

        let path = temp_file.path().to_string_lossy();
        let pattern = "%d/%b/%Y:%H:%M:%S";
        let errant_config = DemoLogsConfig {
            format: OutputFormat::SampleFile {
                path: (&path).to_string(),
                time_format: pattern.to_string(),
            },
            count: 5,
            ..DemoLogsConfig::default()
        };
        let result = errant_config.format.build_gen_ctx();
        match result {
            Ok(_) => panic!("expected error"),
            Err(e) => assert_eq!(e, DemoLogsConfigError::SampleFileDemoLogsEmpty),
        }
    }

    #[test]
    fn config_sample_file_generate_file_does_not_exist() {
        let errant_config = DemoLogsConfig {
            format: OutputFormat::SampleFile {
                path: "invalid/file/path".to_string(),
                time_format: "%y-%m-%d %H:%M:%S".to_string(),
            },
            count: 5,
            ..DemoLogsConfig::default()
        };
        let result = errant_config.format.build_gen_ctx();
        match result {
            Ok(_) => panic!("expected error"),
            Err(e) => {
                assert_eq!(
                    e,
                    DemoLogsConfigError::SampleFileOpenFailed {
                        message: "No such file or directory (os error 2)".to_string(),
                    }
                )
            },
        }
    }

    #[test]
    fn config_shuffle_lines_not_empty() {
        let empty_lines: Vec<String> = Vec::new();

        let errant_config = DemoLogsConfig {
            format: OutputFormat::Shuffle {
                sequence: false,
                lines: empty_lines,
            },
            ..DemoLogsConfig::default()
        };

        assert_eq!(
            errant_config.format.validate(),
            Err(DemoLogsConfigError::ShuffleDemoLogsItemsEmpty)
        );
    }

    #[test]
    fn config_sample_file_path_not_empty() {
        let errant_config = DemoLogsConfig {
            format: OutputFormat::SampleFile {
                path: "/path/to/file".to_string(),
                time_format: "".to_string(),
            },
            ..DemoLogsConfig::default()
        };

        assert_eq!(
            errant_config.format.validate(),
            Err(DemoLogsConfigError::SampleFileTimeFormatEmpty)
        );
    }

    #[test]
    fn config_sample_file_time_format_not_empty() {
        let errant_config = DemoLogsConfig {
            format: OutputFormat::SampleFile {
                path: "".to_string(),
                time_format: "%y-%m-%d %H:%M:%S".to_string(),
            },
            ..DemoLogsConfig::default()
        };

        assert_eq!(
            errant_config.format.validate(),
            Err(DemoLogsConfigError::SampleFileDemoLogsEmpty)
        );
    }

    #[test]
    fn config_sample_file_time_format_invalid() {
        let errant_config = DemoLogsConfig {
            format: OutputFormat::SampleFile {
                path: "/path/to/file".to_string(),
                time_format: "%s.%3N".to_string(),
            },
            ..DemoLogsConfig::default()
        };

        assert_eq!(
            errant_config.format.validate(),
            Err(DemoLogsConfigError::SampleFileTimeFormatInvalid)
        );
    }

    #[tokio::test]
    async fn shuffle_demo_logs_copies_lines() {
        let message_key = log_schema().message_key().unwrap().to_string();
        let mut rx = runit(
            r#"format = "shuffle"
               lines = ["one", "two", "three", "four"]
               count = 5"#,
        )
        .await;

        let lines = &["one", "two", "three", "four"];

        for _ in 0..5 {
            let event = match poll!(rx.next()) {
                Poll::Ready(event) => event.unwrap(),
                _ => unreachable!(),
            };
            let log = event.as_log();
            let message = log[&message_key].to_string_lossy();
            assert!(lines.contains(&&*message));
        }

        assert_eq!(poll!(rx.next()), Poll::Ready(None));
    }

    #[tokio::test]
    async fn shuffle_demo_logs_limits_count() {
        let mut rx = runit(
            r#"format = "shuffle"
               lines = ["one", "two"]
               count = 5"#,
        )
        .await;

        for _ in 0..5 {
            assert!(poll!(rx.next()).is_ready());
        }
        assert_eq!(poll!(rx.next()), Poll::Ready(None));
    }

    #[tokio::test]
    async fn shuffle_demo_logs_adds_sequence() {
        let message_key = log_schema().message_key().unwrap().to_string();
        let mut rx = runit(
            r#"format = "shuffle"
               lines = ["one", "two"]
               sequence = true
               count = 5"#,
        )
        .await;

        for n in 0..5 {
            let event = match poll!(rx.next()) {
                Poll::Ready(event) => event.unwrap(),
                _ => unreachable!(),
            };
            let log = event.as_log();
            let message = log[&message_key].to_string_lossy();
            assert!(message.starts_with(&n.to_string()));
        }

        assert_eq!(poll!(rx.next()), Poll::Ready(None));
    }

    #[tokio::test]
    async fn shuffle_demo_logs_obeys_interval() {
        let start = Instant::now();
        let mut rx = runit(
            r#"format = "shuffle"
               lines = ["one", "two"]
               count = 3
               interval = 1.0"#,
        )
        .await;

        for _ in 0..3 {
            assert!(poll!(rx.next()).is_ready());
        }
        assert_eq!(poll!(rx.next()), Poll::Ready(None));

        let duration = start.elapsed();
        assert!(duration >= Duration::from_secs(2));
    }

    #[tokio::test]
    async fn host_is_set() {
        let host_key = log_schema().host_key().unwrap().to_string();
        let mut rx = runit(
            r#"format = "syslog"
            count = 5"#,
        )
        .await;

        let event = match poll!(rx.next()) {
            Poll::Ready(event) => event.unwrap(),
            _ => unreachable!(),
        };
        let log = event.as_log();
        let host = log[&host_key].to_string_lossy();
        assert_eq!("localhost", host);
    }

    #[tokio::test]
    async fn apache_common_format_generates_output() {
        let mut rx = runit(
            r#"format = "apache_common"
            count = 5"#,
        )
        .await;

        for _ in 0..5 {
            assert!(poll!(rx.next()).is_ready());
        }
        assert_eq!(poll!(rx.next()), Poll::Ready(None));
    }

    #[tokio::test]
    async fn apache_error_format_generates_output() {
        let mut rx = runit(
            r#"format = "apache_error"
            count = 5"#,
        )
        .await;

        for _ in 0..5 {
            assert!(poll!(rx.next()).is_ready());
        }
        assert_eq!(poll!(rx.next()), Poll::Ready(None));
    }

    #[tokio::test]
    async fn syslog_5424_format_generates_output() {
        let mut rx = runit(
            r#"format = "syslog"
            count = 5"#,
        )
        .await;

        for _ in 0..5 {
            assert!(poll!(rx.next()).is_ready());
        }
        assert_eq!(poll!(rx.next()), Poll::Ready(None));
    }

    #[tokio::test]
    async fn syslog_3164_format_generates_output() {
        let mut rx = runit(
            r#"format = "bsd_syslog"
            count = 5"#,
        )
        .await;

        for _ in 0..5 {
            assert!(poll!(rx.next()).is_ready());
        }
        assert_eq!(poll!(rx.next()), Poll::Ready(None));
    }

    #[tokio::test]
    async fn json_format_generates_output() {
        let message_key = log_schema().message_key().unwrap().to_string();
        let mut rx = runit(
            r#"format = "json"
            count = 5"#,
        )
        .await;

        for _ in 0..5 {
            let event = match poll!(rx.next()) {
                Poll::Ready(event) => event.unwrap(),
                _ => unreachable!(),
            };
            let log = event.as_log();
            let message = log[&message_key].to_string_lossy();
            assert!(serde_json::from_str::<serde_json::Value>(&message).is_ok());
        }
        assert_eq!(poll!(rx.next()), Poll::Ready(None));
    }
}
