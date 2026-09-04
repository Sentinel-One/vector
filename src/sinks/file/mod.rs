use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use async_compression::tokio::write::{GzipEncoder, ZstdEncoder};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::{
    future,
    stream::{BoxStream, StreamExt},
    FutureExt,
};
use serde_with::serde_as;
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use tokio_util::codec::Encoder as _;
use vector_lib::codecs::{
    encoding::{Framer, FramingConfig},
    TextSerializerConfig,
};
use vector_lib::configurable::configurable_component;
use vector_lib::{
    internal_event::{CountByteSize, EventsSent, InternalEventHandle as _, Output, Registered},
    EstimatedJsonEncodedSizeOf, TimeZone,
};

use crate::{
    codecs::{Encoder, EncodingConfigWithFraming, SinkType, Transformer},
    config::{AcknowledgementsConfig, GenerateConfig, Input, SinkConfig, SinkContext},
    event::{Event, EventStatus, Finalizable},
    expiring_hash_map::ExpiringHashMap,
    internal_events::{
        FileBytesSent, FileInternalMetricsConfig, FileIoError, FileOpen, TemplateRenderingError,
    },
    sinks::util::{
        path_confinement::{ConfineError, PathConfinement},
        timezone_to_offset, StreamSink,
    },
    template::Template,
};

mod bytes_path;

use bytes_path::BytesPath;

/// Configuration for the `file` sink.
#[serde_as]
#[configurable_component(sink("file", "Output observability events into files."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileSinkConfig {
    /// File path to write events to.
    ///
    /// Compression format extension must be explicit.
    #[configurable(metadata(docs::examples = "/tmp/vector-%Y-%m-%d.log"))]
    #[configurable(metadata(
        docs::examples = "/tmp/application-{{ application_id }}-%Y-%m-%d.log"
    ))]
    #[configurable(metadata(docs::examples = "/tmp/vector-%Y-%m-%d.log.zst"))]
    pub path: Template,

    /// Base directory used to confine templated `path` values.
    ///
    /// When `path` references event fields, Vector rejects any rendered path
    /// that resolves outside of this directory (for example, via a `../`
    /// sequence in the field's value), preventing writes outside the
    /// intended log directory. If unset, the base directory is derived from
    /// the literal prefix of the `path` template, up to the last `/` before
    /// the first field reference.
    #[configurable(metadata(docs::examples = "/var/log/vector"))]
    #[serde(default)]
    pub base_dir: Option<PathBuf>,

    /// Disables confinement of templated `path` values to a base directory.
    ///
    /// This field only has an effect when `path` references event fields.
    ///
    /// **Warning**: enabling this allows any event field referenced by
    /// `path` to place the output file anywhere on the filesystem the
    /// Vector process can write to. Only enable this if every field
    /// referenced in `path` is fully trusted.
    #[serde(default)]
    pub dangerously_allow_unconfined_template_resolution: bool,

    /// The amount of time that a file can be idle and stay open.
    ///
    /// After not receiving any events in this amount of time, the file is flushed and closed.
    #[serde(default = "default_idle_timeout")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "idle_timeout_secs")]
    #[configurable(metadata(docs::examples = 600))]
    #[configurable(metadata(docs::human_name = "Idle Timeout"))]
    pub idle_timeout: Duration,

    #[serde(flatten)]
    pub encoding: EncodingConfigWithFraming,

    #[configurable(derived)]
    #[serde(default, skip_serializing_if = "crate::serde::is_default")]
    pub compression: Compression,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub acknowledgements: AcknowledgementsConfig,

    #[configurable(derived)]
    #[serde(default)]
    pub timezone: Option<TimeZone>,

    #[configurable(derived)]
    #[serde(default)]
    pub internal_metrics: FileInternalMetricsConfig,
}

impl GenerateConfig for FileSinkConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            path: Template::try_from("/tmp/vector-%Y-%m-%d.log").unwrap(),
            base_dir: Default::default(),
            dangerously_allow_unconfined_template_resolution: Default::default(),
            idle_timeout: default_idle_timeout(),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            compression: Default::default(),
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: Default::default(),
        })
        .unwrap()
    }
}

const fn default_idle_timeout() -> Duration {
    Duration::from_secs(30)
}

/// Compression configuration.
// TODO: Why doesn't this already use `crate::sinks::util::Compression`
// `crate::sinks::util::Compression` doesn't support zstd yet
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// [Gzip][gzip] compression.
    ///
    /// [gzip]: https://www.gzip.org/
    Gzip,

    /// [Zstandard][zstd] compression.
    ///
    /// [zstd]: https://facebook.github.io/zstd/
    Zstd,

    /// No compression.
    #[default]
    None,
}

enum OutFile {
    Regular(File),
    Gzip(GzipEncoder<File>),
    Zstd(ZstdEncoder<File>),
}

impl OutFile {
    fn new(file: File, compression: Compression) -> Self {
        match compression {
            Compression::None => OutFile::Regular(file),
            Compression::Gzip => OutFile::Gzip(GzipEncoder::new(file)),
            Compression::Zstd => OutFile::Zstd(ZstdEncoder::new(file)),
        }
    }

    async fn sync_all(&mut self) -> Result<(), std::io::Error> {
        match self {
            OutFile::Regular(file) => file.sync_all().await,
            OutFile::Gzip(gzip) => gzip.get_mut().sync_all().await,
            OutFile::Zstd(zstd) => zstd.get_mut().sync_all().await,
        }
    }

    async fn shutdown(&mut self) -> Result<(), std::io::Error> {
        match self {
            OutFile::Regular(file) => file.shutdown().await,
            OutFile::Gzip(gzip) => gzip.shutdown().await,
            OutFile::Zstd(zstd) => zstd.shutdown().await,
        }
    }

    async fn write_all(&mut self, src: &[u8]) -> Result<(), std::io::Error> {
        match self {
            OutFile::Regular(file) => file.write_all(src).await,
            OutFile::Gzip(gzip) => gzip.write_all(src).await,
            OutFile::Zstd(zstd) => zstd.write_all(src).await,
        }
    }

    /// Shutdowns by flushing data, writing headers, and syncing all of that
    /// data and metadata to the filesystem.
    async fn close(&mut self) -> Result<(), std::io::Error> {
        self.shutdown().await?;
        self.sync_all().await
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "file")]
impl SinkConfig for FileSinkConfig {
    async fn build(
        &self,
        cx: SinkContext,
    ) -> crate::Result<(super::VectorSink, super::Healthcheck)> {
        let sink = FileSink::new(self, cx)?;
        Ok((
            super::VectorSink::from_event_streamsink(sink),
            future::ok(()).boxed(),
        ))
    }

    fn input(&self) -> Input {
        Input::new(self.encoding.config().1.input_type())
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

pub struct FileSink {
    path: Template,
    path_confinement: Option<PathConfinement>,
    transformer: Transformer,
    encoder: Encoder<Framer>,
    idle_timeout: Duration,
    files: ExpiringHashMap<Bytes, OutFile>,
    compression: Compression,
    events_sent: Registered<EventsSent>,
    include_file_metric_tag: bool,
}

impl FileSink {
    pub fn new(config: &FileSinkConfig, cx: SinkContext) -> crate::Result<Self> {
        let transformer = config.encoding.transformer();
        let (framer, serializer) = config.encoding.build(SinkType::StreamBased)?;
        let encoder = Encoder::<Framer>::new(framer, serializer);

        let offset = config
            .timezone
            .or(cx.globals.timezone)
            .and_then(timezone_to_offset);

        let path_confinement = if config.dangerously_allow_unconfined_template_resolution {
            warn!(
                message = "Path confinement is disabled for this file sink; templated \
                           `path` values can write anywhere the Vector process has \
                           filesystem access to.",
            );
            None
        } else {
            PathConfinement::for_template(&config.path, config.base_dir.as_deref())?
        };

        Ok(Self {
            path: config.path.clone().with_tz_offset(offset),
            path_confinement,
            transformer,
            encoder,
            idle_timeout: config.idle_timeout,
            files: ExpiringHashMap::default(),
            compression: config.compression,
            events_sent: register!(EventsSent::from(Output(None))),
            include_file_metric_tag: config.internal_metrics.include_file_tag,
        })
    }

    /// Uses pass the `event` to `self.path` template to obtain the file path
    /// to store the event as.
    fn partition_event(&mut self, event: &Event) -> Option<bytes::Bytes> {
        let bytes = match self.path.render(event) {
            Ok(b) => b,
            Err(error) => {
                emit!(TemplateRenderingError {
                    error,
                    field: Some("path"),
                    drop_event: true,
                });
                return None;
            }
        };

        Some(bytes)
    }

    /// Confines the rendered `path` bytes to the sink's configured base
    /// directory, if confinement is enabled. Returns an owned, normalized
    /// path suitable for filesystem operations.
    fn confine_path(&self, path: &Bytes) -> Result<PathBuf, ConfineError> {
        let bytes_path = BytesPath::new(path.clone());
        let rendered: &Path = bytes_path.as_ref();
        match &self.path_confinement {
            Some(confinement) => confinement.confine(rendered),
            None => Ok(rendered.to_path_buf()),
        }
    }

    fn deadline_at(&self) -> Instant {
        Instant::now()
            .checked_add(self.idle_timeout)
            .expect("unable to compute next deadline")
    }

    async fn run(&mut self, mut input: BoxStream<'_, Event>) -> crate::Result<()> {
        loop {
            tokio::select! {
                event = input.next() => {
                    match event {
                        Some(event) => self.process_event(event).await,
                        None => {
                            // If we got `None` - terminate the processing.
                            debug!(message = "Receiver exhausted, terminating the processing loop.");

                            // Close all the open files.
                            debug!(message = "Closing all the open files.");
                            for (path, file) in self.files.iter_mut() {
                                if let Err(error) = file.close().await {
                                    emit!(FileIoError {
                                        error,
                                        code: "failed_closing_file",
                                        message: "Failed to close file.",
                                        path,
                                        dropped_events: 0,
                                    });
                                } else{
                                    trace!(message = "Successfully closed file.", path = ?path);
                                }
                            }

                            emit!(FileOpen {
                                count: 0
                            });

                            break;
                        }
                    }
                }
                result = self.files.next_expired(), if !self.files.is_empty() => {
                    match result {
                        // We do not poll map when it's empty, so we should
                        // never reach this branch.
                        None => unreachable!(),
                        Some((mut expired_file, path)) => {
                            // We got an expired file. All we really want is to
                            // flush and close it.
                            if let Err(error) = expired_file.close().await {
                                emit!(FileIoError {
                                    error,
                                    code: "failed_closing_file",
                                    message: "Failed to close file.",
                                    path: &path,
                                    dropped_events: 0,
                                });
                            }
                            drop(expired_file); // ignore close error
                            emit!(FileOpen {
                                count: self.files.len()
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_event(&mut self, mut event: Event) {
        let path = match self.partition_event(&event) {
            Some(path) => path,
            None => {
                // We weren't able to find the path to use for the
                // file.
                // The error is already handled at `partition_event`, so
                // here we just skip the event.
                event.metadata().update_status(EventStatus::Errored);
                return;
            }
        };

        let next_deadline = self.deadline_at();
        trace!(message = "Computed next deadline.", next_deadline = ?next_deadline, path = ?path);

        let file = if let Some(file) = self.files.reset_at(&path, next_deadline) {
            trace!(message = "Working with an already opened file.", path = ?path);
            file
        } else {
            trace!(message = "Opening new file.", ?path);
            let confined_path = match self.confine_path(&path) {
                Ok(confined_path) => confined_path,
                Err(error) => {
                    // The rendered path escapes the sink's confinement base
                    // directory (or otherwise fails validation); refuse to
                    // touch the filesystem and drop the event.
                    emit!(FileIoError {
                        code: "path_confinement_violation",
                        message: "Rendered path failed confinement check.",
                        error: std::io::Error::new(std::io::ErrorKind::InvalidInput, error),
                        path: &path,
                        dropped_events: 1,
                    });
                    event.metadata().update_status(EventStatus::Errored);
                    return;
                }
            };
            let file = match open_file(confined_path).await {
                Ok(file) => file,
                Err(error) => {
                    // We couldn't open the file for this event.
                    // Maybe other events will work though! Just log
                    // the error and skip this event.
                    emit!(FileIoError {
                        code: "failed_opening_file",
                        message: "Unable to open the file.",
                        error,
                        path: &path,
                        dropped_events: 1,
                    });
                    event.metadata().update_status(EventStatus::Errored);
                    return;
                }
            };

            let outfile = OutFile::new(file, self.compression);

            self.files.insert_at(path.clone(), outfile, next_deadline);
            emit!(FileOpen {
                count: self.files.len()
            });
            self.files.get_mut(&path).unwrap()
        };

        trace!(message = "Writing an event to file.", path = ?path);
        let event_size = event.estimated_json_encoded_size_of();
        let finalizers = event.take_finalizers();
        match write_event_to_file(file, event, &self.transformer, &mut self.encoder).await {
            Ok(byte_size) => {
                finalizers.update_status(EventStatus::Delivered);
                self.events_sent.emit(CountByteSize(1, event_size));
                emit!(FileBytesSent {
                    byte_size,
                    file: String::from_utf8_lossy(&path),
                    include_file_metric_tag: self.include_file_metric_tag,
                });
            }
            Err(error) => {
                finalizers.update_status(EventStatus::Errored);
                emit!(FileIoError {
                    code: "failed_writing_file",
                    message: "Failed to write the file.",
                    error,
                    path: &path,
                    dropped_events: 1,
                });
            }
        }
    }
}

// `path` is confined (see `FileSink::confine_path`), so this rejects `../`
// escapes. It still resolves through `std::fs`'s plain `open`/`create_dir_all`
// (not `openat`-relative), so a symlink planted at an intermediate component
// before `create_dir_all` runs would still be followed. Closing that
// TOCTOU gap would mean resolving relative to a directory handle instead of
// a path string — evaluate `cap-std` (https://github.com/bytecodealliance/cap-std)
// for that if it's ever worth the added (sync, spawn_blocking-bridged) dependency.
async fn open_file(path: impl AsRef<std::path::Path>) -> std::io::Result<File> {
    let parent = path.as_ref().parent();

    if let Some(parent) = parent {
        fs::create_dir_all(parent).await?;
    }

    fs::OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .append(true)
        .open(path)
        .await
}

async fn write_event_to_file(
    file: &mut OutFile,
    mut event: Event,
    transformer: &Transformer,
    encoder: &mut Encoder<Framer>,
) -> Result<usize, std::io::Error> {
    transformer.transform(&mut event);
    let mut buffer = BytesMut::new();
    encoder
        .encode(event, &mut buffer)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    file.write_all(&buffer).await.map(|()| buffer.len())
}

#[async_trait]
impl StreamSink<Event> for FileSink {
    async fn run(mut self: Box<Self>, input: BoxStream<'_, Event>) -> Result<(), ()> {
        FileSink::run(&mut self, input)
            .await
            .expect("file sink error");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use chrono::{SubsecRound, Utc};
    use futures::{stream, SinkExt};
    use similar_asserts::assert_eq;
    use vector_lib::{
        codecs::JsonSerializerConfig,
        event::{BatchNotifier, BatchStatus, LogEvent, TraceEvent},
        sink::VectorSink,
    };

    use super::*;
    use crate::{
        config::log_schema,
        test_util::{
            components::{assert_sink_compliance, FILE_SINK_TAGS},
            lines_from_file, lines_from_gzip_file, lines_from_zstd_file, random_events_with_stream,
            random_lines_with_stream, random_metrics_with_stream,
            random_metrics_with_stream_timestamp, temp_dir, temp_file, trace_init,
        },
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<FileSinkConfig>();
    }

    #[tokio::test]
    async fn log_single_partition() {
        let template = temp_file();

        let config = FileSinkConfig {
            path: template.clone().try_into().unwrap(),
            base_dir: Default::default(),
            dangerously_allow_unconfined_template_resolution: Default::default(),
            idle_timeout: default_idle_timeout(),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            compression: Compression::None,
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
        };

        let (input, _events) = random_lines_with_stream(100, 64, None);

        run_assert_log_sink(&config, input.clone()).await;

        let output = lines_from_file(template);
        for (input, output) in input.into_iter().zip(output) {
            assert_eq!(input, output);
        }
    }

    #[tokio::test]
    async fn log_single_partition_gzip() {
        let template = temp_file();

        let config = FileSinkConfig {
            path: template.clone().try_into().unwrap(),
            base_dir: Default::default(),
            dangerously_allow_unconfined_template_resolution: Default::default(),
            idle_timeout: default_idle_timeout(),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            compression: Compression::Gzip,
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
        };

        let (input, _) = random_lines_with_stream(100, 64, None);

        run_assert_log_sink(&config, input.clone()).await;

        let output = lines_from_gzip_file(template);
        for (input, output) in input.into_iter().zip(output) {
            assert_eq!(input, output);
        }
    }

    #[tokio::test]
    async fn log_single_partition_zstd() {
        let template = temp_file();

        let config = FileSinkConfig {
            path: template.clone().try_into().unwrap(),
            base_dir: Default::default(),
            dangerously_allow_unconfined_template_resolution: Default::default(),
            idle_timeout: default_idle_timeout(),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            compression: Compression::Zstd,
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
        };

        let (input, _) = random_lines_with_stream(100, 64, None);

        run_assert_log_sink(&config, input.clone()).await;

        let output = lines_from_zstd_file(template);
        for (input, output) in input.into_iter().zip(output) {
            assert_eq!(input, output);
        }
    }

    #[tokio::test]
    async fn log_many_partitions() {
        let directory = temp_dir();

        let mut template = directory.to_string_lossy().to_string();
        template.push_str("/{{level}}s-{{date}}.log");

        trace!(message = "Template.", %template);

        let config = FileSinkConfig {
            path: template.try_into().unwrap(),
            base_dir: Default::default(),
            dangerously_allow_unconfined_template_resolution: Default::default(),
            idle_timeout: default_idle_timeout(),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            compression: Compression::None,
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
        };

        let (mut input, _events) = random_events_with_stream(32, 8, None);
        input[0].as_mut_log().insert("date", "2019-26-07");
        input[0].as_mut_log().insert("level", "warning");
        input[1].as_mut_log().insert("date", "2019-26-07");
        input[1].as_mut_log().insert("level", "error");
        input[2].as_mut_log().insert("date", "2019-26-07");
        input[2].as_mut_log().insert("level", "warning");
        input[3].as_mut_log().insert("date", "2019-27-07");
        input[3].as_mut_log().insert("level", "error");
        input[4].as_mut_log().insert("date", "2019-27-07");
        input[4].as_mut_log().insert("level", "warning");
        input[5].as_mut_log().insert("date", "2019-27-07");
        input[5].as_mut_log().insert("level", "warning");
        input[6].as_mut_log().insert("date", "2019-28-07");
        input[6].as_mut_log().insert("level", "warning");
        input[7].as_mut_log().insert("date", "2019-29-07");
        input[7].as_mut_log().insert("level", "error");

        run_assert_sink(&config, input.clone().into_iter()).await;

        let output = [
            lines_from_file(directory.join("warnings-2019-26-07.log")),
            lines_from_file(directory.join("errors-2019-26-07.log")),
            lines_from_file(directory.join("warnings-2019-27-07.log")),
            lines_from_file(directory.join("errors-2019-27-07.log")),
            lines_from_file(directory.join("warnings-2019-28-07.log")),
            lines_from_file(directory.join("errors-2019-29-07.log")),
        ];

        let message_key = log_schema().message_key().unwrap().to_string();
        assert_eq!(
            input[0].as_log()[&message_key],
            From::<&str>::from(&output[0][0])
        );
        assert_eq!(
            input[1].as_log()[&message_key],
            From::<&str>::from(&output[1][0])
        );
        assert_eq!(
            input[2].as_log()[&message_key],
            From::<&str>::from(&output[0][1])
        );
        assert_eq!(
            input[3].as_log()[&message_key],
            From::<&str>::from(&output[3][0])
        );
        assert_eq!(
            input[4].as_log()[&message_key],
            From::<&str>::from(&output[2][0])
        );
        assert_eq!(
            input[5].as_log()[&message_key],
            From::<&str>::from(&output[2][1])
        );
        assert_eq!(
            input[6].as_log()[&message_key],
            From::<&str>::from(&output[4][0])
        );
        assert_eq!(
            input[7].as_log()[message_key],
            From::<&str>::from(&output[5][0])
        );
    }

    #[tokio::test]
    async fn log_reopening() {
        trace_init();

        let template = temp_file();

        let config = FileSinkConfig {
            path: template.clone().try_into().unwrap(),
            base_dir: Default::default(),
            dangerously_allow_unconfined_template_resolution: Default::default(),
            idle_timeout: Duration::from_secs(1),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            compression: Compression::None,
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
        };

        let (mut input, _events) = random_lines_with_stream(10, 64, None);

        let (mut tx, rx) = futures::channel::mpsc::channel(0);

        let sink_handle = tokio::spawn(async move {
            assert_sink_compliance(&FILE_SINK_TAGS, async move {
                let sink = FileSink::new(&config, SinkContext::default()).unwrap();
                VectorSink::from_event_streamsink(sink)
                    .run(Box::pin(rx.map(Into::into)))
                    .await
                    .expect("Running sink failed");
            })
            .await
        });

        // send initial payload
        for line in input.clone() {
            tx.send(Event::Log(LogEvent::from(line))).await.unwrap();
        }

        // wait for file to go idle and be closed
        tokio::time::sleep(Duration::from_secs(2)).await;

        // trigger another write
        let last_line = "i should go at the end";
        tx.send(LogEvent::from(last_line).into()).await.unwrap();
        input.push(String::from(last_line));

        // wait for another flush
        tokio::time::sleep(Duration::from_secs(1)).await;

        // make sure we appended instead of overwriting
        let output = lines_from_file(template);
        assert_eq!(input, output);

        // make sure sink stops and that it did not panic
        drop(tx);
        sink_handle.await.unwrap();
    }

    #[tokio::test]
    async fn metric_single_partition() {
        let template = temp_file();

        let config = FileSinkConfig {
            path: template.clone().try_into().unwrap(),
            base_dir: Default::default(),
            dangerously_allow_unconfined_template_resolution: Default::default(),
            idle_timeout: default_idle_timeout(),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            compression: Compression::None,
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
        };

        let (input, _events) = random_metrics_with_stream(100, None, None);

        run_assert_sink(&config, input.clone().into_iter()).await;

        let output = lines_from_file(template);
        for (input, output) in input.into_iter().zip(output) {
            let metric_name = input.as_metric().name();
            assert!(output.contains(metric_name));
        }
    }

    #[tokio::test]
    async fn metric_many_partitions() {
        let directory = temp_dir();

        let format = "%Y-%m-%d-%H-%M-%S";
        let mut template = directory.to_string_lossy().to_string();
        template.push_str(&format!("/{}.log", format));

        let config = FileSinkConfig {
            path: template.try_into().unwrap(),
            base_dir: Default::default(),
            dangerously_allow_unconfined_template_resolution: Default::default(),
            idle_timeout: default_idle_timeout(),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            compression: Compression::None,
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
        };

        let metric_count = 3;
        let timestamp = Utc::now().trunc_subsecs(3);
        let timestamp_offset = Duration::from_secs(1);

        let (input, _events) = random_metrics_with_stream_timestamp(
            metric_count,
            None,
            None,
            timestamp,
            timestamp_offset,
        );

        run_assert_sink(&config, input.clone().into_iter()).await;

        let output = (0..metric_count).map(|index| {
            let expected_timestamp = timestamp + (timestamp_offset * index as u32);
            let expected_filename =
                directory.join(format!("{}.log", expected_timestamp.format(format)));

            lines_from_file(expected_filename)
        });
        for (input, output) in input.iter().zip(output) {
            // The format will partition by second and metrics are a second apart.
            assert_eq!(
                output.len(),
                1,
                "Expected the output file to contain one metric"
            );
            let output = &output[0];

            let metric_name = input.as_metric().name();
            assert!(output.contains(metric_name));
        }
    }

    #[tokio::test]
    async fn trace_single_partition() {
        let template = temp_file();

        let config = FileSinkConfig {
            path: template.clone().try_into().unwrap(),
            base_dir: Default::default(),
            dangerously_allow_unconfined_template_resolution: Default::default(),
            idle_timeout: default_idle_timeout(),
            encoding: (None::<FramingConfig>, JsonSerializerConfig::default()).into(),
            compression: Compression::None,
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
        };

        let (input, _events) = random_lines_with_stream(100, 64, None);

        run_assert_trace_sink(&config, input.clone()).await;

        let output = lines_from_file(template);
        for (input, output) in input.iter().zip(output) {
            assert!(output.contains(input));
        }
    }

    async fn run_assert_log_sink(config: &FileSinkConfig, events: Vec<String>) {
        run_assert_sink(
            config,
            events.into_iter().map(LogEvent::from).map(Event::Log),
        )
        .await;
    }

    async fn run_assert_trace_sink(config: &FileSinkConfig, events: Vec<String>) {
        run_assert_sink(
            config,
            events
                .into_iter()
                .map(LogEvent::from)
                .map(TraceEvent::from)
                .map(Event::Trace),
        )
        .await;
    }

    async fn run_assert_sink(config: &FileSinkConfig, events: impl Iterator<Item = Event> + Send) {
        assert_sink_compliance(&FILE_SINK_TAGS, async move {
            let sink = FileSink::new(config, SinkContext::default()).unwrap();
            VectorSink::from_event_streamsink(sink)
                .run(Box::pin(stream::iter(events.map(Into::into))))
                .await
                .expect("Running sink failed")
        })
        .await;
    }

    fn confinement_test_config(
        path: Template,
        base_dir: Option<std::path::PathBuf>,
    ) -> FileSinkConfig {
        FileSinkConfig {
            path,
            base_dir,
            dangerously_allow_unconfined_template_resolution: false,
            idle_timeout: default_idle_timeout(),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            compression: Compression::None,
            acknowledgements: Default::default(),
            timezone: Default::default(),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
        }
    }

    #[tokio::test]
    async fn path_confinement_rejects_traversal() {
        trace_init();

        // `allowed` is the derived confinement base (the template's literal
        // prefix); `secret` is a sibling directory that a `../` escape would
        // land in if confinement didn't reject it.
        let scratch = temp_dir();
        let allowed = scratch.join("allowed");
        let secret = scratch.join("secret");

        let mut template = allowed.to_string_lossy().to_string();
        template.push_str("/{{ appname }}.log");
        let config = confinement_test_config(template.try_into().unwrap(), None);

        let sink = FileSink::new(&config, SinkContext::default()).unwrap();

        let (legit_batch, mut legit_receiver) = BatchNotifier::new_with_receiver();
        let mut legit_event = LogEvent::from("safe line").with_batch_notifier(&legit_batch);
        legit_event.insert("appname", "safe");

        let (evil_batch, mut evil_receiver) = BatchNotifier::new_with_receiver();
        let mut evil_event = LogEvent::from("evil line").with_batch_notifier(&evil_batch);
        evil_event.insert("appname", "../secret/evil");

        drop(legit_batch);
        drop(evil_batch);

        let events = vec![Event::Log(legit_event), Event::Log(evil_event)];

        VectorSink::from_event_streamsink(sink)
            .run(Box::pin(stream::iter(events).map(Into::into)))
            .await
            .expect("Running sink failed");

        assert_eq!(legit_receiver.try_recv(), Ok(BatchStatus::Delivered));
        assert_eq!(evil_receiver.try_recv(), Ok(BatchStatus::Errored));

        assert_eq!(
            lines_from_file(allowed.join("safe.log")),
            vec!["safe line".to_string()]
        );
        assert!(
            !secret.exists(),
            "confinement should have prevented the `../` escape from creating {secret:?}"
        );
    }

    #[tokio::test]
    async fn path_confinement_disabled_by_flag_allows_traversal() {
        trace_init();

        let scratch = temp_dir();
        let allowed = scratch.join("allowed");
        let secret = scratch.join("secret");

        let mut template = allowed.to_string_lossy().to_string();
        template.push_str("/{{ appname }}.log");
        let mut config = confinement_test_config(template.try_into().unwrap(), None);
        config.dangerously_allow_unconfined_template_resolution = true;

        let sink = FileSink::new(&config, SinkContext::default()).unwrap();

        let (evil_batch, mut evil_receiver) = BatchNotifier::new_with_receiver();
        let mut evil_event = LogEvent::from("evil line").with_batch_notifier(&evil_batch);
        evil_event.insert("appname", "../secret/evil");

        drop(evil_batch);

        VectorSink::from_event_streamsink(sink)
            .run(Box::pin(
                stream::iter(vec![Event::Log(evil_event)]).map(Into::into),
            ))
            .await
            .expect("Running sink failed");

        assert_eq!(evil_receiver.try_recv(), Ok(BatchStatus::Delivered));
        assert_eq!(
            lines_from_file(secret.join("evil.log")),
            vec!["evil line".to_string()]
        );
    }

    #[tokio::test]
    async fn path_confinement_base_dir_override() {
        trace_init();

        let base = temp_dir();
        let config = confinement_test_config(
            Template::try_from("{{ appname }}.log").unwrap(),
            Some(base.clone()),
        );

        let sink = FileSink::new(&config, SinkContext::default()).unwrap();

        let (batch, mut receiver) = BatchNotifier::new_with_receiver();
        let mut event = LogEvent::from("hello").with_batch_notifier(&batch);
        event.insert("appname", "safe");

        drop(batch);

        VectorSink::from_event_streamsink(sink)
            .run(Box::pin(
                stream::iter(vec![Event::Log(event)]).map(Into::into),
            ))
            .await
            .expect("Running sink failed");

        assert_eq!(receiver.try_recv(), Ok(BatchStatus::Delivered));
        assert_eq!(
            lines_from_file(base.join("safe.log")),
            vec!["hello".to_string()]
        );
    }

    #[test]
    fn path_confinement_build_error_without_derivable_base() {
        let config =
            confinement_test_config(Template::try_from("{{ appname }}.log").unwrap(), None);

        let error = FileSink::new(&config, SinkContext::default())
            .err()
            .expect("expected sink construction to fail without a derivable base directory");
        assert!(
            error.to_string().contains("no literal directory prefix"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn dangerously_allow_unconfined_skips_confinement_build() {
        let mut config =
            confinement_test_config(Template::try_from("{{ appname }}.log").unwrap(), None);
        config.dangerously_allow_unconfined_template_resolution = true;

        assert!(FileSink::new(&config, SinkContext::default()).is_ok());
    }
}
