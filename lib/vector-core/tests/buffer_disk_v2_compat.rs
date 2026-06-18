//! Integration tests for disk_v2 buffer backwards compatibility with the `enq_tm` proto field.
//!
//! T2: a buffer written with the new (`Timed<EventArray>`-wrapping) topology round-trips correctly.
//! T3: legacy records written before `enq_tm` existed still decode through the new buffer path.
//!     Uses the checked-in fixture at `tests/data/fixtures/legacy_disk_buffer_v2/`.
//! T4a: a buffer containing both legacy records and freshly-written ones drains in FIFO order
//!      with all payloads intact.
//!
//! Histogram emission semantics are verified separately — see `buffer_histogram_demo.rs`.

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU64,
        path::{Path, PathBuf},
    };

    use tempfile::TempDir;
    use tracing::Span;
    use vector_buffers::{
        topology::channel::{BufferReceiver, BufferSender},
        BufferConfig, BufferType, WhenFull,
    };
    use vector_common::finalization::{EventStatus, Finalizable};
    use vector_core::event::{EventArray, LogEvent, Metric, MetricKind, MetricValue};

    const FIXTURE_SUBDIR: &str = "tests/data/fixtures/legacy_disk_buffer_v2";
    const BUFFER_ID: &str = "legacy";
    const MAX_SIZE: u64 = 268_435_488;

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_SUBDIR)
    }

    fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let new_path = dst.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_dir_recursive(&entry.path(), &new_path)?;
            } else {
                std::fs::copy(entry.path(), &new_path)?;
            }
        }
        Ok(())
    }

    fn disk_config() -> BufferConfig {
        BufferConfig::Single(BufferType::DiskV2 {
            when_full: WhenFull::Block,
            max_size: NonZeroU64::new(MAX_SIZE).unwrap(),
        })
    }

    async fn open_buffer(
        data_dir: PathBuf,
    ) -> (BufferSender<EventArray>, BufferReceiver<EventArray>) {
        disk_config()
            .build::<EventArray>(Some(data_dir), BUFFER_ID, Span::none())
            .await
            .expect("build buffer")
    }

    fn sample_logs(message: &str, level: &str) -> EventArray {
        let mut log = LogEvent::default();
        log.insert("message", message);
        log.insert("level", level);
        EventArray::Logs(vec![log])
    }

    fn sample_metric(name: &str, value: f64) -> EventArray {
        EventArray::Metrics(vec![Metric::new(
            name,
            MetricKind::Incremental,
            MetricValue::Counter { value },
        )])
    }

    fn log_message(ea: &EventArray) -> Option<String> {
        match ea {
            EventArray::Logs(logs) => logs.first().and_then(|l| {
                l.get("message")
                    .and_then(|v| v.as_bytes())
                    .map(|b| String::from_utf8_lossy(b).into_owned())
            }),
            _ => None,
        }
    }

    fn metric_name(ea: &EventArray) -> Option<String> {
        match ea {
            EventArray::Metrics(m) => m.first().map(|m| m.name().to_string()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn t2_disk_buffer_new_proto_roundtrip() {
        let tmp = TempDir::new().expect("tempdir");

        let (mut sender, mut receiver) = open_buffer(tmp.path().to_path_buf()).await;
        sender
            .send(sample_logs("alpha", "info"), None)
            .await
            .expect("send");
        sender
            .send(sample_logs("beta", "warn"), None)
            .await
            .expect("send");
        sender
            .send(sample_metric("c", 7.0), None)
            .await
            .expect("send");
        sender.flush().await.expect("flush");
        sender.close().await;
        drop(sender);

        let mut drained = Vec::new();
        while let Some(mut ea) = receiver.next().await {
            ea.take_finalizers().update_status(EventStatus::Delivered);
            tokio::task::yield_now().await;
            drained.push(ea);
        }

        assert_eq!(drained.len(), 3);
        assert_eq!(log_message(&drained[0]).as_deref(), Some("alpha"));
        assert_eq!(log_message(&drained[1]).as_deref(), Some("beta"));
        assert_eq!(metric_name(&drained[2]).as_deref(), Some("c"));
    }

    #[tokio::test]
    async fn t3_legacy_fixture_decodes_through_new_buffer() {
        let tmp = TempDir::new().expect("tempdir");
        copy_dir_recursive(&fixture_root(), tmp.path()).expect("copy fixture");

        let (mut sender, mut receiver) = open_buffer(tmp.path().to_path_buf()).await;
        sender.close().await;
        drop(sender);

        let mut drained = Vec::new();
        while let Some(mut ea) = receiver.next().await {
            ea.take_finalizers().update_status(EventStatus::Delivered);
            tokio::task::yield_now().await;
            drained.push(ea);
        }

        assert_eq!(drained.len(), 2, "fixture has 2 records");

        let logs = match &drained[0] {
            EventArray::Logs(logs) => logs,
            other => panic!("expected Logs, got {other:?}"),
        };
        assert_eq!(logs.len(), 2);
        assert_eq!(
            logs[0]
                .get("message")
                .and_then(|v| v.as_bytes())
                .map(|b| String::from_utf8_lossy(b).into_owned()),
            Some("hello".to_string())
        );
        assert_eq!(
            logs[1]
                .get("message")
                .and_then(|v| v.as_bytes())
                .map(|b| String::from_utf8_lossy(b).into_owned()),
            Some("world".to_string())
        );

        assert_eq!(metric_name(&drained[1]).as_deref(), Some("test_counter"));
    }

    #[tokio::test]
    async fn t4a_mixed_legacy_and_new_records_drain_in_order() {
        let tmp = TempDir::new().expect("tempdir");
        copy_dir_recursive(&fixture_root(), tmp.path()).expect("copy fixture");

        let (mut sender, mut receiver) = open_buffer(tmp.path().to_path_buf()).await;

        sender
            .send(sample_logs("new1", "info"), None)
            .await
            .expect("send");
        sender
            .send(sample_metric("new_counter", 99.0), None)
            .await
            .expect("send");
        sender.flush().await.expect("flush");
        sender.close().await;
        drop(sender);

        let mut drained = Vec::new();
        while let Some(mut ea) = receiver.next().await {
            ea.take_finalizers().update_status(EventStatus::Delivered);
            tokio::task::yield_now().await;
            drained.push(ea);
        }

        assert_eq!(drained.len(), 4, "2 legacy + 2 new");
        assert_eq!(log_message(&drained[0]).as_deref(), Some("hello"));
        assert_eq!(metric_name(&drained[1]).as_deref(), Some("test_counter"));
        assert_eq!(log_message(&drained[2]).as_deref(), Some("new1"));
        assert_eq!(metric_name(&drained[3]).as_deref(), Some("new_counter"));
    }
}
