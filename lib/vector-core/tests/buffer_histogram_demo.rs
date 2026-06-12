//! Demonstrates that `topology_queue_delay_seconds` is updated with the actual queue residency,
//! for both in-memory and disk-backed buffers, using a deterministic clock driven by tokio's
//! paused-time machinery. This is the single place where we verify the histogram values; other
//! buffer-level tests stay focused on payload behavior.

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        num::{NonZeroU64, NonZeroUsize},
        sync::Arc,
        time::{Duration, SystemTime},
    };

    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use tempfile::TempDir;
    use tokio::time::Instant as TokioInstant;
    use tracing::Span;
    use vector_buffers::{BufferConfig, BufferType, Clock, WhenFull};
    use vector_common::finalization::{EventStatus, Finalizable};
    use vector_core::event::{EventArray, LogEvent};

    const QUEUE_DELAY_METRIC: &str = "topology_queue_delay_seconds";
    const MAX_SIZE: u64 = 268_435_488;
    const SLEEP: Duration = Duration::from_millis(100);

    /// `Clock` whose `now()` tracks tokio's (potentially paused) time, offset from an anchor.
    /// With paused tokio time, `tokio::time::sleep(d).await` advances both tokio time and `now()`
    /// by exactly `d`, without any real wall-clock wait.
    struct TokioBackedClock {
        anchor_sys: SystemTime,
        anchor_tokio: TokioInstant,
    }

    impl TokioBackedClock {
        fn new() -> Self {
            Self {
                anchor_sys: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                anchor_tokio: TokioInstant::now(),
            }
        }
    }

    impl Clock for TokioBackedClock {
        fn now(&self) -> SystemTime {
            self.anchor_sys + TokioInstant::now().duration_since(self.anchor_tokio)
        }
    }

    fn sample_logs(message: &str) -> EventArray {
        let mut log = LogEvent::default();
        log.insert("message", message);
        EventArray::Logs(vec![log])
    }

    fn queue_delay_samples(snapshotter: &Snapshotter) -> Vec<f64> {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter_map(|(key, _unit, _desc, value)| {
                if key.key().name() != QUEUE_DELAY_METRIC {
                    return None;
                }
                match value {
                    DebugValue::Histogram(samples) => {
                        Some(samples.into_iter().map(f64::from).collect::<Vec<_>>())
                    }
                    _ => None,
                }
            })
            .flatten()
            .collect()
    }

    fn queue_delay_samples_by_stage(snapshotter: &Snapshotter) -> HashMap<String, Vec<f64>> {
        let mut by_stage: HashMap<String, Vec<f64>> = HashMap::new();
        for (key, _unit, _desc, value) in snapshotter.snapshot().into_vec() {
            if key.key().name() != QUEUE_DELAY_METRIC {
                continue;
            }
            let stage = key
                .key()
                .labels()
                .find(|l| l.key() == "stage")
                .map(|l| l.value().to_string())
                .unwrap_or_default();
            if let DebugValue::Histogram(samples) = value {
                by_stage
                    .entry(stage)
                    .or_default()
                    .extend(samples.into_iter().map(f64::from));
            }
        }
        by_stage
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn histogram_emits_for_in_memory_buffer() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let clock: Arc<dyn Clock> = Arc::new(TokioBackedClock::new());
        let config = BufferConfig::Single(BufferType::Memory {
            when_full: WhenFull::Block,
            max_events: NonZeroUsize::new(16).unwrap(),
        });
        let (mut sender, mut receiver) = config
            .build_with_clock::<EventArray>(None, "histogram_demo_mem", Span::none(), clock)
            .await
            .expect("build");

        sender.send(sample_logs("a"), None).await.expect("send");
        sender.send(sample_logs("b"), None).await.expect("send");
        sender.send(sample_logs("c"), None).await.expect("send");

        tokio::time::sleep(SLEEP).await;

        drop(sender);
        let mut drained = Vec::new();
        while let Some(mut ea) = receiver.next().await {
            ea.take_finalizers().update_status(EventStatus::Delivered);
            tokio::task::yield_now().await;
            drained.push(ea);
        }
        assert_eq!(drained.len(), 3);

        let samples = queue_delay_samples(&snapshotter);
        assert_eq!(samples.len(), 3, "one sample per drained record");
        let expected = SLEEP.as_secs_f64();
        for (i, s) in samples.iter().enumerate() {
            assert!(
                (*s - expected).abs() < 1e-6,
                "sample[{i}] = {s} should equal {expected}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn histogram_emits_for_disk_buffer() {
        let tmp = TempDir::new().expect("tempdir");

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let clock: Arc<dyn Clock> = Arc::new(TokioBackedClock::new());
        let config = BufferConfig::Single(BufferType::DiskV2 {
            when_full: WhenFull::Block,
            max_size: NonZeroU64::new(MAX_SIZE).unwrap(),
        });
        let (mut sender, mut receiver) = config
            .build_with_clock::<EventArray>(
                Some(tmp.path().to_path_buf()),
                "histogram_demo_disk",
                Span::none(),
                clock,
            )
            .await
            .expect("build");

        sender.send(sample_logs("a"), None).await.expect("send");
        sender.send(sample_logs("b"), None).await.expect("send");
        sender.send(sample_logs("c"), None).await.expect("send");
        sender.flush().await.expect("flush");

        tokio::time::sleep(SLEEP).await;

        sender.close().await;
        drop(sender);
        let mut drained = Vec::new();
        while let Some(mut ea) = receiver.next().await {
            ea.take_finalizers().update_status(EventStatus::Delivered);
            tokio::task::yield_now().await;
            drained.push(ea);
        }
        assert_eq!(drained.len(), 3);

        let samples = queue_delay_samples(&snapshotter);
        assert_eq!(samples.len(), 3, "one sample per drained record");
        let expected = SLEEP.as_secs_f64();
        for (i, s) in samples.iter().enumerate() {
            assert!(
                (*s - expected).abs() < 1e-6,
                "sample[{i}] = {s} should equal {expected}"
            );
        }
    }

    // T7: a two-stage (memory base + disk overflow) buffer should emit histogram samples for
    // both stages, and each sample should reflect total queue residency since the original send
    // (the overflow path must preserve `enq_tm`, not re-stamp).
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn histogram_emits_per_stage_for_overflow_buffer() {
        let tmp = TempDir::new().expect("tempdir");

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let clock: Arc<dyn Clock> = Arc::new(TokioBackedClock::new());
        let config = BufferConfig::Chained(vec![
            BufferType::Memory {
                when_full: WhenFull::Overflow,
                max_events: NonZeroUsize::new(1).unwrap(),
            },
            BufferType::DiskV2 {
                when_full: WhenFull::Block,
                max_size: NonZeroU64::new(MAX_SIZE).unwrap(),
            },
        ]);
        let (mut sender, mut receiver) = config
            .build_with_clock::<EventArray>(
                Some(tmp.path().to_path_buf()),
                "histogram_demo_overflow",
                Span::none(),
                clock,
            )
            .await
            .expect("build");

        sender.send(sample_logs("a"), None).await.expect("send");
        sender.send(sample_logs("b"), None).await.expect("send");
        sender.send(sample_logs("c"), None).await.expect("send");
        sender.flush().await.expect("flush");

        tokio::time::sleep(SLEEP).await;

        sender.close().await;
        drop(sender);

        let mut drained = Vec::new();
        while let Some(mut ea) = receiver.next().await {
            ea.take_finalizers().update_status(EventStatus::Delivered);
            tokio::task::yield_now().await;
            drained.push(ea);
        }
        assert_eq!(drained.len(), 3);

        let by_stage = queue_delay_samples_by_stage(&snapshotter);
        let stage_0 = by_stage.get("0").cloned().unwrap_or_default();
        let stage_1 = by_stage.get("1").cloned().unwrap_or_default();

        assert!(
            !stage_0.is_empty(),
            "expected at least one sample for stage=0 (memory base)"
        );
        assert!(
            !stage_1.is_empty(),
            "expected at least one sample for stage=1 (disk overflow)"
        );
        assert_eq!(
            stage_0.len() + stage_1.len(),
            3,
            "total samples across stages should match drained record count"
        );

        let expected = SLEEP.as_secs_f64();
        for s in stage_0.iter().chain(stage_1.iter()) {
            assert!(
                (*s - expected).abs() < 1e-6,
                "every sample (memory or overflow) should reflect total residency: \
                 {s} != {expected}"
            );
        }
    }
}
