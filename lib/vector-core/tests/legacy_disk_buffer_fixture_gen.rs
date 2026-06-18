//! Generator for the legacy disk-buffer fixture used by backwards-compatibility tests.
//!
//! Run on a commit that PRE-dates the `enq_tm` field on `proto::EventArray`. The resulting
//! buffer files become the fixture for tests that verify pre-tag-4 records still decode.
//!
//! Run with:
//!
//! ```text
//! cargo test -p vector-core --test legacy_disk_buffer_fixture_gen -- --ignored --nocapture
//! ```
//!
//! Output: `lib/vector-core/tests/data/fixtures/legacy_disk_buffer_v2/buffer/v2/legacy/`.

use std::{num::NonZeroU64, path::PathBuf};

use tracing::Span;
use vector_buffers::{topology::builder::TopologyBuilder, BufferType, WhenFull};
use vector_core::event::{EventArray, LogEvent, Metric, MetricKind, MetricValue};

const FIXTURE_SUBDIR: &str = "tests/data/fixtures/legacy_disk_buffer_v2";
const BUFFER_ID: &str = "legacy";
const MAX_SIZE: u64 = 268_435_488;

#[tokio::test]
#[ignore = "fixture generator; run explicitly and check in the output"]
async fn generate_legacy_fixture() {
    let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_SUBDIR);

    if fixture_root.exists() {
        std::fs::remove_dir_all(&fixture_root).expect("clean fixture dir");
    }
    std::fs::create_dir_all(&fixture_root).expect("create fixture dir");

    let mut builder = TopologyBuilder::<EventArray>::default();
    BufferType::DiskV2 {
        when_full: WhenFull::Block,
        max_size: NonZeroU64::new(MAX_SIZE).unwrap(),
    }
    .add_to_builder(
        &mut builder,
        Some(fixture_root.clone()),
        BUFFER_ID.to_string(),
    )
    .expect("add disk_v2 stage");

    let (mut sender, _receiver) = builder
        .build(BUFFER_ID.to_string(), Span::current())
        .await
        .expect("build topology");

    for ea in fixture_records() {
        sender.send(ea, None).await.expect("send");
    }
    sender.flush().await.expect("flush");
    drop(sender);

    eprintln!(
        "legacy disk-buffer fixture written to {}",
        fixture_root.display()
    );
}

fn fixture_records() -> Vec<EventArray> {
    let mut l1 = LogEvent::default();
    l1.insert("message", "hello");
    l1.insert("level", "info");
    let mut l2 = LogEvent::default();
    l2.insert("message", "world");
    l2.insert("level", "warn");

    let counter = Metric::new(
        "test_counter",
        MetricKind::Incremental,
        MetricValue::Counter { value: 42.0 },
    );

    vec![
        EventArray::Logs(vec![l1, l2]),
        EventArray::Metrics(vec![counter]),
    ]
}
