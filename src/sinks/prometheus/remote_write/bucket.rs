//! Routing buckets for the Prometheus Remote Write sink.
//!
//! A receiver that shards series across replicas can route on a header instead of decoding
//! the payload. Each metric is assigned a bucket from a stable hash of some of its tags; a
//! request only ever carries one bucket, and requests for the same bucket are sent one at a
//! time, in order, so the receiver never sees a series out of order.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use http::HeaderName;
use snafu::Snafu;
use tokio::sync::oneshot;
use tower::{Layer, Service, ServiceExt};
use vector_lib::{configurable::configurable_component, event::Metric};

const fn default_bucket_count() -> u32 {
    1024
}

/// Splits metrics into routing buckets, optionally naming each request's bucket in a header.
///
/// The bucket is `fnv1a_64(key) mod count`, where `key` is the values of the `key` tags joined
/// with `/`. Tag values that contain `/` can make two different tag sets produce the same key.
///
/// Every request carries metrics of one bucket only, and requests for the same bucket are sent
/// one at a time, retries included. Without `header`, buckets still keep each series in order
/// while different buckets are sent in parallel. Requires a fixed `request.concurrency`: requests waiting for
/// their bucket hold a concurrency slot, which adaptive concurrency would read as congestion.
/// Set it to at least the number of buckets expected to be busy at once.
///
/// Each bucket is batched separately, so up to `count` batches can be open at a time.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct BucketConfig {
    /// Name of the header that carries the bucket number. When unset, no header is sent.
    #[serde(default)]
    #[configurable(metadata(docs::examples = "X-MSA-Bucket"))]
    pub header: Option<String>,

    /// Number of buckets.
    #[serde(default = "default_bucket_count")]
    pub count: u32,

    /// Tags whose values, joined with `/`, form the bucket key.
    #[configurable(metadata(docs::examples = "observo_site_id"))]
    pub key: Vec<String>,

    /// Tags used instead of `key` when a metric lacks any of the `key` tags.
    ///
    /// Tags the metric lacks count as empty values, in `fallback_key`, or in `key` when
    /// `fallback_key` is empty.
    #[serde(default)]
    pub fallback_key: Vec<String>,
}

#[derive(Debug, Snafu)]
pub(super) enum BucketConfigError {
    #[snafu(display("bucket.count must be greater than zero"))]
    ZeroCount,
    #[snafu(display("bucket.key must name at least one tag"))]
    EmptyKey,
    #[snafu(display("bucket.header is not a valid header name: {source}"))]
    InvalidHeader {
        source: http::header::InvalidHeaderName,
    },
    #[snafu(display("bucket requires a fixed request.concurrency, not adaptive"))]
    AdaptiveConcurrency,
}

impl BucketConfig {
    pub(super) fn build(self) -> Result<BucketSettings, BucketConfigError> {
        if self.count == 0 {
            return Err(BucketConfigError::ZeroCount);
        }
        if self.key.is_empty() {
            return Err(BucketConfigError::EmptyKey);
        }
        let header = self
            .header
            .map(|name| HeaderName::from_bytes(name.as_bytes()))
            .transpose()
            .map_err(|source| BucketConfigError::InvalidHeader { source })?;
        Ok(BucketSettings {
            header,
            count: self.count,
            key: self.key,
            fallback_key: self.fallback_key,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct BucketSettings {
    pub(super) header: Option<HeaderName>,
    count: u32,
    key: Vec<String>,
    fallback_key: Vec<String>,
}

impl BucketSettings {
    pub(super) fn bucket_of(&self, metric: &Metric) -> u32 {
        let values: Option<Vec<String>> =
            self.key.iter().map(|tag| metric.tag_value(tag)).collect();
        let key = match values {
            Some(values) => values.join("/"),
            None if self.fallback_key.is_empty() => join_tags(metric, &self.key),
            None => join_tags(metric, &self.fallback_key),
        };
        (fnv1a_64(key.as_bytes()) % u64::from(self.count)) as u32
    }
}

fn join_tags(metric: &Metric, tags: &[String]) -> String {
    tags.iter()
        .map(|tag| metric.tag_value(tag).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("/")
}

/// 64-bit FNV-1a. The receiving side computes the same hash, so it must not change.
pub(super) fn fnv1a_64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// A request that may belong to a routing bucket.
pub(super) trait Bucketed {
    fn bucket(&self) -> Option<u32>;
}

/// Runs requests of the same bucket one after another, in the order they were called.
///
/// Placed outside the retry layer, so a request that is being retried holds back the newer
/// requests of its bucket. Requests of other buckets, and requests without a bucket, run
/// without waiting.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct OrderedByBucketLayer;

impl<S> Layer<S> for OrderedByBucketLayer {
    type Service = OrderedByBucket<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OrderedByBucket {
            inner,
            tails: Arc::default(),
        }
    }
}

#[derive(Clone)]
pub(super) struct OrderedByBucket<S> {
    inner: S,
    /// Per bucket, a receiver that resolves once the latest request of the bucket has finished.
    tails: Arc<Mutex<HashMap<u32, oneshot::Receiver<()>>>>,
}

impl<S, Request> Service<Request> for OrderedByBucket<S>
where
    S: Service<Request> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
    Request: Bucketed + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<S::Response, S::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Capacity is claimed when the request actually runs, after its bucket is free.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let (done, released) = oneshot::channel::<()>();
        let previous = request.bucket().and_then(|bucket| {
            // The map stays consistent even if a holder panicked, so poisoning is ignored.
            self.tails
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(bucket, released)
        });
        // Built before the future, so it is dropped even if the future is never polled.
        let mut turn = Turn {
            previous,
            done: Some(done),
        };
        let inner = self.inner.clone();

        Box::pin(async move {
            if let Some(previous) = turn.previous.as_mut() {
                let _ = previous.await;
            }
            turn.previous = None;
            inner.oneshot(request).await
            // `turn` drops here and releases the next request of the bucket.
        })
    }
}

/// A request's place in its bucket's queue. Dropping it releases the next request, but never
/// before the previous one has finished: a request cancelled while still waiting hands its wait
/// on, so the requests behind it keep their order.
struct Turn {
    previous: Option<oneshot::Receiver<()>>,
    /// Never sent on: dropping it is the release signal.
    done: Option<oneshot::Sender<()>>,
}

impl Drop for Turn {
    fn drop(&mut self) {
        let (Some(previous), Some(done)) = (self.previous.take(), self.done.take()) else {
            return;
        };
        // Without a runtime (process exit) nothing is sent any more, so releasing at once is safe.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = previous.await;
                drop(done);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Duration,
    };

    use futures::future::BoxFuture;
    use tokio::sync::oneshot;
    use tower::{Layer, Service, ServiceExt};
    use vector_lib::event::{Metric, MetricKind, MetricValue};

    use super::*;

    fn metric(tags: &[(&str, &str)]) -> Metric {
        let mut metric_tags = vector_lib::event::metric::MetricTags::default();
        for (key, value) in tags {
            metric_tags.replace((*key).to_string(), (*value).to_string());
        }
        Metric::new(
            "gauge",
            MetricKind::Absolute,
            MetricValue::Gauge { value: 1.0 },
        )
        .with_tags(Some(metric_tags))
    }

    fn settings() -> BucketSettings {
        BucketConfig {
            header: Some("X-MSA-Bucket".to_string()),
            count: 1024,
            key: vec!["observo_site_id".to_string(), "host".to_string()],
            fallback_key: vec![
                "observo_site_id".to_string(),
                "observo_service_name".to_string(),
            ],
        }
        .build()
        .unwrap()
    }

    #[test]
    fn fnv1a_64_matches_reference_values() {
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn buckets_match_the_agreed_examples() {
        let settings = settings();
        let cases = [
            (
                vec![
                    ("observo_site_id", "14406"),
                    ("host", "data-plane-14406-dev-799d87d656-fjmjv"),
                ],
                418,
            ),
            (
                vec![
                    ("observo_site_id", "14406"),
                    ("host", "data-plane-collector-14406-dev-568f5544cb-q77jk"),
                ],
                798,
            ),
            (
                vec![
                    ("observo_site_id", "10880"),
                    ("host", "data-plane-5cf896465f-98j2f"),
                ],
                565,
            ),
            (
                vec![
                    ("observo_site_id", "14406"),
                    ("observo_service_name", "data_plane_collector"),
                ],
                374,
            ),
            (vec![], 510),
        ];
        for (tags, expected) in cases {
            assert_eq!(
                settings.bucket_of(&metric(&tags)),
                expected,
                "tags {tags:?}"
            );
        }
    }

    #[test]
    fn bucket_ignores_tags_outside_the_key() {
        let settings = settings();
        let base = [
            ("observo_site_id", "14406"),
            ("host", "data-plane-14406-dev-799d87d656-fjmjv"),
        ];
        let mut extra = base.to_vec();
        extra.push(("component_id", "anything"));
        assert_eq!(
            settings.bucket_of(&metric(&base)),
            settings.bucket_of(&metric(&extra))
        );
    }

    #[test]
    fn rejects_invalid_config() {
        let mut config = BucketConfig {
            header: Some("X-MSA-Bucket".to_string()),
            count: 1024,
            key: vec!["host".to_string()],
            fallback_key: vec![],
        };
        config.count = 0;
        assert!(config.clone().build().is_err());
        config.count = 1024;
        config.key = vec![];
        assert!(config.clone().build().is_err());
        config.key = vec!["host".to_string()];
        config.header = Some("not a header\n".to_string());
        assert!(config.build().is_err());
    }

    /// A request tagged with a bucket and an id, so the mock can report what it ran.
    #[derive(Clone, Debug)]
    struct TestRequest {
        id: u32,
        bucket: Option<u32>,
    }

    impl Bucketed for TestRequest {
        fn bucket(&self) -> Option<u32> {
            self.bucket
        }
    }

    /// Inner service whose calls block until the test releases them by id.
    #[derive(Clone, Default)]
    struct Gated {
        started: Arc<Mutex<Vec<u32>>>,
        gates: Arc<Mutex<HashMap<u32, oneshot::Receiver<()>>>>,
    }

    impl Gated {
        fn gate(&self, id: u32) -> oneshot::Sender<()> {
            let (tx, rx) = oneshot::channel();
            self.gates.lock().unwrap().insert(id, rx);
            tx
        }

        fn started(&self) -> Vec<u32> {
            self.started.lock().unwrap().clone()
        }
    }

    impl Service<TestRequest> for Gated {
        type Response = u32;
        type Error = crate::Error;
        type Future = BoxFuture<'static, Result<u32, crate::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: TestRequest) -> Self::Future {
            self.started.lock().unwrap().push(request.id);
            let gate = self.gates.lock().unwrap().remove(&request.id);
            Box::pin(async move {
                if let Some(gate) = gate {
                    let _ = gate.await;
                }
                Ok(request.id)
            })
        }
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn same_bucket_waits_for_the_previous_request() {
        let inner = Gated::default();
        let release_first = inner.gate(1);
        let mut service = OrderedByBucketLayer.layer(inner.clone());

        let first = service.ready().await.unwrap().call(TestRequest {
            id: 1,
            bucket: Some(7),
        });
        let second = service.ready().await.unwrap().call(TestRequest {
            id: 2,
            bucket: Some(7),
        });
        let first = tokio::spawn(first);
        let second = tokio::spawn(second);

        settle().await;
        assert_eq!(
            inner.started(),
            vec![1],
            "second request started before the first finished"
        );

        release_first.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap(), 1);
        assert_eq!(second.await.unwrap().unwrap(), 2);
        assert_eq!(inner.started(), vec![1, 2]);
    }

    #[tokio::test]
    async fn other_buckets_do_not_wait() {
        let inner = Gated::default();
        let release_first = inner.gate(1);
        let mut service = OrderedByBucketLayer.layer(inner.clone());

        let first = service.ready().await.unwrap().call(TestRequest {
            id: 1,
            bucket: Some(7),
        });
        let other = service.ready().await.unwrap().call(TestRequest {
            id: 2,
            bucket: Some(8),
        });
        let unbucketed = service.ready().await.unwrap().call(TestRequest {
            id: 3,
            bucket: None,
        });
        let first = tokio::spawn(first);
        settle().await;

        assert_eq!(other.await.unwrap(), 2);
        assert_eq!(unbucketed.await.unwrap(), 3);
        assert_eq!(inner.started(), vec![1, 2, 3]);

        release_first.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap(), 1);
    }

    #[tokio::test]
    async fn keeps_call_order_within_a_bucket() {
        let inner = Gated::default();
        let release_first = inner.gate(1);
        let mut service = OrderedByBucketLayer.layer(inner.clone());

        let mut handles = Vec::new();
        for id in 1..=4 {
            let call = service.ready().await.unwrap().call(TestRequest {
                id,
                bucket: Some(3),
            });
            handles.push(tokio::spawn(call));
        }

        settle().await;
        release_first.send(()).unwrap();
        for handle in handles {
            handle.await.unwrap().unwrap();
        }
        assert_eq!(inner.started(), vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn a_cancelled_waiting_request_keeps_the_order_behind_it() {
        let inner = Gated::default();
        let release_first = inner.gate(1);
        let mut service = OrderedByBucketLayer.layer(inner.clone());

        let first = service.ready().await.unwrap().call(TestRequest {
            id: 1,
            bucket: Some(5),
        });
        let second = service.ready().await.unwrap().call(TestRequest {
            id: 2,
            bucket: Some(5),
        });
        let third = service.ready().await.unwrap().call(TestRequest {
            id: 3,
            bucket: Some(5),
        });
        let first = tokio::spawn(first);
        let third = tokio::spawn(third);
        settle().await;

        // Cancel the second request while it is still waiting for the first.
        drop(second);
        settle().await;
        assert_eq!(
            inner.started(),
            vec![1],
            "third request started while the first was still in flight"
        );

        release_first.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap(), 1);
        assert_eq!(third.await.unwrap().unwrap(), 3);
        assert_eq!(inner.started(), vec![1, 3]);
    }

    #[tokio::test]
    async fn a_failed_request_still_releases_its_bucket() {
        #[derive(Clone)]
        struct FailFirst(Arc<Mutex<u32>>);
        impl Service<TestRequest> for FailFirst {
            type Response = u32;
            type Error = crate::Error;
            type Future = BoxFuture<'static, Result<u32, crate::Error>>;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, request: TestRequest) -> Self::Future {
                let calls = Arc::clone(&self.0);
                Box::pin(async move {
                    *calls.lock().unwrap() += 1;
                    if request.id == 1 {
                        Err("boom".into())
                    } else {
                        Ok(request.id)
                    }
                })
            }
        }

        let mut service = OrderedByBucketLayer.layer(FailFirst(Arc::new(Mutex::new(0))));
        let first = service.ready().await.unwrap().call(TestRequest {
            id: 1,
            bucket: Some(1),
        });
        let second = service.ready().await.unwrap().call(TestRequest {
            id: 2,
            bucket: Some(1),
        });
        assert!(first.await.is_err());
        assert_eq!(second.await.unwrap(), 2);
    }
}
