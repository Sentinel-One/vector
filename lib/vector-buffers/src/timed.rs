//! Wrapper carrying an enqueue timestamp alongside an item moving through a buffer.

use std::time::{Duration, SystemTime};

use bytes::{Buf, BufMut};
use vector_common::{
    byte_size_of::ByteSizeOf,
    finalization::{AddBatchNotifier, BatchNotifier, EventFinalizers, Finalizable},
};

use crate::{
    encoding::{Encodable, FixedEncodable},
    EventCount,
};

/// Source of wall-clock time. Real implementations return `SystemTime::now()`; tests can supply
/// a controllable mock so that elapsed-time assertions are deterministic.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> SystemTime;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A bufferable item paired with the wall-clock time at which it entered a buffer.
///
/// `enq_tm == None` denotes "unknown enqueue time" — typically a record decoded from a buffer
/// written by a Vector binary that predates this field. Receivers treat that as zero delay.
#[derive(Debug, Clone)]
pub struct Timed<T> {
    pub inner: T,
    pub enq_tm: Option<SystemTime>,
}

impl<T> Timed<T> {
    pub fn stamped(inner: T, clock: &dyn Clock) -> Self {
        Self {
            inner,
            enq_tm: Some(clock.now()),
        }
    }

    pub fn untimed(inner: T) -> Self {
        Self {
            inner,
            enq_tm: None,
        }
    }

    /// Duration since `enq_tm` measured against `clock`. Returns `Duration::ZERO` when the
    /// timestamp is missing or when the clock has moved backwards (e.g. NTP correction).
    pub fn elapsed(&self, clock: &dyn Clock) -> Duration {
        match self.enq_tm {
            None => Duration::ZERO,
            Some(t) => clock.now().duration_since(t).unwrap_or(Duration::ZERO),
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: ByteSizeOf> ByteSizeOf for Timed<T> {
    fn allocated_bytes(&self) -> usize {
        self.inner.allocated_bytes()
    }
}

impl<T: EventCount> EventCount for Timed<T> {
    fn event_count(&self) -> usize {
        self.inner.event_count()
    }
}

impl<T: AddBatchNotifier> AddBatchNotifier for Timed<T> {
    fn add_batch_notifier(&mut self, notifier: BatchNotifier) {
        self.inner.add_batch_notifier(notifier);
    }
}

impl<T: Finalizable> Finalizable for Timed<T> {
    fn take_finalizers(&mut self) -> EventFinalizers {
        self.inner.take_finalizers()
    }
}

pub trait TimedEncodable: Encodable {
    fn encode_with_enq_tm<B: BufMut>(
        self,
        enq_tm: Option<SystemTime>,
        buffer: &mut B,
    ) -> Result<(), Self::EncodeError>;

    fn decode_with_enq_tm<B: Buf + Clone>(
        metadata: Self::Metadata,
        buffer: B,
    ) -> Result<(Self, Option<SystemTime>), Self::DecodeError>;
}

impl<T: FixedEncodable> TimedEncodable for T {
    fn encode_with_enq_tm<B: BufMut>(
        self,
        _enq_tm: Option<SystemTime>,
        buffer: &mut B,
    ) -> Result<(), Self::EncodeError> {
        <Self as Encodable>::encode(self, buffer)
    }

    fn decode_with_enq_tm<B: Buf + Clone>(
        metadata: Self::Metadata,
        buffer: B,
    ) -> Result<(Self, Option<SystemTime>), Self::DecodeError> {
        <Self as Encodable>::decode(metadata, buffer).map(|v| (v, None))
    }
}

pub trait TimedBufferable: TimedEncodable + crate::InMemoryBufferable + Clone {}
impl<T> TimedBufferable for T where T: TimedEncodable + crate::InMemoryBufferable + Clone {}

impl<T: TimedEncodable> Encodable for Timed<T> {
    type Metadata = T::Metadata;
    type EncodeError = T::EncodeError;
    type DecodeError = T::DecodeError;

    fn get_metadata() -> Self::Metadata {
        T::get_metadata()
    }

    fn can_decode(metadata: Self::Metadata) -> bool {
        T::can_decode(metadata)
    }

    fn encode<B: BufMut>(self, buffer: &mut B) -> Result<(), Self::EncodeError> {
        self.inner.encode_with_enq_tm(self.enq_tm, buffer)
    }

    fn decode<B: Buf + Clone>(
        metadata: Self::Metadata,
        buffer: B,
    ) -> Result<Self, Self::DecodeError> {
        T::decode_with_enq_tm(metadata, buffer).map(|(inner, enq_tm)| Timed { inner, enq_tm })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Test clock with explicit set/advance for deterministic elapsed-time assertions.
    pub(crate) struct MockClock(Mutex<SystemTime>);

    impl MockClock {
        pub fn new(t: SystemTime) -> Self {
            Self(Mutex::new(t))
        }

        pub fn advance(&self, by: Duration) {
            let mut g = self.0.lock().unwrap();
            *g += by;
        }

        pub fn set(&self, t: SystemTime) {
            *self.0.lock().unwrap() = t;
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> SystemTime {
            *self.0.lock().unwrap()
        }
    }

    #[test]
    fn stamped_records_clock_now() {
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = MockClock::new(t0);
        let timed = Timed::stamped(42_u64, &clock);
        assert_eq!(timed.enq_tm, Some(t0));
        assert_eq!(timed.inner, 42);
    }

    #[test]
    fn untimed_has_no_timestamp() {
        let timed = Timed::untimed(42_u64);
        assert_eq!(timed.enq_tm, None);
    }

    #[test]
    fn elapsed_reads_delta_from_clock() {
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = MockClock::new(t0);
        let timed = Timed::stamped(0_u64, &clock);
        clock.advance(Duration::from_millis(250));
        assert_eq!(timed.elapsed(&clock), Duration::from_millis(250));
    }

    #[test]
    fn elapsed_is_zero_when_clock_moved_backwards() {
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = MockClock::new(t0);
        let timed = Timed::stamped(0_u64, &clock);
        clock.set(t0 - Duration::from_secs(60));
        assert_eq!(timed.elapsed(&clock), Duration::ZERO);
    }

    #[test]
    fn elapsed_is_zero_when_enq_tm_is_none() {
        let clock = MockClock::new(SystemTime::UNIX_EPOCH);
        let timed: Timed<u64> = Timed::untimed(0);
        assert_eq!(timed.elapsed(&clock), Duration::ZERO);
    }
}
