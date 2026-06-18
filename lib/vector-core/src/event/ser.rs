use std::time::{Duration, SystemTime};

use bytes::{Buf, BufMut};
use enumflags2::{bitflags, BitFlags, FromBitsError};
use prost::Message;
use snafu::Snafu;
use vector_buffers::{
    encoding::{AsMetadata, Encodable},
    TimedEncodable,
};

use super::{proto, Event, EventArray};

#[derive(Debug, Snafu)]
pub enum EncodeError {
    #[snafu(display("the provided buffer was too small to fully encode this item"))]
    BufferTooSmall,
}

#[derive(Debug, Snafu)]
pub enum DecodeError {
    #[snafu(display(
        "the provided buffer could not be decoded as a valid Protocol Buffers payload"
    ))]
    InvalidProtobufPayload,
    #[snafu(display("unsupported encoding metadata for this context"))]
    UnsupportedEncodingMetadata,
}
/// Flags for describing the encoding scheme used by our primary event types that flow through buffers.
///
/// # Stability
///
/// This enumeration should never have any flags removed, only added.  This ensures that previously
/// used flags cannot have their meaning changed/repurposed after-the-fact.
#[bitflags]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventEncodableMetadataFlags {
    /// Chained encoding scheme that first tries to decode as `EventArray` and then as `Event`, as a
    /// way to support gracefully migrating existing v1-based disk buffers to the new
    /// `EventArray`-based architecture.
    ///
    /// All encoding uses the `EventArray` variant, however.
    DiskBufferV1CompatibilityMode = 0b1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventEncodableMetadata(BitFlags<EventEncodableMetadataFlags>);

impl EventEncodableMetadata {
    fn contains(self, flag: EventEncodableMetadataFlags) -> bool {
        self.0.contains(flag)
    }
}

impl From<EventEncodableMetadataFlags> for EventEncodableMetadata {
    fn from(flag: EventEncodableMetadataFlags) -> Self {
        Self(BitFlags::from(flag))
    }
}

impl From<BitFlags<EventEncodableMetadataFlags>> for EventEncodableMetadata {
    fn from(flags: BitFlags<EventEncodableMetadataFlags>) -> Self {
        Self(flags)
    }
}

impl TryFrom<u32> for EventEncodableMetadata {
    type Error = FromBitsError<EventEncodableMetadataFlags>;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        BitFlags::try_from(value).map(Self)
    }
}

impl AsMetadata for EventEncodableMetadata {
    fn into_u32(self) -> u32 {
        self.0.bits()
    }

    fn from_u32(value: u32) -> Option<Self> {
        EventEncodableMetadata::try_from(value).ok()
    }
}

impl Encodable for EventArray {
    type Metadata = EventEncodableMetadata;
    type EncodeError = EncodeError;
    type DecodeError = DecodeError;

    fn get_metadata() -> Self::Metadata {
        EventEncodableMetadataFlags::DiskBufferV1CompatibilityMode.into()
    }

    fn can_decode(metadata: Self::Metadata) -> bool {
        metadata.contains(EventEncodableMetadataFlags::DiskBufferV1CompatibilityMode)
    }

    fn encode<B>(self, buffer: &mut B) -> Result<(), Self::EncodeError>
    where
        B: BufMut,
    {
        proto::EventArray::from(self)
            .encode(buffer)
            .map_err(|_| EncodeError::BufferTooSmall)
    }

    fn decode<B>(metadata: Self::Metadata, buffer: B) -> Result<Self, Self::DecodeError>
    where
        B: Buf + Clone,
    {
        if metadata.contains(EventEncodableMetadataFlags::DiskBufferV1CompatibilityMode) {
            proto::EventArray::decode(buffer.clone())
                .map(Into::into)
                .or_else(|_| {
                    proto::EventWrapper::decode(buffer)
                        .map(|pe| EventArray::from(Event::from(pe)))
                        .map_err(|_| DecodeError::InvalidProtobufPayload)
                })
        } else {
            Err(DecodeError::UnsupportedEncodingMetadata)
        }
    }
}

impl EventArray {
    fn enq_tm_to_proto(t: SystemTime) -> prost_types::Timestamp {
        let dur = t
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        prost_types::Timestamp {
            seconds: dur.as_secs() as i64,
            nanos: dur.subsec_nanos() as i32,
        }
    }

    fn enq_tm_from_proto(t: prost_types::Timestamp) -> Option<SystemTime> {
        if t.seconds < 0 || t.nanos < 0 {
            return None;
        }
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(t.seconds as u64, t.nanos as u32))
    }
}

impl TimedEncodable for EventArray {
    fn encode_with_enq_tm<B>(
        self,
        enq_tm: Option<SystemTime>,
        buffer: &mut B,
    ) -> Result<(), Self::EncodeError>
    where
        B: BufMut,
    {
        let mut p = proto::EventArray::from(self);
        p.enq_tm = enq_tm.map(Self::enq_tm_to_proto);
        p.encode(buffer).map_err(|_| EncodeError::BufferTooSmall)
    }

    fn decode_with_enq_tm<B>(
        metadata: Self::Metadata,
        buffer: B,
    ) -> Result<(Self, Option<SystemTime>), Self::DecodeError>
    where
        B: Buf + Clone,
    {
        if !metadata.contains(EventEncodableMetadataFlags::DiskBufferV1CompatibilityMode) {
            return Err(DecodeError::UnsupportedEncodingMetadata);
        }
        match proto::EventArray::decode(buffer.clone()) {
            Ok(mut p) => {
                let enq_tm = p.enq_tm.take().and_then(Self::enq_tm_from_proto);
                Ok((EventArray::from(p), enq_tm))
            }
            Err(_) => {
                let pe = proto::EventWrapper::decode(buffer)
                    .map_err(|_| DecodeError::InvalidProtobufPayload)?;
                Ok((EventArray::from(Event::from(pe)), None))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use vector_buffers::Timed;

    use super::*;
    use crate::event::{LogEvent, Metric, MetricKind, MetricValue};

    fn sample_logs() -> EventArray {
        let mut l = LogEvent::default();
        l.insert("message", "hello");
        EventArray::Logs(vec![l])
    }

    fn sample_metrics() -> EventArray {
        let m = Metric::new(
            "n",
            MetricKind::Incremental,
            MetricValue::Counter { value: 1.0 },
        );
        EventArray::Metrics(vec![m])
    }

    fn encode<E: Encodable>(item: E) -> BytesMut {
        let mut buf = BytesMut::new();
        item.encode(&mut buf).expect("encode");
        buf
    }

    fn metadata() -> EventEncodableMetadata {
        EventEncodableMetadataFlags::DiskBufferV1CompatibilityMode.into()
    }

    #[test]
    fn timed_roundtrip_with_timestamp() {
        let t = SystemTime::UNIX_EPOCH
            + Duration::from_secs(1_700_000_000)
            + Duration::from_nanos(123_456_789);
        let original = Timed {
            inner: sample_logs(),
            enq_tm: Some(t),
        };

        let bytes = encode(original.clone());
        let decoded =
            Timed::<EventArray>::decode(metadata(), bytes.freeze()).expect("decode");

        assert_eq!(decoded.enq_tm, Some(t));
        assert_eq!(decoded.inner, original.inner);
    }

    #[test]
    fn timed_roundtrip_without_timestamp() {
        let original = Timed {
            inner: sample_metrics(),
            enq_tm: None,
        };

        let bytes = encode(original.clone());
        let decoded =
            Timed::<EventArray>::decode(metadata(), bytes.freeze()).expect("decode");

        assert_eq!(decoded.enq_tm, None);
        assert_eq!(decoded.inner, original.inner);
    }

    #[test]
    fn old_reader_ignores_new_timestamp_field() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let timed = Timed {
            inner: sample_logs(),
            enq_tm: Some(t),
        };
        let bytes = encode(timed.clone());

        let decoded = EventArray::decode(metadata(), bytes.freeze()).expect("decode");
        assert_eq!(decoded, timed.inner);
    }

    #[test]
    fn timed_decodes_legacy_bytes_with_none() {
        let ea = sample_logs();
        let bytes = encode(ea.clone());

        let decoded =
            Timed::<EventArray>::decode(metadata(), bytes.freeze()).expect("decode");
        assert_eq!(decoded.enq_tm, None);
        assert_eq!(decoded.inner, ea);
    }
}
