use std::borrow::Cow;

use bytes::Bytes;
use chrono::DateTime;
use derivative::Derivative;
use influxdb_line_protocol::{FieldValue, ParsedLine};
use smallvec::SmallVec;
use vector_config::configurable_component;
use vector_core::config::LogNamespace;
use vector_core::event::{Event, Metric, MetricKind, MetricTags, MetricValue};
use vector_core::{config::DataType, schema};
use vrl::value::kind::Collection;
use vrl::value::Kind;

use crate::decoding::format::default_lossy;

use super::Deserializer;

/// Config used to build a `InfluxdbDeserializer`.
/// - [InfluxDB Line Protocol](https://docs.influxdata.com/influxdb/v1/write_protocols/line_protocol_tutorial/):
#[configurable_component]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InfluxdbDeserializerConfig {
    /// Influxdb-specific decoding options.
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub influxdb: InfluxdbDeserializerOptions,
}

impl InfluxdbDeserializerConfig {
    /// new constructs a new InfluxdbDeserializerConfig
    pub fn new(options: InfluxdbDeserializerOptions) -> Self {
        Self { influxdb: options }
    }

    /// build constructs a new InfluxdbDeserializer
    pub fn build(&self) -> InfluxdbDeserializer {
        Into::<InfluxdbDeserializer>::into(self)
    }

    /// The output type produced by the deserializer.
    pub fn output_type(&self) -> DataType {
        DataType::Metric
    }

    /// The schema produced by the deserializer.
    pub fn schema_definition(&self, log_namespace: LogNamespace) -> schema::Definition {
        schema::Definition::new_with_default_metadata(
            Kind::object(Collection::empty()),
            [log_namespace],
        )
    }
}

/// Influxdb-specific decoding options.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct InfluxdbDeserializerOptions {
    /// Determines whether or not to replace invalid UTF-8 sequences instead of failing.
    ///
    /// When true, invalid UTF-8 sequences are replaced with the [`U+FFFD REPLACEMENT CHARACTER`][U+FFFD].
    ///
    /// [U+FFFD]: https://en.wikipedia.org/wiki/Specials_(Unicode_block)#Replacement_character
    #[serde(
        default = "default_lossy",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    #[derivative(Default(value = "default_lossy()"))]
    pub lossy: bool,
}

/// Deserializer for the influxdb line protocol
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct InfluxdbDeserializer {
    #[derivative(Default(value = "default_lossy()"))]
    lossy: bool,
}

impl InfluxdbDeserializer {
    /// new constructs a new InfluxdbDeserializer
    pub fn new(lossy: bool) -> Self {
        Self { lossy }
    }
}

/// Maximum number of (tag, value) pairs one line may materialise across all of its metrics.
///
/// A line with T tags and F fields produces F metrics that each own a full copy of the T tags, so
/// the memory it costs is T x F -- quadratic in the length of a single line. Hoisting the tag map
/// out of the field loop removes the repeated string conversions but not this: `Metric::with_tags`
/// takes `MetricTags` by value, so every metric genuinely owns its tags. Only a ceiling on the
/// product bounds it.
///
/// The frame length cap bounds a line to 100 KiB by default, which still leaves room for roughly
/// 12k tags x 12k fields -- on the order of 10 GB once materialised -- so the frame cap alone does
/// not close this. Real line protocol carries a handful of tags and at most a few hundred fields,
/// so this ceiling is far above legitimate traffic.
const MAX_TAG_ENTRIES_PER_LINE: usize = 100_000;

impl Deserializer for InfluxdbDeserializer {
    fn parse(
        &self,
        bytes: Bytes,
        _log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        let line: Cow<str> = match self.lossy {
            true => String::from_utf8_lossy(&bytes),
            false => Cow::from(std::str::from_utf8(&bytes)?),
        };
        let parsed_line = influxdb_line_protocol::parse_lines(&line);

        let mut res: SmallVec<[Event; 1]> = SmallVec::new();

        for line in parsed_line.collect::<Result<Vec<_>, _>>()? {
            let ParsedLine {
                series,
                field_set,
                timestamp,
            } = &line;

            // Checked before anything is materialised: the point is never to allocate the
            // quadratic amount in the first place.
            let tag_count = series.tag_set.as_ref().map_or(0, |ts| ts.len());
            let tag_entries = tag_count.saturating_mul(field_set.len());
            if tag_entries > MAX_TAG_ENTRIES_PER_LINE {
                return Err(format!(
                    "influxdb line would expand to {tag_entries} tag entries ({tag_count} tags \
                     x {} fields), above the limit of {MAX_TAG_ENTRIES_PER_LINE}",
                    field_set.len()
                )
                .into());
            }

            // Built once per line rather than once per field. Each emitted metric still owns its
            // own copy, since `Metric::with_tags` takes `MetricTags` by value, but this stops the
            // tags being re-converted from `&str` for every single field.
            let tags = series.tag_set.as_ref().map(|ts| {
                MetricTags::from_iter(ts.iter().map(|t| (t.0.to_string(), t.1.to_string())))
            });

            for f in field_set.iter() {
                let val = match f.1 {
                    FieldValue::I64(v) => v as f64,
                    FieldValue::U64(v) => v as f64,
                    FieldValue::F64(v) => v,
                    FieldValue::Boolean(v) => {
                        if v {
                            1.0
                        } else {
                            0.0
                        }
                    }
                    // String values cannot be modelled in our schema
                    FieldValue::String(_) => continue,
                };

                res.push(Event::Metric(
                    Metric::new(
                        format!("{0}_{1}", series.measurement, f.0),
                        MetricKind::Absolute,
                        MetricValue::Gauge { value: val },
                    )
                    .with_tags(tags.clone())
                    .with_timestamp(timestamp.map(DateTime::from_timestamp_nanos)),
                ));
            }
        }

        Ok(res)
    }
}

impl From<&InfluxdbDeserializerConfig> for InfluxdbDeserializer {
    fn from(config: &InfluxdbDeserializerConfig) -> Self {
        Self {
            lossy: config.influxdb.lossy,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use vector_core::{
        config::LogNamespace,
        event::{Metric, MetricKind, MetricTags, MetricValue},
    };

    use crate::decoding::format::{Deserializer, InfluxdbDeserializer};

    #[test]
    fn deserialize_success() {
        let deser = InfluxdbDeserializer::new(true);
        let now = chrono::Utc::now();
        let now_timestamp_nanos = now.timestamp_nanos_opt().unwrap();
        let buffer = Bytes::from(format!(
            "cpu,host=A,region=west usage_system=64i,usage_user=10i {now_timestamp_nanos}"
        ));
        let events = deser.parse(buffer, LogNamespace::default()).unwrap();
        assert_eq!(events.len(), 2);

        assert_eq!(
            events[0].as_metric(),
            &Metric::new(
                "cpu_usage_system",
                MetricKind::Absolute,
                MetricValue::Gauge { value: 64. },
            )
            .with_tags(Some(MetricTags::from_iter([
                ("host".to_string(), "A".to_string()),
                ("region".to_string(), "west".to_string()),
            ])))
            .with_timestamp(Some(now))
        );
        assert_eq!(
            events[1].as_metric(),
            &Metric::new(
                "cpu_usage_user",
                MetricKind::Absolute,
                MetricValue::Gauge { value: 10. },
            )
            .with_tags(Some(MetricTags::from_iter([
                ("host".to_string(), "A".to_string()),
                ("region".to_string(), "west".to_string()),
            ])))
            .with_timestamp(Some(now))
        );
    }

    #[test]
    fn deserialize_error() {
        let deser = InfluxdbDeserializer::new(true);
        let buffer = Bytes::from("some invalid string");
        assert!(deser.parse(buffer, LogNamespace::default()).is_err());
    }

    // ---- amplification cap (OBE-11568) --------------------------------------------------------

    /// Builds a line with `tags` tags and `fields` fields.
    fn line_with(tags: usize, fields: usize) -> Bytes {
        let mut line = String::from("m");
        for i in 0..tags {
            line.push_str(&format!(",t{i}=v"));
        }
        line.push(' ');
        for i in 0..fields {
            if i > 0 {
                line.push(',');
            }
            line.push_str(&format!("f{i}=1i"));
        }
        Bytes::from(line)
    }

    /// Every field becomes a metric owning a full copy of the line's tags, so one line costs
    /// tags x fields. A line whose product is over the ceiling must be refused before any of it is
    /// materialised.
    #[test]
    fn line_over_the_tag_entry_limit_is_rejected() {
        let deser = InfluxdbDeserializer::new(true);

        // 400 x 400 = 160,000 entries, above the 100,000 ceiling.
        let error = deser
            .parse(line_with(400, 400), LogNamespace::default())
            .expect_err("an over-amplifying line must be rejected");

        let text = error.to_string();
        assert!(
            text.contains("tag entries") && text.contains("100000"),
            "error should name the limit, got: {text}"
        );
    }

    /// The ceiling must sit far above real line protocol: a wide-but-ordinary line still decodes.
    #[test]
    fn ordinary_wide_line_is_still_accepted() {
        let deser = InfluxdbDeserializer::new(true);

        // 20 tags x 200 fields = 4,000 entries — generous for real telemetry, well under the cap.
        let events = deser
            .parse(line_with(20, 200), LogNamespace::default())
            .expect("an ordinary wide line must still decode");

        assert_eq!(events.len(), 200);
        let tags = events[0].as_metric().tags().expect("tags");
        assert_eq!(tags.iter_all().count(), 20);
    }

    /// A line sitting just under the ceiling is accepted, pinning the boundary so the check cannot
    /// drift into rejecting legitimate traffic.
    #[test]
    fn line_just_under_the_limit_is_accepted() {
        let deser = InfluxdbDeserializer::new(true);

        // 100 x 1000 = 100,000 entries, exactly the ceiling.
        let events = deser
            .parse(line_with(100, 1000), LogNamespace::default())
            .expect("a line exactly at the limit must be accepted");
        assert_eq!(events.len(), 1000);
    }

    /// Tags are built once per line and cloned into each metric, so every metric must still carry
    /// the complete tag set — the hoist must not have changed what is emitted.
    #[test]
    fn every_metric_carries_the_full_tag_set() {
        let deser = InfluxdbDeserializer::new(true);

        let events = deser
            .parse(
                Bytes::from("cpu,host=A,region=west a=1i,b=2i,c=3i"),
                LogNamespace::default(),
            )
            .expect("should parse");

        assert_eq!(events.len(), 3);
        for event in &events {
            let tags = event
                .as_metric()
                .tags()
                .expect("every metric keeps its tags");
            assert_eq!(tags.get("host"), Some("A"));
            assert_eq!(tags.get("region"), Some("west"));
        }
    }
}
