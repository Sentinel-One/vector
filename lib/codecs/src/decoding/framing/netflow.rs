use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use byteorder::{ByteOrder, NetworkEndian};
use bytes::BytesMut;
use bytes::Bytes;
use netflow_parser::variable_versions::data_number::FieldValue;
use netflow_parser::variable_versions::ipfix::IPFix;
use netflow_parser::variable_versions::v9::V9;
use netflow_parser::static_versions::v5::V5;
use netflow_parser::static_versions::v7::V7;
use netflow_parser::{NetflowPacket, NetflowParseError, NetflowParser};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::codec::{Decoder, LinesCodecError};
use tracing::warn;
use vrl::core::Value;
use vrl::value::KeyString;

use crate::decoding::BoxedFramingError;
use indexmap::IndexMap;
use vector_config::configurable_component;

/// Maximum number of exporters whose templates are cached at once.
///
/// The map is keyed by attacker-influenceable data (the source address of a datagram), so it needs
/// a ceiling of its own: without one, spraying spoofed source addresses grows it without bound.
/// When full the least recently used exporter is evicted, which costs that exporter a template
/// refresh rather than dropping its data permanently.
const MAX_TRACKED_EXPORTERS: usize = 1024;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

/// Which template cache a decoder reads and writes.
///
/// NetFlow v9/IPFIX templates are defined by the exporter and are only meaningful in its own
/// context (RFC 3954 section 5.2, RFC 7011 section 8): template id 260 from one exporter says
/// nothing about template id 260 from another. Sharing one cache across peers lets any host that
/// can reach the collector redefine the layout that another exporter's data records are decoded
/// with, so each scope gets its own parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ExporterScope {
    /// A datagram peer. Keyed on the address only, deliberately not the port: an exporter's source
    /// port can change between datagrams, and including it would hide templates it already sent.
    Datagram(IpAddr),
    /// One stream connection. Templates live and die with the connection.
    Connection(u64),
}

/// Config used to build a `NetflowDecoderDecoder`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetflowDecoderConfig {
    /// Options for the netflow decoder.
    pub netflow_decoder_options: NetflowDecoderOptions,
}

impl NetflowDecoderConfig {
    /// Build the `NetflowDecoderDecoder` from this configuration.
    pub fn build(&self) -> NetflowDecoder {
        if let Some(max_length) = self.netflow_decoder_options.max_length {
            NetflowDecoder::new_with_max_length(max_length)
        } else {
            NetflowDecoder::new()
        }
    }
}

/// Options for building a `NetflowDecoderDecoder`.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetflowDecoderOptions {
    /// The maximum length of the byte buffer.
    ///
    /// This length does *not* include the trailing delimiter.
    ///
    /// By default, there is no maximum length enforced. If events are malformed, this can lead to
    /// additional resource usage as events continue to be buffered in memory, and can potentially
    /// lead to memory exhaustion in extreme cases.
    ///
    /// If there is a risk of processing malformed data, such as logs with user-controlled input,
    /// consider setting the maximum length to a reasonably large value as a safety net. This
    /// ensures that processing is not actually unbounded.
    #[serde(skip_serializing_if = "vector_core::serde::is_default")]
    pub max_length: Option<usize>,
}

impl NetflowDecoderOptions {
    /// Create a `NetflowDecoderDecoderOptions` with a delimiter and optional max_length.
    pub fn new(max_length: Option<usize>) -> Self {
        Self { max_length }
    }
}

/// A decoder for handling netflow packets. Will be moved to its own source in future.
#[derive(Clone, Debug)]
pub struct NetflowDecoder {
    /// The maximum length of the byte buffer.
    pub max_length: usize,
    /// One stateful parser per exporter, shared across clones. UDP clones this decoder per
    /// datagram, so the cache cannot live in the clone: templates arrive in one datagram and the
    /// data records referencing them in later ones.
    parsers: Arc<Mutex<IndexMap<ExporterScope, TrackedParser>>>,
    /// Which entry of `parsers` this clone uses. Defaults to a fresh connection scope so a caller
    /// that forgets to set it gets isolation rather than a shared cache.
    scope: ExporterScope,
}

#[derive(Debug)]
struct TrackedParser {
    parser: NetflowParser,
    last_used: u64,
}

impl NetflowDecoder {
    /// Creates a `NetflowDecoderDecoder` with a default maximum frame length limit.
    ///
    /// Any frames longer than `max_length` bytes will be discarded entirely.
    pub fn new() -> Self {
        // Use a more reasonable default maximum length
        Self::new_with_max_length(65536) // 64KB is a common maximum for UDP packets
    }

    /// Creates a `NetflowDecoderDecoder` with a maximum frame length limit.
    ///
    /// Any frames longer than `max_length` bytes will be discarded entirely.
    pub fn new_with_max_length(max_length: usize) -> Self {
        Self {
            max_length,
            parsers: Arc::new(Mutex::new(IndexMap::new())),
            scope: ExporterScope::Connection(NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)),
        }
    }

    /// Scopes this decoder's templates to a datagram peer.
    ///
    /// Call on the per-datagram clone before decoding, so each exporter resolves its data records
    /// against templates it sent itself.
    pub fn set_datagram_peer(&mut self, peer: IpAddr) {
        self.scope = ExporterScope::Datagram(peer);
    }

    /// Scopes this decoder's templates to a fresh connection.
    ///
    /// Call once per accepted connection. Without this every connection built from the same
    /// configured decoder would inherit one scope and share a template cache.
    pub fn set_new_connection_scope(&mut self) {
        self.scope = ExporterScope::Connection(NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed));
    }

    /// Returns the maximum frame length when decoding.
    pub const fn max_length(&self) -> usize {
        self.max_length
    }

    /// Returns the parser for `scope`, creating it if this exporter has not been seen before and
    /// evicting the least recently used exporter if the cache is full.
    fn parser_for<'a>(
        parsers: &'a mut IndexMap<ExporterScope, TrackedParser>,
        scope: &ExporterScope,
    ) -> &'a mut NetflowParser {
        // Monotonic tick rather than a clock: only the ordering matters, and this keeps the hot
        // path free of a syscall.
        static TICK: AtomicU64 = AtomicU64::new(0);
        let now = TICK.fetch_add(1, Ordering::Relaxed);

        if !parsers.contains_key(scope) {
            if parsers.len() >= MAX_TRACKED_EXPORTERS {
                // Eviction is O(n) but only runs when the cache is full; lookups stay O(1).
                if let Some((index, _, _)) = parsers
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, tracked))| tracked.last_used)
                    .map(|(index, (key, tracked))| (index, key.clone(), tracked.last_used))
                {
                    parsers.shift_remove_index(index);
                    warn!(
                        message = "Netflow template cache is full; evicted the least recently \
                                   used exporter, which must resend its templates.",
                        max_tracked_exporters = MAX_TRACKED_EXPORTERS,
                        internal_log_rate_limit = true
                    );
                }
            }
            parsers.insert(
                scope.clone(),
                TrackedParser {
                    parser: NetflowParser::default(),
                    last_used: now,
                },
            );
        }

        let tracked = parsers
            .get_mut(scope)
            .expect("entry was just inserted if absent");
        tracked.last_used = now;
        &mut tracked.parser
    }

    fn insert_v9_header_fields(v9pkt: &V9) -> BTreeMap<KeyString, Value> {
        let mut pkt: BTreeMap<KeyString, Value> = BTreeMap::new();
        pkt.insert(
            KeyString::from("version"),
            Value::from(v9pkt.header.version),
        );
        pkt.insert(
            KeyString::from("sys_up_time"),
            Value::from(v9pkt.header.sys_up_time),
        );
        pkt.insert(
            KeyString::from("unix_secs"),
            Value::from(v9pkt.header.unix_secs),
        );
        pkt.insert(
            KeyString::from("source_id"),
            Value::from(v9pkt.header.source_id),
        );
        pkt.insert(
            KeyString::from("sequence_number"),
            Value::from(v9pkt.header.sequence_number),
        );
        pkt
    }

    fn insert_v5_header_fields(v5pkt: &V5) -> BTreeMap<KeyString, Value> {
        let mut pkt: BTreeMap<KeyString, Value> = BTreeMap::new();
        pkt.insert(KeyString::from("version"), Value::from(v5pkt.header.version));
        pkt.insert(KeyString::from("count"), Value::from(v5pkt.header.count));
        pkt.insert(KeyString::from("sys_up_time"), Value::from(v5pkt.header.sys_up_time));
        pkt.insert(KeyString::from("unix_secs"), Value::from(v5pkt.header.unix_secs));
        pkt.insert(KeyString::from("unix_nsecs"), Value::from(v5pkt.header.unix_nsecs));
        pkt.insert(KeyString::from("flow_sequence"), Value::from(v5pkt.header.flow_sequence));
        pkt.insert(KeyString::from("engine_type"), Value::from(v5pkt.header.engine_type));
        pkt.insert(KeyString::from("engine_id"), Value::from(v5pkt.header.engine_id));
        pkt.insert(KeyString::from("sampling_interval"), Value::from(v5pkt.header.sampling_interval));
        pkt
    }

    fn insert_v7_header_fields(v7pkt: &V7) -> BTreeMap<KeyString, Value> {
        let mut pkt: BTreeMap<KeyString, Value> = BTreeMap::new();
        pkt.insert(KeyString::from("version"), Value::from(v7pkt.header.version));
        pkt.insert(KeyString::from("count"), Value::from(v7pkt.header.count));
        pkt.insert(KeyString::from("sys_up_time"), Value::from(v7pkt.header.sys_up_time));
        pkt.insert(KeyString::from("unix_secs"), Value::from(v7pkt.header.unix_secs));
        pkt.insert(KeyString::from("unix_nsecs"), Value::from(v7pkt.header.unix_nsecs));
        pkt.insert(KeyString::from("flow_sequence"), Value::from(v7pkt.header.flow_sequence));
        pkt.insert(KeyString::from("reserved"), Value::from(v7pkt.header.reserved));
        pkt
    }

    fn insert_ipfix_header_fields(ipfix: &IPFix) -> BTreeMap<KeyString, Value> {
        let mut pkt: BTreeMap<KeyString, Value> = BTreeMap::new();
        pkt.insert(KeyString::from("version"), Value::from(ipfix.header.version));
        pkt.insert(KeyString::from("length"), Value::from(ipfix.header.length));
        pkt.insert(KeyString::from("export_time"), Value::from(ipfix.header.export_time));
        pkt.insert(KeyString::from("sequence_number"), Value::from(ipfix.header.sequence_number));
        pkt.insert(KeyString::from("observation_domain_id"), Value::from(ipfix.header.observation_domain_id));
        pkt
    }

    fn insert_data_fields(
        pkt: &mut BTreeMap<KeyString, Value>,
        data_fields: BTreeMap<usize, (impl Serialize, FieldValue)>,
    ) {
        for (_, (field_name, field_value)) in data_fields {
            pkt.insert(
                serialize(&field_name, |k| KeyString::from(k)),
                FormattedFieldValue(field_value).stringify(),
            );
        }
    }
}

pub const NETFLOW_V5_VERSION: u16 = 5;
pub const NETFLOW_V7_VERSION: u16 = 7;
pub const NETFLOW_V9_VERSION: u16 = 9;
pub const NETFLOW_IPFIX_VERSION: u16 = 10;
impl Decoder for NetflowDecoder {
    type Item = Bytes; // Output is json as bytes
    type Error = BoxedFramingError; // Or a custom error type

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        //We can do elaborate error handling here but it will not help much as the underlying protocol is broken
        if src.len() < 20 {
            return Ok(None);
        }

        let version: u16 = NetworkEndian::read_u16(&src[0..2]);

        if !matches!(version, NETFLOW_V5_VERSION | NETFLOW_V7_VERSION | NETFLOW_V9_VERSION | NETFLOW_IPFIX_VERSION) {
            src.clear();
            warn!(
                message = "Unsupported NetFlow version",
                version = version,
                internal_log_rate_limit = true
            );
            return Err(BoxedFramingError::from(LinesCodecError::Io(
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Unsupported NetFlow version {}, discarding buf", version),
                ),
            )));
        }

        if src.len() > self.max_length {
            warn!(
                message = "Discarding frame larger than max_length.",
                buf_len = src.len(),
                max_length = self.max_length,
                internal_log_rate_limit = true
            );
            src.clear();
            return Err(BoxedFramingError::from(LinesCodecError::Io(
                io::Error::new(io::ErrorKind::Other, "Frame length limit exceeded"),
            )));
        }

        let mut packets = Vec::new();
        let mut parsers = self.parsers.lock().expect("Failed to lock NetflowParser");
        let parser = Self::parser_for(&mut parsers, &self.scope);
        let parse_results = parser.parse_bytes(src.as_mut());

        let mut had_fatal_error = false;
        let mut is_incomplete = false;
        for result in parse_results {
            match result {
                NetflowPacket::Error(err) => {
                    if matches!(err.error, NetflowParseError::Incomplete(_) | NetflowParseError::Partial(_)) {
                        is_incomplete = true;
                        continue;
                    }
                    warn!(
                        message = "Error parsing NetFlow packet",
                        error = ?err,
                        internal_log_rate_limit = true
                    );
                    had_fatal_error = true;
                }
                NetflowPacket::V9(v9pkt) => {
                    let base_pkt = Self::insert_v9_header_fields(&v9pkt);
                    for flowset in v9pkt.flowsets {
                        let flowset_id = flowset.header.flowset_id;
                        if let Some(templates) = flowset.body.templates {
                            for tmpl in templates {
                                let mut pkt = base_pkt.clone();
                                let mut fields: Vec<BTreeMap<KeyString, Value>> = Vec::new();
                                for f in tmpl.fields {
                                    let mut field: BTreeMap<KeyString, Value> = BTreeMap::new();
                                    field.insert(
                                        KeyString::from("field_type_number"),
                                        Value::from(f.field_type_number),
                                    );
                                    field.insert(
                                        KeyString::from("field_length"),
                                        Value::from(f.field_length),
                                    );
                                    field.insert(
                                        KeyString::from("field_type"),
                                        serialize(&f.field_type, |v| Value::from(v)),
                                    );
                                    fields.push(field)
                                }
                                pkt.insert(KeyString::from("template_id"), Value::from(tmpl.template_id));
                                pkt.insert(KeyString::from("template_field_count"), Value::from(tmpl.field_count));
                                pkt.insert(KeyString::from("fields"), Value::from(fields));
                                pkt.insert(KeyString::from("template_type"), Value::from("template"));
                                packets.push(pkt);
                            }
                        }
                        if let Some(data) = flowset.body.data {
                            if flowset_id > 255 {
                                for record in data.data_fields {
                                    let mut pkt = base_pkt.clone();
                                    Self::insert_data_fields(&mut pkt, record);
                                    pkt.insert(KeyString::from("template_type"), Value::from("data"));
                                    packets.push(pkt);
                                }
                            }
                        }
                        if flowset.body.options_data.is_some() {
                            let mut pkt = base_pkt.clone();
                            pkt.insert(KeyString::from("template_type"), Value::from("options_data"));
                            packets.push(pkt);
                        }
                        if flowset.body.options_templates.is_some() {
                            let mut pkt = base_pkt.clone();
                            pkt.insert(KeyString::from("template_type"), Value::from("options_templates"));
                            packets.push(pkt);
                        }
                        if flowset.body.unparsed_data.is_some() {
                            let mut pkt = base_pkt.clone();
                            pkt.insert(KeyString::from("template_type"), Value::from("unparsed_data"));
                            packets.push(pkt);
                        }
                    }
                }
                NetflowPacket::V5(v5pkt) => {
                    let base_pkt = Self::insert_v5_header_fields(&v5pkt);
                    for flowset in v5pkt.flowsets {
                        let mut pkt = base_pkt.clone();
                        pkt.insert(KeyString::from("src_addr"), Value::from(flowset.src_addr.to_string()));
                        pkt.insert(KeyString::from("dst_addr"), Value::from(flowset.dst_addr.to_string()));
                        pkt.insert(KeyString::from("next_hop"), Value::from(flowset.next_hop.to_string()));
                        pkt.insert(KeyString::from("input"), Value::from(flowset.input));
                        pkt.insert(KeyString::from("output"), Value::from(flowset.output));
                        pkt.insert(KeyString::from("d_pkts"), Value::from(flowset.d_pkts));
                        pkt.insert(KeyString::from("d_octets"), Value::from(flowset.d_octets));
                        pkt.insert(KeyString::from("first"), Value::from(flowset.first));
                        pkt.insert(KeyString::from("last"), Value::from(flowset.last));
                        pkt.insert(KeyString::from("src_port"), Value::from(flowset.src_port));
                        pkt.insert(KeyString::from("dst_port"), Value::from(flowset.dst_port));
                        pkt.insert(KeyString::from("tcp_flags"), Value::from(flowset.tcp_flags));
                        pkt.insert(KeyString::from("protocol_number"), Value::from(flowset.protocol_number));
                        pkt.insert(KeyString::from("protocol_type"), serialize(&flowset.protocol_type, |v| Value::from(v)));
                        pkt.insert(KeyString::from("tos"), Value::from(flowset.tos));
                        pkt.insert(KeyString::from("src_as"), Value::from(flowset.src_as));
                        pkt.insert(KeyString::from("dst_as"), Value::from(flowset.dst_as));
                        pkt.insert(KeyString::from("src_mask"), Value::from(flowset.src_mask));
                        pkt.insert(KeyString::from("dst_mask"), Value::from(flowset.dst_mask));
                        pkt.insert(KeyString::from("template_type"), Value::from("data"));
                        packets.push(pkt);
                    }
                }
                NetflowPacket::V7(v7pkt) => {
                    let base_pkt = Self::insert_v7_header_fields(&v7pkt);
                    for flowset in v7pkt.flowsets {
                        let mut pkt = base_pkt.clone();
                        pkt.insert(KeyString::from("src_addr"), Value::from(flowset.src_addr.to_string()));
                        pkt.insert(KeyString::from("dst_addr"), Value::from(flowset.dst_addr.to_string()));
                        pkt.insert(KeyString::from("next_hop"), Value::from(flowset.next_hop.to_string()));
                        pkt.insert(KeyString::from("input"), Value::from(flowset.input));
                        pkt.insert(KeyString::from("output"), Value::from(flowset.output));
                        pkt.insert(KeyString::from("d_pkts"), Value::from(flowset.d_pkts));
                        pkt.insert(KeyString::from("d_octets"), Value::from(flowset.d_octets));
                        pkt.insert(KeyString::from("first"), Value::from(flowset.first));
                        pkt.insert(KeyString::from("last"), Value::from(flowset.last));
                        pkt.insert(KeyString::from("src_port"), Value::from(flowset.src_port));
                        pkt.insert(KeyString::from("dst_port"), Value::from(flowset.dst_port));
                        pkt.insert(KeyString::from("flags_fields_valid"), Value::from(flowset.flags_fields_valid));
                        pkt.insert(KeyString::from("tcp_flags"), Value::from(flowset.tcp_flags));
                        pkt.insert(KeyString::from("protocol_number"), Value::from(flowset.protocol_number));
                        pkt.insert(KeyString::from("protocol_type"), serialize(&flowset.protocol_type, |v| Value::from(v)));
                        pkt.insert(KeyString::from("tos"), Value::from(flowset.tos));
                        pkt.insert(KeyString::from("src_as"), Value::from(flowset.src_as));
                        pkt.insert(KeyString::from("dst_as"), Value::from(flowset.dst_as));
                        pkt.insert(KeyString::from("src_mask"), Value::from(flowset.src_mask));
                        pkt.insert(KeyString::from("dst_mask"), Value::from(flowset.dst_mask));
                        pkt.insert(KeyString::from("flags_fields_invalid"), Value::from(flowset.flags_fields_invalid));
                        pkt.insert(KeyString::from("router_src"), Value::from(flowset.router_src.to_string()));
                        pkt.insert(KeyString::from("template_type"), Value::from("data"));
                        packets.push(pkt);
                    }
                }
                NetflowPacket::IPFix(ipfix_pkt) => {
                    let base_pkt = Self::insert_ipfix_header_fields(&ipfix_pkt);
                    for flowset in ipfix_pkt.flowsets {
                        if let Some(template) = flowset.body.templates {
                            let mut pkt = base_pkt.clone();
                            let mut fields: Vec<BTreeMap<KeyString, Value>> = Vec::new();
                            for tmpl_field in template.fields {
                                let mut field: BTreeMap<KeyString, Value> = BTreeMap::new();
                                field.insert(
                                    KeyString::from("field_type_number"),
                                    Value::from(tmpl_field.field_type_number),
                                );
                                field.insert(
                                    KeyString::from("field_length"),
                                    Value::from(tmpl_field.field_length),
                                );
                                field.insert(
                                    KeyString::from("field_type"),
                                    serialize(&tmpl_field.field_type, |v| Value::from(v)),
                                );
                                if let Some(enterprise_number) = tmpl_field.enterprise_number {
                                    field.insert(
                                        KeyString::from("enterprise_number"),
                                        Value::from(enterprise_number),
                                    );
                                }
                                fields.push(field);
                            }
                            pkt.insert(KeyString::from("template_id"), Value::from(template.template_id));
                            pkt.insert(KeyString::from("template_field_count"), Value::from(template.field_count));
                            pkt.insert(KeyString::from("fields"), Value::from(fields));
                            pkt.insert(KeyString::from("template_type"), Value::from("template"));
                            packets.push(pkt);
                        }
                        if let Some(options_template) = flowset.body.options_templates {
                            let mut pkt = base_pkt.clone();
                            pkt.insert(KeyString::from("template_id"), Value::from(options_template.template_id));
                            pkt.insert(KeyString::from("field_count"), Value::from(options_template.field_count));
                            pkt.insert(KeyString::from("scope_field_count"), Value::from(options_template.scope_field_count));
                            pkt.insert(KeyString::from("template_type"), Value::from("options_template"));
                            packets.push(pkt);
                        }
                        if let Some(data) = flowset.body.data {
                            for record in data.data_fields {
                                let mut pkt = base_pkt.clone();
                                Self::insert_data_fields(&mut pkt, record);
                                pkt.insert(KeyString::from("template_type"), Value::from("data"));
                                packets.push(pkt);
                            }
                        }
                        if let Some(options_data) = flowset.body.options_data {
                            for record in options_data.data_fields {
                                let mut pkt = base_pkt.clone();
                                Self::insert_data_fields(&mut pkt, record);
                                pkt.insert(KeyString::from("template_type"), Value::from("options_data"));
                                packets.push(pkt);
                            }
                        }
                    }
                }
            }
        }

        if is_incomplete {
            return Ok(None);
        }

        if packets.is_empty() {
            if had_fatal_error {
                src.clear();
                return Err(BoxedFramingError::from(LinesCodecError::Io(
                    io::Error::new(io::ErrorKind::InvalidData, "Failed to parse NetFlow packet"),
                )));
            }
            Ok(None)
        } else {
            src.clear();
            Ok(Some(Bytes::from(json!(packets).to_string())))
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None if src.is_empty() => Ok(None),
            None => {
                let len = src.len();
                src.clear();
                Err(BoxedFramingError::from(LinesCodecError::Io(
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("Incomplete NetFlow packet: {} bytes remaining at EOF", len),
                    ),
                )))
            }
        }
    }
}

#[derive(Debug)]
struct FormattedFieldValue(FieldValue);

impl FormattedFieldValue {
    pub fn stringify(self) -> Value {
        match self.0 {
            FieldValue::String(s) => Value::from(s),
            FieldValue::DataNumber(d) => Value::from(usize::from(d)),
            FieldValue::Float64(f) => Value::from(f),
            FieldValue::Duration(d) => Value::from(d.as_secs()),
            FieldValue::Ip4Addr(ip) => Value::from(ip.to_string()),
            FieldValue::Ip6Addr(ip) => Value::from(ip.to_string()),
            FieldValue::MacAddr(mac) => Value::from(mac),
            FieldValue::ProtocolType(proto) =>
                serialize(&proto, |v| Value::from(v)),
            FieldValue::Vec(v) => Value::from(base64::encode(v)),
            FieldValue::Unknown => Value::from(""),
        }
    }
}

fn remove_quotes(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

fn serialize<D, T>(f: &D, convert: fn(&str) -> T) -> T
    where D: ?Sized + Serialize,
{
    let q_str = serde_json::to_string(f).unwrap();
    let unq_str = remove_quotes(q_str.as_str());
    convert(unq_str)
}

#[cfg(test)]
mod tests {
    use parquet::data_type::AsBytes;

    use super::*;

    fn test_data_decoder(base64_string: &str) -> Option<Bytes> {
        let mut input = BytesMut::from(
            base64::decode(base64_string)
                .expect("should decode")
                .as_bytes(),
        );
        let mut decoder = NetflowDecoder::new();
        let res = decoder.decode(&mut input).expect("Should not fail");
        if let Some(ref bytes) = res {
            println!("{:?}", bytes);
        }
        res
    }

    // to generate test functions
    // ls netflow9_* | xargs -S65999 -I{} bash -c 'echo -e "#[test] \n fn test_data_decoder_$(echo "{}" | sed "s/.dat//g")() { \n let data = \"" && /opt/homebrew/bin/gbase64 -w 0 {} && echo -e "\";\n let res = test_data_decoder(data); \n assert_eq!(res.is_some(), true) }"'
    #[test]
    fn test_data_decoder_netflow9_cisco_asr1001x_tpl259() {
        let data = "AAkAGpylMkVZ29qLAA4IAQAAAgAAAABEAQMADwAIAAQADAAEAAUAAQAEAAEABwACAAsAAgAKAAQAXwAEAA8ABAAOAAQAPQABAAEABAACAAQAmAAIAJkACAEDBWQKb2/yCgxkDQAGzNzP4gAAAAQNAAUeCgoFZAAAABABAAADxQAAAAcAAAFfAs123QAAAV8CzXc7CgoEHQpkaVUAEQChoxIAAAAQAwAAoQoKA3IAAAAEAAAAARwAAAABAAABXwLNdt4AAAFfAs123goMZA0Kb2/yAAbP4szcAAAAEA0ABR4KCgNyAAAABAAAAAKeAAAABgAAAV8CzXbfAAABXwLNdzMKDGjvCgoLFbgGBrjwAAAAABANAABACgoDcgAAAAQAAAAAUAAAAAIAAAFfAs124AAAAV8CzXcQCgoLFQoMaO+4BvAABrgAAAAEDQAAQAoKBWQAAAAQAQAAAFAAAAACAAABXwLNduAAAAFfAs13DgpkZS0KD4NiSBEANfuQAAAABAMAADUKCgU+AAAAEAEAAABlAAAAAQAAAV8CzXbgAAABXwLNduAKZGUrCgxpF0gRAAAAAAAAAAQDAAcUCgoFZAAAABABAAAEbgAAAA4AAAFfAs124AAAAV8CzXckHw1HBwoLH2wABgG7yfwAAAAEDQACBgoKBR4AAAAQAQAAAO0AAAAEAAABXwLNduEAAAFfAs128AoLFTwKZGlWABEAoeXaAAAAEAMAAKEKCgNyAAAABAAAAABbAAAAAQAAAV8CzXbiAAABXwLNduIKDFxmrNkLBQAGxk4BuwAAABANAAHOCgoDcgAAAAQAAAAAKQAAAAEAAAFfAs124gAAAV8CzXbiCmRpVgoLFTxgEeXbAKEAAAAEAwAAoQoKBR0AAAAQAQAAAG8AAAABAAABXwLNduMAAAFfAs124woKBOoKZGlVABEAoaGHAAAAEAMAAKEKCgNyAAAABAAAAASMAAAABAAAAV8CzXbkAAABXwLNdwcKDGpTCgoLFbgGBrjwAAAAABANAABACgoDcgAAAAQAAAAAUAAAAAIAAAFfAs125AAAAV8CzXcArNkLBQoMXGYABgG7xk4AAAAEDQABzgoKBaIAAAAQAQAAADQAAAABAAABXwLNduQAAAFfAs125AoKCxUKDGpTuAbwAAa4AAAABA0AAEAKCgVkAAAAEAEAAABQAAAAAgAAAV8CzXblAAABXwLNdv0KDFFWSsmBHQAG5SEBuwAAABANAAHFCgoDcgAAAAQAAAAMEAAAAAoAAAFfAs125gAAAV8CzXdvCg55YgoMZA0ABsP+AYUAAAAQDQAB2QoKBWQAAAAQAAAAFLoAAAAYAAABXwLNducAAAFfAs13cgoLFTwKZGlWABEAoeXbAAAAEAMAAKEKCgNyAAAABAAAAAB0AAAAAQAAAV8CzXbpAAABXwLNdukKDGQNCg55YgAGAYXD/gAAABANAAHZCgoFGQAAABAAAABY7AAAAB4AAAFfAs126QAAAV8CzXd0CgxmfQoKCxW4Bga48AMAAAAQDQAAQAoKA3IAAAAEAAAAAFAAAAACAAABXwLNduoAAAFfAs13KApkaVYKCxU8YBHl3AChAAAABAMAAKEKCgUdAAAAEAEAAABLAAAAAQAAAV8CzXbqAAABXwLNduoKCgsVCgxmfbgG8AMGuAAAAAQNAABACgoFZAAAABABAAAAUAAAAAIAAAFfAs126gAAAV8CzXcmCmRpVQoKBJdgEZGRAKEAAAAEAwAAoQoKBZYAAAAQAQAAAKAAAAACAAABXwLNdusAAAFfAs129goOGVAR/Rj9ABHz2wB7AAAAEAMAAHsKCgNyAAAABAAAAABMAAAAAQAAAV8CzXbrAAABXwLNdusKDJYNCmRlKwAG8WDABAAAABANAAHZCgoDcgAAAAQAAAAFPAAAAAIAAAFfAs127AAAAV8CzXcUAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_0length_fields_tpla() {
        let data = "AAkAAgA/tYlYXH9jBgEAAQAAAAAAAAC0AQAAFQAIAAQADAAEAAoAAgAOAAIAAgAEAAEABAAYAAQAFwAEABYABAAVAAQABwACAAsAAgAGAAEABAABAAkAAQANAAEAPQABACcAAQAAAAAAAAAAAAAAAAEBABUAGwAQABwAEAAKAAIADgACAAIABAABAAQAGAAEABcABAAWAAQAFQAEAAcAAgALAAIABgABAAQAAQAdAAEAHgABAD0AAQAnAAEAAAAAAAAAAAAAAAABAAHQ7///+sCoAVAAAwACAAAAAAAAAAAAAAAAAAAAAAA/DrwAPw68AAAAAAACICABAsCoAVDv///6AAIAAwAAAAAAAAAAAAAAAQAAACAAPw68AD8OvAAAAAAAAiAgAQHv///6wKgBXwADAAIAAAAAAAAAAAAAAAAAAAAAAD8bHgA/Gx4AAAAAAAIgIAACwKgBX+////oAAgADAAAAAQAAACAAAAAAAAAAAAA/Gx4APxseAAAAAAACICAAAe////rAqAFfAAMAAgAAAAAAAAAAAAAAAAAAAAAAPxseAD8bHgAAAAAAAiAgAQLAqAFf7///+gACAAMAAAAAAAAAAAAAAAEAAAAgAD8bHgA/Gx4AAAAAAAIgIAEB7///+sCoASEAAwACAAAAAAAAAAAAAAAAAAAAAAA/G4IAPxuCAAAAAAACICAAAsCoASHv///6AAIAAwAAAAEAAAAgAAAAAAAAAAAAPxuCAD8bggAAAAAAAiAgAAHv///6wKgBIQADAAIAAAAAAAAAAAAAAAAAAAAAAD8bggA/G4IAAAAAAAIgIAECwKgBIe////oAAgADAAAAAAAAAAAAAAABAAAAIAA/G4IAPxuCAAAAAAACICABAQ==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_1941k9() {
        let data = "AAkAHgyInrhZ08LrAAY0AAAAAAAAAABEAQAADwAIAAQADAAEAAoABAAHAAIACwACAAUAAQAEAAEABgABAD0AAQDzAAIAOAAGAA8ABAABAAQAAgAEAF8ABAEABQDAqABvPtnBAQAAABGRtQA1ABEAAAAA7B9yEZ/BAAAAAAAAAEsAAAABBQAASMCoAG8+2cFBAAAAEeQrADUAEQAAAADsH3IRn8EAAAAAAAAASwAAAAEFAABIwKgAbz7ZwQEAAAARkx0ANQARAAAAAOwfchGfwQAAAAAAAABLAAAAAQUAAEjAqABvPtnBQQAAABHrNAA1ABEAAAAA7B9yEZ/BAAAAAAAAAEsAAAABBQAASJ5VOnPAqAOOAAAACxRmkkowBh0BA2gAIwQY70DAqAOOAAADxAAAAAoFAAABwKgAWNg61MMAAAAR8DIBuwARAAAAAKTRjOkwLG2m2F0AAAq8AAAACAUAAELYOtTDwKgAWAAAAAsBu/AyMBEAAQNoACMEGO9AwKgAWAAAB+cAAAAJBQAAAcCoAcnYOslqAAAAEcR7AbsABhgAAACYAaefjV9tpthdAAAIhAAAAAkFAAAB2DrJasCoAckAAAALAbvEezAGGAEDaAAjBBjvQMCoAckAAAK8AAAACQUAABA07CGjwKgCdgAAAAsBu++pMAYYAQNoACMEGO9AwKgCdgAAAKEAAAACBQAAEMCoAyI02ILtAAAAEfDqAbsABhsAAAAcXPIHDyptpthdAAAG5AAAABUFAAAQ0cUDE8CoAyIAAAALAbvw6DAGHwEDaAAjBBjvQMCoAyIAADXzAAAAHgUAABA02ILtwKgDIgAAAAsBu/DqMAYbAQNoACMEGO9AwKgDIgAAEm0AAAAQBQAAEMCoAJ2s2RfoAAAAEcgJAbsABhoAAACwNJUN0l1tpthdAAAJcwAAAA0FAAAQrNkX6MCoAJ0AAAALAbvICTAGGgEDaAAjBBjvQMCoAJ0AABWvAAAACgUAABBrFeiuwKgDsgAAAAsBu7IQMAYZAQNoACMEGO9AwKgDsgAAALsAAAADBQAAEMCoA7JrFeiuAAAAEbIQAbsABhEAAADc78pM2ldtpthdAAAAaAAAAAIFAAAQwKgCdl8AkfIAAAAR+ukIrgAGGwAAAHAYi1zJtW2m2F0AAA/SAAAASAUAAAFfAJHywKgCdgAAAAsIrvrpMAYbAQNoACMEGO9AwKgCdgAADocAAABIBQAAAcCoAE8XBWRCAAAAEdQDAbsABhoAAACMKTd6KMBtpthdAAAFegAAABAFAAAQwKgATxcFZEIAAAAR1AQBuwAGGgAAAIwpN3oowG2m2F0AAAYCAAAAEQUAABAXBWRCwKgATwAAAAsBu9QEMAYaAQNoACMEGO9AwKgATwAAMsoAAAAOBQAAEKr7tA/AqAA9AAAACwG73q8wBhgBA2gAIwQY70DAqAA9AAAEqgAAAAQFAAAQwKgAPar7tA8AAAAR3q8BuwAGGAAAAJBhrnbl6W2m2F0AAAKqAAAAAgUAABDAqAMiSnd3VAAAABHw/gG7AAYaAAAAHFzyBw8qbabYXQAABwwAAAALBQAAELk82hPAqAOOAAAACwG76EMwBhoBA2gAIwQY70DAqAOOAAASpgAAAAkFAAABwKgDyLk82g8AAAAR++0BuwAGGAAAABggMrsdYm2m2F0AAACHAAAAAgUAAAG5PNoPwKgDyAAAAAsBu/vtMAYYAQNoACMEGO9AwKgDyAAAAIcAAAACBQAAEMCoAF+pLdb2AAAAEYjtFGYABhgAAACgOfdNSdVtpthdAAAAwgAAAAMFAAAB";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_1a() {
        let data = "AAkADgAfgP1WF41HAAAClgAAAAABCQWYAAAhNMCoDgEAAAADAgICC0SNAAIBAADAqA4BAgICCwAARI0CB+kAAAFQS//X3wAAADgAAAFQS//P8Q+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhNcCoFxZEjQACpKQlCwAAAAMBCADAqBcWpKQlC0SNAAACB+kAAAFQS//aIwAAADgAAAFQS//SSQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhNqSkJQsAAAADwKgXFkSNAAIBAACkpCULwKgXFgAARI0CB+kAAAFQS//aSwAAADgAAAFQS//SUw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhN8CoFxRFjQACpKQlCwAAAAMBCADAqBcUpKQlC0WNAAACB+kAAAFQS//bEwAAADgAAAFQS//TLw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhOKSkJQsAAAADwKgXFEWNAAIBAACkpCULwKgXFAAARY0CB+kAAAFQS//bHQAAADgAAAFQS//TOQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhOcCoDgtFjQADAgICCwAAAAIBCADAqA4LAgICC0WNAAACB+kAAAFQS//b2wAAADgAAAFQS//T7Q+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhOgICAgsAAAACwKgOC0WNAAMBAAACAgILwKgOCwAARY0CB+kAAAFQS//b7wAAADgAAAFQS//T9w+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhOwICAgtFjQACwKgOAQAAAAMBCAACAgILwKgOAUWNAAACB+kAAAFQS//b7wAAADgAAAFQS//UAQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhPMCoDgEAAAADAgICC0WNAAIBAADAqA4BAgICCwAARY0CB+kAAAFQS//b7wAAADgAAAFQS//UCw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhTaSkJQsAAAADwKgXAQAAAAIBAwOkpCULwKgXAQAAAAACB+AAAAFQS//eZQAAAKAAAAFQS//eZQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhPcCoFxZGjQACpKQlCwAAAAMBCADAqBcWpKQlC0aNAAACB+kAAAFQS//eZQAAADgAAAFQS//WgQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhPqSkJQsAAAADwKgXFkaNAAIBAACkpCULwKgXFgAARo0CB+kAAAFQS//eeQAAADgAAAFQS//Wiw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhP8CoFxRGjQACpKQlCwAAAAMBCADAqBcUpKQlC0aNAAACB+kAAAFQS//fQQAAADgAAAFQS//XXQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhQKSkJQsAAAADwKgXFEaNAAIBAACkpCULwKgXFAAARo0CB+kAAAFQS//fVQAAADgAAAFQS//XZw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_1_tpl() {
        let data = "AAkADQAfesRWF41FAAAClQAAAAAAAAPgAQAAFQCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAGcQQAEnEIABJxDAAKcRAACnEUAAYDqAAIBQwAIAFUABIDoAAyA6QAMnEAAFAEBABUAlAAEAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABnEEABJxCAAScQwACnEQAApxFAAGA6gACAUMACABVAASA6AAMgOkADJxAAEEBAgARAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAZxFAAGA6gACAUMACABVAASA6AAMgOkADJxAABQBAwARAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAZxFAAGA6gACAUMACABVAASA6AAMgOkADJxAAEEBBAASAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABnEEABJxCAAScQwACnEQAApxFAAGA6gACAUMACIDoAAyA6QAMAQUADgAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAZxFAAGA6gACAUMACIDoAAyA6QAMAQYADgAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAZxFAAGA6gACAUMACIDoAAyA6QAMAQcAEgCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAGcQQAEnEIABJxDAAKcRAACnEUAAYDqAAIBQwAIAFUABAEIAA4AlAAEABsAEAAHAAIACgACABwAEAALAAIADgACAAQAAQCyAAEAswABnEUAAYDqAAIBQwAIAFUABAEJABYAlAAEAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABnEEABJxCAAScQwACnEQAApxFAAGA6gACAUMACABVAAQAmAAIgOgADIDpAAycQAAUAQoAFgCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAGcQQAEnEIABJxDAAKcRAACnEUAAYDqAAIBQwAIAFUABACYAAiA6AAMgOkADJxAAEEBCwASAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAZxFAAGA6gACAUMACABVAAQAmAAIgOgADIDpAAycQAAUAQwAEgCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAGcRQABgOoAAgFDAAgAVQAEAJgACIDoAAyA6QAMnEAAQQ==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_2a() {
        let data = "AAkAEywSgQ5XkNMtAAAAHwAAAAABBwG4LEaHfcCoAALxTwADwKgAEQBQAAQGAADAqAACwKgAEfFPAFACB+4AAAFWDbjYNwAAAFEAAAL7AAABVg241/ssRod+wKgAAvFQAAPAqAARAFAABAYAAMCoAALAqAAR8VAAUAUH7gAAAVYNuNhLAAAAUQAAGD8AAAFWDbjX+yxGh37AqAAC8VAAA8CoABEAUAAEBgAAwKgAAsCoABHxUABQAgfuAAABVg242EsAAABRAAAYPwAAAVYNuNf7LEaHI8CoAAHdOwADwKgAEgBQAAQGAADAqAABwKgAEt07AFAFB+4AAAFWDbjYmwAAAFEAACNzAAABVg241hssRocjwKgAAd07AAPAqAASAFAABAYAAMCoAAHAqAAS3TsAUAIH7gAAAVYNuNibAAAAUQAAI3MAAAFWDbjWGyxGh3vAqAAC8U0AA8CoABEAUAAEBgAAwKgAAsCoABHxTQBQBQfuAAABVg242OEAAABRAAAVoAAAAVYNuNf7LEaHe8CoAALxTQADwKgAEQBQAAQGAADAqAACwKgAEfFNAFACB+4AAAFWDbjY4QAAAFEAABWgAAABVg241/sAAAEAAGgsRoe9wKgAAd1JAAPAqAASAFAABAYAAMCoAAHAqAAS3UkAUAEAAAAAAVYNuNmpAAABVg242ak+3N5JCqYqw6iip2sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQcAgCxGh73AqAAB3UkAA8CoABIAUAAEBgAAwKgAAcCoABLdSQBQBQfuAAABVg242gMAAABFAAA3YwAAAVYNuNmpLEaHvcCoAAHdSQADwKgAEgBQAAQGAADAqAABwKgAEt1JAFACB+4AAAFWDbjaAwAAAEUAADdjAAABVg242akBAABoLEaIucCoAALxUQADwKgAEQBQAAQGAADAqAACwKgAEfFRAFABAAAAAAFWDbjgGwAAAVYNuOAbPtzeSQqmKsNW6FEuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEHAIAsRoi5wKgAAvFRAAPAqAARAFAABAYAAMCoAALAqAAR8VEAUAUH7gAAAVYNuOB1AAAARQAAN2IAAAFWDbjgGyxGiLnAqAAC8VEAA8CoABEAUAAEBgAAwKgAAsCoABHxUQBQAgfuAAABVg244HUAAABFAAA3YgAAAVYNuOAbAQAAaCxGiTnAqAAB3UoAA8CoABEAUAAEBgAAwKgAAcCoABHdSgBQAQAAAAABVg244wkAAAFWDbjjCT7c3kkKpirDVuhRLgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBwCALEaJOcCoAAHdSgADwKgAEQBQAAQGAADAqAABwKgAEd1KAFAFB+4AAAFWDbjjlQAAAEsAAANxAAABVg244wksRok5wKgAAd1KAAPAqAARAFAABAYAAMCoAAHAqAAR3UoAUAIH7gAAAVYNuOOVAAAASwAAA3EAAAFWDbjjCQEAAGgsRol/wKgAAd1LAAPAqAASAFAABAYAAMCoAAHAqAAS3UsAUAEAAAAAAVYNuOVrAAABVg245Ws+3N5JCqYqw6iip2sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQcAgCxGiX/AqAAB3UsAA8CoABIAUAAEBgAAwKgAAcCoABLdSwBQBQfuAAABVg245c8AAABFAAA3YgAAAVYNuOVrLEaJf8CoAAHdSwADwKgAEgBQAAQGAADAqAABwKgAEt1LAFACB+4AAAFWDbjlzwAAAEUAADdiAAABVg245Ws=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_2_tpl_26x() {
        let data = "AAkAECwTuoBXkNN9AAAASgAAAAAAAAVYAQAAFQCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAJgACIDoAAyA6QAMnEAAFAEBABUAlAAEAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABAOEABADiAAQA4wACAOQAAgDpAAGA6gACAUMACACYAAiA6AAMgOkADJxAAEEBAgAVAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgAmAAIgOgADIDpAAycQAAUAQMAFQCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAJgACIDoAAyA6QAMnEAAQQEEABIACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIgOgADIDpAAwBBQAOAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABAOkAAYDqAAIBQwAIgOgADIDpAAwBBgAOABsAEAAHAAIACgACABwAEAALAAIADgACAAQAAQCyAAEAswABAOkAAYDqAAIBQwAIgOgADIDpAAwBBwAUAJQABAAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQDhAAQA4gAEAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAgBCAAUAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAgBCQAXAJQABAAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQDhAAQA4gAEAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAiA6AAMgOkADJxAABQBCgAXAJQABAAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQDhAAQA4gAEAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAiA6AAMgOkADJxAAEEBCwAXAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAiA6AAMgOkADJxAABQBDAAXAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAiA6AAMgOkADJxAAEEBDQAVAJQABAAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgAmAAIgOgADIDpAAycQAAUAQ4AFQCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAJgACIDoAAyA6QAMnEAAQQEPABUAlAAEABsAEAAHAAIACgACABwAEAALAAIADgACAAQAAQCyAAEAswABAOEABADiAAQA4wACAOQAAgDpAAGA6gACAUMACACYAAiA6AAMgOkADJxAABQ=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_2_tpl_27x() {
        let data = "AAkADiwTuoBXkNN9AAAASwAAAAAAAASoARAAFQCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAJgACIDoAAyA6QAMnEAAQQERABIAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIgOgADIDpAAwBEgASAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABARkAEAEaABAA4wACAOQAAgDpAAGA6gACAUMACIDoAAyA6QAMARMAEgAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQDhAAQBGgAQAOMAAgDkAAIA6QABgOoAAgFDAAiA6AAMgOkADAEUABIAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIgOgADIDpAAwBFQASABsAEAAHAAIACgACABwAEAALAAIADgACAAQAAQCyAAEAswABARkAEADiAAQA4wACAOQAAgDpAAGA6gACAUMACIDoAAyA6QAMARYAFACUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIARcAFACUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEA4QAEARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIARgAFACUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIARkAFACUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEBGQAQAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIARoAFwCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIgOgADIDpAAycQAAUARsAFwCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIgOgADIDpAAycQABBARwAFwCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIgOgADIDpAAycQAAUAR0AFwCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIgOgADIDpAAycQABB";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9ka256() {
        let data = "AAkAE2WdGn1YRo5sAXXKjwAACIEBAAVcwcS+QwAAAEpUZW5HaWdFMF8wXzFfMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAEtUZW5HaWdFMF8wXzFfMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAExUZW5HaWdFMF8wXzFfMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADZHaWdhYml0RXRoZXJuZXQwXzBfMF8wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADdHaWdhYml0RXRoZXJuZXQwXzBfMF8xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADhHaWdhYml0RXRoZXJuZXQwXzBfMF8yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADpHaWdhYml0RXRoZXJuZXQwXzBfMF80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADtHaWdhYml0RXRoZXJuZXQwXzBfMF81AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADxHaWdhYml0RXRoZXJuZXQwXzBfMF82AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAEJHaWdhYml0RXRoZXJuZXQwXzBfMF8xMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAFZUZW5HaWdFMF8xXzBfMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAFdUZW5HaWdFMF8xXzBfMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAFhUZW5HaWdFMF8xXzBfMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAKJCdW5kbGUtRXRoZXIyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAG5UZW5HaWdFMF82XzFfMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAG9UZW5HaWdFMF82XzFfMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAGZUZW5HaWdFMF82XzBfMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAGdUZW5HaWdFMF82XzBfMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAGhUZW5HaWdFMF82XzBfMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9ka260() {
        let data = "AAkAFWWcvHFYRo5UAXXGoQAACIEBBAVcAAAAAQAAACgKAAmSCgAfUQAAAG4AAACeZZxHBWWcRwXTAQG7AAAAAAAA+/AKAA4hEBQGEAABQAABYAAAAGAAAAAAAAACAAAAaAoAESoKACMEAAAAVwAAAJ5lnEmIZZxHB46EAbsAAAAAAAD78AoADiEVEAYQAAFAAAFgAAAAYAAAAAAAAAEAAAA0CgAWbwoAIo0AAABoAAAAnmWcRwplnEcKQa4BuwAAAAAAAPvwCgAOIRgQBhEAAUAAAWAAAABgAAAAAAAAAQAAAbMKABc7CgAkqgAAAFYAAACeZZxHDGWcRwwANf0sAAAAAAAA+/EKAA4fGRMRAAABQAABYAAAAGAAAAAAAAABAAADyQoAIkcKABTyAAAAngAAAGplnEcNZZxHDQG7B90AAPvwAAD/ogoAEgUQFQYYAABAAAFgAAAAYAAAAAAAAAIAAABoCgAKhQoAHmYAAABuAAAAnmWcRw1lnEa6ickAUAAAAAAAAPvwCgAOIRAQBhAAAUAAAWAAAABgAAAAAAAAAQAAADQKACUdCgAGGAAAAGYAAACiZZxHEGWcRxAAUN3DAAA7HQAA/5cKAADyGBAGECAAQAABYAAAAGAAAAAAAAABAAACZgoAILAKAAtxAAAAngAAAC5lnEcQZZxHEAG73f4AAPvwAAD/mAoAEmkUEAYYAABAAAFgAAAAYAAAAAAAAAMAABD+CgAMFQoADyYAAABXAAAAnmWcRxFlnDHnAbucjgAAgKYAAPvyCgAOGxgYBhAAAUAAAWAAAABgAAAAAAAAAgAAAhUKAATUCgADbgAAAKIAAABmZZxUB2WcRxLGAwG7AAD/lwAAAEYKABBlEBEGGAABQAABYAAAAGAAAAAAAAFFAAA1XAoAIXoKAAGIAAAAngAAAGhlnG/QZZwiGuW+AFAAAPvxAAAAAAAAAAAVGwYQAABAAAFgAAAAYAAAAAAAAAEAAABZCgAU8goAIkcAAABqAAAAnmWcRxRlnEcUB90BuwAA/6IAAPvwCgAOIRUQBhhgAUAAAWAAAABgAAAAAAAAAQAAA0EKAA0ZCgAPJgAAAFcAAACeZZxHFmWcRxYBu8mlAACApgAA+/IKAA4bGBgGGAABQAABYAAAAGAAAAAAAAACAAAGWQoAGTsKAAISAAAAngAAAG5lnEcYZZxGvwG79AAAAPvwAAD/nQoAEn4QEAYYAABAAAFgAAAAYAAAAAAAAGEAAitoCgAHSQoAG6gAAABWAAAAnmWcdatlnDH+65gB0QAA/5wAAPvwCgAOIRAQBhgAAUAAAWAAAABgAAAAAAAAOgAAC8gKABMyCgAbqQAAAGoAAACeZZxPy2WcRTqGlAPjAAD/twAA+/AKAA4hEhAGEAABQAABYAAAAGAAAAAAAAAVAAB7DAoAHJYKABgNAAAAngAAAGhlnEhZZZxG8AG7wv0AAPvwAAAAAAAAAAAQGQYQAABAAAFgAAAAYAAAAAAAAAMAAAtnCgAavAoAFcgAAACeAAAAV2WcR2ZlnEXsA+HETgAA+/AAAAAAAAAAABAZBhgAAEAAAWAAAABgAAAAAAAABQAAEaIKAB0iCgAPJgAAAEsAAACeZZxtYGWcQf4Bu4yPAAA7QQAA+/IKAA4bGBgGGAABQAABYAAAAGAAAAAAAAABAAABRgoACMgKAAXgAAAAZgAAAKJlnEcdZZxHHVpYydcAAAMVAAD/lwoAAPIQEAYYAABAAAFgAAAAYAAAAAAAAAIAAABwCgAdLgoADyYAAABLAAAAnmWcRx1lnEDqAbvMjAAAO0EAAPvyCgAOGxgYBhIAAUAAAWAAAABgAAAAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_opttpl256() {
        let data = "AAkAAWWdGn1YRo5sAXXKjgAACIEAAQAYAQAABAAIAAEABAAKAAQAUwBAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_opttpl257() {
        let data = "AAkAAWWdGn1YRo5sAXXKjAAACIEAAQAgAQEABAAQAAEABAAwAAIAMgAEADEAAQBUACAAAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_opttpl334() {
        let data = "AAkAAWWdGn1YRo5sAXXKiwAACIEAAQAYAU4ABAAIAAEABADqAAQA7AAgAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_tpl260() {
        let data = "AAkAAWWcwF9YRo5VAXXHAwAACIEAAABkAQQAFwACAAQAAQAEAAgABAAMAAQACgAEAA4ABAAVAAQAFgAEAAcAAgALAAIAEAAEABEABAASAAQACQABAA0AAQAEAAEABgABAAUAAQA9AAEAWQABADAAAgDqAAQA6wAE";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_tpl266() {
        let data = "AAkAAWWcsqJYRo5RAXXGmwAACIEAAABsAQoAGQACAAQAAQAEABsAEAAcABAACgAEAA4ABAAWAAQAFQAEAB8ABABAAAQABwACAAsAAgAQAAQAEQAEAD8AEAAeAAEAHQABAAQAAQAGAAEABQABAD0AAQBZAAEAMAACAOoABADrAAQ=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_nbara262() {
        let data = "AAkABfQeqxBYouWsABcHDgAAAAABBgGZCh4SPgoeE7QBAAABAAAAAQAAAAAAAAgAAAABFwAAUFaRVoYc3w9+w1gAAAAAAAAAAAAAAAAKHhIAAAAAAAAAACwAAAAB9B5qGPQeahgAAAAACh4SPgoeE7QFAAAmAAAAAQAAAACFrAChAAARFwAAUFaRVoYc3w9+w1gAAAAAAAAAoQAAAAAKHhIAAAAAAAAAAGoAAAAB9B5qGPQeahgAAAAACgqsPAoeE7QBAAABAAAAAQAAAAAAAAgAAAABAAAAGBmebAEc3w9+w1gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAAAB9B5sRPQebEQAAAAACgqsPAoeE7QDAAB7AAAAAQAAAAAAewB7AMARADAAGBmebAEc3w9+w1gAAAAAAAAAewAAAAAAAAAAAAAAAAAAAEwAAAAB9B5sjPQebIwAAAAACgqsPAoeE7QFAAAmAAAAAQAAAACw1QChAAARAAAAGBmebAEc3w9+w1gAAAAAAAAAoQAAAAAAAAAAAAAAAAAACuoAAAAk9B5sUPQebJgAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_nbar_opttpl260() {
        let data = "AAkAEHYKb6xYouWHAAoB9AAAAAAAAQAaAQQABAAMAAEABABfAAQAYAAYAF4ANwEEBR0KDwFzAQAACGVncAAAAAAAAAAAAAAAAAAAAAAAAAAAAEV4dGVyaW9yIEdhdGV3YXkgUHJvdG9jb2wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAL2dyZQAAAAAAAAAAAAAAAAAAAAAAAAAAAEdlbmVyYWwgUm91dGluZyBFbmNhcHN1bGF0aW9uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAAWljbXAAAAAAAAAAAAAAAAAAAAAAAAAAAEludGVybmV0IENvbnRyb2wgTWVzc2FnZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAWGVpZ3JwAAAAAAAAAAAAAAAAAAAAAAAAAEVuaGFuY2VkIEludGVyaW9yIEdhdGV3YXkgUm91dGluZyBQcm90b2NvbAAAAAAAAAAAAAAAAAAKDwFzAQAABGlwaW5pcAAAAAAAAAAAAAAAAAAAAAAAAElQIGluIElQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAWW9zcGYAAAAAAAAAAAAAAAAAAAAAAAAAAE9wZW4gU2hvcnRlc3QgUGF0aCBGaXJzdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAAGhvcG9wdAAAAAAAAAAAAAAAAAAAAAAAAElQdjYgSG9wLWJ5LUhvcCBPcHRpb24AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAA2dncAAAAAAAAAAAAAAAAAAAAAAAAAAAAEdhdGV3YXktdG8tR2F0ZXdheQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAABXN0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAFN0cmVhbQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAB2NidAAAAAAAAAAAAAAAAAAAAAAAAAAAAENCVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAACWlncnAAAAAAAAAAAAAAAAAAAAAAAAAAAENpc2NvIGludGVyaW9yIGdhdGV3YXkgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAACmJibnJjY21vbgAAAAAAAAAAAAAAAAAAAEJCTiBSQ0MgTW9uaXRvcmluZwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAC252cC1paQAAAAAAAAAAAAAAAAAAAAAAAE5ldHdvcmsgVm9pY2UgUHJvdG9jb2wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAADHB1cAAAAAAAAAAAAAAAAAAAAAAAAAAAAFBVUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAADWFyZ3VzAAAAAAAAAAAAAAAAAAAAAAAAAEFSR1VTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_nbar_tpl262() {
        let data = "AAkAAfQeLhBYouWMABcG2wAAAAAAAABwAQYAGgAIAAQADAAEAF8ABAAKAAQADgAEAAcAAgALAAIAPQABAAUAAQAEAAEACQABAMMAAQA4AAYAUAAGABAAAgARAAIAtgACALUAAgAPAAQALAAEADAABAABAAQAAgAEABYABAAVAAQANgAE";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_wlc_8510_tpl_262() {
        let data = "AAkABEN0865ZyOW4AAEI5QAAAAEAAQAYAQAABAAIAAEABABfAAQAYABAYW4AAQAYAQIABAAIAAEABE4gAAIAkwAhAGcAAQAYAQMABAAIAAEABAA6AAIAUgAgbmUAAABMAQYAEQAIAAQADAAEAAcAAgALAAIABAABAD0AAQBfAAQBbQAGAW8ABk4gAAIAOgACAAUAAQAWAAQAFQAEAAEACAACAAgBcwAh";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_wlca261() {
        let data = "AAkAAU+roJ5ZS2QyAAAATgAAAAEBBQVcNAKGdcBRwKgUeQ0AAd9UZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADPgAAAAAAAAAUwAAAPZjzIBgNAKGdcBRwKgUeQ0AAd9UZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAADPgAAAAAAAAAUwAAAPZjzIBgNAKGdcBRwKgUeQMAADVUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHlAAAAAAAAAARQAAAPZjzIBgNAKGdcBRwKgUeQMAADVUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAJ/UAAAAAAAAARQAAAPZjzIBgNAKGdcBRwKgUeQMAAIpUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANcAAAAAAAAAAQAAAPZjzIBgNAKGdcBRwKgUeQ0AAAFUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAn5YAAAAAAAAA4QAAAPZjzIBgNAKGdcBRwKgUeQ0AAAFUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAjBoAAAAAAAAAmgAAAPZjzIBgNAKGdcBRwKgUeQMAAFBUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL/cAAAAAAAAAPwAAAPZjzIBgNAKGdcBRwKgUeQMAAFBUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAapcAAAAAAAAAPQAAAPZjzIBgNAKGdcBRwKgUeQ0AAcVUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACPskAAAAAAAADBQAAAPZjzIBgNAKGdcBRwKgUeQ0AAcVUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAASC+cAAAAAAAAFYwAAAPZjzIBgNAKGdcBRwKgUeQ0AAghUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGnkAAAAAAAAAGgAAAPZjzIBgNAKGdcBRwKgUeQ0AAghUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAIbEAAAAAAAAAGgAAAPZjzIBgNAKGdcBRwKgUeQMAAbtUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlH+kAAAAAAABP0gAAAPZjzIBgNAKGdcBRwKgUeQMAAbtUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAANfpIAAAAAAAACfFgAAAPZjzIBgNAKGdcBRwKgUeQEAAAFUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnoAAAAAAAAADwAAAPZjzIBgNAKGdcBRwKgUeQEAAAFUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAA7YAAAAAAAAADgAAAPZjzIBgNAKGdcBRwKgUeQ0AAa9UZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAW0g8AAAAAAAA/EQAAAPZjzIBgNAKGdcBRwKgUeQ0AAa9UZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAATTkDgAAAAAAADQcgAAAPZjzIBg";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_wlc_tpl() {
        let data = "AAkAAk+r9pZZS2RIAAAAUAAAAAEAAQAYAQAABAAIAAEABABfAAQAYABALWcAAAAwAQUACgFtAAYBbgAEAF8ABACTACEAPQABAAEACAACAAgAYgABAMMAAQFvAAY=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_field_layer2segmentida() {
        let data = "AAkAAQBVNIBaXcmeAAASpQAEAAABCgBAwKjIiFBS7SgG8eYBvQAMZgAAAAAAAAAAAAAABwAAAAAAAFT56ABU+ehiAAAAAAAAADQAAAAAAAAAAQAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_field_layer2segmentid_tpl() {
        let data = "AAkAAQBVLLBaXcmcAAASoQAEAAAAAABMAQoAEQAIAAQADAAEAAQAAQAHAAIACwACAAUAAQA6AAIBXwAIAAoABADqAAQAPQABABYABAAVAAQAMAABAAEACAACAAgA0gAC";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_521a256() {
        let data =
            "AAkAAQE3sapZbZ+2AAA1SQAAAAEBAAAoAAEAAAABmZAB5wAAAAAAteXWAAAAAAABpVgHCAAPAAAAAQEA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_521a257() {
        let data = "AAkAAQE3dxJZbZ+nAAA1QwAAAAEBAQA4AAAAAAAAAJgAAAAAAAAAAAAAAAMAAAAAJQ9UpCUPd8zx1gG7AAkAAwbAqGMHHw1XJAAAAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_521_tpl() {
        let data = "AAkAAgE37EJZbZ/FAAA1TAAAAAEAAADcAQEADQABAAgAFwAIAAIABAAYAAQAFgAEABUABAAHAAIACwACAAoAAgAOAAIABAABAAgABAAMAAQBAgANAAEACAAXAAgAAgAEABgABAAWAAQAFQAEAAcAAgALAAIACgACAA4AAgAEAAEAGwAQABwAEAEDAAwAAQAIABcACAACAAQAGAAEABYABAAVAAQACgACAA4AAgAgAAIABAABAAgABAAMAAQBBAAMAAEACAAXAAgAAgAEABgABAAWAAQAFQAEAAoAAgAOAAIAIAACAAQAAQAbABAAHAAQAAEALAEAAAQAHAABAAIAKAAIACkACAAqAAgAJAACACUAAgAiAAQAIwABAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_542_appida258_262() {
        let data = "AAkAEQAlHGRa9OmzAAABXgAAAAEBBgBQAAAAAAAAAuwAAAAAAAAC7AAAAAYAAAAGACUW2AAlGHKxRABQAAgAAgYUAAAwRAAAjzQMTEADwKhkl7YyiO8KAAD6AAAAALFEAAAAAAEGAFAAAAAAAAAbJAAAAAAAABskAAAACgAAAAoAJRMOACUXeAG7ruoAAgAIBhQAADBEAACeeAxMQAPQZBG7wKhklwAAAAAKAAD6AACu6gAAAQYAUAAAAAAAAAYwAAAAAAAABjAAAAAOAAAADgAlEw4AJRd4ruoBuwAIAAIGFAAAMEQAAJ54DExAA8CoZJfQZBG7CgAA+gAAAACu6gAAAAABBgBQAAAAAAAAIAkAAAAAAAAgCQAAAAsAAAALACUTaAAlF3gBu8W6AAIACAYUAAAwRAAAnngMTEAD0GQRvcCoZJcAAAAACgAA+gAAxboAAAEGAFAAAAAAAAAGwQAAAAAAAAbBAAAADwAAAA8AJRNoACUXeMW6AbsACAACBhQAADBEAACeeAxMQAPAqGSX0GQRvQoAAPoAAAAAxboAAAAAAQYAUAAAAAAAAARiAAAAAAAABGIAAAAFAAAABQAlE2gAJRUCAFCDfAACAAgGFAAAMEQAAGTzDExAA7L/UwHAqGSXAAAAAAoAAPoAAIN8AAABBgBQAAAAAAAAAsEAAAAAAAACwQAAAAUAAAAFACUTaAAlFQKDfABQAAgAAgYUAAAwRAAAZPMMTEADwKhkl7L/UwEKAAD6AAAAAIN8AAAAAAEGAFAAAAAAAAAEYwAAAAAAAARjAAAABQAAAAUAJRFMACUSvgBQg24AAgAIBhQAADBEAABk8wxMQAOy/1MBwKhklwAAAAAKAAD6AACDbgAAAQYAUAAAAAAAAALCAAAAAAAAAsIAAAAFAAAABQAlEUwAJRK+g24AUAAIAAIGFAAAMEQAAGTzDExAA8CoZJey/1MBCgAA+gAAAACDbgAAAAABAgBEAAAAAAAAAEoAAAAAAAAASgAAAAEAAAABACJTsgAiVAIANc7qAAAAABEUAAAwRAAAAAAOBMMAwKhkb8CoZJYAAAECAEQAAAAAAAAAOgAAAAAAAAA6AAAAAQAAAAEAIlOyACJUAs7qADUAAAAAERQAADBEAAAAAA4EwwDAqGSWwKhkbwAAAQIARAAAAAAAAABKAAAAAAAAAEoAAAABAAAAAQAiU7IAIlQCADXAnwAAAAARFAAAMEQAAAAADgTDAMCoZG/AqGSWAAABAgBEAAAAAAAAADoAAAAAAAAAOgAAAAEAAAABACJTsgAiVALAnwA1AAAAABEUAAAwRAAAAAAOBMMAwKhklsCoZG8AAAECAEQAAAAAAAAELwAAAAAAAAQvAAAABQAAAAUAJQHKACUJrgBQyiIAAAAIBhQAADBEAAAAAA4MwwPAqGRvwKhklgAAAQIARAAAAAAAAAR7AAAAAAAABHsAAAAGAAAABgAlAcoAJQmuyiIAUAAIAAAGFAAAMEQAAAAADgzDA8CoZJbAqGRvAAABAgBEAAAAAAAAB7wAAAAAAAAHvAAAAAYAAAAGACTiigAk8ioAUMohAAAACAYUAAAwRAAAAAAODMMDwKhkb8CoZJYAAAECAEQAAAAAAAAIdAAAAAAAAAh0AAAACAAAAAgAJOKKACTyKsohAFAACAAABhQAADBEAAAAAA4MwwPAqGSWwKhkbwAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_542_appid_tpl258_269() {
        let data = "AAkAAwAhMBha9OiyAAABMgAAAAEAAAPMAQIAEQABAAgAFwAIAAIABAAYAAQAFgAEABUABAAHAAIACwACAAoAAgAOAAIABAABAF8ACQBBAAIAWQABAIgAAQAIAAQADAAEAQQAEAABAAgAFwAIAAIABAAYAAQAFgAEABUABAAKAAIADgACACAAAgAEAAEAXwAJAEEAAgBZAAEAiAABAAgABAAMAAQBBgAVAAEACAAXAAgAAgAEABgABAAWAAQAFQAEAAcAAgALAAIACgACAA4AAgAEAAEAXwAJAEEAAgBZAAEAiAABAAgABAAMAAQA4QAEAOIABADjAAIA5AACAQoAFAABAAgAFwAIAAIABAAYAAQAFgAEABUABAAKAAIADgACACAAAgAEAAEAXwAJAEEAAgBZAAEAiAABAAgABAAMAAQA4QAEAOIABADjAAIA5AACAQcAFQABAAgAFwAIAAIABAAYAAQAFgAEABUABAAHAAIACwACAAoAAgAOAAIABAABAF8ACQBBAAIAWQABAIgAAQAIAAQADAAEARkAEAEaABAA4wACAOQAAgELABQAAQAIABcACAACAAQAGAAEABYABAAVAAQACgACAA4AAgAgAAIABAABAF8ACQBBAAIAWQABAIgAAQAIAAQADAAEARkAEAEaABAA4wACAOQAAgEDABEAAQAIABcACAACAAQAGAAEABYABAAVAAQABwACAAsAAgAKAAIADgACAAQAAQBfAAkAQQACAFkAAQCIAAEAGwAQABwAEAEFABAAAQAIABcACAACAAQAGAAEABYABAAVAAQACgACAA4AAgAgAAIABAABAF8ACQBBAAIAWQABAIgAAQAbABAAHAAQAQgAFQABAAgAFwAIAAIABAAYAAQAFgAEABUABAAHAAIACwACAAoAAgAOAAIABAABAF8ACQBBAAIAWQABAIgAAQAbABAAHAAQARkAEAEaABAA4wACAOQAAgEMABQAAQAIABcACAACAAQAGAAEABYABAAVAAQACgACAA4AAgAgAAIABAABAF8ACQBBAAIAWQABAIgAAQAbABAAHAAQARkAEAEaABAA4wACAOQAAgEJABUAAQAIABcACAACAAQAGAAEABYABAAVAAQABwACAAsAAgAKAAIADgACAAQAAQBfAAkAQQACAFkAAQCIAAEAGwAQABwAEADhAAQA4gAEAOMAAgDkAAIBDQAUAAEACAAXAAgAAgAEABgABAAWAAQAFQAEAAoAAgAOAAIAIAACAAQAAQBfAAkAQQACAFkAAQCIAAEAGwAQABwAEADhAAQA4gAEAOMAAgDkAAIAAQAsAQAABAAcAAEAAgAoAAgAKQAIACoACAAkAAIAJQACACIABAAjAAEAAAABACABAQAEABAAAQACAF8ACQBgAEAAXgBAAXQAIAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_h3ca3281() {
        let data = "AAkAEOvuoHVbApBwA5jABQAACwAM0QBUAAAAAAAAArkAAAAAAA+sD+vtQYPr7p8yAAAKZgAABjYKFqYeChajFQoVGY4AAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAAYAAAAAAAAYOOvttL7r7p8jAAAKZgAAAe4KFqYMChUDrAoVBwYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABUAAAAAAAAueOvttK3r7p8dAAAKZgAAC1wKFqYhChayJQoVGcoAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAAMAAAAAAAAEEevtP3Xr7p8QAAAKZgAAAxUKFqYjChRk/QoUEUYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABQAAAAAAAAGzOvtP3Lr7bSiAAAKZgAABN4KFqYkChSIJAoUEaIAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABAAAAAAAAALtuvtQa/r7bTKAAAKZgAABQUKFqYkChSTHAoUEc4AAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAACUAAAAAAADZ3evtQb/r7bTLAAAKZgAABPcKFqYcChSNEAoUEbYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAACFcAAAAAADFuDuvtQdDr7bTZAAAKZgAABcAKFqYjChSiEQoUE4oAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABQAAAAAAAAWRevtP6rr7bTaAAAKZgAABekKFqYPChSrJAoUE64AAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAACvQAAAAAAEDtJOvtQhHr7bTgAAAKZgAAC5cKFqYCChbQDAoVHUIAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABkAAAAAAACStevtQtzr7bToAAAKZgAACp8KFqYcChbEFQoVHRIAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAEQAAAAAAABcfOvtP+7r7bUeAAAKZgAAC4kKFqYZChbKDwoVHSoAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAB4AAAAAAABZJevtQ5br7qBYAAAKZgAABdQKFqYZChSmGgoUE5oAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAAIAAAAAAAACDuvtQKfr7qBDAAAKZgAAAe4KFqYMChUDdQoVBwYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAANwAAAAAAACBaevttdLr7qA3AAAKZgAABUUKFqYRChaRGgoVGUYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAAkAAAAAAAAT5Ovttcfr7qAtAAAKZgAABs8KFqYkChVLJgoVEU4AAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_h3c_netstream_varstringa3281() {
        let data = "AAkAAQAcjYxbTplnAAAAhQAAAAAM0QBYAAAAAAAAAAkAAAAAAAACvgAbnG4AHBBtAAAAEQAAAAAUFBQUFBT//wAAAAAAAAAAAAAAAACJAIkEABEAICAAAAAAAAAAAAAA/////wAAAAD/AAEA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_h3c_netstream_varstring_tpl3281() {
        let data = "AAkAAQAchZhbTpllAAAADAAAAAAAAAB4DNEAHAACAAgAAQAIABYABAAVAAQACgAEAA4ABAAIAAQADAAEAA8ABAAQAAQAEQAEAAcAAgALAAIAPAABAAYAAQAEAAEABQABAAkAAQANAAEAPQABAFkAAQArAAIAIwABAAAAAQAiAAQAXQAEAFwABADs//8=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_h3c_tpl3281() {
        let data = "AAkAAevuQeBbApBYAAALJwAACwAAAAB0DNEAGwACAAgAAQAIABYABAAVAAQACgAEAA4ABAAIAAQADAAEAA8ABAAQAAQAEQAEAAcAAgALAAIAPAABAAYAAQAEAAEABQABAAkAAQANAAEAPQABAFkAAQArAAIAIwABAAAAAQAiAAQAXQAEAFwABA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_huawei_netstreama() {
        let data = "AAkAAZ+mjdhabo68AAH7ogAAAAAFIwBACmzbNQpvcMwKbPwpAAAABAAAAMifoYxcn6aJ8AAAAAAACAAfshMKJgAAAAAAAAAAAAAYBgAYGQEAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_huawei_netstream_tpl() {
        let data = "AAkAAZ+marBabo6zAAByGgAAAAAAAABsBSMAGQAIAAQADAAEAA8ABAACAAQAAQAEABYABAAVAAQAEgAEAAoAAgAOAAIABwACAAsAAgAQAAIAEQACADoAAgA7AAIA6AACAAYAAQAEAAEABQABAAkAAQANAAEAPQABAFkAAQDSAAM=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_invalid01() {
        let data = "AAkAAgAGHCJV3PXJAAAAAAAAAAAAAAA8BAAADQAIAAQADAAEABUABAAWAAQAAQAEAAIABAAKAAQADgAEAAcAAgALAAIABAABAAYAAQA8AAEAAAA8CAAADQAbABAAHAAQABUABAAWAAQAAQAEAAIABAAKAAQADgAEAAcAAgALAAIABAABAAYAAQA8AAEAAQAWAQAABAAIAAIABAAiAAQAIwABAQAAEAAAAAAAAABkAQAAAAgAAEYgAUS4ERhyAAAAAAAAAAAQIAFEuEAwzZGAdQuu050mIQAA2OAAANjgAAAAYAAAAAEAAAAAAAAAAAB7AHsRAAYAAAAEAAAswKgAAcCoAGkAAVukAAFbpAAAAGIAAAABAAAAAAAAAAAANdkXEQAEAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_iptnetflow_reduced_size_encoding_tpa260() {
        let data = "AAkAFUzY50BaiRNdAAVBoQAAAAABAwBAw0DVEArriAoK6AUBAbu2SAAABwAIAAcACAAAAd0ACYHoTNhsCEzYrJwRAAAbIbwk3ZDiuiMJ/AgAAAAAAAAAWAEEABQACAAEAAwABAAPAAQABwACAAsAAgAGAAEACgACAA4AAgD8AAIA/QACAAIABAABAAQAFgAEABUABAAEAAEABQABANEABABQAAYAOAAGAQAAAgEEATglegHiwZfGpsGXwBFr5oy5AgAHAAcABwAHAAAAAwAAAJxM2ImATNispAYA8AAAAAAbIbwk3ZDiuiMJ/AgABY3npsGXx0XBl8ARecpzngIABwAHAAcABwAAAAEAAAAwTNisoEzYrKAGANAAAAAAGyG8JN2Q4rojCfwIAArpgATU4HFKwZfAEdG4AbvTAAgABwAIAAcAAAALAAACSEzYjrhM2KycBgDxAAABABshvCTcAASWl7jNCADBl8AuCuwIBAroBQEAUMldGwB7AAgAewAIAAAABAAAAkFM2KyQTNisoAYA8QAAAAAbIbwk3AAaShYBgQgACuvFBj7dc83Bl8AR4KEEAAIACAAHAAgABwAAAAMAAACYTNioDEzYrJwGAPAAAAAAGyG8JNwABJaXuM0IAAAAAAEDAHi/uDzqwZfJOcGXwBEEERrhAAAHAAcABwAHAAAAAgAAAQZM2JSoTNispBEAABshvCTdkOK6Iwn8CAAK6+MCLiBD9sGXwBGATpFZAAAIAAcACAAHAAAAAwAAAJBM2Ij0TNispBEAABshvCTcAASWl7jNCAAAAAEEAEQK7B8HJZJ9QMGXwBHwHwylAgAIAAcACAAHAAAAAwAAAJhM2ImATNisoAYA8AAAAAAbIbwk3AAElpe4zQgAAAAAAQMAQMNA1REK6ehdCugFAQG7zDcAAAcACAAHAAgAAAADAAAA/UzYrEhM2KycEQAAGyG8JN2Q4rojCfwIAAAAAAEEALwK6ZcINMbWSMGXwBHivAG7HwAIAAcACAAHAAAADwAABxFM2JtQTNisoAYA+QAAAAAbIbwk3AAElpe4zQgACuoWBEDpobzBl8AR7KcUbBgACAAHAAgABwAAAAMAAADqTNisVEzYrKQGAIEAAAAAGyG8JNwABJaXuM0IAArpJAe50RTwwZfAEcjHAFAbAAgABwAIAAcAAAAWAAAGkUzYqxBM2KygBgDxAAAAABshvCTcAASWl7jNCAAAAQYAPC7p7JcK6Y0ECugFAQAAAwMABwAIAAcACAAAAAEAAACBTNisoEzYrKABAAAbIbwk3ZDiuiMJ/AgAAQMAQEBfYAXBl8eAwZfAEQG76j0EAAcABwAHAAcAAAABAAAAKEzYrKRM2KykBgAAGyG8JN2Q4rojCfwIAAAAAAEEAEQK6cgHVCf1r8GXwBHxfEiUAgAIAAcACAAHAAAAAwAAAJhM2IlcTNisnAYA8AAAAAAbIbwk3AAElpe4zQgAAAAAAQMAeArp4Siw0QFnwZfAESs/cgoAAAgABwAIAAcAAAABAAAA60zYrJxM2KycEQAAGyG8JNwABJaXuM0IAAroIlJIBQEBwZfAEc3lhFIAAAgABwAIAAcAAAABAAAAHUzYrKRM2KykEQAAGyG8JNwABJaXuM0IAAAAAQQAgBcrixsK6AgtCugFAQBQ28EaAAcACAAHAAgAAAADAAAHSkzYrGRM2KygBgDwAAAAABshvCTdkOK6Iwn8CAACEYwvCumWFQroBQEBu5UUGQAHAAgABwAIAAAAAwAAALtM2KvgTNisoAYAgQAAAAAbIbwk3ZDiuiMJ/AgAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_juniper_srx_tplopt() {
        let data = "AAkAA9SXYnZYPMokAAABUgAAAI4AAQAYAQAABAAIAAEAAAAjAAEAIgAEAAABAAAMAgAAAAEAAAAAAABcAQEAFQAIAAQADAAEAAUAAQAEAAEABwACAAsAAgAgAAIACgAEAAkAAQANAAEAEAAEABEABAASAAQABgABAA4ABAAPAAQAAQAEAAIABAAWAAQAFQAEADwAAQ==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_macaddra() {
        let data = "AAkAAQAAhrhWGNCFAAAAAgAAAGEBAQLcBv4irBAgAQAWrBAgyQBQVsAAAQAMKXCGCREAe6wQIMkAe6wQIGQADClwhgkADCmNr8MRAHusECBkAHusECDJAAwpja/DAAwpcIYJBucVrBAgAQBQrBAgyQBQVsAAAQAMKXCGCQYAUKwQIMnnFawQIAEADClwhgkAUFbAAAEG5xasECABAbusECDJAFBWwAABAAwpcIYJBgG7rBAgyecWrBAgAQAMKXCGCQBQVsAAAQbnF6wQIAEAi6wQIMkAUFbAAAEADClwhgkGAIusECDJ5xesECABAAwpcIYJAFBWwAABBucYrBAgAQAXrBAgyQBQVsAAAQAMKXCGCQYAF6wQIMnnGKwQIAEADClwhgkAUFbAAAEG5xmsECABA+OsECDJAFBWwAABAAwpcIYJBgPjrBAgyecZrBAgAQAMKXCGCQBQVsAAAQbnGqwQIAEBu6wQIMkAUFbAAAEADClwhgkGAbusECDJ5xqsECABAAwpcIYJAFBWwAABBucbrBAgAQCHrBAgyQBQVsAAAQAMKXCGCQYAh6wQIMnnG6wQIAEADClwhgkAUFbAAAEG5xysECABAG6sECDJAFBWwAABAAwpcIYJBgBurBAgyeccrBAgAQAMKXCGCQBQVsAAAQbnHawQIAEAb6wQIMkAUFbAAAEADClwhgkGAG+sECDJ5x2sECABAAwpcIYJAFBWwAABBucerBAgAQCPrBAgyQBQVsAAAQAMKXCGCQYAj6wQIMnnHqwQIAEADClwhgkAUFbAAAEG5x+sECABDT2sECDJAFBWwAABAAwpcIYJBg09rBAgyecfrBAgAQAMKXCGCQBQVsAAAQbnIKwQIAEAUKwQIMkAUFbAAAEADClwhgkGAFCsECDJ5yCsECABAAwpcIYJAFBWwAABBuchrBAgAQAZrBAgyQBQVsAAAQAMKXCGCQYAGawQIMnnIawQIAEADClwhgkAUFbAAAEAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_macaddr_tpl() {
        let data = "AAkAAwAAdUhWGNCAAAAAAAAAAGEAAABEAQEABwAEAAEABwACAAgABAALAAIADAAEADgABgBQAAYBAgAHAAQAAQAHAAIACwACABsAEAAcABAAOAAGAFAABgABABgBAwAEAAgAAQAEACoABAApAAQAAAEDABAAAAAAAAAAAQAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_nprobea() {
        let data = "AAkAAQAAhMZWFr61AAAAAQAAAJMBAQA4AAAAyAAAAAIGEBgAFqwQIMkAAAD+IqwQIAEAAAAAAAAAAAAAAAAAAAAAAAAFAAAAAA0AAQ==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_nprobe_dpi() {
        let data = "AAkAAgABY3gAAAH2AAAAAgAAAAAAAAA8AQAADQAWAAQAFQAEAAQAAQAIAAQADAAEAAcAAgALAAIAAQAEAAIABABfAAQAYAAg4PYAAuD3ABABAABoAAGKiAABlkAAAAAAAAAAAAAAAAAAAAAAUgAAAAEAAABSAAAAAAAiAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUgDBAAABrBAAZORP7///+gdsAAAAEQAAAAAAAAAAAAAAAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_nprobe_tpl() {
        let data = "AAkAAwAAhMZWFr61AAAAAAAAAJMAAACcAQEAEgABAAQAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACQABAAoAAgALAAIADAAEAA0AAQAOAAIADwAEABAABAARAAQAFQAEABYABAECABIAAQAEAAIABAAEAAEABQABAAYAAQAHAAIACgACAAsAAgAOAAIAEAAEABEABAAVAAQAFgAEABsAEAAcABAAHQABAB4AAQA+ABAAAQAYAQMABAAIAAEABAAqAAQAKQAEAAABAwAQAAAAAAAAAAEAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_paloalto_81a257_1flowset_in_large_zerofilled_packet() {
        let data = "AAkAAT9TEgBbF9+ROd2xIwEAAAABAQCgAAAAAAAAAWsAAAADBgBeAFiG3AIGHc2MKMQ6htwBnB3NjBI/UtdoP1LXaAAAAAAAAAAAFcukAgAAY3VrZXJiZXJvcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHVua25vd24AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_paloalto_81_tpl256_263() {
        let data = "AAkACD9TEgBbF9+ROd2xIAEAAAAAAAK0AQAAEQABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAQEAFAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAVoABN19ACDdfgBAAQQAFQABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAOEABADiAAQA4wACAOQAAgEFABgAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQDhAAQA4gAEAOMAAgDkAAIBWgAE3X0AIN1+AEABAgARAAEACAACAAQABAABAAUAAQAGAAEABwACABsAEAAKAAQACwACABwAEAAOAAQAFQAEABYABAAgAAIAPQABAJQACADpAAEBAwAUAAEACAACAAQABAABAAUAAQAGAAEABwACABsAEAAKAAQACwACABwAEAAOAAQAFQAEABYABAAgAAIAPQABAJQACADpAAEBWgAE3X0AIN1+AEABBgAVAAEACAACAAQABAABAAUAAQAGAAEABwACABsAEAAKAAQACwACABwAEAAOAAQAFQAEABYABAAgAAIAPQABAJQACADpAAEBGQAQARoAEADjAAIA5AACAQcAGAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAbABAACgAEAAsAAgAcABAADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABARkAEAEaABAA4wACAOQAAgFaAATdfQAg3X4AQA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_paloalto_panosa() {
        let data = "AAkACGt7OuBaCa6jDFyPcwAAAAEBAQCfAAAAAAAAAEYAAAABBgASAFAXI6sbAAAAF8FvCiBbzQAAABhrezrga3s64AAAAAAAAAAABm7kAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAG8AAAABBgAamxYKIGlnAAAAGAG7onMYHgAAABdrezrga3YOqAAAAAAAAAAABlZzBQAAY3Vzc2wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAEYAAAABBgACy2UKIJCRAAAAGAG7IsqtfgAAABdrezrga3s64AAAAAAAAAACFDUgAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAEYAAAABBgASAbsX0TRjAAAAF8EpCoKRLAAAABhrezrga3s64AAAAAAAAAACD58DAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAE4AAAABBgAC2LkKMmE5AAAAFxU4CjJgFAAAABhrezrga3s64AAAAAAAAAACB/+uAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAE4AAAABBgASFTgKMmAUAAAAGNi5CjJhOQAAABdrezrga3s64AAAAAAAAAACB/+uAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAEYAAAABBgASAbsi6q2TAAAAF+qkCjDQ0QAAABhrezrga3s64AAAAAAAAAAABEmMAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAEYAAAABBgAC8vQKgqcrAAAAGAG7QTRs/gAAABdrezrga3s64AAAAAAAAAACFp3LAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_paloalto_panos_tpl() {
        let data = "AAkACGt7OuBaCa6jDFyPbQAAAAEAAABMAQAAEQABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAAAAXAEEABUAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQDhAAQA4gAEAOMAAgDkAAIAAABMAQIAEQABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAbABAACgAEAAsAAgAcABAADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAAAAXAEGABUAAQAIAAIABAAEAAEABQABAAYAAQAHAAIAGwAQAAoABAALAAIAHAAQAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQEZABABGgAQAOMAAgDkAAIAAABYAQEAFAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAVoABN19ACDdfgBAAAAAaAEFABgAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQDhAAQA4gAEAOMAAgDkAAIBWgAE3X0AIN1+AEAAAABYAQMAFAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAbABAACgAEAAsAAgAcABAADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAVoABN19ACDdfgBAAAAAaAEHABgAAQAIAAIABAAEAAEABQABAAYAAQAHAAIAGwAQAAoABAALAAIAHAAQAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQEZABABGgAQAOMAAgDkAAIBWgAE3X0AIN1+AEA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_softflowd_tpla() {
        let data = "AAkACQAAsBRWFr4+AAAAAQAAAAAAAABABAAADgAIAAQADAAEABUABAAWAAQAAQAEAAIABAAKAAQADgAEAAcAAgALAAIABAABAAYAAQA8AAEABQABAAAAQAgAAA4AGwAQABwAEAAVAAQAFgAEAAEABAACAAQACgAEAA4ABAAHAAIACwACAAQAAQAGAAEAPAABAAUAAQQAAPSsECBkrBAg+AAABMEAAATAAAAATAAAAAEAAAAAAAAAAAB7AHsRAAQArBAg+KwQIGQAAATBAAAEwAAAAEwAAAABAAAAAAAAAAAAewB7EQAEAKwQIGSsECDJAAAa6gAAGukAAABMAAAAAQAAAAAAAAAAAHsAexEABACsECDJrBAgZAAAGuoAABrpAAAATAAAAAEAAAAAAAAAAAB7AHsRAAQArBAgZKwQIMoAACsaAAArGgAAAEwAAAABAAAAAAAAAAAAewB7EQAEAKwQIMqsECBkAAArGgAAKxoAAABMAAAAAQAAAAAAAAAAAHsAexEABAAIAABE/oAAAAAAAAACDCn//oM7bv8CAAAAAAAAAAAAAAAAAAEAAKAQAAALTwAAAqAAAAAHAAAAAAAAAAAAAIYAOgAGAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_streamcore_tpla256() {
        let data = "AAkAAmaYVl9Ydht/f7xq8gAAAAAAAALMAQAAFwABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiDAAAQgwQAEIMIABCDDAAQgxAAEAQEAHAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiDAAAQgwQAEIMIABCDDAAQgxAAEIMUABCDGAAQgxwAEIMgABCDJAAQBAgAcAAEACAACAAQABAABAAUAAQAGAAEABwACAAgABAAKAAQACwACAAwABAAOAAQAFQAEABYABCAEAAEggAACIIEAAiCCAAIggwACIIQAAiCFAAEghgABIIcAASCIAAEgwAAEIMEABCDCAAQgwwAEIMQABAEDACEAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEIAQAASCAAAIggQACIIIAAiCDAAIghAACIIUAASCGAAEghwABIIgAASDAAAQgwQAEIMIABCDDAAQgxAAEIMUABCDGAAQgxwAEIMgABCDJAAQBBAAeAAEACAACAAQABAABAAUAAQAGAAEABwACAAgABAAKAAQACwACAAwABAAOAAQAFQAEABYABCAEAAEgAAAEIAEABCACAAQgAwACIEAAKCBBAJYgwAAEIMEABCDCAAQgwwAEIMQABCDFAAQgxgAEIMcABCDIAAQgyQAEAQUAHgABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiBCAB4gQwAeIMAABCDBAAQgwgAEIMMABCDEAAQgxQAEIMYABCDHAAQgyAAEIMkABAEAAKAAAAAAAAAAgAAAAAMGKBMfkGROKMkAAASAw5kK54CWAAAEfGaXojZml4q6AQAAAAAAAAAAAAAAAAAAAAAEkwAABJsAAASoAAAFmwAAAAAAAAAAAAAArAAAAAQGKBPDmQrngJYAAAR8H5BkTijJAAAEgGaXoj1ml4q5AAAAAAAAAAAAAAAAAAAAAAAEkwAABJsAAASoAAAFmwAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_streamcore_tpla260() {
        let data = "AAkAAmaB/8NYdhXHf7SlJAAAAAAAAALMAQAAFwABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiDAAAQgwQAEIMIABCDDAAQgxAAEAQEAHAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiDAAAQgwQAEIMIABCDDAAQgxAAEIMUABCDGAAQgxwAEIMgABCDJAAQBAgAcAAEACAACAAQABAABAAUAAQAGAAEABwACAAgABAAKAAQACwACAAwABAAOAAQAFQAEABYABCAEAAEggAACIIEAAiCCAAIggwACIIQAAiCFAAEghgABIIcAASCIAAEgwAAEIMEABCDCAAQgwwAEIMQABAEDACEAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEIAQAASCAAAIggQACIIIAAiCDAAIghAACIIUAASCGAAEghwABIIgAASDAAAQgwQAEIMIABCDDAAQgxAAEIMUABCDGAAQgxwAEIMgABCDJAAQBBAAeAAEACAACAAQABAABAAUAAQAGAAEABwACAAgABAAKAAQACwACAAwABAAOAAQAFQAEABYABCAEAAEgAAAEIAEABCACAAQgAwACIEAAKCBBAJYgwAAEIMEABCDCAAQgwwAEIMQABCDFAAQgxgAEIMcABCDIAAQgyQAEAQUAHgABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiBCAB4gQwAeIMAABCDBAAQgwgAEIMMABCDEAAQgxQAEIMYABCDHAAQgyAAEIMkABAEEAkQAAAAAAAAPZwAAAAoGKBofkGROKMkAAASA0OsKGwgUAAAEfGaBwQNmgPnOAQAAAAAAAAARAAAAEwAAbGl2ZS5sZW1kZS5mcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9tdXguanNvbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJMAAASbAAAEqAAABZsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL7AAAAAsGKBrQ6wobCBQAAAR8H5BkTijJAAAEgGaBwRVmgPnOAAAAAAAAAAARAAAAEwAAbGl2ZS5sZW1kZS5mcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9tdXguanNvbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJMAAASbAAAEqAAABZsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_ubnt_edgeroutera1024() {
        let data = "AAkACBhmVoJX1DOCAAB8UgAAAAAEAAHcGGDH8xhgx/MAAACuAAAAAgQABAAAAAAAAAAKAQCHCgQA+wA1Q1AAABEGvu++709E2ee+74kAAAAAAAQYYMfzGGDH8wAAAFcAAAABBAAEAAAAAAAAAAoBAIgKBAD7ADVDUAAAEQa+777vT0TZ577viQAAAAAABBgugR0YLF1aAAAHgAAAAA8EAAQAAAAAAAAACgEA6AoEAPsBu8ipABsGBr7vvu9PRNnnvu+JAAAAAAAEGC6BHRgsXVoAAAJiAAAACAQABAAAAAAAAAAKAQDoCgQA+wG7yKoAGwYGvu++709E2ee+74kAAAAAAAQYY6ItGGDuXwAACXQAAAAVBAAEAAAAAAAAAAoFAFsKBAD7Abur5gAfBga+777vT0TZ577viQAAAAAABBhjocwYYO7FAAAn3AAAAB4EAAQAAAAAAAAACgEAHgoEAPsBu4ICAB8GBr7vvu9PRNnnvu+JAAAAAAAEGC6V4RguleEAAADYAAAABAQABAAAAAAAAAAKAwBkCgQA+wG7/IIAGwYGvu++709E2ee+74kAAAAAAAQYYO5fGGDuXwAAAJgAAAABBAAEAAAAAAAAAAoBAIcKBAD7ADUlGQAAEQa+777vT0TZ577viQAAAAAABA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_ubnt_edgeroutera1025() {
        let data = "AAkACBhm66lX1DOoAAB7sAAAAAAEAQHcGC+LsBgvizwAAAEEAAAABQQAAgAEAQAAAADAqAFiCgAASddBAbsAGwZE2ee+7yJE2ee+744AAAAAAAQYYeg8GGHoPAAAACAAAAABBAAAAAQBAAAAAAoEAPv/////pgonEQAAEQAAAAAAAAAAAAAAAAAAAAAABBhh6DwYYeg8AAAAhwAAAAEEAAAABAEAAAAACgQA+/////+dZ5PsAAARAAAAAAAAAAAAAAAAAAAAAAAEGGHoPBhh6DwAAACHAAAAAQQAAAAEAQAAAAAKBAD7/////4zn3k8AABEAAAAAAAAAAAAAAAAAAAAAAAQYYeg8GGHoPAAAAIcAAAABBAAAAAQBAAAAAAoEAPv/////wqXcBwAAEQAAAAAAAAAAAAAAAAAAAAAABBhh6DwYYeg8AAAAhwAAAAEEAAAABAEAAAAACgQA+/////+I89uvAAARAAAAAAAAAAAAAAAAAAAAAAAEGGHoPBhh6DwAAACHAAAAAQQAAAAEAQAAAAAKBAD7/////5VXm5gAABEAAAAAAAAAAAAAAAAAAAAAAAQYL6DUGByKKAAADlQAAAAVBAACAAQBAAAAAMCoAWYKAgBfukoBuwAbBga+777vuUTZ577vjgAAAAAABA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_ubnt_edgerouter_tpl() {
        let data = "AAkABBhm66lX1DOoAAB7rwAAAAAAAABYBAAAFAAVAAQAFgAEAAEABAACAAQAPAABAAoAAgAOAAIAPQABAAMABAAIAAQADAAEAAcAAgALAAIABQABAAYAAQAEAAEAOAAGAFAABgA6AAIAyQAEAAAAWAQBABQAFQAEABYABAABAAQAAgAEADwAAQAKAAIADgACAD0AAQADAAQACAAEAAwABAAHAAIACwACAAUAAQAGAAEABAABAFEABgA5AAYAOwACAMkABAAAAFgIAAAUABUABAAWAAQAAQAEAAIABAA8AAEACgACAA4AAgA9AAEAAwAEABsAEAAcABAABQABAAcAAgALAAIABgABAAQAAQA4AAYAUAAGADoAAgDJAAQAAABYCAEAFAAVAAQAFgAEAAEABAACAAQAPAABAAoAAgAOAAIAPQABAAMABAAbABAAHAAQAAUAAQAHAAIACwACAAYAAQAEAAEAUQAGADkABgA7AAIAyQAE";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_unknown_tpl266_292a() {
        let data = "AAkABgAJCF9aIYunAACJEAAAAAAAAQAaAQAABAAMAAEABAApAAQAKgAEACgABAABABoBAQAEAAwAAQAEADAAAQAxAAEAMgAEAAAARAEKAA8ACAAEAAwABAAEAAEABwACAAsAAgAFAAEACgAEAD0AAQCWAAQAlwAEAAEACAACAAgA6gAEAOsABAAwAAEAAABEASQADwAIAAQADAAEAAQAAQAHAAIACwACAAUAAQAOAAQAPQABAJYABACXAAQAAQAIAAIACADqAAQA6wAEADAAAQEKADjAqAADwKgAAhEAiQCJAAAAAA0AWiGLmlohi5oAAAAAAAAATgAAAAAAAAABAAAAAAAAAAABASQAOMCoAATAqAAFEeMSGMcAAAAADQFaIYudWiGLnQAAAAAAAADoAAAAAAAAAAEAAAAAAAAAAAE=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_valid01() {
        let data = "AAkACQAAsBRWFr4+AAAAAQAAAAAAAABABAAADgAIAAQADAAEABUABAAWAAQAAQAEAAIABAAKAAQADgAEAAcAAgALAAIABAABAAYAAQA8AAEABQABAAAAQAgAAA4AGwAQABwAEAAVAAQAFgAEAAEABAACAAQACgAEAA4ABAAHAAIACwACAAQAAQAGAAEAPAABAAUAAQQAAPSsECBkrBAg+AAABMEAAATAAAAATAAAAAEAAAAAAAAAAAB7AHsRAAQArBAg+KwQIGQAAATBAAAEwAAAAEwAAAABAAAAAAAAAAAAewB7EQAEAKwQIGSsECDJAAAa6gAAGukAAABMAAAAAQAAAAAAAAAAAHsAexEABACsECDJrBAgZAAAGuoAABrpAAAATAAAAAEAAAAAAAAAAAB7AHsRAAQArBAgZKwQIMoAACsaAAArGgAAAEwAAAABAAAAAAAAAAAAewB7EQAEAKwQIMqsECBkAAArGgAAKxoAAABMAAAAAQAAAAAAAAAAAHsAexEABAAIAABE/oAAAAAAAAACDCn//oM7bv8CAAAAAAAAAAAAAAAAAAEAAKAQAAALTwAAAqAAAAAHAAAAAAAAAAAAAIYAOgAGAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }

    #[test]
    fn test_data_decoder_netflow_v5() {
        let data = "AAUAAwADeaNegMWGIqVasAAAAAAAAAAArBEAAqwRAAEAAAAAAAAAAAAAAAoAAANIAAAvTAAAUnYAAAgAAAABAAAAAAAAAAAArBEAAawRAAIAAAAAAAAAAAAAAAoAAANIAAAvTAAAUnYAAAAAAAABAAAAAAAAAAAArBEAAeAAAPsAAAAAAAAAAAAAAAEAAACpAADgHAAA4BwU6RTpAAARAAAAAAAAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true);
        let json_str = String::from_utf8(res.unwrap().to_vec()).expect("valid utf8");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid json");
        let arr = parsed.as_array().expect("should be array");
        assert_eq!(arr.len(), 3);
        for record in arr {
            assert_eq!(record["version"], 5);
            assert_eq!(record["template_type"], "data");
        }
    }

    #[test]
    fn test_data_decoder_netflow_v7() {
        let data = "AAcAAQAAA+hlU/EAAAAAAAAAAAEAAAAAwKgBAQoAAAHAqAH+AAEAAgAAAGQAABOIAAAB9AAAA+gwOQBQAAIGAABkAMgYGAAAwKgB/g==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true);
        let json_str = String::from_utf8(res.unwrap().to_vec()).expect("valid utf8");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid json");
        let arr = parsed.as_array().expect("should be array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["version"], 7);
        assert_eq!(arr[0]["template_type"], "data");
    }

    #[test]
    fn test_data_decoder_ipfix_template() {
        let data = "AAoAJGKgsbkAAAAIbGp+EQACABQBAAADAAgABAAMAAQABAAB";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true);
        let json_str = String::from_utf8(res.unwrap().to_vec()).expect("valid utf8");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid json");
        let arr = parsed.as_array().expect("should be array");
        assert!(arr.len() >= 1);
        assert_eq!(arr[0]["version"], 10);
        assert_eq!(arr[0]["template_type"], "template");
    }

    #[test]
    fn test_data_decoder_ipfix_template_then_data() {
        let template_data = "AAoAJGKgsbkAAAAIbGp+EQACABQBAAADAAgABAAMAAQABAAB";
        let data_data = "AAoAIGKxAbkAAAAJbGp+EQEAABDAqAABCgAAAQYAAAA=";

        let mut decoder = NetflowDecoder::new();

        let mut input1 = BytesMut::from(
            base64::decode(template_data).expect("should decode").as_bytes(),
        );
        let res1 = decoder.decode(&mut input1).expect("Should not fail");
        assert!(res1.is_some());
        let json_str = String::from_utf8(res1.unwrap().to_vec()).expect("valid utf8");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid json");
        let arr = parsed.as_array().expect("should be array");
        assert!(arr.iter().any(|r| r["template_type"] == "template"));

        let mut input2 = BytesMut::from(
            base64::decode(data_data).expect("should decode").as_bytes(),
        );
        let res2 = decoder.decode(&mut input2).expect("Should not fail");
        assert!(res2.is_some());
        let json_str2 = String::from_utf8(res2.unwrap().to_vec()).expect("valid utf8");
        let parsed2: serde_json::Value = serde_json::from_str(&json_str2).expect("valid json");
        let arr2 = parsed2.as_array().expect("should be array");
        assert!(arr2.iter().any(|r| r["template_type"] == "data"));
    }

    fn test_byte_at_a_time(decoder: &mut NetflowDecoder, packet_bytes: &[u8]) -> Vec<Bytes> {
        let mut buf = BytesMut::new();
        let mut results = Vec::new();
        for (i, &b) in packet_bytes.iter().enumerate() {
            buf.extend_from_slice(&[b]);
            let res = decoder.decode(&mut buf);
            match res {
                Ok(None) => {}
                Ok(Some(data)) => results.push(data),
                Err(e) => panic!(
                    "Decoder errored at byte {}/{}: {}",
                    i + 1,
                    packet_bytes.len(),
                    e
                ),
            }
        }
        assert!(
            !results.is_empty(),
            "Decoder never returned data after feeding all {} bytes",
            packet_bytes.len()
        );
        results
    }

    fn collect_records(results: &[Bytes]) -> Vec<serde_json::Value> {
        let mut records = Vec::new();
        for r in results {
            let parsed: serde_json::Value = serde_json::from_slice(r).expect("valid json");
            records.extend(parsed.as_array().unwrap().clone());
        }
        records
    }

    #[test]
    fn test_byte_at_a_time_v5() {
        let packet = base64::decode(
            "AAUAAwADeaNegMWGIqVasAAAAAAAAAAArBEAAqwRAAEAAAAAAAAAAAAAAAoAAANIAAAvTAAAUnYAAAgAAAABAAAAAAAAAAAArBEAAawRAAIAAAAAAAAAAAAAAAoAAANIAAAvTAAAUnYAAAAAAAABAAAAAAAAAAAArBEAAeAAAPsAAAAAAAAAAAAAAAEAAACpAADgHAAA4BwU6RTpAAARAAAAAAAAAAAA",
        ).unwrap();
        let mut decoder = NetflowDecoder::new();
        let results = test_byte_at_a_time(&mut decoder, &packet);
        let all_records = collect_records(&results);
        assert_eq!(all_records.len(), 3);
        for r in &all_records {
            assert_eq!(r["version"], 5);
        }
    }

    #[test]
    fn test_byte_at_a_time_v7() {
        let packet = base64::decode(
            "AAcAAQAAA+hlU/EAAAAAAAAAAAEAAAAAwKgBAQoAAAHAqAH+AAEAAgAAAGQAABOIAAAB9AAAA+gwOQBQAAIGAABkAMgYGAAAwKgB/g==",
        ).unwrap();
        let mut decoder = NetflowDecoder::new();
        let results = test_byte_at_a_time(&mut decoder, &packet);
        let all_records = collect_records(&results);
        assert_eq!(all_records.len(), 1);
        assert_eq!(all_records[0]["version"], 7);
    }

    #[test]
    fn test_byte_at_a_time_v9() {
        let packet = base64::decode(
            "AAkAAWWdGn1YRo5sAXXKjgAACIEAAQAYAQAABAAIAAEABAAKAAQAUwBAAAA=",
        ).unwrap();
        let mut decoder = NetflowDecoder::new();
        let results = test_byte_at_a_time(&mut decoder, &packet);
        let all_records = collect_records(&results);
        assert!(!all_records.is_empty());
        for r in &all_records {
            assert_eq!(r["version"], 9);
        }
    }

    #[test]
    fn test_byte_at_a_time_ipfix() {
        let packet = base64::decode(
            "AAoAJGKgsbkAAAAIbGp+EQACABQBAAADAAgABAAMAAQABAAB",
        ).unwrap();
        let mut decoder = NetflowDecoder::new();
        let results = test_byte_at_a_time(&mut decoder, &packet);
        let all_records = collect_records(&results);
        assert!(!all_records.is_empty());
        assert_eq!(all_records[0]["version"], 10);
        assert_eq!(all_records[0]["template_type"], "template");
    }

    #[test]
    fn test_byte_at_a_time_ipfix_template_then_data() {
        let template = base64::decode(
            "AAoAJGKgsbkAAAAIbGp+EQACABQBAAADAAgABAAMAAQABAAB",
        ).unwrap();
        let mut decoder = NetflowDecoder::new();
        let tmpl_results = test_byte_at_a_time(&mut decoder, &template);
        let tmpl_records = collect_records(&tmpl_results);
        assert!(tmpl_records.iter().any(|r| r["template_type"] == "template"));

        let data = base64::decode(
            "AAoAIGKxAbkAAAAJbGp+EQEAABDAqAABCgAAAQYAAAA=",
        ).unwrap();
        let data_results = test_byte_at_a_time(&mut decoder, &data);
        let data_records = collect_records(&data_results);
        assert!(data_records.iter().any(|r| r["template_type"] == "data"));
    }


    // ---- template scoping (OBE-11566) ---------------------------------------------------------
    //
    // Minimal hand-built v9 packets rather than base64 captures: what matters here is exactly
    // which template id each exporter defined, which a capture blob would hide.

    /// v9 header: version, flowset count, uptime, epoch, sequence, source id.
    fn v9_header(flowset_count: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&9u16.to_be_bytes());
        p.extend_from_slice(&flowset_count.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // sys_up_time
        p.extend_from_slice(&1u32.to_be_bytes()); // unix_secs
        p.extend_from_slice(&0u32.to_be_bytes()); // sequence
        p.extend_from_slice(&0u32.to_be_bytes()); // source_id
        p
    }

    /// Template flowset (flowset id 0) defining `template_id` as the given (field_type, length)s.
    fn v9_template(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&template_id.to_be_bytes());
        body.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        for (ty, len) in fields {
            body.extend_from_slice(&ty.to_be_bytes());
            body.extend_from_slice(&len.to_be_bytes());
        }
        let mut p = v9_header(1);
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        p.extend_from_slice(&body);
        p
    }

    /// Data flowset referencing `template_id`.
    fn v9_data(template_id: u16, record: &[u8]) -> Vec<u8> {
        let mut p = v9_header(1);
        p.extend_from_slice(&template_id.to_be_bytes());
        p.extend_from_slice(&((record.len() + 4) as u16).to_be_bytes());
        p.extend_from_slice(record);
        p
    }

    /// IPV4_SRC_ADDR then IPV4_DST_ADDR — what the legitimate exporter registers.
    fn honest_fields() -> Vec<(u16, u16)> {
        vec![(8, 4), (12, 4)]
    }

    /// The same template id with a different layout — what a spoofing peer registers so the
    /// victim's records decode against the wrong offsets.
    fn poisoned_fields() -> Vec<(u16, u16)> {
        vec![(2, 4), (1, 4)] // IN_PKTS, IN_BYTES
    }

    const RECORD: [u8; 8] = [10, 0, 0, 9, 10, 0, 0, 8];

    fn decode_from(decoder: &NetflowDecoder, peer: &str, packet: &[u8]) -> String {
        let mut decoder = decoder.clone();
        decoder.set_datagram_peer(peer.parse().expect("valid ip"));
        let mut buf = BytesMut::from(packet);
        decoder
            .decode(&mut buf)
            .expect("decode should not fail")
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    }

    /// The feature itself: a template learned from one datagram must still decode data records
    /// arriving in a later datagram from the same exporter. Without this, "isolation" could be
    /// satisfied trivially by never caching anything.
    #[test]
    fn templates_persist_across_datagrams_from_the_same_exporter() {
        let decoder = NetflowDecoder::new();

        decode_from(&decoder, "10.0.0.1", &v9_template(256, &honest_fields()));
        let text = decode_from(&decoder, "10.0.0.1", &v9_data(256, &RECORD));

        assert!(
            text.contains("10.0.0.9"),
            "data should decode against the template this exporter sent, got: {text}"
        );
    }

    /// The finding: another peer redefining the same template id must not change how this
    /// exporter's records are decoded.
    #[test]
    fn one_exporter_cannot_poison_another_exporters_template() {
        let decoder = NetflowDecoder::new();

        decode_from(&decoder, "10.0.0.1", &v9_template(256, &honest_fields()));
        decode_from(&decoder, "10.0.0.2", &v9_template(256, &poisoned_fields()));

        let text = decode_from(&decoder, "10.0.0.1", &v9_data(256, &RECORD));
        assert!(
            text.contains("10.0.0.9"),
            "another exporter poisoned this exporter's template 256, got: {text}"
        );
    }

    /// Templates must not leak the other way either: an exporter that never sent one must not
    /// decode against a template another exporter happened to register.
    #[test]
    fn an_exporter_cannot_borrow_another_exporters_template() {
        let decoder = NetflowDecoder::new();

        decode_from(&decoder, "10.0.0.1", &v9_template(256, &honest_fields()));

        let text = decode_from(&decoder, "10.0.0.3", &v9_data(256, &RECORD));
        assert!(
            !text.contains("10.0.0.9"),
            "an exporter that sent no template decoded against another's, got: {text}"
        );
    }

    /// Stream peers are isolated too, and each connection scope is distinct from every other.
    #[test]
    fn each_connection_scope_is_distinct() {
        let decoder = NetflowDecoder::new();

        let mut first = decoder.clone();
        first.set_new_connection_scope();
        let mut buf = BytesMut::from(&v9_template(256, &honest_fields())[..]);
        first.decode(&mut buf).expect("template should decode");

        let mut second = decoder.clone();
        second.set_new_connection_scope();
        let mut buf = BytesMut::from(&v9_data(256, &RECORD)[..]);
        let text = second
            .decode(&mut buf)
            .expect("decode should not fail")
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();

        assert!(
            !text.contains("10.0.0.9"),
            "a second connection reused the first connection's template, got: {text}"
        );
    }

    /// The cache is keyed on the datagram source address, which an attacker controls, so it needs
    /// a ceiling of its own.
    #[test]
    fn exporter_cache_is_bounded() {
        let decoder = NetflowDecoder::new();

        for i in 0..(MAX_TRACKED_EXPORTERS + 50) {
            let peer = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
            decode_from(&decoder, &peer, &v9_template(256, &honest_fields()));
        }

        let tracked = decoder.parsers.lock().expect("lock").len();
        assert!(
            tracked <= MAX_TRACKED_EXPORTERS,
            "cache grew to {tracked} entries, above the {MAX_TRACKED_EXPORTERS} ceiling",
        );
    }

}
