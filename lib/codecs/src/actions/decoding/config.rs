use crate::decoding::{DeserializerConfig, FramingConfig};
use serde::{Deserialize, Serialize};
use vector_common::limits::OperationalLimits;
use vector_core::config::LogNamespace;

use super::Decoder;

/// Config used to build a `Decoder`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecodingConfig {
    /// The framing config.
    framing: FramingConfig,
    /// The decoding config.
    decoding: DeserializerConfig,
    /// The namespace used when decoding.
    log_namespace: LogNamespace,
    /// Limits applied by framers that decompress or buffer an incomplete frame.
    #[serde(default, skip)]
    operational_limits: OperationalLimits,
}

impl DecodingConfig {
    /// Creates a new `DecodingConfig`.
    ///
    /// `operational_limits` are the limits framers run under. Take them from the component's
    /// context (`cx.globals.ops_limits`) so the deployment controls the caps.
    pub fn new(
        framing: FramingConfig,
        decoding: DeserializerConfig,
        log_namespace: LogNamespace,
        operational_limits: OperationalLimits,
    ) -> Self {
        Self {
            framing,
            decoding,
            log_namespace,
            operational_limits,
        }
    }

    /// Get the decoding configuration.
    pub const fn config(&self) -> &DeserializerConfig {
        &self.decoding
    }

    /// Get the framing configuration.
    pub const fn framing(&self) -> &FramingConfig {
        &self.framing
    }

    /// Builds a `Decoder` from the provided configuration.
    pub fn build(&self) -> vector_common::Result<Decoder> {
        // Build the framer.
        let framer = self.framing.build(self.operational_limits);

        // Build the deserializer.
        let deserializer = self.decoding.build()?;

        Ok(Decoder::new(framer, deserializer).with_log_namespace(self.log_namespace))
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use tokio_util::codec::Decoder as _;
    use vector_common::limits::{FramingLimits, OperationalLimits};
    use vector_core::config::LogNamespace;

    use super::DecodingConfig;
    use crate::decoding::{DeserializerConfig, FramingConfig, NewlineDelimitedDecoderConfig};

    fn newline_decoder_capped_at(max_frame_length_bytes: usize) -> super::Decoder {
        let limits = OperationalLimits {
            framing: FramingLimits::with_max_frame_length_bytes(max_frame_length_bytes),
            ..Default::default()
        };
        DecodingConfig::new(
            FramingConfig::NewlineDelimited(NewlineDelimitedDecoderConfig::new()),
            DeserializerConfig::Bytes,
            LogNamespace::Legacy,
            limits,
        )
        .build()
        .unwrap()
    }

    #[test]
    fn framer_rejects_frame_over_the_operational_limit() {
        let mut buf = BytesMut::from(&[b'a'; 5000][..]);
        assert!(newline_decoder_capped_at(4096).decode(&mut buf).is_err());
    }

    #[test]
    fn framer_buffers_frame_under_the_operational_limit() {
        let mut buf = BytesMut::from(&[b'a'; 5000][..]);
        assert!(matches!(
            newline_decoder_capped_at(8192).decode(&mut buf),
            Ok(None)
        ));
    }
}
