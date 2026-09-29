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
    ///
    /// Defaults to the documented caps; a component with access to its context should override
    /// this with `GlobalOptions`' value via [`Self::with_operational_limits`].
    #[serde(default, skip)]
    operational_limits: OperationalLimits,
}

impl DecodingConfig {
    /// Creates a new `DecodingConfig` with the provided `FramingConfig` and
    /// `DeserializerConfig`.
    pub fn new(
        framing: FramingConfig,
        decoding: DeserializerConfig,
        log_namespace: LogNamespace,
    ) -> Self {
        Self {
            framing,
            decoding,
            log_namespace,
            operational_limits: OperationalLimits::default(),
        }
    }

    /// Sets the operational limits framers should run under.
    ///
    /// Take these from the component's context (`cx.globals.ops_limits`) so the deployment controls
    /// the caps rather than a process-wide default.
    #[must_use]
    pub const fn with_operational_limits(mut self, limits: OperationalLimits) -> Self {
        self.operational_limits = limits;
        self
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

    fn newline_config() -> DecodingConfig {
        DecodingConfig::new(
            FramingConfig::NewlineDelimited(NewlineDelimitedDecoderConfig::new()),
            DeserializerConfig::Bytes,
            LogNamespace::Legacy,
        )
    }

    #[test]
    fn framer_rejects_frame_over_the_operational_limit() {
        let limits = OperationalLimits {
            framing: FramingLimits::with_max_frame_length_bytes(4096),
            ..Default::default()
        };
        let mut decoder = newline_config()
            .with_operational_limits(limits)
            .build()
            .unwrap();
        let mut buf = BytesMut::from(&[b'a'; 5000][..]);
        assert!(decoder.decode(&mut buf).is_err());
    }

    #[test]
    fn framer_buffers_same_frame_under_default_limits() {
        let mut decoder = newline_config().build().unwrap();
        let mut buf = BytesMut::from(&[b'a'; 5000][..]);
        assert!(matches!(decoder.decode(&mut buf), Ok(None)));
    }
}
