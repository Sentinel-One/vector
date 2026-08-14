use crate::decoding::{DeserializerConfig, FramingConfig};
use serde::{Deserialize, Serialize};
use vector_common::decompression::CompressionLimits;
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
    /// Limits applied by framers that decompress.
    ///
    /// Defaults to the documented cap; a component with access to its context should override this
    /// with `GlobalOptions`' value via [`Self::with_compression_limits`].
    #[serde(default, skip)]
    compression_limits: CompressionLimits,
}

impl DecodingConfig {
    /// Creates a new `DecodingConfig` with the provided `FramingConfig` and
    /// `DeserializerConfig`.
    pub const fn new(
        framing: FramingConfig,
        decoding: DeserializerConfig,
        log_namespace: LogNamespace,
    ) -> Self {
        Self {
            framing,
            decoding,
            log_namespace,
            compression_limits: CompressionLimits::with_max_decompressed_size_bytes(
                vector_common::decompression::DEFAULT_MAX_DECOMPRESSED_SIZE_BYTES,
            ),
        }
    }

    /// Sets the compression limits framers should decompress under.
    ///
    /// Take these from the component's context (`cx.globals.limits.compression`) so the deployment
    /// controls the cap rather than a process-wide default.
    #[must_use]
    pub const fn with_compression_limits(mut self, limits: CompressionLimits) -> Self {
        self.compression_limits = limits;
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
        let framer = self.framing.build(self.compression_limits);

        // Build the deserializer.
        let deserializer = self.decoding.build()?;

        Ok(Decoder::new(framer, deserializer).with_log_namespace(self.log_namespace))
    }
}
