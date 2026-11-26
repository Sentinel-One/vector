/**
This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
Proprietary and Confidential – © 2025 Observo Inc.
Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
This file is distributed separately and is not subject to the terms of the MPL-2.0.
**/

use crate::{
    config::{AcknowledgementsConfig, Input, SinkConfig, SinkContext},
    http::HttpClient,
    sinks::{
        util::{
            http::BatchedHttpSink,
            BatchConfig,
            JsonArrayBuffer, RealtimeSizeBasedDefaultBatchSettings,
            TowerRequestConfig,
        },
        Healthcheck, VectorSink,
    },
    tls::TlsSettings,
};
use azs::{healthcheck, AzsConfig, AzureSentinelLogsSink};

use futures::{FutureExt, SinkExt};
use vector_config::{configurable_component, impl_generate_config_from_default};
use vector_lib::schema;
use vrl::value::Kind;

/// Configuration for the `azure_sentinel_logs` sink.
#[configurable_component(sink("azure_sentinel_logs"))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AzureSentinelLogsConfig {
    #[configurable(derived)]
    #[serde(flatten)]
    pub azs_config: AzsConfig,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: BatchConfig<RealtimeSizeBasedDefaultBatchSettings>,

    #[configurable(derived)]
    #[serde(default)]
    pub request: TowerRequestConfig,

    #[configurable(derived)]
    pub tls: Option<crate::tls::TlsConfig>,

    #[configurable(derived)]
    #[serde(default)]
    pub acknowledgements: AcknowledgementsConfig,
}

impl Default for AzureSentinelLogsConfig {
    fn default() -> Self {
        Self {
            azs_config: Default::default(),
            batch: Default::default(),
            request: Default::default(),
            tls: None,
            acknowledgements: Default::default(),
        }
    }
}

impl_generate_config_from_default!(AzureSentinelLogsConfig);

// Implement the AzsSinkBuilder trait
/// Max number of bytes in request body
const MAX_BATCH_SIZE: usize = 1 * 1024 * 1024;

#[async_trait::async_trait]
#[typetag::serde(name = "azure_sentinel_logs")]
impl SinkConfig for AzureSentinelLogsConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let batch_settings = self
            .batch
            .validate()?
            .limit_max_bytes(MAX_BATCH_SIZE)?
            .into_batch_settings()?;

        let tls_settings = TlsSettings::from_options(self.tls.as_ref())?;
        let app_info = crate::app_info();
        let client = HttpClient::new(Some(tls_settings), &cx.proxy, &app_info)?;

        let sink =     AzureSentinelLogsSink::new(&self.azs_config)?;
        let request_settings = self.request.into_settings();

        let healthcheck = healthcheck(sink.clone(), client.clone()).boxed();

        let sink = BatchedHttpSink::new(
            sink,
            JsonArrayBuffer::new(batch_settings.size),
            request_settings,
            batch_settings.timeout,
            client,
            cx.bytes_sent(),
        )
        .sink_map_err(|error| error!(message = "Fatal azure_sentinel_logs sink error.", %error));

        #[allow(deprecated)]
        Ok((VectorSink::from_event_sink(sink), healthcheck))
    }

    fn input(&self) -> Input {
        let requirements =
            schema::Requirement::empty().optional_meaning("timestamp", Kind::timestamp());

        Input::log().with_schema_requirement(requirements)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}


