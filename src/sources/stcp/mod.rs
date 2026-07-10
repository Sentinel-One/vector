/**
This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
Proprietary and Confidential – © 2025 Observo Inc.
Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
This file is distributed separately and is not subject to the terms of the MPL-2.0.
**/
use std::net::SocketAddr;
use std::time::Duration;
use vrl::compiler::conversion::Conversion;
use crate::sources::Source;
use crate::tls::MaybeTlsSettings;
pub use stcp::{STcpSource, STcpAcker};
pub use stcp::stcp_decoder::{STcpDecoder, STcpDecoderError, STcpEventsFrame};
use vector_lib::config::{DataType, LogNamespace, SourceOutput};
use crate::config::{SourceConfig, SourceContext};
use crate::config::Resource;
use crate::event::Event;
use super::util::net::TcpSource;
use stcp::config::STcpConfig;

#[async_trait::async_trait]
#[typetag::serde(name = "stcp")]
impl SourceConfig for STcpConfig {

    async fn build(&self, cx: SourceContext) -> vector_common::Result<Source> {
        let log_namespace = cx.log_namespace(self.log_namespace);
        let source = STcpSource::new(
            Conversion::Timestamp(cx.globals.timezone()),
            log_namespace,
            self,
        );
        let shutdown_secs = Duration::from_secs(30);
        let tls_config = self.tls.as_ref();
        let tls_client_metadata_key = self
            .tls
            .as_ref()
            .and_then(|tls| tls.client_metadata_key.clone())
            .and_then(|k| k.path);

        let tls = MaybeTlsSettings::from_config(
            tls_config.map(|c| &c.tls_config),
            true)?;
        source.run(
            self.address,
            self.keepalive,
            shutdown_secs,
            tls,
            tls_client_metadata_key,
            self.receive_buffer_bytes,
            None,
            cx,
            self.acknowledgements,
            self.connection_limit,
            None,
            self.typetag_name(),
            log_namespace,
        )
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        // There is a global and per-source `log_namespace` config.
        // The source config overrides the global setting and is merged here.
        vec![SourceOutput::new_maybe_logs(
            DataType::Log,
            self.schema_definition(global_log_namespace.merge(self.log_namespace)),
        )]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![self.address.as_tcp_resource()]
    }

    fn can_acknowledge(&self) -> bool {
        true
    }
}

impl TcpSource for STcpSource {
    type Error = STcpDecoderError;
    type Item = STcpEventsFrame;
    type Decoder = STcpDecoder;
    type Acker = STcpAcker;

    fn decoder(&self) -> Self::Decoder {
        self.make_decoder()
    }

    fn handle_events(&self, events: &mut [Event], host: SocketAddr) {
        self.enrich_events(events, host);
    }

    fn build_acker(&self, frames: &[Self::Item]) -> Self::Acker {
        STcpAcker::new(frames)
    }
}

#[cfg(test)]
async fn start_stcp(config: STcpConfig) -> impl futures::Stream<Item = Event> + Unpin {
    use crate::event::EventStatus;
    use crate::test_util::wait_for_tcp;
    use vector_lib::net::SocketListenAddr;

    let addr = match config.address {
        SocketListenAddr::SocketAddr(a) => a,
        _ => panic!("expected SocketAddr in test config"),
    };
    let (sender, recv) = crate::SourceSender::new_test_finalize(EventStatus::Delivered);
    let source = config
        .build(crate::config::SourceContext::new_test(sender, None))
        .await
        .unwrap();
    tokio::spawn(source);
    wait_for_tcp(addr).await;
    recv
}

#[cfg(test)]
mod tests {
    use crate::test_util::next_addr;
    use stcp::test_scenarios as s;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_happy_path() {
        s::test_happy_path(next_addr(), super::start_stcp).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_error_scenarios() {
        s::test_error_scenarios(next_addr(), super::start_stcp).await;
    }
}
