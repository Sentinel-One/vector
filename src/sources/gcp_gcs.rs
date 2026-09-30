/// This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
/// Proprietary and Confidential – © 2025 Observo Inc.
/// Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
/// This file is distributed separately and is not subject to the terms of the MPL-2.0.
use crate::config::SourceConfig;
use crate::config::SourceContext;
use crate::APP_INFO;
use vector_lib::config::LogNamespace;
use vector_lib::config::SourceOutput;

pub use gcs::GcsConfig;

#[async_trait::async_trait]
#[typetag::serde(name = "gcp_gcs")]
impl SourceConfig for GcsConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<crate::sources::Source> {
        let log_namespace = cx.log_namespace(self.log_namespace);
        let ack = cx.do_acknowledgements(self.acknowledgements);
        self.build_source(log_namespace, ack, cx.shutdown, cx.out, &APP_INFO, cx.globals.ops_limits)
            .await
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        self.define_outputs(global_log_namespace)
    }

    fn can_acknowledge(&self) -> bool {
        self.can_ack()
    }
}
