/// This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
/// Proprietary and Confidential – © 2025 Observo Inc.
/// Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
/// This file is distributed separately and is not subject to the terms of the MPL-2.0.
use futures_util::FutureExt;
use std::collections::BTreeSet;

pub use scol::Config;
use vector_lib::{
    config::{DataType, LogNamespace, SourceOutput},
    schema::Definition,
    source::Source,
    Result,
};

use crate::config::{SourceConfig, SourceContext};

#[async_trait::async_trait]
#[typetag::serde(name = "scol")]
impl SourceConfig for Config {
    async fn build(&self, cx: SourceContext) -> Result<Source> {
        let lns = cx.log_namespace(self.log_namespace);
        let chkptr = cx.checkpoint_accessor().await;
        let src = self
            .clone()
            .build_source(cx.out, cx.shutdown, chkptr, lns)
            .map(|r| match r {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("Source terminated: {}", e);
                    Err(())
                }
            });
        Ok(Box::pin(src))
    }

    fn outputs(&self, global: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = global.merge(self.log_namespace);

        let lns_set = BTreeSet::from([log_namespace]);

        let schema_definition =
            Definition::default_for_namespace(&lns_set).with_standard_vector_source_metadata();

        vec![SourceOutput::new_maybe_logs(
            DataType::Log,
            schema_definition,
        )]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::{
        future::{
            self,
            Either::{Left, Right},
        },
        StreamExt,
    };
    use scol::Config;
    // NOTE: Not having this conditionally compiled on `scol` feature `test-scenarios` is _deliberate_.
    // We don't want surprises where-in the tests run while feature `observo` is enabled and yet
    // this test is skipped. The right way to run tests including private features is
    // `cargo test -F observo-test` (so we want `cargo build -F observo` to work but
    // `cargo test -F observo` to fail, at the time of writing this there is no better way
    // to do this in Cargo). -jj
    use crate::test_util::components::{assert_source_compliance, SOURCE_TAGS};
    use scol::test_scenarios as s;
    use vector_common::await_result;
    use vector_lib::config::LogNamespace;
    use vector_lib::event::Event;
    use vector_lib::shutdown::ShutdownSignal;
    use vector_lib::{chkpts::Store, Result};

    use crate::SourceSender;

    type CheckpointStore = Box<dyn Store>;

    async fn run(
        config: String,
        n_evts: usize,
        ckkpt_store: Option<CheckpointStore>,
    ) -> Result<Vec<Event>> {
        let chkptr = if let Some(chkpt_store) = ckkpt_store {
            Some(chkpt_store.accessor(s::COMPONENT_KEY.into()))
        } else {
            None
        };
        assert_source_compliance(&SOURCE_TAGS, async move {
            let (tx, rx) = SourceSender::new_test();
            let (trigger, signal, _) = ShutdownSignal::new_wired();
            let config: Config = toml::from_str(config.as_str()).unwrap();
            let src = Box::pin(config.build_source(tx, signal, chkptr, LogNamespace::Legacy));
            let evts = Box::pin(rx.take(n_evts as usize).collect::<Vec<_>>());

            match await_result!(future::select(src, evts), Duration::from_secs(5)) {
                Right((evts, mut f_src)) => {
                    trigger.cancel();
                    f_src.as_mut().await.expect("Source did not stop cleanly");
                    Ok(evts)
                }
                Left((Err(e), _)) => {
                    error!("Source failed to start: {:?}", e);
                    Err(e)
                }
                Left((Ok(_), _)) => {
                    panic!("Unreacheable branch taken while trying to run source!")
                }
            }
        })
        .await
    }

    #[tokio::test]
    async fn test_basic_event_gen() {
        s::test_basic_event_gen(run).await;
    }
}
