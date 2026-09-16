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
            .build_source(cx.out, cx.shutdown, chkptr, lns, cx.globals.ops_limits.compression)
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
    use vector_common::limits::CompressionLimits;
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
            let src = Box::pin(config.build_source(
                tx,
                signal,
                chkptr,
                LogNamespace::Legacy,
                CompressionLimits::default(),
            ));
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

    #[test]
    fn source_outer_limits_does_not_shadow_scol_limits() {
        use crate::config::{load_from_str, Format};
        use vector_lib::config::ComponentKey;

        let toml_str = r#"
            [sources.demo_scol_source]
            type = "scol"

            [sources.demo_scol_source.trigger]
            interval_secs = 60

            [sources.demo_scol_source.limits]
            max_entries = 500
            max_bytes = 11111111

            [sources.demo_scol_source.limits.completion]
            max_entries = 250

            [sinks.out]
            type = "console"
            inputs = ["demo_scol_source"]
            encoding.codec = "json"
        "#;

        let config =
            load_from_str(toml_str, Format::Toml).expect("config should load without error");
        let outer = config
            .source(&ComponentKey::from("demo_scol_source"))
            .expect("source should be present");

        // The wrapper's own override ends up empty: `max_entries`/`max_bytes` aren't fields of
        // `OperationalLimitsOverride`, so they were never recognised as a raise/lower request.
        assert!(
            outer.ops_limits.is_empty(),
            "expected the outer `ops_limits` override to be empty (it only understands \
             compression/framing/connection), got {:?}",
            outer.ops_limits
        );

        // The flattened SCOL config must actually receive the `limits` key: `max_bytes` should
        // reflect the configured (11111111), not SCOL's own 200 MiB default.
        let inner_debug = format!("{:?}", outer.inner);
        assert!(
            inner_debug.contains("max_bytes: 11111111"),
            // inner_debug.contains("max_bytes: 209715200"),
            "expected SCOL's `limits.max_bytes` to be the configured 11111111, not \
             silently defaulted to SCOL's own 209715200 (200 MiB); got: {inner_debug}"
        );
    }
}
