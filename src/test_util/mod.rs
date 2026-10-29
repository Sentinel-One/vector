#![allow(missing_docs)]

use crate::{
    config::{Config, GenerateConfig},
    topology::{RunningTopology, ShutdownErrorReceiver},
    trace,
};

pub async fn start_topology(
    mut config: Config,
    require_healthy: impl Into<Option<bool>>,
) -> (RunningTopology, ShutdownErrorReceiver) {
    config.healthchecks.set_require_healthy(require_healthy);
    RunningTopology::start_init_validated(config, Default::default())
        .await
        .unwrap()
}

#[cfg(any(test, feature = "test-utils"))]
pub mod components;

#[cfg(test)]
pub mod http;

#[cfg(test)]
pub mod metrics;

#[cfg(test)]
pub mod mock;

#[cfg(all(test, feature = "sources-vector"))]
pub mod jwt_auth;

pub mod stats;

pub use vector_lib::test_util::*;

#[cfg(test)]
pub use vector_lib::assert_downcast_matches;

#[cfg(test)]
pub use collect_ready_async as collect_ready;

pub fn test_generate_config<T>()
where
    for<'de> T: GenerateConfig + serde::Deserialize<'de>,
{
    let cfg = toml::to_string(&T::generate_config()).unwrap();

    toml::from_str::<T>(&cfg)
        .unwrap_or_else(|e| panic!("Invalid config generated from string:\n\n{}\n'{}'", e, cfg));
}

#[cfg(test)]
pub use vector_lib::inet_test_util::*;

pub fn trace_init() {
    #[cfg(unix)]
    let color = {
        use std::io::IsTerminal;
        std::io::stdout().is_terminal()
    };
    // Windows: ANSI colors are not supported by cmd.exe
    // Color is false for everything except unix.
    #[cfg(not(unix))]
    let color = false;

    let levels = std::env::var("TEST_LOG").unwrap_or_else(|_| "error".to_string());

    trace::init(color, false, &levels, 10, false);

    // Initialize metrics as well
    vector_lib::metrics::init_test();
}
