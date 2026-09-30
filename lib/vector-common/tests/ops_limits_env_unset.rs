//! Runs as its own process: with no overrides set, bootstrap keeps the built-in defaults.

use vector_common::limits::{
    init_env_defaults, OperationalLimits, ACK_WRITE_TIMEOUT_SECS_ENV,
    MAX_DECOMPRESSED_SIZE_BYTES_ENV, MAX_FRAME_LENGTH_BYTES_ENV,
};

#[tracing_test::traced_test]
#[test]
fn unset_env_overrides_keep_the_built_in_defaults() {
    for name in [
        MAX_DECOMPRESSED_SIZE_BYTES_ENV,
        MAX_FRAME_LENGTH_BYTES_ENV,
        ACK_WRITE_TIMEOUT_SECS_ENV,
    ] {
        std::env::remove_var(name);
    }
    let built_in = OperationalLimits::default();

    init_env_defaults().expect("no overrides must bootstrap");

    assert!(logs_contain("Resolved ops_limits defaults."));
    assert!(logs_contain("source=\"built-in\""));
    assert!(!logs_contain("source=\"env\""));

    assert_eq!(OperationalLimits::default(), built_in);
    let parsed: OperationalLimits = serde_json::from_str("{}").unwrap();
    assert_eq!(parsed, built_in);
}
