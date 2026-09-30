//! Runs as its own process: sets real `VECTOR_OPS_LIMITS_*` variables and bootstraps once.

use vector_common::limits::{
    init_env_defaults, CompressionLimits, ConnectionLimits, FramingLimits, InitEnvDefaultsError,
    OperationalLimits, OperationalLimitsOverride, ACK_WRITE_TIMEOUT_SECS_ENV,
    MAX_DECOMPRESSED_SIZE_BYTES_ENV, MAX_FRAME_LENGTH_BYTES_ENV,
};

#[tracing_test::traced_test]
#[test]
fn valid_env_overrides_replace_the_built_in_defaults() {
    let built_in = OperationalLimits::default();

    std::env::set_var(MAX_DECOMPRESSED_SIZE_BYTES_ENV, "4096");
    std::env::set_var(MAX_FRAME_LENGTH_BYTES_ENV, " 8192 ");
    std::env::set_var(ACK_WRITE_TIMEOUT_SECS_ENV, "7");
    init_env_defaults().expect("valid overrides must bootstrap");

    // Bootstrap logs the resolved defaults and where each one came from.
    assert!(logs_contain("Resolved ops_limits defaults."));
    assert!(logs_contain("max_decompressed_size_bytes=4096"));
    assert!(logs_contain("max_frame_length_bytes=8192"));
    assert!(logs_contain("ack_write_timeout_secs=7"));
    assert!(logs_contain("source=\"env\""));

    // The env values, not the compiled constants, are now the defaults.
    assert_ne!(built_in.compression.max_decompressed_size_bytes, 4096);
    assert_ne!(built_in.framing.max_frame_length_bytes, 8192);
    assert_ne!(built_in.connection.ack_write_timeout_secs, 7);
    assert_eq!(
        CompressionLimits::default().max_decompressed_size_bytes,
        4096
    );
    assert_eq!(FramingLimits::default().max_frame_length_bytes, 8192);
    assert_eq!(ConnectionLimits::default().ack_write_timeout_secs, 7);

    // The serde default for a missing field goes through the same values.
    let parsed: OperationalLimits = serde_json::from_str("{}").unwrap();
    assert_eq!(parsed.compression.max_decompressed_size_bytes, 4096);
    assert_eq!(parsed.framing.max_frame_length_bytes, 8192);
    assert_eq!(parsed.connection.ack_write_timeout_secs, 7);

    // A value set in config still wins over the env default.
    let parsed: OperationalLimits =
        serde_json::from_str(r#"{"framing":{"max_frame_length_bytes":65536}}"#).unwrap();
    assert_eq!(parsed.framing.max_frame_length_bytes, 65536);
    assert_eq!(parsed.compression.max_decompressed_size_bytes, 4096);

    // A per-component raise is clamped to the env-derived global, not the compiled constant.
    let over: OperationalLimitsOverride =
        serde_json::from_str(r#"{"framing":{"max_frame_length_bytes":16384}}"#).unwrap();
    let (resolved, raises) = OperationalLimits::default().resolve(&over, false);
    assert_eq!(resolved.framing.max_frame_length_bytes, 8192);
    assert_eq!(raises.len(), 1);
    assert_eq!(raises[0].allowed, 8192);

    // Bootstrap happens exactly once: a second call is an error and changes nothing.
    std::env::set_var(MAX_FRAME_LENGTH_BYTES_ENV, "1");
    assert_eq!(
        init_env_defaults(),
        Err(InitEnvDefaultsError::AlreadyInitialized)
    );
    assert_eq!(FramingLimits::default().max_frame_length_bytes, 8192);
}
