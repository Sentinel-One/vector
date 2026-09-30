//! Runs as its own process: an invalid override must fail bootstrap and store nothing.

use vector_common::limits::{
    init_env_defaults, FramingLimits, InitEnvDefaultsError, OperationalLimits,
    ACK_WRITE_TIMEOUT_SECS_ENV, MAX_DECOMPRESSED_SIZE_BYTES_ENV, MAX_FRAME_LENGTH_BYTES_ENV,
};

#[test]
fn invalid_env_overrides_fail_bootstrap_and_store_nothing() {
    let built_in = OperationalLimits::default();

    std::env::set_var(MAX_DECOMPRESSED_SIZE_BYTES_ENV, "1024");
    std::env::set_var(MAX_FRAME_LENGTH_BYTES_ENV, "abc");
    std::env::set_var(ACK_WRITE_TIMEOUT_SECS_ENV, "0");

    let Err(InitEnvDefaultsError::InvalidOverrides(errors)) = init_env_defaults() else {
        panic!("invalid overrides must fail bootstrap");
    };
    let variables: Vec<_> = errors.iter().map(|error| error.variable).collect();
    assert_eq!(
        variables,
        vec![MAX_FRAME_LENGTH_BYTES_ENV, ACK_WRITE_TIMEOUT_SECS_ENV]
    );
    assert_eq!(errors[0].value, "abc");
    assert_eq!(errors[1].value, "0");

    // Nothing was stored, not even the valid decompression override.
    assert_eq!(OperationalLimits::default(), built_in);

    // Once the env is fixed, bootstrap succeeds and applies it.
    std::env::set_var(MAX_FRAME_LENGTH_BYTES_ENV, "8192");
    std::env::set_var(ACK_WRITE_TIMEOUT_SECS_ENV, "7");
    init_env_defaults().expect("corrected overrides must bootstrap");
    assert_eq!(FramingLimits::default().max_frame_length_bytes, 8192);
}
