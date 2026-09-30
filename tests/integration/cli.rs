use std::collections::HashSet;
use std::{fs::read_dir, process::Command};

use assert_cmd::prelude::*;

use crate::{create_directory, create_file, overwrite_file};

const FAILING_HEALTHCHECK: &str = r#"
data_dir = "${VECTOR_DATA_DIR}"

[sources.in]
    type = "demo_logs"
    lines = ["log"]
    format = "shuffle"

[sinks.out]
    inputs = ["in"]
    type = "socket"
    address = "192.168.0.0:62178"
    encoding.codec = "json" # required
    mode = "tcp"
"#;

/// Returns `stdout` of `vector arguments`
fn run_command(arguments: Vec<&str>) -> Vec<u8> {
    let mut cmd = Command::cargo_bin("vector").unwrap();
    for arg in arguments {
        cmd.arg(arg);
    }

    let output = cmd.output().expect("Failed to execute process");

    output.stdout
}

fn assert_no_log_lines(output: Vec<u8>) {
    let output = String::from_utf8(output).expect("Vector output isn't a valid utf8 string");

    // Assert there are no lines with keywords
    let keywords = ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
    for line in output.lines() {
        let present = keywords.iter().any(|word| line.contains(word));
        assert!(!present, "Log detected in output line: {:?}", line);
    }
}

fn source_config(source: &str) -> String {
    format!(
        r#"
data_dir = "${{VECTOR_DATA_DIR}}"

[sources.in]
{}

[sinks.out]
    inputs = ["in"]
    type = "blackhole"
"#,
        source
    )
}

#[test]
fn clean_list() {
    assert_no_log_lines(run_command(vec!["list"]));
}

#[test]
fn clean_generate() {
    assert_no_log_lines(run_command(vec!["generate", "stdin//console"]));
}

#[test]
fn validate_cleanup() {
    // Create component directories with some file.
    let dir = create_directory();
    let mut path = dir.clone();
    path.push("tmp");
    path.set_extension("data");
    overwrite_file(path.clone(), "");

    // Config with some components that write to file system.
    let config = create_file(
        source_config(
            r#"
    type = "file"
    include = ["./*.log_dummy"]"#,
        )
        .as_str(),
    );

    // Run vector
    let mut cmd = Command::cargo_bin("vector").unwrap();
    cmd.arg("validate")
        .arg(config)
        .env("VECTOR_DATA_DIR", dir.clone());

    let output = cmd.output().expect("Failed to execute process");
    println!(
        "{}",
        String::from_utf8(output.stdout.clone()).expect("Vector output isn't a valid utf8 string")
    );

    assert_no_log_lines(output.stdout);
    assert_eq!(output.status.code(), Some(0));

    // Assert that data folder didn't change
    assert_eq!(
        HashSet::from([path]),
        read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<HashSet<_>>()
    );
}

#[test]
fn validate_failing_healthcheck() {
    assert_eq!(validate(FAILING_HEALTHCHECK), exitcode::CONFIG);
}

#[test]
fn validate_ignore_healthcheck() {
    assert_eq!(
        validate(&format!(
            r#"
        healthchecks.enabled = false
        {}
        "#,
            FAILING_HEALTHCHECK
        )),
        exitcode::OK
    );
}

const DEMO_TO_BLACKHOLE: &str = r#"
data_dir = "${VECTOR_DATA_DIR}"

[sources.in]
    type = "demo_logs"
    format = "shuffle"
    lines = ["log"]

[sinks.out]
    inputs = ["in"]
    type = "blackhole"
"#;

#[test]
fn validate_fails_on_invalid_ops_limits_env_override() {
    let (code, output) = validate_with_env(
        DEMO_TO_BLACKHOLE,
        &[("VECTOR_OPS_LIMITS_MAX_FRAME_LENGTH_BYTES", "abc")],
    );
    assert_eq!(code, exitcode::CONFIG, "{output}");
    assert!(
        output.contains("VECTOR_OPS_LIMITS_MAX_FRAME_LENGTH_BYTES") && output.contains("abc"),
        "the error must name the variable and value: {output}"
    );
}

#[test]
fn validate_succeeds_with_valid_ops_limits_env_overrides() {
    let (code, output) = validate_with_env(
        DEMO_TO_BLACKHOLE,
        &[
            ("VECTOR_OPS_LIMITS_MAX_DECOMPRESSED_SIZE_BYTES", "4194304"),
            ("VECTOR_OPS_LIMITS_MAX_FRAME_LENGTH_BYTES", "4194304"),
            ("VECTOR_OPS_LIMITS_ACK_WRITE_TIMEOUT_SECS", "60"),
        ],
    );
    assert_eq!(code, exitcode::OK, "{output}");
}

#[test]
fn validate_clamps_component_raise_to_env_global() {
    let config = format!(
        r#"
        {DEMO_TO_BLACKHOLE}
        [sources.in.ops_limits.framing]
            max_frame_length_bytes = 5000000
        "#
    );
    let (code, output) = validate_with_env(
        &config,
        &[("VECTOR_OPS_LIMITS_MAX_FRAME_LENGTH_BYTES", "4194304")],
    );
    assert_eq!(code, exitcode::OK, "{output}");
    assert!(
        output.contains("above the global limit of 4194304"),
        "the env value must be the global the raise is clamped to: {output}"
    );
}

/// Runs `vector validate` with the given environment; returns the exit code and combined output.
fn validate_with_env(config: &str, env: &[(&str, &str)]) -> (i32, String) {
    let dir = create_directory();
    let config = create_file(config);

    let mut cmd = Command::cargo_bin("vector").unwrap();
    cmd.arg("validate").arg(config).env("VECTOR_DATA_DIR", dir);
    for name in [
        "VECTOR_OPS_LIMITS_MAX_DECOMPRESSED_SIZE_BYTES",
        "VECTOR_OPS_LIMITS_MAX_FRAME_LENGTH_BYTES",
        "VECTOR_OPS_LIMITS_ACK_WRITE_TIMEOUT_SECS",
    ] {
        cmd.env_remove(name);
    }
    cmd.envs(env.iter().copied());

    let output = cmd.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.code().unwrap(), text)
}

fn validate(config: &str) -> i32 {
    let dir = create_directory();

    // Config with some components that write to file system.
    let config = create_file(config);

    // Run vector
    let mut cmd = Command::cargo_bin("vector").unwrap();
    cmd.arg("validate").arg(config).env("VECTOR_DATA_DIR", dir);

    let output = cmd.output().unwrap();
    println!(
        "{}",
        String::from_utf8(output.stdout).expect("Vector output isn't a valid utf8 string")
    );
    output.status.code().unwrap()
}
