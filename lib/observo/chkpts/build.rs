//This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
//Proprietary and Confidential – © 2025 Observo Inc.
//Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
//This file is distributed separately and is not subject to the terms of the MPL-2.0.

// Generates the tonic client for the control-agent `CheckpointService` (see
// proto/checkpoint.proto, a byte-identical copy of the contract owned by the control-agent).
// Server code is only generated for tests (feature `test-server`, enabled via the
// self dev-dependency in Cargo.toml), so it never reaches a production build.
fn main() {
    let proto = "proto/checkpoint.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_build::configure()
        .build_client(true)
        .build_server(std::env::var_os("CARGO_FEATURE_TEST_SERVER").is_some())
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&[proto], &["proto"])
        .expect("could not compile checkpoint.proto");
}
