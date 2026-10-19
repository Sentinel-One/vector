use std::path::Path;

// Emits NATIVE_JAQ_VERSIONS from the workspace Cargo.lock so the jaqwasm version-match test can
// assert the committed jaq.wasm was built against the same jaq the host links natively.
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let lock = Path::new(&manifest).join("../../../Cargo.lock");
    let text =
        std::fs::read_to_string(&lock).unwrap_or_else(|error| panic!("read {}: {error}", lock.display()));
    let versions = format!(
        "jaq-core={}|jaq-json={}|jaq-std={}",
        lock_version(&text, "jaq-core"),
        lock_version(&text, "jaq-json"),
        lock_version(&text, "jaq-std"),
    );
    println!("cargo:rustc-env=NATIVE_JAQ_VERSIONS={versions}");
    println!("cargo:rerun-if-changed={}", lock.display());
}

fn lock_version(lock: &str, name: &str) -> String {
    let mut is_match = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            is_match = false;
        } else if line.starts_with("name = ") {
            is_match = line == format!("name = \"{name}\"");
        } else if is_match && line.starts_with("version = ") {
            return line.trim_start_matches("version = ").trim_matches('"').to_string();
        }
    }
    panic!("`{name}` not found in {}", "Cargo.lock");
}
