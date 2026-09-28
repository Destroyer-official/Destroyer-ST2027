// Bakes the exact toolchain identity into the binary for attestation
// (tsrt_version): no external crates required.
fn main() {
    let v = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "rustc-unknown".to_string());
    println!("cargo:rustc-env=TSRT_RUSTC={v}");
    println!("cargo:rerun-if-changed=build.rs");
}
