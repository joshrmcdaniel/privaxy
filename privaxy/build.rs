use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let scriptlets_src = manifest_dir.join("src/resources/vendor/ublock/scriptlets.js");
    let builder = manifest_dir.join("build-scriptlets.mjs");
    let out_dir = std::env::var("OUT_DIR").expect("cargo provides OUT_DIR");
    let out_path = PathBuf::from(&out_dir).join("scriptlets-resources.json");

    println!("cargo:rerun-if-changed={}", scriptlets_src.display());
    println!("cargo:rerun-if-changed={}", builder.display());

    // Allow cross-compile environments without Node (e.g. the cross-rs MIPS
    // container) to skip the Node preprocessing step by dropping a pre-built
    // JSON at a known workspace-relative path. CI generates this artifact in
    // the host-side build_frontend job and downloads it before cross-building.
    let prebuilt = manifest_dir.join("prebuilt/scriptlets-resources.json");
    println!("cargo:rerun-if-changed={}", prebuilt.display());
    if prebuilt.exists() {
        std::fs::copy(&prebuilt, &out_path).unwrap_or_else(|e| {
            panic!(
                "failed to copy prebuilt scriptlets from {}: {e}",
                prebuilt.display()
            )
        });
        return;
    }

    let status = Command::new("node")
        .arg(&builder)
        .arg(&scriptlets_src)
        .arg(&out_path)
        .status()
        .expect("failed to invoke `node` for scriptlet preprocessing — is Node.js installed and on PATH?");

    if !status.success() {
        panic!(
            "build-scriptlets.mjs exited with non-zero status: {:?}",
            status
        );
    }
}
