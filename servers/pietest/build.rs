use std::path::PathBuf;
fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("aarch64-unknown-none") {
        return;
    }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("link-pie.x");
    println!("cargo:rustc-link-arg=-T{}", p.display());
    println!("cargo:rustc-link-arg=-pie");
    println!("cargo:rustc-link-arg=--build-id=none");
    println!("cargo:rerun-if-changed={}", p.display());
}
