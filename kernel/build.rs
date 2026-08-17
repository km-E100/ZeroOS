use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let boot_dir = manifest_dir.join("../boot");
    let boot_s = boot_dir.join("boot.S");
    let linker = boot_dir.join("linker.ld");

    println!(
        "cargo:rerun-if-changed={}",
        boot_s.to_str().expect("boot.S path should be UTF-8")
    );
    println!(
        "cargo:rerun-if-changed={}",
        linker.to_str().expect("linker.ld path should be UTF-8")
    );
    let linker_abs = linker.canonicalize().expect("canonicalizing linker script");
    println!(
        "cargo:rustc-link-arg=-T{}",
        linker_abs.to_str().expect("canonical path should be UTF-8")
    );
}
