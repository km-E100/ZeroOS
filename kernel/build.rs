use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let boot_dir = manifest_dir.join("../boot");
    let boot_s = boot_dir.join("boot.S");
    let target = std::env::var("TARGET").unwrap_or_default();
    let pie = target.contains("aarch64-unknown-none-pic");
    let linker = boot_dir.join(if pie { "linker-pie.ld" } else { "linker.ld" });
    println!("cargo:rerun-if-changed={}", boot_s.display());
    println!(
        "cargo:rerun-if-changed={}",
        boot_dir.join("linker.ld").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        boot_dir.join("linker-pie.ld").display()
    );
    let linker_abs = linker.canonicalize().expect("canonicalizing linker script");
    println!(
        "cargo:rustc-link-arg=-T{}",
        linker_abs.to_str().expect("canonical path should be UTF-8")
    );
    if pie {
        println!("cargo:rustc-link-arg=-pie");
    }
}
