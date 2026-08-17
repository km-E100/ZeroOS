fn main() {
    println!("cargo:rerun-if-changed=boot/boot.S");
    println!("cargo:rerun-if-changed=boot/linker.ld");
}
