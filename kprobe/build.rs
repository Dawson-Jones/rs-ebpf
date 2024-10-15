use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;


const SRC: &str = "src/bpf/kprobe.bpf.c";


fn main() {
    let out = PathBuf::from("src/krpobe_skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
}