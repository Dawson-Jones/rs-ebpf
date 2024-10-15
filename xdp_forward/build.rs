use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;


const SRC: &str = "src/bpf/vxlan_modify.bpf.c";


fn main() {
    let out = PathBuf::from("src/vxlan_modify_skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
}