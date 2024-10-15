use std::path::PathBuf;
use std::env;
use libbpf_cargo::SkeletonBuilder;


const SRC: &str = "src/bpf/tc_whiteports.bpf.c";

macro_rules! p {
    ($($tokens: tt)*) => {
        println!("cargo:warning={}", format!($($tokens)*))
    }
}


fn main() {
    let mut out = PathBuf::from(
        env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script")
    );

    out.push("tc_whiteports.skel.rs");
    p!("now out dir is: {}", out.to_str().unwrap());

    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();

    let mut gen = PathBuf::from("src");
    gen.push("tc_whiteports_skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&gen)
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
}