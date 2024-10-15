use std::process::Command;

const SRC: &str = "src/bpf/kprobe.bpf.c";

macro_rules! p {
    ($($tokens: tt)*) => {
        println!("cargo:warning={}", format!($($tokens)*))
    };
}


fn main() {
    // let arch = std::env::consts::ARCH;
    // p!("arch: {}", arch);

    let out_dir = "src/bpf";
    let ret = Command::new("clang")
        .args(&[
        "-target", "bpf", "-g", "-O2", "-Wall",
        // &format!("-D__TARGET_ARCH_{}", arch), "-c", SRC, "-o"
        "-D__TARGET_ARCH_x86", "-c", SRC, "-o"
    ])
        .arg(&format!("{}/kprobe.bpf.o", out_dir))
        .output()
        //.status()
        .unwrap();

    p!("ret: {}", String::from_utf8(ret.stdout).unwrap());
    p!("ret: {}", String::from_utf8(ret.stderr).unwrap());
    println!("cargo:rerun-if-changed={}", SRC);
}
