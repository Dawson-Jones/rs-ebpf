use std::io::Read;

use anyhow::{Result, Ok};
use kprobe::krpobe_skel::KprobeSkelBuilder;
use libbpf_rs::skel::{SkelBuilder, OpenSkel, Skel};

fn bump_memlock_rlimit() -> Result<libc::rlimit> {
    let mut origin_rlimit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut origin_rlimit)
    };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {}", ret);
        return Err(anyhow::anyhow!("get rlimit on locked memory failed, ret is: {}", ret));
    }
    println!("origin rlimit: {}, {}", origin_rlimit.rlim_cur, origin_rlimit.rlim_max);

    let setting_rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &setting_rlimit)
    };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {}", ret);
        return Err(anyhow::anyhow!("remove limit on locked memory failed, ret is: {}", ret));
    }

    Ok(origin_rlimit)
}


fn main() -> Result<()> {
    let _rlimit = bump_memlock_rlimit()?;

    // let probe = "sys_execve";

    let builder = KprobeSkelBuilder::default();

    let skel = builder.open()?;
    let mut loader = skel.load()?;
    loader.progs_mut().bpf_prog1().attach()?;
    // loader.attach()?;

    read_trace_pipe();

    Ok(())
}


fn read_trace_pipe() {
    let mut pipe = std::fs::File::open("/sys/kernel/debug/tracing/trace_pipe").unwrap();
    let mut buf = [0; 1024];
    loop {
        let n = pipe.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        let s = String::from_utf8_lossy(&buf[..n]);
        println!("{}", s);
    }
}