use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{thread, time};
use std::any::Any;
use std::ffi::CString;
use std::os::fd::AsFd;
use clap::Parser;
use xdp_forward::vxlan_modify_skel::{VxlanModifyLinks, VxlanModifySkelBuilder};
use anyhow::Result;
use libbpf_rs::libbpf_sys::{bpf_xdp_attach, bpf_xdp_attach_opts};
use libbpf_rs::ProgramType;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libc::c_char;
use log::debug;

#[derive(Debug, Parser)]
struct Command {
    #[arg(short, long, default_value = "192.168.100.5")]
    target_addr: String,

    #[arg(short, long, default_value = "192.168.100.3")]
    current_addr: String,

    #[arg(short, long)]
    iface: String,

    #[arg(short, long)]
    verbose: bool,
}

fn bump_memlock_rlimit() -> Result<libc::rlimit> {
    let mut origin_rlimit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut origin_rlimit)
    };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
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
        debug!("remove limit on locked memory failed, ret is: {}", ret);
        return Err(anyhow::anyhow!("remove limit on locked memory failed, ret is: {}", ret));
    }

    Ok(origin_rlimit)
}

fn restore_memlock_rlimit(origin_rlimit: libc::rlimit) {
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &origin_rlimit)
    };
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let _rlimit = bump_memlock_rlimit()?;

    let mut skel_builder = VxlanModifySkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut open_skel = skel_builder.open()?;
    println!("prog type: {}", open_skel.progs().xdp_fwd_prog().prog_type());
    open_skel
        .progs_mut()
        .xdp_fwd_prog()
        .set_prog_type(ProgramType::Xdp);
    println!("prog type: {}", open_skel.progs().xdp_fwd_prog().prog_type());

    let current_addr = opts.current_addr.parse::<Ipv4Addr>().unwrap();
    let current_addr: u32 = current_addr.into();
    open_skel.rodata().current_addr = current_addr.to_be();
    let target_addr = opts.target_addr.parse::<Ipv4Addr>().unwrap();
    let target_addr: u32 = target_addr.into();
    open_skel.rodata().target_addr = target_addr.to_be();

    let mut skel = open_skel.load()?;
    println!("skel load");

    let ifindex = unsafe {
        nix::net::if_::if_nametoindex(opts.iface.as_str())? as i32
        // let c_interface = CString::new(opts.iface).unwrap();
        // unsafe { if_nametoindex(c_interface.as_ptr()) };
    };
    println!("ifindex: {}", ifindex);

    let link = skel.progs_mut().xdp_fwd_prog().attach_xdp(ifindex)?;
    skel.links = VxlanModifyLinks {
        xdp_fwd_prog: Some(link)
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        eprint!(".");
        thread::sleep(time::Duration::from_secs(1));
    }

    Ok(())
}
