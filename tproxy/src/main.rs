use std::{
    net::Ipv4Addr,
    str::FromStr,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use anyhow::Result;
use anyhow::Context;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::{TcHookBuilder, TC_INGRESS};

use std::os::unix::io::AsFd as _;
// mod tproxy {
//     include!(concat!(env!("OUT_DIR"), "/tproxy.skel.rs"));
// }
// use tproxy::*;

use tproxy::tproxy::*;

#[derive(Debug, Parser)]
struct Commnad {
    #[arg(short, long, default_value = "1003")]
    port: u16,

    #[arg(short, long, default_value = "1")]
    ifindex: i32,

    #[arg(long, default_value = "127.0.0.1")]
    proxy_addr: String,

    #[arg(long, default_value = "9999")]
    proxy_port: u16,

    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let opts = Commnad::parse();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    })?;

    let proxy_addr = Ipv4Addr::from_str(&opts.proxy_addr)?;
    let proxy_addr: u32 = proxy_addr.into();

    let mut skel_builder = TproxySkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    // Set constants
    let mut open_skel = skel_builder.open()?;
    open_skel.rodata().target_port = opts.port.to_be();
    open_skel.rodata().proxy_addr = proxy_addr.to_be();
    open_skel.rodata().proxy_port = opts.proxy_port.to_be();

    // Load into kernel
    let skel = open_skel.load()?;
    let progs: TproxyProgs<'_> = skel.progs();

    // Set up and attach ingress TC hook
    let mut ingress = TcHookBuilder::new(progs.tproxy().as_fd())
        .ifindex(opts.ifindex)
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_INGRESS);

    ingress
        .create()
        .context("Failed to create ingress TC qdisc")?;

    ingress
        .attach()
        .context("Failed to attach ingress TC qdisc")?;

    // Block until SIGINT
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(Duration::new(1, 0));
    }

    if let Err(e) = ingress.detach() {
        eprintln!("Failed to detach prog: {}", e);
    }
    if let Err(e) = ingress.destroy() {
        eprintln!("Failed to destroy TC hook: {}", e);
    }

    Ok(())
}
