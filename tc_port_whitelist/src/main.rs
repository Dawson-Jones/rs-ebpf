use std::os::fd::AsFd;
use anyhow::{bail, Context};
use clap::Parser;
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapFlags, TC_CUSTOM, TC_EGRESS, TC_H_CLSACT, TC_H_MIN_INGRESS, TC_INGRESS, TcHookBuilder};
use tc_port_whitelist::tc_whiteports_skel::TcWhiteportsSkelBuilder;

#[derive(Debug, Parser)]
struct Command {
    #[arg(short, long)]
    ports: Vec<u16>,

    #[arg(short, long)]
    attach: bool,

    #[arg(short, long)]
    detach: bool,

    #[arg(short='D', long="destroy")]
    destroy: bool,

    #[arg(short, long)]
    query: bool,

    #[arg(short='i', long="interface")]
    iface: String,
}


fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}


fn main() ->Result<()> {
    let opts: Command = Command::parse();
    
    bump_memlock_rlimit()?;

    let builder = TcWhiteportsSkelBuilder::default();
    let opened = builder.open()?;
    let mut skel = opened.load()?;
    let progs = skel.progs();
    let if_idx = nix::net::if_::if_nametoindex(opts.iface.as_str())? as i32;

    let mut tc_builder = TcHookBuilder::new(progs.handle_tc().as_fd());
    tc_builder
        .ifindex(if_idx)
        .replace(true)
        .handle(1)
        .priority(1);

    let mut egress = tc_builder.hook(TC_EGRESS);
    let mut ingress = tc_builder.hook(TC_INGRESS);
    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS).handle(2);

    let mut destroy_all = libbpf_rs::TcHook::new(progs.handle_tc().as_fd());
    destroy_all.ifindex(if_idx)
        .attach_point(TC_EGRESS | TC_INGRESS);

    if opts.query {
        match custom.query() {
            Err(e) => println!("failed to find custom hook: {e}"),
            Ok(prog_id) => println!("dound custom hook prog_id: {prog_id}"),
        }
        match egress.query() {
            Err(e) => println!("failed to find custom hook: {e}"),
            Ok(prog_id) => println!("found custom hook prog_id: {prog_id}"),
        }
        match ingress.query() {
            Err(e) => println!("failed to find custom hook: {e}"),
            Ok(prog_id) => println!("found custom hook prog_id: {prog_id}"),
        }
    }

    if opts.detach {
        if let Err(e) = ingress.detach() {
            println!("failed to detach ingress hook {e}");
        }
        if let Err(e) = egress.detach() {
            println!("failed to detach egress hook {e}");
        }
        if let Err(e) = custom.detach() {
            println!("failed to detach custom hook {e}");
        }
    }

    if opts.attach {
        for (i, port) in opts.ports.iter().enumerate() {
            let key = (i as u32).to_ne_bytes();
            let val = port.to_ne_bytes();
            let () = skel
                .maps_mut()
                .ports()
                .update(&key, &val, MapFlags::ANY)
                .context("Example limited to 10 ports")?;
        }

        ingress.create()?;

        if let Err(e) = egress.attach() {
            println!("failed to attach egress hook {e}");
        }
        if let Err(e) = ingress.attach() {
            println!("failed to attach ingress hook {e}");
        }

        if let Err(e) = custom.attach() {
            println!("failed to attach custom hook {e}");
        }
    }

    if opts.destroy {
        if let Err(e) = destroy_all.detach() {
            println!("failed to destroy all {e}");
        }
    }

    Ok(())
}
