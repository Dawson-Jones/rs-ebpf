use std::{str::FromStr, net::{TcpListener, TcpStream}, os::fd::FromRawFd};

use anyhow::{Context, Ok};
use anyhow::Result;
use clap::Parser;
use nix::sys::socket::{
    setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, SockaddrIn,
    bind, listen
};

#[derive(Debug, Parser)]
struct Command {
    #[arg(long, value_parser, default_value = "127.0.0.1")]
    addr: String,
    #[arg(long, default_value = "9999")]
    port: u16,
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let fd = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .context("Failed to create listener socket")?;

    setsockopt(fd, sockopt::ReuseAddr, &true).context("Failed to set SO_REUSEADDR")?;
    setsockopt(fd, sockopt::IpTransparent, &true).context("Failed to set IP_TRANSPARENT")?;

    let addr = format!("{}:{}", opts.addr, opts.port);
    let addr = SockaddrIn::from_str(&addr).context("Failed to parse socketaddr")?;
    bind(fd, &addr).context("Failed to bind socket")?;

    listen(fd, 128).context("Failed to listen")?;
    let listener = unsafe {
        TcpListener::from_raw_fd(fd)
    };

    for client in listener.incoming() {
        let client = client.context("Failed to connect client")?;
        handle_client(client).context("Failed to handle client")?
    }

    Ok(())
}


fn handle_client(client: TcpStream) -> Result<()> {
    let local_addr = client.local_addr().context("Failed to get local addr")?;
    let peer_addr = client.peer_addr().context("Failed to get peer addr")?;

    println!("New connection:");
    println!("\tlocal: {local_addr}");
    println!("\tpeer: {peer_addr}");
    println!();

    Ok(())
}