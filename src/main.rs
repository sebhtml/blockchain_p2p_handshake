// TODO write it in Docker

use clap::Parser;
use handshake_error::HandshakeError;
use rlpx_handshake::do_handshake;
pub mod handshake_error;
pub mod rlpx_handshake;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    target_node: String,
    #[arg(short, long)]
    target_port: String,
}

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

fn get_socket(ip_address: &str, port: &str) -> Result<SocketAddr, HandshakeError> {
    let addr = if let Ok(addr) = Ipv4Addr::from_str(&ip_address) {
        Ok(IpAddr::V4(addr))
    } else if let Ok(addr) = Ipv6Addr::from_str(&ip_address) {
        Ok(IpAddr::V6(addr))
    } else {
        Err(HandshakeError::BadTargetNodeAddress)
    }?;
    let port = u16::from_str_radix(port, 10).map_err(|_| HandshakeError::BadTargetPortInteger)?;
    let socket = SocketAddr::new(addr, port);
    Ok(socket)
}

fn get_stream_and_do_handshake(
    target_node: &str,
    target_port: &str,
) -> Result<bool, HandshakeError> {
    let socket = get_socket(&target_node, &target_port)?;
    let mut stream = TcpStream::connect(socket).map_err(|err| HandshakeError::IOError(err))?;
    do_handshake(&mut stream)
}

fn main() {
    let args = Args::parse();
    let target_node = args.target_node;
    let target_port = args.target_port;
    let result = get_stream_and_do_handshake(&target_node, &target_port);
    match result {
        Ok(result) => println!(
            "Handshake with {}:{} was successful: {}",
            target_node, target_port, result
        ),
        Err(err) => println!("Handshake failed with error {}", err),
    }
}
