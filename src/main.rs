// TODO write it in Docker

use clap::Parser;
use enode::ENode;
use handshake_error::HandshakeError;
use rlpx_handshake::do_rlpx_handshake;
pub mod enode;
pub mod handshake_error;
pub mod rlpx_handshake;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    recipient: String,
}

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

fn get_socket(ip_address: &str, port: u16) -> Result<SocketAddr, HandshakeError> {
    let addr = if let Ok(addr) = Ipv4Addr::from_str(&ip_address) {
        Ok(IpAddr::V4(addr))
    } else if let Ok(addr) = Ipv6Addr::from_str(&ip_address) {
        Ok(IpAddr::V6(addr))
    } else {
        Err(HandshakeError::BadRecipientNodeAddress)
    }?;

    let socket = SocketAddr::new(addr, port);
    Ok(socket)
}

fn main() {
    let args = Args::parse();
    let recipient = args.recipient;
    let recipient: ENode = recipient.as_str().try_into().unwrap();
    let recipient_ip_addr = recipient.ip_addr;
    let recipient_tcp_port = recipient.port;
    let recipient_pub_key = recipient.id;
    let socket = match get_socket(&recipient_ip_addr, recipient_tcp_port) {
        Ok(socket) => socket,
        _ => panic!(
            "Failed to make socket for addr {} and port {}",
            recipient_ip_addr, recipient_tcp_port
        ),
    };
    let mut stream = match TcpStream::connect(socket).map_err(|err| HandshakeError::IOError(err)) {
        Ok(stream) => stream,
        _ => panic!(
            "Could not establish TCP connection to addr {} and port {}",
            recipient_ip_addr, recipient_tcp_port
        ),
    };
    let result = do_rlpx_handshake(&mut stream, &recipient_pub_key);
    match result {
        Ok(result) => println!(
            "Handshake with {}:{} was successful: {}",
            recipient_ip_addr, recipient_tcp_port, result
        ),
        Err(err) => println!("Handshake failed with error {}", err),
    }
}
