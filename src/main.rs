use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    target_node: String,
    #[arg(short, long)]
    target_port: String,
}

use std::{
    fmt::Display,
    io::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

pub enum HandshakeError {
    BadTargetNodeAddress,
    BadTargetPortInteger,
    IOError(Error),
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::BadTargetNodeAddress => write!(f, "BadTargetNodeAddress"),
            HandshakeError::BadTargetPortInteger => write!(f, "BadTargetPortInteger"),
            HandshakeError::IOError(err) => write!(f, "IOError: {}", err),
        }
    }
}

fn get_socket(ip_address: &str, port: &str) -> Result<SocketAddr, HandshakeError> {
    let addr = if let Ok(addr) = Ipv4Addr::from_str(&ip_address) {
        Ok(IpAddr::V4(addr))
    } else if let Ok(addr) = Ipv6Addr::from_str(&ip_address) {
        Ok(IpAddr::V6(addr))
    } else {
        Err(HandshakeError::BadTargetNodeAddress)
    }?;
    let port = u16::from_str_radix(port, 10).map_err(|_| HandshakeError::BadTargetPortInteger)?;
    let socket = SocketAddr::new((addr), port);
    Ok(socket)
}

fn do_handshake(target_node: &str, target_port: &str) -> Result<bool, HandshakeError> {
    let socket = get_socket(&target_node, &target_port)?;
    let stream = TcpStream::connect(socket).map_err(|err| HandshakeError::IOError(err))?;

    Ok(true)
}

fn main() {
    let args = Args::parse();
    let target_node = args.target_node;
    let target_port = args.target_port;
    let result = do_handshake(&target_node, &target_port);
    match result {
        Ok(result) => println!(
            "Handshake with {}:{} was successful: {}",
            target_node, target_port, result
        ),
        Err(err) => println!("Handshake failed with error {}", err),
    }
}
