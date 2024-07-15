use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

use secp256k1::PublicKey;

use super::{enode::ENode, handshake_error::HandshakeError};

pub struct Connection {
    recipient_static_pk: PublicKey,
    stream: TcpStream,
}

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

impl Connection {
    pub fn new(recipient_enode: &ENode) -> Result<Self, HandshakeError> {
        let static_pk: PublicKey = recipient_enode.try_into().unwrap();
        let recipient_socket = get_socket(&recipient_enode.ip_addr, recipient_enode.port)?;
        let stream = TcpStream::connect(recipient_socket).unwrap();
        let peer = Self {
            recipient_static_pk: static_pk,
            stream,
        };

        Ok(peer)
    }

    pub fn static_pk(&self) -> &PublicKey {
        &self.recipient_static_pk
    }

    pub fn write_bytes(&mut self, packet: &[u8]) -> Result<usize, HandshakeError> {
        let bytes_written = self
            .stream
            .write(&packet)
            .map_err(|err| HandshakeError::IOError(err.to_string()))?;
        Ok(bytes_written)
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>, HandshakeError> {
        let mut buffer = vec![0; 2048];
        let bytes_read = self
            .stream
            .read(&mut buffer)
            .map_err(|err| HandshakeError::IOError(err.to_string()))?;
        Ok(buffer[0..bytes_read].to_vec())
    }
}
