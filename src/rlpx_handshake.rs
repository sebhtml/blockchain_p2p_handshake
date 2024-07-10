use rand::Rng;
use rlp::Encodable;
use secp256k1::{generate_keypair, PublicKey};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

use crate::{
    auth_message::AuthMessage, ecies::ecies_encrypt, enode::ENode, handshake_error::HandshakeError,
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

fn prepare_eip8_auth_packet(
    recipient_pk: &PublicKey,
    auth_message: &AuthMessage,
) -> Result<Vec<u8>, HandshakeError> {
    // Encode auth with RLP
    let auth_body = auth_message.rlp_bytes().to_vec();

    // Add random padding
    let mut rng = rand::thread_rng();
    let random_padding = rng.gen_range(100..300);
    let random_bytes: Vec<u8> = (0..random_padding).map(|_| rand::random::<u8>()).collect();
    let auth_body = [auth_body.to_vec(), random_bytes].concat();

    // Encrypt auth with secp256k1
    let enc_auth_body = &ecies_encrypt(&recipient_pk, &auth_body).unwrap();

    // Make auth-body
    let auth_size = enc_auth_body.len() as u16;
    let auth_size = auth_size.to_be_bytes();
    let auth_packet = [&auth_size, enc_auth_body.as_slice()].concat();

    Ok(auth_packet)
}

/// See RLPx : https://github.com/ethereum/devp2p/blob/master/rlpx.md
/// See EIP-8 : https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8.md
pub fn do_rlpx_handshake(recipient_enode: &ENode) -> Result<bool, HandshakeError> {
    let socket = get_socket(&recipient_enode.ip_addr, recipient_enode.port)?;
    let mut stream = TcpStream::connect(socket).unwrap();
    let mut rng = rand::thread_rng();
    let (initiator_sk, initiator_pk) = generate_keypair(&mut rng);
    let recipient_pk: PublicKey = recipient_enode.try_into()?;

    // Generate auth
    let auth_message = AuthMessage::try_new(&initiator_sk, &initiator_pk, &recipient_pk)?;
    let auth_packet = prepare_eip8_auth_packet(&recipient_pk, &auth_message)?;

    stream
        .write(&auth_packet)
        .map_err(|err| HandshakeError::IOError(err.to_string()))?;

    // Read Ack message.
    let mut ack_size_bytes = vec![0; 2];
    stream
        .read(&mut ack_size_bytes)
        .map_err(|err| HandshakeError::IOError(err.to_string()))?;
    let ack_size = u16::from_be_bytes([ack_size_bytes[0], ack_size_bytes[1]]);
    println!("ack_size: {}", ack_size);

    Ok(false)
}
