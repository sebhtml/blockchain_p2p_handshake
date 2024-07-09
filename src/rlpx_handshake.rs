use ecies::{encrypt, utils::generate_keypair, PublicKey};
use keccak_hash::keccak_256;
use rand::Rng;
use rlp::encode_list;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

use crate::{enode::ENode, handshake_error::HandshakeError};

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

/// See RLPx : https://github.com/ethereum/devp2p/blob/master/rlpx.md
/// See EIP-8 : https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8.md
fn get_auth_message(initiator_pub_key: &PublicKey, recipient_pub_key: &PublicKey) -> Vec<u8> {
    let initiator_pub_key = &initiator_pub_key.serialize();
    let recipient_pub_key = &recipient_pub_key.serialize();

    // TODO vsn must be a u32 in big endian.
    let auth_vsn = vec![4];

    let initiator_nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    println!("initiator_nonce: {}", hex::encode(&initiator_nonce));

    // TODO the sig must be a signature of XOR(nonce, shared-secret),
    // not a signature of the  initiator pub key.
    let mut sig = vec![0 as u8; 256 / 8];
    keccak_256(initiator_pub_key, sig.as_mut());
    println!("sig: {}", hex::encode(&sig));

    let initiator_pub_key_vec = initiator_pub_key.to_vec();
    println!(
        "initiator_pub_key_vec: {}",
        hex::encode(&initiator_pub_key_vec)
    );

    let list_for_auth_body = [&sig, &initiator_pub_key_vec, &initiator_nonce, &auth_vsn];
    let auth_body = encode_list::<Vec<u8>, &Vec<u8>>(&list_for_auth_body);

    let mut rng = rand::thread_rng();
    let random_padding = rng.gen_range(100..300);
    let random_bytes: Vec<u8> = (0..random_padding).map(|_| rand::random::<u8>()).collect();
    let auth_body = [auth_body.to_vec(), random_bytes].concat();

    println!("auth_body {}", hex::encode(&auth_body));
    let msg = &auth_body;
    let enc_auth_body = &encrypt(recipient_pub_key, msg).unwrap();

    let auth_size = enc_auth_body.len() as u16;
    let auth_size = auth_size.to_be_bytes();
    let auth = [&auth_size, enc_auth_body.as_slice()].concat();
    auth
}

fn get_recipient_pub_key(enode: &ENode) -> Result<PublicKey, HandshakeError> {
    let bytes = hex::decode(&enode.id).map_err(|err| HandshakeError::HexError(err.to_string()))?;
    let recipient_pub_key = PublicKey::parse_slice(&bytes, None)
        .map_err(|err| HandshakeError::Secp256k1Error(err.to_string()))?;
    Ok(recipient_pub_key)
}

pub fn do_rlpx_handshake(enode: &ENode) -> Result<bool, HandshakeError> {
    let socket = get_socket(&enode.ip_addr, enode.port)?;
    let mut stream =
        TcpStream::connect(socket).map_err(|err| HandshakeError::IOError(err.to_string()))?;
    let (_initiator_pri_key, initiator_pub_key) = generate_keypair();
    let recipient_pub_key = get_recipient_pub_key(enode)?;

    // Write auth message.
    let auth = get_auth_message(&initiator_pub_key, &recipient_pub_key);
    println!("auth: {}", hex::encode(&auth));
    stream
        .write(&auth)
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
