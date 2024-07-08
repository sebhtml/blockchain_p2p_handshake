use ecies::{encrypt, utils::generate_keypair, PublicKey, SecretKey};
use keccak_hash::keccak_256;
use rlp::encode_list;
use std::{
    io::{Read, Write},
    net::TcpStream,
};

use crate::handshake_error::HandshakeError;

/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
/// See https://github.com/ethereum/go-ethereum/tree/master/p2p/rlpx/rlpx.go
/// See makeAuthMsg https://github.com/ethereum/go-ethereum/blob/master/p2p/rlpx/rlpx.go#L543
/// See sealEIP8 https://github.com/ethereum/go-ethereum/blob/master/p2p/rlpx/rlpx.go#L629
pub fn get_auth_message(sk: &SecretKey, pk: &PublicKey) -> Vec<u8> {
    #[cfg(not(feature = "x25519"))]
    let (_sk, pk) = (&sk.serialize(), &pk.serialize());
    #[cfg(feature = "x25519")]
    let (sk, pk) = (sk.as_bytes(), pk.as_bytes());

    let initiator_nonce = vec![99];
    let auth_vsn = vec![4];
    let mut sig = vec![0 as u8; 256 / 8];
    keccak_256(pk, sig.as_mut());
    let pk_vec = pk.to_vec();
    let list_for_auth_body = [&sig, &pk_vec, &initiator_nonce, &auth_vsn];
    let auth_body = encode_list::<Vec<u8>, &Vec<u8>>(&list_for_auth_body);
    let msg = &auth_body;
    let enc_auth_body = &encrypt(pk, msg).unwrap();
    let auth_size = enc_auth_body.len();
    let auth_size = auth_size.to_be_bytes();
    let auth = [&auth_size, enc_auth_body.as_slice()].concat();
    auth
}

pub fn do_handshake(stream: &mut TcpStream) -> Result<bool, HandshakeError> {
    let (sk, pk) = generate_keypair();
    let auth = get_auth_message(&sk, &pk);
    stream
        .write(&auth)
        .map_err(|err| HandshakeError::IOError(err))?;

    let mut ack_size_bytes = vec![0; 2];
    stream
        .read(&mut ack_size_bytes)
        .map_err(|err| HandshakeError::IOError(err))?;
    let ack_size = u16::from_be_bytes([ack_size_bytes[0], ack_size_bytes[1]]);
    println!("ack_size: {}", ack_size);
    Ok(false)
}
