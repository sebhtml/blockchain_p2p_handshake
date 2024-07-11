use rand::Rng;
use secp256k1::{generate_keypair, PublicKey};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

use crate::{
    auth_message::AuthMessage,
    ecies::{ecies_decrypt, ecies_encrypt, ECIES_EPHEMERAL_PK_LEN, ECIES_IV_LEN, ECIES_TAG_LEN},
    enode::ENode,
    handshake_error::HandshakeError,
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
    initiator_static_pk: &PublicKey,
    recipient_static_pk: &PublicKey,
    auth_message: &AuthMessage,
) -> Result<Vec<u8>, HandshakeError> {
    // Encode auth with RLP
    let auth_body = auth_message.as_rlp_list();

    // Add random padding
    let mut rng = rand::thread_rng();
    let random_padding = rng.gen_range(100..200);
    let random_bytes: Vec<u8> = vec![0; random_padding];
    let auth_body = [auth_body.to_vec(), random_bytes].concat();

    // Encrypt auth with secp256k1
    let auth_size: usize = ECIES_EPHEMERAL_PK_LEN // ephemeral public key
     + ECIES_IV_LEN // initialization vector (iv)
     + auth_body.len() // encrypted message
     + ECIES_TAG_LEN; // message authentication code (MAC) - note that MAC key and HMAC tag have the same length.
    let auth_size = u16::try_from(auth_size).unwrap();
    let auth_size = auth_size.to_be_bytes();
    let enc_auth_body = &ecies_encrypt(&recipient_static_pk, &auth_body, &auth_size).unwrap();

    // Make auth-packet
    let auth_packet = [&auth_size, enc_auth_body.as_slice()].concat();

    Ok(auth_packet)
}

fn write_packet(fd: &mut impl Write, packet: &[u8]) -> Result<usize, HandshakeError> {
    let bytes_written = fd
        .write(&packet)
        .map_err(|err| HandshakeError::IOError(err.to_string()))?;
    Ok(bytes_written)
}

/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
/// ack = ack-size || enc-ack-body
/// ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
fn read_ack_packet(fd: &mut impl Read) -> Result<Vec<u8>, HandshakeError> {
    let mut ack_size_bytes = vec![0; 2];

    let bytes_read = fd
        .read(&mut ack_size_bytes)
        .map_err(|err| HandshakeError::IOError(err.to_string()))?;
    if bytes_read == ack_size_bytes.len() {
        let ack_size = u16::from_be_bytes([ack_size_bytes[0], ack_size_bytes[1]]);
        println!("ack_size_bytes: {:?}", ack_size_bytes);
        println!("ack_size: {:?}", ack_size);
        let mut enc_ack_body_bytes = vec![0; ack_size as usize];
        let bytes_read = fd
            .read(&mut enc_ack_body_bytes)
            .map_err(|err| HandshakeError::IOError(err.to_string()))?;
        if bytes_read == enc_ack_body_bytes.len() {
            let ack = vec![ack_size_bytes, enc_ack_body_bytes].concat();
            return Ok(ack);
        }
    }

    return Err(HandshakeError::IOError(
        "Could not read from socket the ack message from recipient".into(),
    ));
}

/// See RLPx : https://github.com/ethereum/devp2p/blob/master/rlpx.md
/// See EIP-8 : https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8.md
pub fn do_rlpx_handshake_as_initiator(recipient_enode: &ENode) -> Result<bool, HandshakeError> {
    let socket = get_socket(&recipient_enode.ip_addr, recipient_enode.port)?;
    let mut stream = TcpStream::connect(socket).unwrap();
    let mut rng = secp256k1::rand::thread_rng();
    let (initiator_static_sk, initiator_static_pk) = generate_keypair(&mut rng);
    let recipient_static_pk: PublicKey = recipient_enode.try_into()?;

    // Generate auth packet.
    let auth_message = AuthMessage::try_new(
        &initiator_static_sk,
        &initiator_static_pk,
        &recipient_static_pk,
    )?;
    let auth_packet =
        prepare_eip8_auth_packet(&initiator_static_pk, &recipient_static_pk, &auth_message)?;

    let bytes_written = write_packet(&mut stream, &auth_packet)?;
    if bytes_written != auth_packet.len() {
        return Err(HandshakeError::IOError("bad bytes_written".into()));
    }

    // Read Ack packet.
    let ack_packet = read_ack_packet(&mut stream)?;

    // ack = ack-size || enc-ack-body
    // ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
    let (ack_size, enc_ack_body) = ack_packet.split_at(2);

    #[allow(unused)]
    let ack_body = ecies_decrypt(&initiator_static_sk, &enc_ack_body, &ack_size)?;
    // TODO convert arc-body to AckMessage.

    // TODO send hello to recipient
    // TODO receive hello from recipient
    Ok(false)
}
