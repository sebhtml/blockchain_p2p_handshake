use rand::Rng;
use secp256k1::{generate_keypair, PublicKey};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
    thread, time,
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
    let auth_body = auth_message.as_rlp_list();

    // Add random padding
    let mut rng = rand::thread_rng();
    let random_padding = rng.gen_range(100..200);
    let random_bytes: Vec<u8> = vec![0; random_padding];
    let auth_body = [auth_body.to_vec(), random_bytes].concat();

    // Encrypt auth with secp256k1
    let auth_size: usize = 65 // ephemeral public key
     + 16 // initialization vector (iv)
     + auth_body.len() // encrypted message
     + 32; // message authentication code (MAC) - note that MAC key and HMAC tag have the same length.
    let auth_size = u16::try_from(auth_size).unwrap();
    println!("auth_size: {}", auth_size);
    let auth_size = auth_size.to_be_bytes();
    let enc_auth_body = &ecies_encrypt(&recipient_pk, &auth_body, &auth_size).unwrap();

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

fn read_packet(fd: &mut impl Read) -> Result<Vec<u8>, HandshakeError> {
    let mut ack_size: Option<u16> = None;
    let mut read_bytes = vec![];
    while ack_size == None {
        let mut ack_size_bytes = vec![0; 2];
        let bytes_read = fd
            .read(&mut ack_size_bytes)
            .map_err(|err| HandshakeError::IOError(err.to_string()))?;
        println!("Read bytes: {}", bytes_read);
        if bytes_read == ack_size_bytes.len() {
            let read_ack_size = u16::from_be_bytes([ack_size_bytes[0], ack_size_bytes[1]]);
            read_bytes.extend_from_slice(&ack_size_bytes);
            println!("ack_size: {}", read_ack_size);
            ack_size = Some(read_ack_size);
        }
        let wait_duration = time::Duration::from_millis(100);
        thread::sleep(wait_duration);
    }

    Ok(read_bytes)
}

/// See RLPx : https://github.com/ethereum/devp2p/blob/master/rlpx.md
/// See EIP-8 : https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8.md
pub fn do_rlpx_handshake(recipient_enode: &ENode) -> Result<bool, HandshakeError> {
    let socket = get_socket(&recipient_enode.ip_addr, recipient_enode.port)?;
    let mut stream = TcpStream::connect(socket).unwrap();
    let mut rng = secp256k1::rand::thread_rng();
    let (initiator_sk, initiator_pk) = generate_keypair(&mut rng);
    let recipient_pk: PublicKey = recipient_enode.try_into()?;

    // Generate auth packet.
    let auth_message = AuthMessage::try_new(&initiator_sk, &initiator_pk, &recipient_pk)?;
    let auth_packet = prepare_eip8_auth_packet(&recipient_pk, &auth_message)?;

    let bytes_written = write_packet(&mut stream, &auth_packet)?;
    println!("bytes_written: {}", bytes_written);

    // Read Ack packet.
    let ack_packet = read_packet(&mut stream)?;
    println!("bytes_read: {}", ack_packet.len());

    Ok(false)
}
