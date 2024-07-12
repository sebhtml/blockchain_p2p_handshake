use rand::Rng;
use secp256k1::{generate_keypair, PublicKey, SecretKey};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

use crate::rlpx::{
    ack_message::AckMessage,
    ecies::ecies_decrypt,
    p2p::{
        frame::{read_frame, write_frame},
        mac::CommMacState,
        message::{Hello, Message, HELLO_MSG_ID},
    },
};

use super::{
    auth_message::AuthMessage,
    ecies::{ecies_encrypt, ECIES_IV_LEN, ECIES_PUBK_LEN, ECIES_TAG_LEN},
    enode::ENode,
    handshake_error::HandshakeError,
    nonce::make_nonce,
    secrets::Secrets,
    IntoRlpList,
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

fn prepare_auth_packet(
    initiator_ephemeral_sk: &SecretKey,
    initiator_ephemeral_pk: &PublicKey,
    recipient_static_pk: &PublicKey,
    auth_message: &AuthMessage,
) -> Result<Vec<u8>, HandshakeError> {
    // Encode auth with RLP
    let auth_body = auth_message.into_rlp_list();

    // Add random padding
    let mut rng = rand::thread_rng();
    let random_padding = rng.gen_range(100..200);
    let random_bytes: Vec<u8> = vec![0; random_padding];
    let auth_body = [auth_body.to_vec(), random_bytes].concat();

    // Encrypt
    let auth_size: usize = ECIES_PUBK_LEN + ECIES_IV_LEN + auth_body.len() + ECIES_TAG_LEN;
    let auth_size = u16::try_from(auth_size).unwrap();
    let auth_size = auth_size.to_be_bytes();
    let enc_auth_body = &ecies_encrypt(
        initiator_ephemeral_pk,
        initiator_ephemeral_sk,
        &recipient_static_pk,
        &auth_body,
        &auth_size,
    )
    .unwrap();

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
fn read_ack(fd: &mut impl Read) -> Result<Vec<u8>, HandshakeError> {
    let mut ack_size_bytes = vec![0; 2];

    let bytes_read = fd
        .read(&mut ack_size_bytes)
        .map_err(|err| HandshakeError::IOError(err.to_string()))?;
    if bytes_read == ack_size_bytes.len() {
        let ack_size = u16::from_be_bytes([ack_size_bytes[0], ack_size_bytes[1]]);
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

fn read_hello(fd: &mut impl Read) -> Result<Vec<u8>, HandshakeError> {
    let mut buffer = vec![0; 2048];
    let bytes_read = fd
        .read(&mut buffer)
        .map_err(|err| HandshakeError::IOError(err.to_string()))?;
    Ok(buffer[0..bytes_read].to_vec())
}

/// See RLPx : https://github.com/ethereum/devp2p/blob/master/rlpx.md
pub fn do_rlpx_handshake_as_initiator(
    initiator_static_sk: &SecretKey,
    initiator_static_pk: &PublicKey,
    recipient_enode: &ENode,
) -> Result<Secrets, HandshakeError> {
    let socket = get_socket(&recipient_enode.ip_addr, recipient_enode.port)?;
    let mut stream = TcpStream::connect(socket).unwrap();
    let mut rng = secp256k1::rand::thread_rng();

    let (initiator_ephemeral_sk, initiator_ephemeral_pk) = generate_keypair(&mut rng);

    let recipient_static_pk: PublicKey = recipient_enode.try_into()?;
    let initiator_nonce = make_nonce();

    // Generate auth packet.
    let auth_message = AuthMessage::try_new(
        &initiator_nonce,
        initiator_static_sk,
        initiator_static_pk,
        &recipient_static_pk,
    )?;
    let auth_packet = prepare_auth_packet(
        &initiator_ephemeral_sk,
        &initiator_ephemeral_pk,
        &recipient_static_pk,
        &auth_message,
    )?;

    let bytes_written = write_packet(&mut stream, &auth_packet)?;
    println!("wrote auth with len {}", bytes_written);
    if bytes_written != auth_packet.len() {
        return Err(HandshakeError::IOError("bad bytes_written".into()));
    }

    // Read Ack packet.
    let ack_packet = read_ack(&mut stream)?;
    println!("read ack_packet with len {}", ack_packet.len());

    // ack = ack-size || enc-ack-body
    // ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
    let (ack_size, enc_ack_body) = ack_packet.split_at(2);

    let ack_body = ecies_decrypt(&initiator_static_sk, &enc_ack_body, &ack_size)?;

    // Convert arc-body to AckMessage.
    let ack = AckMessage::from_rlp_list(&ack_body)?;
    let remote_ephemeral_pk = PublicKey::from_slice(&ack.recipient_ephemeral_pubk).unwrap();

    // Generate secrets.
    let secrets = Secrets::new(
        initiator_static_sk,
        &recipient_static_pk,
        &initiator_ephemeral_sk,
        &remote_ephemeral_pk,
        &ack.recipient_nonce,
        &initiator_nonce,
    );
    println!("Got secrets");

    let mut egress_mac = CommMacState::new();
    let mut ingress_mac = CommMacState::new();

    // TODO send Hello to recipient
    let hello = Message::hello(&initiator_static_pk.serialize_uncompressed());
    let hello_frame = write_frame(&hello, &secrets.aes_secret, &mut egress_mac);

    let bytes_written = write_packet(&mut stream, &hello_frame)?;
    println!("wrote hello with len {}", bytes_written);
    if bytes_written != hello_frame.len() {
        return Err(HandshakeError::IOError("bad bytes_written".into()));
    }

    // TODO receive hello from recipient
    // Read hello packet.
    let recipient_hello_frame = read_hello(&mut stream)?;
    println!(
        "read recipient_hello with len {}",
        recipient_hello_frame.len()
    );
    let recipient_hello = read_frame(
        &recipient_hello_frame,
        &secrets.aes_secret,
        &mut ingress_mac,
    );
    if recipient_hello.msg_id != HELLO_MSG_ID {
        return Err(HandshakeError::BadRecipientHelloMsgId);
    }
    let recipient_hello_data = recipient_hello.to_hello_msg_data();
    if recipient_hello_data.protocol_version != 5 {
        return Err(HandshakeError::RecipientHelloP2pProtocolMismatch);
    }
    if recipient_hello_data.node_id != recipient_static_pk.serialize_uncompressed() {
        return Err(HandshakeError::RecipientHelloP2pProtocolMismatch);
    }

    // TODO verify that the recipient has not disconnected from the TCP/IP connection.
    // If the recipient disconnected, it means that its igress MAC check.

    Ok(secrets)
}
