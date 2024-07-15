use crate::rlpx::ecies_handshake::{
    ack_message::AckMessage, ecies::ecies_decrypt, nonce::make_nonce, secrets::Secrets,
};
use crate::rlpx::p2p::disconnect_message::{DisconnectMessageData, Reason, DISCONNECT_MSG_ID};
use crate::rlpx::p2p::frame::Frame;
use crate::rlpx::p2p::hello_message::{HelloMessageData, HELLO_MSG_ID};
use crate::rlpx::{
    ecies_handshake::{
        auth_message::{prepare_auth_packet, AuthMessage},
        xor,
    },
    p2p::mac::MacState,
};

use aes::cipher::KeyIvInit;
use aes::Aes256;
use ctr::Ctr64BE;
use secp256k1::{generate_keypair, PublicKey, SecretKey};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

use super::{enode::ENode, handshake_error::HandshakeError};

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

fn write_bytes(fd: &mut impl Write, packet: &[u8]) -> Result<usize, HandshakeError> {
    let bytes_written = fd
        .write(&packet)
        .map_err(|err| HandshakeError::IOError(err.to_string()))?;
    Ok(bytes_written)
}

fn read_bytes(fd: &mut impl Read) -> Result<Vec<u8>, HandshakeError> {
    let mut buffer = vec![0; 2048];
    let bytes_read = fd
        .read(&mut buffer)
        .map_err(|err| HandshakeError::IOError(err.to_string()))?;
    Ok(buffer[0..bytes_read].to_vec())
}

// TODO add struct EthereumNode

/// See RLPx : https://github.com/ethereum/devp2p/blob/master/rlpx.md
pub fn do_rlpx_handshake_as_initiator(
    initiator_static_sk: &SecretKey,
    initiator_static_pk: &PublicKey,
    recipient_enode: &ENode,
) -> Result<Secrets, HandshakeError> {
    let socket = get_socket(&recipient_enode.ip_addr, recipient_enode.port)?;
    let mut stream = TcpStream::connect(socket).unwrap();
    let mut rng = secp256k1::rand::thread_rng();

    let recipient_static_pk: PublicKey = recipient_enode.try_into()?;
    let initiator_nonce = make_nonce();

    // TODO it is weird that we don't need initiator_ephemeral_pk.
    let (initiator_ephemeral_sk, _initiator_ephemeral_pk) = generate_keypair(&mut rng);

    // Generate auth packet.
    let auth_message = AuthMessage::try_new(
        &initiator_nonce,
        initiator_static_sk,
        initiator_static_pk,
        &initiator_ephemeral_sk,
        &recipient_static_pk,
    )?;
    let auth = prepare_auth_packet(
        &initiator_static_sk,
        &initiator_static_pk,
        &recipient_static_pk,
        &auth_message,
    )?;

    let bytes_written = write_bytes(&mut stream, &auth)?;

    if bytes_written != auth.len() {
        return Err(HandshakeError::IOError("bad bytes_written".into()));
    }

    // Read Ack packet.
    let ack = read_bytes(&mut stream)?;

    if ack.len() == 0 {
        return Err(HandshakeError::RecipientDisconnected);
    }

    // ack = ack-size || enc-ack-body
    // ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
    let (ack_size, enc_ack_body) = ack.split_at(2);
    let ack_body = ecies_decrypt(
        &initiator_static_sk,
        &recipient_static_pk,
        &enc_ack_body,
        &ack_size,
    )?;

    // Convert arc-body to AckMessage.
    let ack_message = AckMessage::from_rlp_list(&ack_body)?;
    let remote_ephemeral_pk = PublicKey::from_slice(&ack_message.recipient_ephemeral_pubk).unwrap();

    let recipient_nonce = &ack_message.recipient_nonce;

    // Generate session secrets.
    let secrets = Secrets::new(
        initiator_static_sk,
        &recipient_static_pk,
        &initiator_ephemeral_sk,
        &remote_ephemeral_pk,
        recipient_nonce,
        &initiator_nonce,
    );

    // key and iv for egress and ingress
    let aes_secret = secrets.aes_secret.as_slice();
    let iv = [0 as u8; 16].as_slice();

    // TODO add state machine for the message to handle.

    // Initiate egress
    let mut egress_mac = MacState::new(&secrets.mac_secret);
    egress_mac.update(&xor(&secrets.mac_secret, recipient_nonce));
    egress_mac.update(&auth);
    let mut egress_cipher = Ctr64BE::<Aes256>::new(aes_secret.into(), iv.into());

    // Ingress MAC and cipher
    let mut ingress_mac = MacState::new(&secrets.mac_secret);
    ingress_mac.update(&xor(&secrets.mac_secret, &initiator_nonce));
    ingress_mac.update(&ack);
    let mut ingress_cipher = Ctr64BE::<Aes256>::new(aes_secret.into(), iv.into());

    // Send Hello to recipient
    let egress_frame: Frame = HelloMessageData::new(
        &initiator_static_pk.serialize_uncompressed()[1..]
            .try_into()
            .unwrap(),
    )
    .into();
    let egress_frame_bytes = egress_frame.write_frame(&mut egress_cipher, &mut egress_mac)?;

    // Send hello to recipient
    let bytes_written = write_bytes(&mut stream, &egress_frame_bytes)?;
    println!("wrote hello with len {}", bytes_written);
    if bytes_written != egress_frame_bytes.len() {
        return Err(HandshakeError::IOError("bad bytes_written".into()));
    }

    // Receive hello from recipient
    let ingress_frame_bytes = read_bytes(&mut stream)?;

    let ingress_frame =
        Frame::read_frame(&ingress_frame_bytes, &mut ingress_cipher, &mut ingress_mac)?;

    // Check message id
    if ingress_frame.msg_id != HELLO_MSG_ID {
        return Err(HandshakeError::BadRecipientHelloMsgId);
    }

    let ingress_msg_data: HelloMessageData = ingress_frame.try_into()?;
    println!("recipient HelloMessageData {:?}", ingress_msg_data);

    // Check protocol version
    if ingress_msg_data.protocol_version != 5 {
        return Err(HandshakeError::RecipientHelloP2pProtocolMismatch);
    }

    // The recipient node is probably going to disconnect since we don't implement the
    // "eth" capability in this handshake client.
    let ingress_frame_bytes = read_bytes(&mut stream)?;
    let ingress_frame =
        Frame::read_frame(&ingress_frame_bytes, &mut ingress_cipher, &mut ingress_mac)?;

    // Check message id
    if ingress_frame.msg_id != DISCONNECT_MSG_ID {
        return Err(HandshakeError::RecipientDidNotDisconnect);
    }

    let ingress_msg_data: DisconnectMessageData = ingress_frame.try_into()?;
    println!("recipient DisconnectMessageData {:?}", ingress_msg_data);

    // Check protocol version
    if ingress_msg_data.reason()? != Reason::UselessPeer {
        return Err(HandshakeError::RecipientHelloP2pProtocolMismatch);
    }

    // Verify that the peer has disconnected.
    let recipient_disconnect_bytes = read_bytes(&mut stream)?;
    if recipient_disconnect_bytes.len() != 0 {
        return Err(HandshakeError::RecipientDidNotDisconnect);
    }

    // TODO Also disconnect the initiator.
    // The specification at https://github.com/ethereum/devp2p/blob/master/rlpx.md says
    // that the initiator has 2 seconds to comply and send a Disconnect message to the
    // recipient.

    Ok(secrets)
}
