use crate::rlpx::ecies_handshake::{
    ack_message::AckMessage, ecies::ecies_decrypt, nonce::make_nonce, secrets::Secrets,
};
use crate::rlpx::p2p::frame::Frame;
use crate::rlpx::p2p::hello_message::{Hello, HELLO_MSG_ID};
use crate::rlpx::{
    ecies_handshake::{
        auth_message::{prepare_auth_packet, AuthMessage},
        xor,
    },
    p2p::mac::MacState,
};

use secp256k1::{generate_keypair, PublicKey, SecretKey};
use std::io::ErrorKind;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
    time::Duration,
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

    let (initiator_ephemeral_sk, initiator_ephemeral_pk) = generate_keypair(&mut rng);

    // Generate auth packet.
    let auth_message = AuthMessage::try_new(
        &initiator_nonce,
        initiator_static_sk,
        initiator_static_pk,
        &initiator_ephemeral_sk,
        &initiator_ephemeral_pk,
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

    // Initiate egress
    let mut egress_mac = MacState::new(&secrets.mac_secret);
    egress_mac.update(&xor(&secrets.mac_secret, recipient_nonce));
    egress_mac.update(&auth);

    // Ingress MAC states.
    let mut ingress_mac = MacState::new(&secrets.mac_secret);
    ingress_mac.update(&xor(&secrets.mac_secret, &initiator_nonce));
    ingress_mac.update(&ack);

    // Send Hello to recipient
    // TODO don't put hello method in Message namespace.
    let hello = Frame::hello(
        &initiator_static_pk.serialize_uncompressed()[1..]
            .try_into()
            .unwrap(),
    );
    let hello_bytes = hello.write_frame(&secrets.aes_secret, &mut egress_mac)?;

    // Send hello to recipient
    let bytes_written = write_bytes(&mut stream, &hello_bytes)?;
    println!("wrote hello with len {}", bytes_written);
    if bytes_written != hello_bytes.len() {
        return Err(HandshakeError::IOError("bad bytes_written".into()));
    }

    // Receive hello from recipient

    let recipient_hello_frame = read_bytes(&mut stream)?;

    let recipient_hello = Frame::read_frame(
        &recipient_hello_frame,
        &secrets.aes_secret,
        &mut ingress_mac,
    )?;

    // Check message id
    if recipient_hello.msg_id != HELLO_MSG_ID {
        return Err(HandshakeError::BadRecipientHelloMsgId);
    }

    let recipient_hello_data = recipient_hello.to_hello_msg_data()?;
    println!("recipient_hello_data {:?}", recipient_hello_data);

    // Check protocol version
    if recipient_hello_data.protocol_version != 5 {
        return Err(HandshakeError::RecipientHelloP2pProtocolMismatch);
    }

    // Verify that the recipient has not disconnected from the TCP/IP connection.
    // If the recipient disconnected, it means that its igress MAC check.
    // If the recipient is not disconnected, doing a read with timeout should time out.

    // TODO Implement Disconnect since the recipient node is probably going to disconnect since we don't implement the
    // eth capability.
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|err| HandshakeError::IOError(err.to_string()))?;
    let mut buffer = vec![0; 2048];
    let result = stream.read(&mut buffer);
    match result {
        Ok(bytes_read) => {
            if bytes_read == 0 {
                return Err(HandshakeError::RecipientDisconnected);
            } else {
                println!("bytes_read {}", bytes_read);
                // this is a Disconnect
                // TRACE[07-15|06:27:50.989] Rejected peer                            id=7de4abe34ed36789 addr=127.0.0.1:52118 conn=inbound err="useless peer"
                return Err(HandshakeError::RecipientReturnedUndesiredBytes);
            }
        }
        Err(err) => {
            if err.kind() != ErrorKind::TimedOut {
                return Err(HandshakeError::IOError(err.to_string()));
            }
        }
    }

    Ok(secrets)
}
