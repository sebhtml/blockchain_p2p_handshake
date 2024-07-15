use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

use aes::{cipher::KeyIvInit, Aes256};
use alloy_rlp::Decodable;
use ctr::Ctr64BE;
use secp256k1::{generate_keypair, PublicKey, SecretKey};

use crate::rlpx::{
    ecies_handshake::{
        ack_message::AckMessage, ecies::ecies_decrypt, nonce::make_nonce, secrets::Secrets,
        xor::xor,
    },
    p2p::{
        disconnect_message::{DisconnectMessageData, Reason, DISCONNECT_MSG_ID},
        frame::Frame,
        hello_message::{HelloMessageData, HELLO_MSG_ID},
        mac::MacState,
    },
};

use super::{
    ecies_handshake::auth_message::{prepare_auth_packet, AuthMessage},
    enode::ENode,
    handshake_error::HandshakeError,
};

pub struct Connection {
    pub recipient_static_pk: PublicKey,
    pub stream: TcpStream,
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

    /// Use the 'p2p' capability to add a peer to do a handshake.
    /// See RLPx : https://github.com/ethereum/devp2p/blob/master/rlpx.md
    pub fn handshake(
        &mut self,
        initiator_static_sk: &SecretKey,
        initiator_static_pk: &PublicKey,
    ) -> Result<bool, HandshakeError> {
        let mut rng = secp256k1::rand::thread_rng();

        let initiator_nonce = make_nonce();

        // TODO it is weird that we don't need initiator_ephemeral_pk.
        let (initiator_ephemeral_sk, _initiator_ephemeral_pk) = generate_keypair(&mut rng);

        // Send Auth
        let auth = self.send_auth(
            initiator_static_sk,
            initiator_static_pk,
            &initiator_nonce,
            &initiator_ephemeral_sk,
        )?;

        // Read Ack
        let ack = self.read_bytes()?;

        if ack.len() == 0 {
            return Err(HandshakeError::RecipientDisconnected);
        }

        // ack = ack-size || enc-ack-body
        // ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
        let (ack_size, enc_ack_body) = ack.split_at(2);
        let ack_body = ecies_decrypt(
            initiator_static_sk,
            &self.recipient_static_pk,
            &enc_ack_body,
            &ack_size,
        )?;

        // Convert arc-body to AckMessage.
        let ack_message = AckMessage::decode(&mut ack_body.as_slice()).unwrap();
        let recipient_ephemeral_pubk = vec![
            [4].as_slice(),
            ack_message.recipient_ephemeral_pubk.as_slice(),
        ]
        .concat();
        let remote_ephemeral_pk = PublicKey::from_slice(&recipient_ephemeral_pubk).unwrap();

        let recipient_nonce = &ack_message.recipient_nonce;

        // Generate session secrets.
        let secrets = Secrets::new(
            initiator_static_sk,
            &self.recipient_static_pk,
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
            initiator_static_pk.serialize_uncompressed()[1..]
                .try_into()
                .unwrap(),
        )
        .into();
        let egress_frame_bytes = egress_frame.write_frame(&mut egress_cipher, &mut egress_mac)?;

        let bytes_written = self.write_bytes(&egress_frame_bytes)?;
        println!("wrote Hello with len {}", bytes_written);
        if bytes_written != egress_frame_bytes.len() {
            return Err(HandshakeError::IOError("bad bytes_written".into()));
        }

        // Receive hello from recipient
        let ingress_frame_bytes = self.read_bytes()?;

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

        // Receive Disconnect from recipient.
        // The recipient node is probably going to disconnect since we don't implement the
        // "eth" capability in this handshake client.
        let ingress_frame_bytes = self.read_bytes()?;
        let ingress_frame =
            Frame::read_frame(&ingress_frame_bytes, &mut ingress_cipher, &mut ingress_mac)?;

        if ingress_frame.msg_id != DISCONNECT_MSG_ID {
            return Err(HandshakeError::RecipientDidNotDisconnect);
        }

        let ingress_msg_data: DisconnectMessageData = ingress_frame.try_into()?;
        println!("recipient DisconnectMessageData {:?}", ingress_msg_data);

        // Check protocol version
        if ingress_msg_data.reason()? != Reason::UselessPeer {
            return Err(HandshakeError::RecipientHelloP2pProtocolMismatch);
        }

        // Send Disconnect to recipient
        let egress_frame: Frame = DisconnectMessageData::new(Reason::DisconnectRequested).into();
        let egress_frame_bytes = egress_frame.write_frame(&mut egress_cipher, &mut egress_mac)?;

        // TODO move the bytes_written check in the write_bytes fn
        let bytes_written = self.write_bytes(&egress_frame_bytes)?;
        println!("wrote Disconnect with len {}", bytes_written);
        if bytes_written != egress_frame_bytes.len() {
            return Err(HandshakeError::IOError("bad bytes_written".into()));
        }

        // Verify that the peer has disconnected.
        let recipient_disconnect_bytes = self.read_bytes()?;
        if recipient_disconnect_bytes.len() != 0 {
            return Err(HandshakeError::RecipientDidNotDisconnect);
        }

        Ok(true)
    }

    fn send_auth(
        &mut self,
        initiator_static_sk: &SecretKey,
        initiator_static_pk: &PublicKey,
        initiator_nonce: &[u8; 32],
        initiator_ephemeral_sk: &SecretKey,
    ) -> Result<Vec<u8>, HandshakeError> {
        let auth_message = AuthMessage::try_new(
            &initiator_nonce,
            initiator_static_sk,
            initiator_static_pk,
            initiator_ephemeral_sk,
            &self.recipient_static_pk,
        )?;
        let auth = prepare_auth_packet(
            initiator_static_sk,
            initiator_static_pk,
            &self.recipient_static_pk,
            &auth_message,
        )?;

        let bytes_written = self.write_bytes(&auth)?;

        if bytes_written != auth.len() {
            return Err(HandshakeError::IOError("bad bytes_written".into()));
        }
        Ok(auth)
    }
}
