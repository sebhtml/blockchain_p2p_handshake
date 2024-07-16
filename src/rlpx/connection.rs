use aes::{cipher::KeyIvInit, Aes256};
use alloy_rlp::Decodable;
use ctr::Ctr64BE;
use log::info;
use secp256k1::{generate_keypair, PublicKey, SecretKey};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str::FromStr,
};

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
    pub recipient_static_pubk: PublicKey,
    pub stream: TcpStream,
}

struct MacsAndCiphers {
    egress: MacAndCipher,
    ingress: MacAndCipher,
}

struct MacAndCipher {
    mac: MacState,
    cipher: Ctr64BE<Aes256>,
}

fn get_socket(ip_address: &str, port: u16) -> Result<SocketAddr, HandshakeError> {
    let addr = if let Ok(addr) = Ipv4Addr::from_str(ip_address) {
        Ok(IpAddr::V4(addr))
    } else if let Ok(addr) = Ipv6Addr::from_str(ip_address) {
        Ok(IpAddr::V6(addr))
    } else {
        Err(HandshakeError::BadRecipientNodeAddress)
    }?;

    let socket = SocketAddr::new(addr, port);
    Ok(socket)
}

impl Connection {
    pub fn new(recipient_enode: &ENode) -> Result<Self, HandshakeError> {
        let static_pubk: PublicKey = recipient_enode
            .try_into()
            .map_err(|_| HandshakeError::CryptoKeyError)?;
        let recipient_socket = get_socket(&recipient_enode.ip_addr, recipient_enode.port)?;
        let stream = TcpStream::connect(recipient_socket)
            .map_err(|err| HandshakeError::IOError(err.to_string()))?;
        let peer = Self {
            recipient_static_pubk: static_pubk,
            stream,
        };

        Ok(peer)
    }

    pub fn write_bytes(&mut self, packet: &[u8]) -> Result<usize, HandshakeError> {
        let bytes_written = self
            .stream
            .write(packet)
            .map_err(|err| HandshakeError::IOError(err.to_string()))?;
        if bytes_written != packet.len() {
            return Err(HandshakeError::IOError("bad bytes_written".into()));
        }
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

    /// Use the 'p2p' capability to do a handshake.
    /// See https://github.com/ethereum/devp2p/blob/master/rlpx.md#initial-handshake
    pub fn handshake(
        &mut self,
        initiator_static_seck: &SecretKey,
        #[allow(unused)] initiator_static_pubk: &PublicKey,
    ) -> Result<bool, HandshakeError> {
        let mut rng = secp256k1::rand::thread_rng();

        let initiator_nonce = make_nonce()?;

        let (initiator_ephemeral_seck, initiator_ephemeral_pubk) = generate_keypair(&mut rng);

        // Send Auth
        let auth = self.send_auth(
            &initiator_ephemeral_pubk,
            &initiator_nonce,
            &initiator_ephemeral_seck,
        )?;
        info!("Initiator wrote Auth to Recipient with len {}", auth.len());

        // Read Ack
        let ack = self.read_bytes()?;

        if ack.is_empty() {
            return Err(HandshakeError::RecipientDisconnected);
        }

        // ack = ack-size || enc-ack-body
        // ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
        let (ack_size, enc_ack_body) = ack.split_at(2);
        let ack_body = ecies_decrypt(&initiator_ephemeral_seck, enc_ack_body, ack_size)?;
        info!("Initiator read Ack from Recipient with len {}", ack.len());

        // Convert arc-body to AckMessage.
        let ack_message = AckMessage::decode(&mut ack_body.as_slice())
            .map_err(|_| HandshakeError::RlpDecodeError)?;
        let recipient_ephemeral_pubk = [
            [4].as_slice(),
            ack_message.recipient_ephemeral_pubk.as_slice(),
        ]
        .concat();
        let remote_ephemeral_pubk = PublicKey::from_slice(&recipient_ephemeral_pubk)
            .map_err(|_| HandshakeError::CryptoKeyError)?;

        let recipient_nonce = &ack_message.recipient_nonce;

        // The Auth and Ack things are done.
        let mut macs_and_ciphers = setup_cryptographic_connection(
            &auth,
            &ack,
            initiator_static_seck,
            &self.recipient_static_pubk,
            &initiator_ephemeral_seck,
            &remote_ephemeral_pubk,
            recipient_nonce,
            &initiator_nonce,
        )?;

        let egress_mac = &mut macs_and_ciphers.egress.mac;
        let egress_cipher = &mut macs_and_ciphers.egress.cipher;
        let ingress_mac = &mut macs_and_ciphers.ingress.mac;
        let ingress_cipher = &mut macs_and_ciphers.ingress.cipher;

        // Send Hello to recipient
        // In https://github.com/ethereum/devp2p/blob/master/rlpx.md#hello-0x00 ,
        // it says that node_id is the node's public key.
        // However, that does not work so we send the initiator ephemeral pub key instead.
        let binding = initiator_ephemeral_pubk.serialize_uncompressed();
        let node_id = binding[1..]
            .try_into()
            .map_err(|_| HandshakeError::CryptoKeyError)?;
        let hello_from_initiator = HelloMessageData::new(node_id);
        let egress_frame: Frame = (&hello_from_initiator).into();

        let egress_frame_bytes = egress_frame.write_frame(egress_cipher, egress_mac)?;

        let _ = self.write_bytes(&egress_frame_bytes)?;
        info!("Initiator wrote Hello to Recipient",);
        info!("{}", hello_from_initiator);

        // Receive hello from recipient
        let ingress_frame_bytes = self.read_bytes()?;

        let ingress_frame = Frame::read_frame(&ingress_frame_bytes, ingress_cipher, ingress_mac)?;

        // Check message id
        if ingress_frame.msg_id != HELLO_MSG_ID {
            return Err(HandshakeError::BadRecipientHelloMsgId);
        }

        let hello_from_recipient: HelloMessageData = ingress_frame.try_into()?;
        info!("Initiator received Hello from Recipient",);
        info!("{}", hello_from_recipient);

        // Check protocol version
        if hello_from_recipient.protocol_version != 5 {
            return Err(HandshakeError::RecipientHelloP2pProtocolMismatch);
        }

        // Receive Disconnect from recipient.
        // The recipient node is probably going to disconnect since we don't implement the
        // "eth" capability in this handshake client.
        let ingress_frame_bytes = self.read_bytes()?;
        let ingress_frame = Frame::read_frame(&ingress_frame_bytes, ingress_cipher, ingress_mac)?;

        if ingress_frame.msg_id != DISCONNECT_MSG_ID {
            return Err(HandshakeError::RecipientDidNotDisconnect);
        }

        let ingress_msg_data: DisconnectMessageData = ingress_frame.try_into()?;
        info!(
            "Initiator received Disconnect from Recipient {:?}",
            ingress_msg_data
        );
        info!("Reason: {:?}", ingress_msg_data.reason());

        // Check protocol version
        if ingress_msg_data.reason()? != Reason::UselessPeer {
            return Err(HandshakeError::RecipientHelloP2pProtocolMismatch);
        }

        // Send Disconnect to recipient
        let egress_frame: Frame = DisconnectMessageData::new(Reason::DisconnectRequested).into();
        let egress_frame_bytes = egress_frame.write_frame(egress_cipher, egress_mac)?;

        let bytes_written = self.write_bytes(&egress_frame_bytes)?;
        info!(
            "Initiator wrote Disconnect to Recipient with len {}",
            bytes_written
        );
        // Verify that the peer has disconnected.
        let recipient_disconnect_bytes = self.read_bytes()?;
        if !recipient_disconnect_bytes.is_empty() {
            return Err(HandshakeError::RecipientDidNotDisconnect);
        }

        // https://github.com/ethereum/devp2p/blob/master/rlpx.md#initial-handshake
        // cryptographic handshake is complete if MAC of first encrypted frame is valid on both sides
        Ok(true)
    }

    fn send_auth(
        &mut self,
        initiator_ephemeral_pubk: &PublicKey,
        initiator_nonce: &[u8; 32],
        initiator_ephemeral_seck: &SecretKey,
    ) -> Result<Vec<u8>, HandshakeError> {
        let auth_message = AuthMessage::try_new(
            initiator_nonce,
            initiator_ephemeral_pubk,
            initiator_ephemeral_seck,
            &self.recipient_static_pubk,
        )?;
        let auth = prepare_auth_packet(
            initiator_ephemeral_seck,
            initiator_ephemeral_pubk,
            &self.recipient_static_pubk,
            &auth_message,
        )?;

        let _ = self.write_bytes(&auth)?;

        Ok(auth)
    }
}

fn setup_cryptographic_connection(
    auth: &[u8],
    ack: &[u8],
    initiator_static_seck: &SecretKey,
    recipient_static_pubk: &PublicKey,
    initiator_ephemeral_seck: &SecretKey,
    recipient_ephemeral_pubk: &PublicKey,
    recipient_nonce: &[u8; 32],
    initiator_nonce: &[u8; 32],
) -> Result<MacsAndCiphers, HandshakeError> {
    // Generate session secrets.
    let secrets = Secrets::new(
        initiator_static_seck,
        recipient_static_pubk,
        initiator_ephemeral_seck,
        recipient_ephemeral_pubk,
        recipient_nonce,
        initiator_nonce,
    )?;

    // key and iv for egress and ingress
    let aes_secret = secrets.aes_secret.as_slice();
    let iv = [0_u8; 16].as_slice();

    // Initiate egress
    let mut egress_mac = MacState::new(&secrets.mac_secret)?;
    egress_mac.update(&xor(&secrets.mac_secret, recipient_nonce));
    egress_mac.update(auth);
    let egress_cipher = Ctr64BE::<Aes256>::new(aes_secret.into(), iv.into());

    // Ingress MAC and cipher
    let mut ingress_mac = MacState::new(&secrets.mac_secret)?;
    ingress_mac.update(&xor(&secrets.mac_secret, initiator_nonce));
    ingress_mac.update(ack);
    let ingress_cipher = Ctr64BE::<Aes256>::new(aes_secret.into(), iv.into());

    let macs_and_ciphers = MacsAndCiphers {
        egress: MacAndCipher {
            mac: egress_mac,
            cipher: egress_cipher,
        },
        ingress: MacAndCipher {
            mac: ingress_mac,
            cipher: ingress_cipher,
        },
    };

    Ok(macs_and_ciphers)
}
