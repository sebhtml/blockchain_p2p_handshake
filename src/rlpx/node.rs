use crate::rlpx::ecies_handshake::{
    ack_message::AckMessage, ecies::ecies_decrypt, nonce::make_nonce, secrets::Secrets,
};
use crate::rlpx::p2p::disconnect_message::{DisconnectMessageData, Reason, DISCONNECT_MSG_ID};
use crate::rlpx::p2p::frame::Frame;
use crate::rlpx::p2p::hello_message::{HelloMessageData, HELLO_MSG_ID};
use crate::rlpx::peer::Peer;
use crate::rlpx::{
    ecies_handshake::{
        auth_message::{prepare_auth_packet, AuthMessage},
        xor,
    },
    p2p::mac::MacState,
};

use aes::cipher::KeyIvInit;
use aes::Aes256;
use alloy_rlp::Decodable;
use ctr::Ctr64BE;
use secp256k1::{generate_keypair, PublicKey, SecretKey};

use super::{enode::ENode, handshake_error::HandshakeError};

pub struct EthereumNode {
    static_sk: SecretKey,
    static_pk: PublicKey,
}

impl EthereumNode {
    pub fn new() -> Self {
        let mut rng = secp256k1::rand::thread_rng();
        let (static_sk, static_pk) = generate_keypair(&mut rng);

        Self {
            static_sk,
            static_pk,
        }
    }

    /// Use the 'p2p' capability to add a peer.
    /// See RLPx : https://github.com/ethereum/devp2p/blob/master/rlpx.md
    pub fn add_peer(&self, recipient_enode: &ENode) -> Result<Secrets, HandshakeError> {
        let mut peer = Peer::new(recipient_enode)?;

        let mut rng = secp256k1::rand::thread_rng();

        let initiator_nonce = make_nonce();

        // TODO it is weird that we don't need initiator_ephemeral_pk.
        let (initiator_ephemeral_sk, _initiator_ephemeral_pk) = generate_keypair(&mut rng);

        // Generate auth packet.
        let auth_message = AuthMessage::try_new(
            &initiator_nonce,
            &self.static_sk,
            &self.static_pk,
            &initiator_ephemeral_sk,
            peer.static_pk(),
        )?;
        let auth = prepare_auth_packet(
            &self.static_sk,
            &self.static_pk,
            peer.static_pk(),
            &auth_message,
        )?;

        let bytes_written = peer.write_bytes(&auth)?;

        if bytes_written != auth.len() {
            return Err(HandshakeError::IOError("bad bytes_written".into()));
        }

        // Read Ack packet.
        let ack = peer.read_bytes()?;

        if ack.len() == 0 {
            return Err(HandshakeError::RecipientDisconnected);
        }

        // ack = ack-size || enc-ack-body
        // ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
        let (ack_size, enc_ack_body) = ack.split_at(2);
        let ack_body = ecies_decrypt(&self.static_sk, peer.static_pk(), &enc_ack_body, &ack_size)?;

        // Convert arc-body to AckMessage.
        // TODO remove from_rlp_list.
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
            &self.static_sk,
            &peer.static_pk(),
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
            &self.static_pk.serialize_uncompressed()[1..]
                .try_into()
                .unwrap(),
        )
        .into();
        let egress_frame_bytes = egress_frame.write_frame(&mut egress_cipher, &mut egress_mac)?;

        let bytes_written = peer.write_bytes(&egress_frame_bytes)?;
        println!("wrote Hello with len {}", bytes_written);
        if bytes_written != egress_frame_bytes.len() {
            return Err(HandshakeError::IOError("bad bytes_written".into()));
        }

        // Receive hello from recipient
        let ingress_frame_bytes = peer.read_bytes()?;

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
        let ingress_frame_bytes = peer.read_bytes()?;
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
        let bytes_written = peer.write_bytes(&egress_frame_bytes)?;
        println!("wrote Disconnect with len {}", bytes_written);
        if bytes_written != egress_frame_bytes.len() {
            return Err(HandshakeError::IOError("bad bytes_written".into()));
        }

        // Verify that the peer has disconnected.
        let recipient_disconnect_bytes = peer.read_bytes()?;
        if recipient_disconnect_bytes.len() != 0 {
            return Err(HandshakeError::RecipientDidNotDisconnect);
        }

        // TODO don't return secrets
        Ok(secrets)
    }
}
