use rand::Rng;
use rlp::RlpStream;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

use crate::rlpx::{handshake_error::HandshakeError, IntoRlpList};

use super::{
    ecies::{ecdh_agree, ecies_encrypt},
    xor,
};

pub const NONCE_LENGTH: usize = 32;

/// auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
#[derive(Debug)]
pub struct AuthMessage {
    pub sig: [u8; 65],
    // TODO use 65 for pubk
    pub initiator_pubk: [u8; 64],
    pub initiator_nonce: [u8; 32],
    pub auth_vsn: u32,
}

impl AuthMessage {
    pub fn try_new(
        initiator_nonce: &[u8; 32],
        initiator_static_sk: &SecretKey,
        initiator_static_pk: &PublicKey,
        initiator_ephemeral_sk: &SecretKey,
        _initiator_ephemeral_pk: &PublicKey,
        recipient_static_pk: &PublicKey,
    ) -> Result<AuthMessage, HandshakeError> {
        let shared_secret = ecdh_agree(initiator_static_sk, recipient_static_pk);
        let xored: [u8; 32] = xor(&shared_secret, initiator_nonce).try_into().unwrap();
        let msg = Message::from_digest(xored);

        let context = Secp256k1::new();
        let recoverable_signature = context.sign_ecdsa_recoverable(&msg, &initiator_ephemeral_sk);
        let (recovery_id, signature_bytes) = recoverable_signature.serialize_compact();
        let recovery_id = u8::try_from(recovery_id.to_i32()).unwrap();
        let signature = vec![signature_bytes.to_vec(), vec![recovery_id]].concat();

        let auth_vsn = 4;

        let auth = AuthMessage {
            sig: signature.try_into().unwrap(),
            initiator_pubk: initiator_static_pk.serialize_uncompressed()[1..]
                .try_into()
                .unwrap(),
            initiator_nonce: initiator_nonce.to_owned(),
            auth_vsn,
        };

        Ok(auth)
    }
}

impl IntoRlpList for AuthMessage {
    fn into_rlp_list(&self) -> Vec<u8> {
        let mut auth_body = RlpStream::new_list(4);
        auth_body.append(&self.sig.as_slice());
        auth_body.append(&self.initiator_pubk.to_vec());
        auth_body.append(&self.initiator_nonce.as_slice());
        auth_body.append(&self.auth_vsn);
        let auth_body = auth_body.out();
        auth_body.to_vec()
    }
}

pub fn prepare_auth_packet(
    initiator_ephemeral_sk: &SecretKey,
    initiator_static_pk: &PublicKey,
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
    let auth_size: usize = 65 /* pk */ + 16 /* iv */ + auth_body.len() + 32 /* tag */;
    let auth_size = u16::try_from(auth_size).unwrap();
    let auth_size = auth_size.to_be_bytes();
    let enc_auth_body = &ecies_encrypt(
        initiator_static_pk,
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
