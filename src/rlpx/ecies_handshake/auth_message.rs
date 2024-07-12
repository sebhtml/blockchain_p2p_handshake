use rand::Rng;
use rlp::RlpStream;
use secp256k1::{ecdh::SharedSecret, Message, PublicKey, Secp256k1, SecretKey};

use crate::rlpx::{handshake_error::HandshakeError, IntoRlpList};

use super::ecies::{ecies_encrypt, ECIES_IV_LEN, ECIES_PUBK_LEN, ECIES_TAG_LEN};

pub const NONCE_LENGTH: usize = 32;

/// auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
#[derive(Debug)]
pub struct AuthMessage {
    pub sig: Vec<u8>,
    pub initiator_pubk: Vec<u8>,
    // TODO use [u8; 32] for nonce
    pub initiator_nonce: Vec<u8>,
    pub auth_vsn: u32,
}

impl AuthMessage {
    pub fn try_new(
        initiator_nonce: &[u8; 32],
        initiator_sk: &SecretKey,
        initiator_pk: &PublicKey,
        recipient_pk: &PublicKey,
    ) -> Result<AuthMessage, HandshakeError> {
        let auth_vsn = 4;

        let shared_secret = SharedSecret::new(&recipient_pk, &initiator_sk)
            .secret_bytes()
            .to_vec();

        let msg: [u8; 32] = shared_secret.try_into().unwrap();
        let msg = Message::from_digest(msg);

        let context = Secp256k1::new();
        let recoverable_signature =
            context.sign_ecdsa_recoverable_with_noncedata(&msg, &initiator_sk, initiator_nonce);
        let (recovery_id, signature_bytes) = recoverable_signature.serialize_compact();
        let recovery_id = u8::try_from(recovery_id.to_i32()).unwrap();
        let signature = vec![signature_bytes.to_vec(), vec![recovery_id]].concat();

        let auth = AuthMessage {
            sig: signature,
            initiator_pubk: initiator_pk.serialize_uncompressed()[1..].to_vec(),
            initiator_nonce: initiator_nonce.to_vec(),
            auth_vsn,
        };

        Ok(auth)
    }
}

impl IntoRlpList for AuthMessage {
    fn into_rlp_list(&self) -> Vec<u8> {
        let mut auth_body = RlpStream::new_list(4);
        auth_body.append(&self.sig);
        auth_body.append(&self.initiator_pubk);
        auth_body.append(&self.initiator_nonce);
        auth_body.append(&self.auth_vsn);
        let auth_body = auth_body.out();
        auth_body.to_vec()
    }
}

pub fn prepare_auth_packet(
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
