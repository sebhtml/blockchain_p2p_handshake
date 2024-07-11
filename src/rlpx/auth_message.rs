use super::handshake_error::HandshakeError;
use rlp::RlpStream;
use secp256k1::{ecdh::SharedSecret, Message, PublicKey, Secp256k1, SecretKey};

pub const NONCE_LENGTH: usize = 32;

/// auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
#[derive(Debug)]
pub struct AuthMessage {
    pub sig: Vec<u8>,
    pub initiator_pubk: Vec<u8>,
    pub initiator_nonce: Vec<u8>,
    pub auth_vsn: u32,
}

impl AuthMessage {
    pub fn try_new(
        initiator_sk: &SecretKey,
        initiator_pk: &PublicKey,
        recipient_pk: &PublicKey,
    ) -> Result<AuthMessage, HandshakeError> {
        let auth_vsn = 4;

        // TODO don't use unwrap.
        let nonce: [u8; NONCE_LENGTH] = (0..NONCE_LENGTH)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let shared_secret = SharedSecret::new(&recipient_pk, &initiator_sk)
            .secret_bytes()
            .to_vec();

        let msg: [u8; 32] = shared_secret.try_into().unwrap();
        let msg = Message::from_digest(msg);

        let context = Secp256k1::new();
        let recoverable_signature =
            context.sign_ecdsa_recoverable_with_noncedata(&msg, &initiator_sk, &nonce);
        let (recovery_id, signature_bytes) = recoverable_signature.serialize_compact();
        let recovery_id = u8::try_from(recovery_id.to_i32()).unwrap();
        let signature = vec![signature_bytes.to_vec(), vec![recovery_id]].concat();

        let auth = AuthMessage {
            sig: signature,
            initiator_pubk: initiator_pk.serialize_uncompressed()[1..].to_vec(),
            initiator_nonce: nonce.to_vec(),
            auth_vsn,
        };

        Ok(auth)
    }

    pub fn into_rlp_list(&self) -> Vec<u8> {
        let mut auth_body = RlpStream::new_list(4);
        auth_body.append(&self.sig);
        auth_body.append(&self.initiator_pubk);
        auth_body.append(&self.initiator_nonce);
        auth_body.append(&self.auth_vsn);
        let auth_body = auth_body.out();
        auth_body.to_vec()
    }
}
