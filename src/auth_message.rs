use crate::handshake_error::HandshakeError;
use rlp::{RlpDecodable, RlpEncodable};
use secp256k1::{ecdh::SharedSecret, Message, PublicKey, Secp256k1, SecretKey};

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct AuthMessage {
    pub signature: Vec<u8>,
    pub initiator_pub_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub version: u32,
}

impl AuthMessage {
    pub fn try_new(
        initiator_sk: &SecretKey,
        initiator_pk: &PublicKey,
        recipient_pk: &PublicKey,
    ) -> Result<AuthMessage, HandshakeError> {
        let initiator_pub_key = &initiator_pk.serialize();
        let initiator_pub_key_vec = initiator_pub_key.to_vec();

        let auth_vsn = 4;

        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let shared_secret = SharedSecret::new(&recipient_pk, &initiator_sk)
            .secret_bytes()
            .to_vec();
        let msg: Vec<u8> = shared_secret
            .iter()
            .zip(nonce.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        let msg: [u8; 32] = msg.try_into().unwrap();
        let msg = Message::from_digest(msg);

        let context = Secp256k1::new();
        let signature = context
            .sign_ecdsa(&msg, &initiator_sk)
            .serialize_compact()
            .to_vec();
        let auth = AuthMessage {
            signature,
            initiator_pub_key: initiator_pub_key_vec,
            nonce,
            version: auth_vsn,
        };
        Ok(auth)
    }
}
