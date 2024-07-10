use crate::handshake_error::HandshakeError;
use keccak_hash::keccak_256;
use rlp::{RlpDecodable, RlpEncodable};
use secp256k1::PublicKey;

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct AuthMessage {
    pub signature: Vec<u8>,
    pub initiator_pub_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub version: u32,
}

impl AuthMessage {
    pub fn try_new(initiator_pub_key: &PublicKey) -> Result<AuthMessage, HandshakeError> {
        let initiator_pub_key = &initiator_pub_key.serialize();
        let initiator_pub_key_vec = initiator_pub_key.to_vec();

        let auth_vsn = 4;

        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        // TODO the sig must be a signature of XOR(nonce, shared-secret),
        // not a signature of the  initiator pub key.
        let mut signature = vec![0 as u8; 256 / 8];
        keccak_256(initiator_pub_key, signature.as_mut());

        let auth = AuthMessage {
            signature,
            initiator_pub_key: initiator_pub_key_vec,
            nonce,
            version: auth_vsn,
        };
        Ok(auth)
    }
}
