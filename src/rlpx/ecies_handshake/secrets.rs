use secp256k1::{PublicKey, SecretKey};
use sha3::{Digest, Keccak256};

use crate::rlpx::handshake_error::HandshakeError;

use super::ecies::ecdh_agree;

#[derive(Debug)]
pub struct Secrets {
    #[allow(unused)]
    static_shared_secret: [u8; 32],
    #[allow(unused)]
    ephemeral_key: [u8; 32],
    pub aes_secret: [u8; 32],
    pub mac_secret: [u8; 32],
}

impl Secrets {
    pub fn new(
        static_seck: &SecretKey,
        remote_static_pk: &PublicKey,
        ephemeral_seck: &SecretKey,
        remote_ephemeral_pk: &PublicKey,
        nonce: &[u8; 32],
        initiator_nonce: &[u8; 32],
    ) -> Result<Self, HandshakeError> {
        let static_shared_secret = ecdh_agree(static_seck, remote_static_pk)?;
        let ephemeral_key = ecdh_agree(ephemeral_seck, remote_ephemeral_pk)?;

        //Hash the nonces
        let nonces_hash = {
            let mut hasher = Keccak256::new();
            hasher.update(nonce);
            hasher.update(initiator_nonce);
            hasher.finalize().to_vec()
        };

        // Shared secret
        let shared_secret = {
            let mut hasher = Keccak256::new();
            hasher.update(&ephemeral_key);
            hasher.update(&nonces_hash);
            hasher.finalize().to_vec()
        };

        // AES secret
        let aes_secret = {
            let mut hasher = Keccak256::new();
            hasher.update(&ephemeral_key);
            hasher.update(&shared_secret);
            hasher.finalize().to_vec()
        };

        // MAC secret
        let mac_secret = {
            let mut hasher = Keccak256::new();
            hasher.update(&ephemeral_key);
            hasher.update(&aes_secret);
            hasher.finalize().to_vec()
        };

        let secrets = Self {
            static_shared_secret: static_shared_secret
                .try_into()
                .map_err(|_| HandshakeError::CryptoKeyError)?,
            ephemeral_key: ephemeral_key
                .try_into()
                .map_err(|_| HandshakeError::CryptoKeyError)?,
            aes_secret: aes_secret
                .to_vec()
                .try_into()
                .map_err(|_| HandshakeError::CryptoKeyError)?,
            mac_secret: mac_secret
                .to_vec()
                .try_into()
                .map_err(|_| HandshakeError::CryptoKeyError)?,
        };

        Ok(secrets)
    }
}
