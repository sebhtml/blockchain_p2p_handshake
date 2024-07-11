use secp256k1::{ecdh::shared_secret_point, PublicKey, SecretKey};
use sha3::{Digest, Keccak256};

use super::nonce::make_nonce;

#[derive(Debug)]
pub struct EphemeralSecrets {
    #[allow(unused)]
    static_shared_secret: [u8; 32],
    pub ephemeral_key: [u8; 32],
}

impl EphemeralSecrets {
    pub fn new(
        static_sk: &SecretKey,
        remote_static_pk: &PublicKey,
        ephemeral_sk: &SecretKey,
        remote_ephemeral_pk: &PublicKey,
    ) -> Self {
        let static_shared_secret = shared_secret_point(remote_static_pk, static_sk)[0..32].to_vec();
        let ephemeral_key = shared_secret_point(remote_ephemeral_pk, ephemeral_sk)[0..32].to_vec();

        Self {
            static_shared_secret: static_shared_secret.try_into().unwrap(),
            ephemeral_key: ephemeral_key.try_into().unwrap(),
        }
    }
}

pub struct FrameSecrets {
    pub nonce: [u8; 32],
    pub aes_secret: [u8; 32],
    pub mac_secret: [u8; 32],
    pub iv: [u8; 32],
}

impl FrameSecrets {
    pub fn make_nonce_secrets(initiator_once: &[u8; 32], ephemeral_key: &[u8; 32]) -> FrameSecrets {
        let nonce = make_nonce();
        //Hash the nonces
        let mut hasher = Keccak256::new();
        hasher.update(nonce);
        hasher.update(initiator_once);
        let nonces_hash = hasher.finalize();

        // Shared secret
        let mut hasher = Keccak256::new();
        hasher.update(ephemeral_key);
        hasher.update(&nonces_hash);
        let shared_secret = hasher.finalize();

        // AES secret
        let mut hasher = Keccak256::new();
        hasher.update(ephemeral_key);
        hasher.update(&shared_secret);
        let aes_secret = hasher.finalize();

        // MAC secret
        let mut hasher = Keccak256::new();
        hasher.update(ephemeral_key);
        hasher.update(&aes_secret);
        let mac_secret = hasher.finalize();

        let iv: [u8; 32] = (0..32)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let frame_secrets = FrameSecrets {
            nonce,
            aes_secret: aes_secret.to_vec().try_into().unwrap(),
            mac_secret: mac_secret.to_vec().try_into().unwrap(),
            iv,
        };

        frame_secrets
    }
}
