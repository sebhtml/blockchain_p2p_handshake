use aes::cipher::KeyIvInit;
use aes::cipher::StreamCipher;
use aes::Aes128;
use ctr::Ctr128BE;
use hmac::Hmac;
use hmac::Mac;
use secp256k1::ecdh::shared_secret_point;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Digest;
use sha2::Sha256;

use crate::handshake_error::HandshakeError;

/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
/// Elliptic Curve Integrated Encryption Scheme
pub fn ecies_encrypt(
    pub_key: &PublicKey,
    message: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let mut rng = secp256k1::rand::thread_rng();
    let ephemeral_sk = SecretKey::new(&mut rng);
    let context = Secp256k1::new();
    let ephemeral_pk = PublicKey::from_secret_key(&context, &ephemeral_sk).serialize_uncompressed();
    let shared_secret = shared_secret_point(&pub_key, &ephemeral_sk)[0..32].to_vec();

    // KDF(k, len): the NIST SP 800-56 Concatenation Key Derivation Function
    let mut shared_secret_derived_key = [0_u8; 32];
    concat_kdf::derive_key_into::<Sha256>(&shared_secret, &[], &mut shared_secret_derived_key)
        .unwrap();
    let enc_key: [u8; 16] = shared_secret_derived_key[0..16].try_into().unwrap();

    // AES(k, iv, m): the AES-128 encryption function in CTR mode.
    let aes_key_len_bits = 128;
    let aes_key_len = aes_key_len_bits / u8::BITS;
    let initialization_vector: [u8; 16] = (0..aes_key_len)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let mut cipher = Ctr128BE::<Aes128>::new(&enc_key.into(), &initialization_vector.into());
    let mut encrypted_message = message.to_vec();
    cipher.apply_keystream(&mut encrypted_message);

    // MAC(k, m): HMAC using the SHA-256 hash function.
    let mac_key = Sha256::digest(&shared_secret_derived_key[16..32]).to_vec();
    let mut hmac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
    hmac.update(&initialization_vector);
    hmac.update(&encrypted_message);
    hmac.update(auth_data);
    let hmac_tag = hmac.finalize().into_bytes().to_vec();

    Ok(vec![
        ephemeral_pk.to_vec(),
        initialization_vector.to_vec(),
        encrypted_message,
        hmac_tag,
    ]
    .concat())
}
