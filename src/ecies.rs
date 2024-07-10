use aes::cipher::KeyIvInit;
use aes::cipher::StreamCipher;
use aes::Aes128;
use ctr::Ctr128BE;
use hmac::Hmac;
use hmac::Mac;
use secp256k1::{ecdh::SharedSecret, PublicKey, Secp256k1, SecretKey};
use sha2::Digest;
use sha2::Sha256;

use crate::handshake_error::HandshakeError;

/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
pub fn ecies_encrypt(recipient_pk: &PublicKey, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let mut rng = secp256k1::rand::thread_rng();
    let ephemeral_secret_key = SecretKey::new(&mut rng);
    let context = Secp256k1::new();
    let ephemeral_public_key =
        PublicKey::from_secret_key(&context, &ephemeral_secret_key).serialize_uncompressed();
    let shared_secret = SharedSecret::new(&recipient_pk, &ephemeral_secret_key)
        .secret_bytes()
        .to_vec();

    // KDF(k, len): the NIST SP 800-56 Concatenation Key Derivation Function
    let mut shared_secret_derived_key = [0_u8; 32];
    concat_kdf::derive_key_into::<Sha256>(&shared_secret, &[], &mut shared_secret_derived_key)
        .unwrap();
    let enc_key: [u8; 16] = shared_secret_derived_key[0..16].try_into().unwrap();

    // AES(k, iv, m): the AES-128 encryption function in CTR mode.
    let aes_key_len_bits = 128;
    let aes_key_len = aes_key_len_bits / u8::BITS;
    let iv: [u8; 16] = (0..aes_key_len)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let mut cipher = Ctr128BE::<Aes128>::new(&enc_key.into(), &iv.into());
    let mut encrypted = message.to_vec();
    cipher.apply_keystream(&mut encrypted);

    // MAC(k, m): HMAC using the SHA-256 hash function.
    let mac_key = Sha256::digest(&shared_secret_derived_key[16..32]);
    let total_size: usize = ephemeral_public_key.len() // epehemeral public key
     + iv.len() // initialization vector
     + encrypted.len() // encrypted message
     + mac_key.len(); // HMAC tag - note that MAC key and HMAC tag have the same length.
    let total_size = u16::try_from(total_size).unwrap();
    let mut hmac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
    hmac.update(&iv);
    hmac.update(&encrypted);
    hmac.update(&total_size.to_be_bytes());
    let hmac_tag = hmac.finalize().into_bytes().to_vec();
    println!("ephemeral_public_key: {}", ephemeral_public_key.len());
    println!("iv: {}", iv.len());
    println!("encrypted: {}", encrypted.len());
    println!("hmac_tag: {}", hmac_tag.len());
    Ok(vec![
        ephemeral_public_key.to_vec(),
        iv.to_vec(),
        encrypted,
        hmac_tag,
    ]
    .concat())
}
