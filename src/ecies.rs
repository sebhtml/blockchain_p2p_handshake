use aes::cipher::KeyIvInit;
use aes::cipher::StreamCipher;
use aes::Aes128;
use ctr::Ctr128BE;
use hmac::Hmac;
use hmac::Mac;
use secp256k1::ecdh::shared_secret_point;
use secp256k1::{PublicKey, SecretKey};
use sha2::Digest;
use sha2::Sha256;

use crate::handshake_error::HandshakeError;

pub const ECIES_EPHEMERAL_PK_LEN: usize = 65;
pub const ECIES_AES_KEY_LEN: usize = 128 / u8::BITS as usize;
pub const ECIES_IV_LEN: usize = ECIES_AES_KEY_LEN;
pub const ECIES_TAG_LEN: usize = 32;

/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
/// Elliptic Curve Integrated Encryption Scheme
pub fn ecies_encrypt(
    initiator_ephemeral_sk: &SecretKey,
    initiator_ephemeral_pk: &PublicKey,
    recipient_static_pk: &PublicKey,
    message: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let shared_secret =
        shared_secret_point(&recipient_static_pk, &initiator_ephemeral_sk)[0..32].to_vec();

    // KDF(k, len): the NIST SP 800-56 Concatenation Key Derivation Function
    let mut shared_secret_derived_key = [0_u8; 32];
    concat_kdf::derive_key_into::<Sha256>(&shared_secret, &[], &mut shared_secret_derived_key)
        .unwrap();
    let enc_key: [u8; ECIES_AES_KEY_LEN] = shared_secret_derived_key[0..16].try_into().unwrap();

    // AES(k, iv, m): the AES-128 encryption function in CTR mode.
    let iv: [u8; ECIES_IV_LEN] = (0..ECIES_AES_KEY_LEN)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let mut cipher = Ctr128BE::<Aes128>::new(&enc_key.into(), &iv.into());
    let mut encrypted_message = message.to_vec();
    cipher.apply_keystream(&mut encrypted_message);

    // MAC(k, m): HMAC using the SHA-256 hash function.
    let mac_key = Sha256::digest(&shared_secret_derived_key[16..32]).to_vec();
    let mut hmac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
    hmac.update(&iv);
    hmac.update(&encrypted_message);
    hmac.update(auth_data);
    let tag = hmac.finalize().into_bytes().to_vec();

    Ok(vec![
        initiator_ephemeral_pk.serialize_uncompressed().to_vec(),
        iv.to_vec(),
        encrypted_message,
        tag,
    ]
    .concat())
}

pub fn ecies_decrypt(
    ecies_encrypted_message: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let mut offset = 0;

    let recipient_ephemeral_pk = &ecies_encrypted_message[offset..ECIES_EPHEMERAL_PK_LEN];
    offset += recipient_ephemeral_pk.len();

    let iv = &ecies_encrypted_message[offset..(offset + ECIES_IV_LEN)];
    offset += iv.len();

    let encrypted_message =
        &ecies_encrypted_message[offset..ecies_encrypted_message.len() - ECIES_TAG_LEN];
    offset += encrypted_message.len();

    let tag = &ecies_encrypted_message[offset..offset + ECIES_TAG_LEN];

    // TODO

    println!(
        "TODO must decrypt encrypted_message of length {}",
        encrypted_message.len()
    );

    println!("recipient_ephemeral_pk {}", recipient_ephemeral_pk.len());

    println!("iv {}", iv.len());

    println!("encrypted_message {}", encrypted_message.len());

    println!("tag {}", tag.len());

    Ok(vec![])
}
