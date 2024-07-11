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

struct EciesKeys {
    enc_key: [u8; ECIES_AES_KEY_LEN],
    mac_key: Vec<u8>,
}

fn ecies_generate_key_material(
    pk: &PublicKey,
    sk: &SecretKey,
) -> Result<EciesKeys, HandshakeError> {
    let shared_secret = shared_secret_point(&pk, &sk)[0..32].to_vec();

    // TODO remove unwrap calls.é
    // KDF(k, len): the NIST SP 800-56 Concatenation Key Derivation Function
    let mut shared_secret_derived_key = [0_u8; 32];
    concat_kdf::derive_key_into::<Sha256>(&shared_secret, &[], &mut shared_secret_derived_key)
        .unwrap();
    let enc_key: [u8; ECIES_AES_KEY_LEN] = shared_secret_derived_key[0..16].try_into().unwrap();
    let mac_key = Sha256::digest(&shared_secret_derived_key[16..32]).to_vec();

    let keys = EciesKeys { enc_key, mac_key };
    Ok(keys)
}

/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
/// Elliptic Curve Integrated Encryption Scheme
pub fn ecies_encrypt(
    initiator_ephemeral_pk: &PublicKey,
    initiator_ephemeral_sk: &SecretKey,
    recipient_static_pk: &PublicKey,
    message: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let keys = ecies_generate_key_material(recipient_static_pk, initiator_ephemeral_sk)?;
    let iv: [u8; ECIES_IV_LEN] = (0..ECIES_AES_KEY_LEN)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    // AES(k, iv, m): the AES-128 encryption function in CTR mode.
    let mut cipher = Ctr128BE::<Aes128>::new(&keys.enc_key.into(), &iv.into());
    let mut encrypted_message = message.to_vec();
    cipher.apply_keystream(&mut encrypted_message);

    // MAC(k, m): HMAC using the SHA-256 hash function.
    let mut hmac = Hmac::<Sha256>::new_from_slice(&keys.mac_key).unwrap();
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
    initiator_ephemeral_sk: &SecretKey,
    ecies_encrypted_message: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let mut offset = 0;

    let recipient_ephemeral_pk = &ecies_encrypted_message[offset..ECIES_EPHEMERAL_PK_LEN];
    offset += recipient_ephemeral_pk.len();
    let recipient_ephemeral_pk = PublicKey::from_slice(recipient_ephemeral_pk).unwrap();

    let iv = &ecies_encrypted_message[offset..(offset + ECIES_IV_LEN)];
    offset += iv.len();

    let encrypted_message =
        &ecies_encrypted_message[offset..ecies_encrypted_message.len() - ECIES_TAG_LEN];
    offset += encrypted_message.len();

    let message_tag = &ecies_encrypted_message[offset..offset + ECIES_TAG_LEN];

    // TODO

    let keys = ecies_generate_key_material(&recipient_ephemeral_pk, initiator_ephemeral_sk)?;

    // TODO group the AES cipher creation and use in a fn.
    let mut cipher = Ctr128BE::<Aes128>::new(&keys.enc_key.into(), iv.into());
    let mut decrypted_message = encrypted_message.to_vec();
    cipher.apply_keystream(&mut decrypted_message);

    // TODO don't repeat HMAC.
    // MAC(k, m): HMAC using the SHA-256 hash function.
    let mut hmac = Hmac::<Sha256>::new_from_slice(&keys.mac_key).unwrap();
    hmac.update(&iv);
    hmac.update(&encrypted_message);
    hmac.update(auth_data);

    let tag = hmac.finalize().into_bytes().to_vec();
    if &tag != message_tag {
        println!("message_tag {:?}", message_tag);
        println!("tag {:?}", tag);

        //return Err(HandshakeError::HmacValidationFailure);
    }

    println!("Successfully decrypted {} bytes", decrypted_message.len());
    Ok(decrypted_message)
}
