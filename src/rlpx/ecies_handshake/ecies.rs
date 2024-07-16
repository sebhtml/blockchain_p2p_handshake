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

use crate::rlpx::handshake_error::HandshakeError;

struct EciesKeys {
    k_e: [u8; 16],
    k_m: [u8; 32],
}

pub fn ecdh_agree(sk: &SecretKey, pk: &PublicKey) -> Result<[u8; 32], HandshakeError> {
    shared_secret_point(pk, sk)[..32]
        .to_vec()
        .try_into()
        .map_err(|_| HandshakeError::CryptoKeyError)
}

fn ecies_generate_key_material(
    pk: &PublicKey,
    sk: &SecretKey,
) -> Result<EciesKeys, HandshakeError> {
    let shared_secret = ecdh_agree(sk, pk)?;

    let shared_secret_derived_key = kdf(&shared_secret)?;
    let k_e: [u8; 16] = shared_secret_derived_key[0..16]
        .try_into()
        .map_err(|_| HandshakeError::CryptoKeyError)?;
    let k_m: [u8; 16] = shared_secret_derived_key[16..32]
        .try_into()
        .map_err(|_| HandshakeError::CryptoKeyError)?;
    let mac_key: [u8; 32] = Sha256::digest(k_m)
        .to_vec()
        .try_into()
        .map_err(|_| HandshakeError::CryptoKeyError)?;

    let keys = EciesKeys { k_e, k_m: mac_key };
    Ok(keys)
}

/// KDF(k, len): the NIST SP 800-56 Concatenation Key Derivation Function
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
fn kdf(shared_secret: &[u8; 32]) -> Result<[u8; 32], HandshakeError> {
    let mut shared_secret_derived_key = [0_u8; 32];
    concat_kdf::derive_key_into::<Sha256>(shared_secret, &[], &mut shared_secret_derived_key)
        .map_err(|_| HandshakeError::CryptoKeyError)?;
    Ok(shared_secret_derived_key)
}

/// MAC(k, m): HMAC using the SHA-256 hash function.
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
fn generate_hmac_tag(
    mac_key: &[u8],
    iv: &[u8],
    encrypted_message: &[u8],
    auth_data: &[u8],
) -> Result<[u8; 32], HandshakeError> {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(mac_key).map_err(|_| HandshakeError::MacGenerationError)?;
    hmac.update(iv);
    hmac.update(encrypted_message);
    hmac.update(auth_data);
    let tag = hmac.finalize().into_bytes().to_vec();
    tag
        .try_into()
        .map_err(|_| HandshakeError::MacGenerationError)
}

/// AES(k, iv, m): the AES-128 encryption function in CTR mode.
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
fn aes_128_ctr_128(key: &[u8], iv: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut cipher = Ctr128BE::<Aes128>::new(key.into(), iv.into());
    let mut applied_message = msg.to_owned();
    cipher.apply_keystream(&mut applied_message);
    applied_message
}

/// Elliptic Curve Integrated Encryption Scheme
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
pub fn ecies_encrypt(
    initiator_static_pubk: &PublicKey,
    initiator_ephemeral_seck: &SecretKey,
    recipient_static_pubk: &PublicKey,
    message: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let keys = ecies_generate_key_material(recipient_static_pubk, initiator_ephemeral_seck)?;

    let iv: [u8; 16] = (0..16)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| HandshakeError::EncryptError)?;

    let encrypted_message = aes_128_ctr_128(&keys.k_e, &iv, message);

    let tag = generate_hmac_tag(&keys.k_m, &iv, &encrypted_message, auth_data)?;

    Ok([initiator_static_pubk.serialize_uncompressed().to_vec(),
        iv.to_vec(),
        encrypted_message,
        tag.to_vec()]
    .concat())
}

pub fn ecies_decrypt(
    initiator_static_seck: &SecretKey,
    enc_ack_body: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let (recipient_ephemeral_pubk, rest) = enc_ack_body.split_at(65);
    let (iv, rest) = rest.split_at(16);
    let (encrypted_message, msg_hmac_tag) = rest.split_at(rest.len() - 32);

    let recipient_ephemeral_pubk = PublicKey::from_slice(recipient_ephemeral_pubk)
        .map_err(|_| HandshakeError::CryptoKeyError)?;
    let keys = ecies_generate_key_material(&recipient_ephemeral_pubk, initiator_static_seck)?;
    let aes_key = &keys.k_e;
    let mac_key = &keys.k_m;

    let tag = generate_hmac_tag(mac_key, iv, encrypted_message, auth_data)?;

    if &tag != msg_hmac_tag {
        return Err(HandshakeError::MacValidationFailure);
    }

    let ack_body_and_padding = aes_128_ctr_128(aes_key, iv, encrypted_message);

    Ok(ack_body_and_padding)
}
