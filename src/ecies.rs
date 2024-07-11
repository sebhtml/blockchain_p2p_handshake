use aes::cipher::KeyIvInit;
use aes::cipher::StreamCipher;
use aes::Aes128;
use ctr::Ctr128BE;
use hmac::Hmac;
use hmac::Mac;
use secp256k1::ecdh::shared_secret_point;
use secp256k1::Secp256k1;
use secp256k1::{PublicKey, SecretKey};
use sha2::Digest;
use sha2::Sha256;

use crate::handshake_error::HandshakeError;

pub const ECIES_EPHEMERAL_PK_LEN: usize = 65;
pub const ECIES_AES_KEY_LEN: usize = 16;
pub const ECIES_MAC_LEN: usize = 16;
pub const ECIES_IV_LEN: usize = 16;
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

/// MAC(k, m): HMAC using the SHA-256 hash function.
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
fn generate_hmac_tag(
    mac_key: &[u8],
    iv: &[u8],
    encrypted_message: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(mac_key).map_err(|_| HandshakeError::HmacGenerationError)?;
    hmac.update(&iv);
    hmac.update(&encrypted_message);
    hmac.update(auth_data);
    let tag = hmac.finalize().into_bytes().to_vec();
    Ok(tag)
}

/// Elliptic Curve Integrated Encryption Scheme
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
pub fn ecies_encrypt(
    recipient_pubk: &PublicKey,
    message: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let context = Secp256k1::new();
    let mut rng = secp256k1::rand::thread_rng();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from_secret_key(&context, &sk);
    let keys = ecies_generate_key_material(recipient_pubk, &sk)?;
    let iv: [u8; ECIES_IV_LEN] = (0..ECIES_AES_KEY_LEN)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    // AES(k, iv, m): the AES-128 encryption function in CTR mode.
    let mut cipher = Ctr128BE::<Aes128>::new(&keys.enc_key.into(), &iv.into());
    let mut encrypted_message = message.to_vec();
    cipher.apply_keystream(&mut encrypted_message);

    let tag = generate_hmac_tag(&keys.mac_key, &iv, &encrypted_message, auth_data)?;

    Ok(vec![
        pk.serialize_uncompressed().to_vec(),
        iv.to_vec(),
        encrypted_message,
        tag,
    ]
    .concat())
}

pub fn ecies_decrypt(
    sk: &SecretKey,
    ecies_encrypted_message: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let (recipient_ephemeral_pk, rest) = ecies_encrypted_message.split_at(ECIES_EPHEMERAL_PK_LEN);
    let (iv, rest) = rest.split_at(ECIES_IV_LEN);
    let (encrypted_message, hmac_tag) = rest.split_at(rest.len() - ECIES_TAG_LEN);

    let recipient_ephemeral_pk = PublicKey::from_slice(recipient_ephemeral_pk).unwrap();
    let keys = ecies_generate_key_material(&recipient_ephemeral_pk, sk)?;

    let tag = generate_hmac_tag(&keys.mac_key, &iv, &encrypted_message, auth_data)?;

    if &tag != hmac_tag {
        return Err(HandshakeError::HmacValidationFailure);
    }

    // TODO group the AES cipher creation and use in a fn.
    let mut cipher = Ctr128BE::<Aes128>::new(&keys.enc_key.into(), iv.into());
    let mut decrypted_message = encrypted_message.to_vec();
    cipher.apply_keystream(&mut decrypted_message);

    println!("Successfully decrypted {} bytes", decrypted_message.len());

    Ok(decrypted_message)
}
