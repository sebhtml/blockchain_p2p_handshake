use secp256k1::PublicKey;

use crate::handshake_error::HandshakeError;

pub fn ecies_encrypt(
    recipient_pub_key: &PublicKey,
    message: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    // TODO
    Ok(vec![])
}
