use secp256k1::PublicKey;

use crate::handshake_error::HandshakeError;

pub fn ecies_encrypt(
    _recipient_pub_key: &PublicKey,
    _message: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    // TODO
    Ok(vec![])
}
