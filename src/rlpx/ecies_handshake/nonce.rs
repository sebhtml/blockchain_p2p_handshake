use crate::rlpx::handshake_error::HandshakeError;

pub const NONCE_LENGTH: usize = 32;

pub fn make_nonce() -> Result<[u8; NONCE_LENGTH], HandshakeError> {
    let nonce: [u8; NONCE_LENGTH] = (0..NONCE_LENGTH)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| HandshakeError::EncryptError)?;
    Ok(nonce)
}
