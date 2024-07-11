use rlp::Rlp;

use super::{auth_message::NONCE_LENGTH, ecies::ECIES_PUBK_LEN, handshake_error::HandshakeError};

/// ack-body = [recipient-ephemeral-pubk, recipient-nonce, ack-vsn, ...]
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
#[derive(Debug)]
pub struct AckMessage {
    pub recipient_ephemeral_pubk: [u8; ECIES_PUBK_LEN],
    pub recipient_nonce: [u8; NONCE_LENGTH],
    pub ack_vsn: u32,
}

impl AckMessage {
    pub fn from_rlp_list(rlp: &[u8]) -> Result<AckMessage, HandshakeError> {
        let reader = Rlp::new(rlp);
        let mut it = reader.into_iter();
        let recipient_ephemeral_pubk: Vec<u8> = it
            .next()
            .ok_or(HandshakeError::RlpDecodeError)?
            .as_val()
            .map_err(|_| HandshakeError::RlpDecodeError)?;
        let recipient_ephemeral_pubk = if recipient_ephemeral_pubk.len() == 64 {
            vec![vec![4], recipient_ephemeral_pubk].concat()
        } else if recipient_ephemeral_pubk.len() == 65 {
            recipient_ephemeral_pubk
        } else {
            return Err(HandshakeError::RlpDecodeError);
        };

        let recipient_nonce: Vec<u8> = it
            .next()
            .ok_or(HandshakeError::RlpDecodeError)?
            .as_val()
            .map_err(|_| HandshakeError::RlpDecodeError)?;
        let ack_vsn: u32 = it
            .next()
            .ok_or(HandshakeError::RlpDecodeError)?
            .as_val()
            .map_err(|_| HandshakeError::RlpDecodeError)?;

        let ack = AckMessage {
            recipient_ephemeral_pubk: recipient_ephemeral_pubk
                .try_into()
                .map_err(|_| HandshakeError::RlpDecodeError)?,
            recipient_nonce: recipient_nonce
                .try_into()
                .map_err(|_| HandshakeError::RlpDecodeError)?,
            ack_vsn,
        };
        Ok(ack)
    }
}
