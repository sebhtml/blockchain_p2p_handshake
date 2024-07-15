use alloy_rlp::{RlpDecodable, RlpEncodable};

/// ack-body = [recipient-ephemeral-pubk, recipient-nonce, ack-vsn, ...]
/// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
#[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct AckMessage {
    pub recipient_ephemeral_pubk: [u8; 64],
    pub recipient_nonce: [u8; 32],
    pub ack_vsn: u32,
}

#[cfg(test)]
mod tests {
    use alloy_rlp::{Decodable, Encodable};

    use super::*;

    #[test]
    fn test_encode_decode_auth() {
        let encodable = AckMessage {
            recipient_ephemeral_pubk: [3; 64],
            recipient_nonce: [2; 32],
            ack_vsn: 7,
        };
        let mut rlp_bytes = vec![];
        encodable.encode(&mut rlp_bytes);
        let mut rlp_bytes = rlp_bytes.as_slice();
        let decoded_msg_data = AckMessage::decode(&mut rlp_bytes).unwrap();
        assert_eq!(decoded_msg_data, encodable);
    }
}
