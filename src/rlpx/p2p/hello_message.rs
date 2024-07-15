use crate::rlpx::handshake_error::HandshakeError;
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};

use super::frame::Frame;

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct Capability {
    pub name: String,
    pub version: u32,
}

pub const HELLO_MSG_ID: u64 = 0x00;

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct HelloMessageData {
    pub protocol_version: u64,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u64,
    pub node_id: [u8; 64],
}

impl HelloMessageData {
    pub fn new(node_id: &[u8; 64]) -> Self {
        Self {
            protocol_version: 5,
            client_id: "sebhtml/blockchain_p2p_handshake/0.0.1".into(),
            capabilities: vec![Capability {
                name: "foo".into(),
                version: 1,
            }],
            listen_port: 0,
            node_id: node_id.to_owned(),
        }
    }
}

impl Into<Frame> for HelloMessageData {
    fn into(self) -> Frame {
        let mut message_data = vec![];
        self.encode(&mut message_data);

        Frame {
            msg_id: HELLO_MSG_ID,
            msg_data: message_data.into(),
        }
    }
}

impl TryFrom<Frame> for HelloMessageData {
    type Error = HandshakeError;

    fn try_from(value: Frame) -> Result<Self, Self::Error> {
        let mut msg_data = value.msg_data.as_slice();
        let msg_data = HelloMessageData::decode(&mut msg_data).unwrap();
        Ok(msg_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_hello_msg_data() {
        let node_id = vec![3; 64];
        let encodable = HelloMessageData::new(&node_id.try_into().unwrap());
        let mut rlp_bytes = vec![];
        encodable.encode(&mut rlp_bytes);
        let mut rlp_bytes = rlp_bytes.as_slice();
        let decoded = HelloMessageData::decode(&mut rlp_bytes).unwrap();
        assert_eq!(decoded, encodable);
    }
}
