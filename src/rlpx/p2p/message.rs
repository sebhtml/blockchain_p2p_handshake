use rlp::{RlpDecodable, RlpEncodable};

use crate::rlpx::handshake_error::HandshakeError;

pub struct Message {
    pub msg_id: u64,
    pub msg_data: Vec<u8>,
}

#[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct Capability {
    pub cap: String,
    pub version: u32,
}

pub const HELLO_MSG_ID: u64 = 0;

#[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct HelloMessageData {
    pub protocol_version: u64,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u64,
    pub node_id: Vec<u8>,
}

impl HelloMessageData {
    pub fn new(node_id: &[u8; 64]) -> Self {
        Self {
            protocol_version: 5,
            client_id: "sebhtml/blockchain_p2p_handshake/0.0.1".into(),
            capabilities: vec![Capability {
                cap: "p2p".into(),
                version: 5,
            }],
            listen_port: 0,
            node_id: node_id.to_vec(),
        }
    }
}

pub trait Hello {
    fn hello(node_id: &[u8; 64]) -> Message;
}

// TODO move Hello things to hello.rs
impl Hello for Message {
    fn hello(node_id: &[u8; 64]) -> Message {
        let hello_msg_data = HelloMessageData::new(node_id);
        let message_data = rlp::encode(&hello_msg_data);

        Message {
            msg_id: HELLO_MSG_ID,
            msg_data: message_data.into(),
        }
    }
}

impl Message {
    pub fn to_hello_msg_data(&self) -> Result<HelloMessageData, HandshakeError> {
        // Decode msg_data into HelloMessageData
        let msg_data = &self.msg_data;
        let hello_msg_data: HelloMessageData = rlp::decode(msg_data).unwrap();
        Ok(hello_msg_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let node_id = vec![3; 64];
        let hello_msg_data = HelloMessageData::new(&node_id.try_into().unwrap());
        let rlp_bytes = rlp::encode(&hello_msg_data);
        let decoded_hello_msg_data: HelloMessageData = rlp::decode(&rlp_bytes).unwrap();
        assert_eq!(decoded_hello_msg_data, hello_msg_data);
    }
}
