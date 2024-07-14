use rlp::{Rlp, RlpEncodable};

use crate::rlpx::handshake_error::HandshakeError;

pub struct Message {
    pub msg_id: u64,
    pub msg_data: Vec<u8>,
}

#[derive(Debug, PartialEq, RlpEncodable)]
pub struct Capability {
    pub cap: String,
    pub version: u32,
}

pub const HELLO_MSG_ID: u64 = 0;

#[derive(Debug, PartialEq, RlpEncodable)]
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
            capabilities: vec![],
            listen_port: 0,
            node_id: node_id.to_vec(),
        }
    }

    // TODO add trait for decode.
    pub fn decode(rlp: &[u8]) -> Result<HelloMessageData, HandshakeError> {
        let reader = Rlp::new(rlp);
        let mut it = reader.into_iter();

        let protocol_version: u64 = it
            .next()
            .ok_or(HandshakeError::RlpDecodeError)?
            .as_val()
            .map_err(|_| HandshakeError::RlpDecodeError)?;

        let client_id: String = it
            .next()
            .ok_or(HandshakeError::RlpDecodeError)?
            .as_val()
            .map_err(|_| HandshakeError::RlpDecodeError)?;

        let capabilities = it
            .next()
            .ok_or(HandshakeError::RlpDecodeError)?;

        let listen_port: u64 = it
            .next()
            .ok_or(HandshakeError::RlpDecodeError)?
            .as_val()
            .map_err(|_| HandshakeError::RlpDecodeError)?;

        let node_id: Vec<u8> = it
            .next()
            .ok_or(HandshakeError::RlpDecodeError)?
            .as_val()
            .map_err(|_| HandshakeError::RlpDecodeError)?;

        println!("Got node_id {}", hex::encode(&node_id));
        let hello = HelloMessageData {
            protocol_version,
            client_id,
            capabilities: vec![],
            listen_port,
            node_id,
        };
        Ok(hello)
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
        let hello_msg_data = HelloMessageData::decode(&msg_data).unwrap();
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
        let decoded_hello_msg_data = HelloMessageData::decode(&rlp_bytes).unwrap();
        assert_eq!(decoded_hello_msg_data, hello_msg_data);
    }
}
