use rlp::{RlpDecodable, RlpEncodable, RlpStream};

use crate::rlpx::{handshake_error::HandshakeError, IntoRlpList};

pub struct Message {
    pub msg_id: u64,
    pub msg_data: Vec<u8>,
}

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct Capability {
    pub cap: String,
    pub version: u32,
}

pub const HELLO_MSG_ID: u64 = 0;

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct HelloMessageData {
    // TODO validate type of integer
    pub protocol_version: u32,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u16,
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

impl IntoRlpList for HelloMessageData {
    fn into_rlp_list(&self) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new_list(4);

        rlp_stream.append(&self.protocol_version);

        rlp_stream.append(&self.client_id);

        let mut cap_rlp_stream = RlpStream::new_list(self.capabilities.len());
        for cap in self.capabilities.iter() {
            let mut cap_p2p_rlp_stream = RlpStream::new_list(2);
            cap_p2p_rlp_stream.append(&cap.cap);
            cap_p2p_rlp_stream.append(&cap.version);
            cap_rlp_stream.append(&cap_p2p_rlp_stream.out());
        }

        rlp_stream.append(&self.listen_port);

        rlp_stream.append(&self.node_id.to_vec());

        let message_data = rlp_stream.out().to_vec();
        message_data
    }
}

pub trait Hello {
    fn hello(node_id: &[u8; 64]) -> Message;
}

impl Hello for Message {
    fn hello(node_id: &[u8; 64]) -> Message {
        let hello = HelloMessageData::new(node_id);
        let message_data = hello.into_rlp_list();

        Message {
            msg_id: HELLO_MSG_ID,
            msg_data: message_data,
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
