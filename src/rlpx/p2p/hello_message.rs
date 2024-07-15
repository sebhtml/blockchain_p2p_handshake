use crate::rlpx::{handshake_error::HandshakeError, IntoRlpList};
use alloy_rlp::{Decodable, Encodable};
use rlp::Rlp;

use super::frame::Message;

#[derive(Debug, PartialEq, alloy_rlp::RlpDecodable, alloy_rlp::RlpEncodable)]
pub struct Capability {
    pub name: String,
    pub version: u32,
}

impl IntoRlpList for Capability {
    fn into_rlp_list(&self) -> Vec<u8> {
        rlp::encode_list(&vec![rlp::encode(&self.name), rlp::encode(&self.version)].concat())
            .to_vec()
    }
}

pub const HELLO_MSG_ID: u64 = 0;

#[derive(Debug, PartialEq, alloy_rlp::RlpDecodable, alloy_rlp::RlpEncodable)]
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

    /*
    pub fn decode3(bytes: &[u8]) -> Result<HelloMessageData, HandshakeError> {
        let hello_msg_data = HelloMessageData::de
    }
     */

    // TODO add trait for decode.
    pub fn decode2(bytes: &[u8]) -> Result<HelloMessageData, HandshakeError> {
        //println!("DECODE bytes {:?}", bytes);
        let mut buffer = bytes;
        //let rlp = alloy_rlp::Rlp::new(bytes).unwrap();
        //let list: Vec<u8> = rlp.as_list().unwrap();
        //let mut it = rlp.into_iter();
        //let rlp = Rlp::new(&list);
        //let list = &list[rlp.payload_info().unwrap().total()..];
        let protocol_version = u64::decode(&mut buffer).unwrap();
        println!("protocol_version {}", protocol_version);

        //let rlp = Rlp::new(&list);
        //let list = &list[rlp.payload_info().unwrap().total()..];
        //let client_id: String = it.next().unwrap().as_val().unwrap();
        let client_id = String::decode(&mut buffer).unwrap();
        println!("client id {}", client_id);

        //let rlp = Rlp::new(&list);
        //let list = &list[rlp.payload_info().unwrap().total()..];
        let _capabilities = Vec::<u8>::decode(&mut buffer).unwrap();
        let capabilities: Vec<Capability> = {
            //let rlp = it.next().unwrap();
            /*
            println!("rlp is_list {}", rlp.is_list());
            println!("rlp as_raw {:?}", rlp.as_raw());
            println!("rlp payload_info {:?}", rlp.payload_info().unwrap());
            // Re-create the Rlp such that its total length is sane, otherwise the crate 'rlp'
            // generates an error of type RlpIsTooBig.
            let rlp = Rlp::new(&rlp.as_raw()[..rlp.payload_info().unwrap().total()]);
            println!("rlp is_list {}", rlp.is_list());
            println!("rlp as_raw {:?}", rlp.as_raw());
            //let val: Vec<u8> = rlp.as().unwrap();
            //println!("rlp as_val {:?}", val);
            let capabilities: u64 = rlp::decode(rlp.as_raw()).unwrap();
            //let capabilities: Vec<u8> = rlp::decode(rlp.as_raw()).unwrap();
            //let capabilities: Vec<u8> = rlp.as_list().unwrap();
            let mut capabilities = vec![];
            //let rlp = Rlp::new(&rlp.as_raw()[..rlp.payload_info().unwrap().total()]);
            //let list: Vec<u8> = rlp.as_list().unwrap();
             */
            /*
            println!("DECODE capabilities list {:?}", list);
            let mut offset = 0;
            while offset < list.len() {
                // Capability list
                let rlp = Rlp::new(&list[offset..]);
                offset += rlp.payload_info().unwrap().total();
                let rlp = Rlp::new(&rlp.as_raw()[..rlp.payload_info().unwrap().total()]);
                println!("Cap list rlp raw {:?}", rlp.as_raw());
                let list: Vec<u8> = rlp.as_list().unwrap();

                let mut cap_offset = 0;
                // name rlp
                let rlp = Rlp::new(&list);
                cap_offset += rlp.payload_info().unwrap().total();
                let rlp = Rlp::new(&rlp.as_raw()[..rlp.payload_info().unwrap().total()]);
                println!("name rlp raw {:?}", rlp.as_raw());
                let name: String = rlp.as_val().unwrap();

                // version rlp
                let rlp = Rlp::new(&list[cap_offset..]);
                offset += rlp.payload_info().unwrap().total();
                let rlp = Rlp::new(&rlp.as_raw()[..rlp.payload_info().unwrap().total()]);
                let version: u32 = rlp.as_val().unwrap();
                capabilities.push(Capability { name, version, });

                offset += cap_offset;
            }
             */
            vec![]
        };

        //let rlp = Rlp::new(&list);
        //let list = &list[rlp.payload_info().unwrap().total()..];
        //let listen_port: u64 = it.next().unwrap().as_val().unwrap();//rlp.as_val().unwrap();
        let listen_port = u64::decode(&mut buffer).unwrap();
        println!("Got listen_port {}", listen_port);

        //let rlp = Rlp::new(&list);
        //let _list = &list[rlp.payload_info().unwrap().total()..];
        //let node_id: Vec<u8> = it.next().unwrap().as_val().unwrap();//rlp.as_val().unwrap();
        let node_id = Vec::<u8>::decode(&mut buffer).unwrap();
        println!("Got node_id {}", hex::encode(&node_id));

        let hello = HelloMessageData {
            protocol_version,
            client_id,
            capabilities,
            listen_port,
            node_id: node_id.try_into().unwrap(),
        };
        Ok(hello)
    }
}

impl IntoRlpList for HelloMessageData {
    fn into_rlp_list(&self) -> Vec<u8> {
        let capabilities = rlp::encode_list(
            &self
                .capabilities
                .iter()
                .map(|cap| cap.into_rlp_list())
                .collect::<Vec<_>>()
                .concat(),
        );
        let list = Rlp::new(&capabilities).as_raw();
        println!("capabilities raw {:?}", list);
        let list: Vec<u8> = Rlp::new(&capabilities).as_list().unwrap();
        println!("capabilities list {:?}", list);
        println!(
            "capabilities payload info {:?}",
            Rlp::new(&capabilities).payload_info().unwrap()
        );
        let rlp_bytes = rlp::encode_list(
            &vec![
                rlp::encode(&self.protocol_version),
                rlp::encode(&self.client_id),
                capabilities,
                rlp::encode(&self.listen_port),
                rlp::encode(&self.node_id.to_vec()),
            ]
            .concat(),
        )
        .to_vec();
        rlp_bytes
    }
}

pub trait Hello {
    fn hello(node_id: &[u8; 64]) -> Message;
}

// TODO move Hello things to hello.rs
impl Hello for Message {
    fn hello(node_id: &[u8; 64]) -> Message {
        let hello_msg_data = HelloMessageData::new(node_id);
        let mut message_data = vec![];
        hello_msg_data.encode(&mut message_data);

        Message {
            msg_id: HELLO_MSG_ID,
            msg_data: message_data.into(),
        }
    }
}

impl Message {
    pub fn to_hello_msg_data(&self) -> Result<HelloMessageData, HandshakeError> {
        // Decode msg_data into HelloMessageData
        let mut msg_data = self.msg_data.as_slice();
        let hello_msg_data = HelloMessageData::decode(&mut msg_data).unwrap();
        Ok(hello_msg_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_hello_msg_data() {
        let node_id = vec![3; 64];
        let hello_msg_data = HelloMessageData::new(&node_id.try_into().unwrap());
        let mut rlp_bytes = vec![];
        hello_msg_data.encode(&mut rlp_bytes);
        let mut rlp_bytes = rlp_bytes.as_slice();
        let decoded_hello_msg_data = HelloMessageData::decode(&mut rlp_bytes).unwrap();
        assert_eq!(decoded_hello_msg_data, hello_msg_data);
    }
}
