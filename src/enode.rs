use std::str::FromStr;

use crate::handshake_error::HandshakeError;
use regex::Regex;
use secp256k1::PublicKey;

pub const PUB_KEY_LEN: usize = 512 / 8;
pub struct ENode {
    pub id: String,
    pub ip_addr: String,
    pub port: u16,
}

impl TryFrom<&str> for ENode {
    type Error = HandshakeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let re = Regex::new(r"^enode:\/\/([0-9a-f]+)@(.+):([0-9]+)$")
            .map_err(|err| HandshakeError::BadRegex(err.to_string()))?;
        let captures = re.captures(&value).ok_or(HandshakeError::BadENodeId)?;
        if captures.len() != 4 {
            return Err(HandshakeError::BadENodeId);
        }
        let id = captures[1].to_owned();
        let ip_addr = captures[2].to_owned();
        let port = &captures[3];
        let port =
            u16::from_str_radix(port, 10).map_err(|_| HandshakeError::BadRecipientPortInteger)?;

        let enode = ENode { id, ip_addr, port };
        Ok(enode)
    }
}

impl TryInto<PublicKey> for &ENode {
    type Error = HandshakeError;

    fn try_into(self) -> Result<PublicKey, Self::Error> {
        let bytes =
            hex::decode(&self.id).map_err(|err| HandshakeError::HexError(err.to_string()))?;
        let mut data = [0_u8; 65];
        data[0] = 4;
        data[1..].copy_from_slice(&bytes);
        let recipient_pub_key = PublicKey::from_slice(&data).unwrap();
        Ok(recipient_pub_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_id() {
        let enode_string = "enode://c88b0b80d60d73a91179062402e65971510390813dcd5af34a9306da8c085ca1d75e3b398b6eacbdfcabc4038596fc2ea0fe35faf5ccf6202daf19db586ed2e7@127.0.0.1:30303";
        let enode: ENode = enode_string.try_into().unwrap();
        assert_eq!(enode.id, "c88b0b80d60d73a91179062402e65971510390813dcd5af34a9306da8c085ca1d75e3b398b6eacbdfcabc4038596fc2ea0fe35faf5ccf6202daf19db586ed2e7");
    }

    #[test]
    fn test_parse_ip_addr() {
        let enode_string = "enode://c88b0b80d60d73a91179062402e65971510390813dcd5af34a9306da8c085ca1d75e3b398b6eacbdfcabc4038596fc2ea0fe35faf5ccf6202daf19db586ed2e7@127.0.0.1:30303";
        let enode: ENode = enode_string.try_into().unwrap();
        assert_eq!(enode.ip_addr, "127.0.0.1");
    }

    #[test]
    fn test_parse_port() {
        let enode_string = "enode://c88b0b80d60d73a91179062402e65971510390813dcd5af34a9306da8c085ca1d75e3b398b6eacbdfcabc4038596fc2ea0fe35faf5ccf6202daf19db586ed2e7@127.0.0.1:30303";
        let enode: ENode = enode_string.try_into().unwrap();
        assert_eq!(enode.port, 30303);
    }
}
