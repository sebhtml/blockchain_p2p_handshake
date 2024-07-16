use alloy_rlp::{Decodable, Encodable, RlpEncodable};

use crate::rlpx::handshake_error::HandshakeError;

use super::frame::Frame;

pub const DISCONNECT_MSG_ID: u64 = 0x01;

#[derive(Debug, Clone, PartialEq)]
pub enum Reason {
    DisconnectRequested = 0x00,
    TcpSubsystemError = 0x01,
    BreachOfProtocol = 0x02,
    UselessPeer = 0x03,
    TooManyPeers = 0x04,
    AlreadyConnected = 0x05,
    IncompatibleP2pProtocolVersion = 0x06,
    NullNodeIdentityReceived = 0x07,
    ClientQuitting = 0x08,
    UnexpectedIdentityInHandshake = 0x09,
    IdentityIsTheSameAsThisNode = 0x0a,
    PingTimeout = 0x0b,
    SomeOtherReasonSpecificToASubProtocol = 0x10,
}

impl TryFrom<u8> for Reason {
    type Error = HandshakeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let variants = vec![
            Reason::DisconnectRequested,
            Reason::TcpSubsystemError,
            Reason::BreachOfProtocol,
            Reason::UselessPeer,
            Reason::TooManyPeers,
            Reason::AlreadyConnected,
            Reason::IncompatibleP2pProtocolVersion,
            Reason::NullNodeIdentityReceived,
            Reason::ClientQuitting,
            Reason::UnexpectedIdentityInHandshake,
            Reason::IdentityIsTheSameAsThisNode,
            Reason::PingTimeout,
            Reason::SomeOtherReasonSpecificToASubProtocol,
        ];
        let result = variants
            .into_iter()
            .find(|variant| variant.to_owned() as u8 == value);
        match result {
            Some(variant) => Ok(variant),
            _ => Err(HandshakeError::InvalidDisconnectReason),
        }
    }
}

#[derive(Debug, PartialEq, RlpEncodable)]
pub struct DisconnectMessageData {
    reason: u8,
}

impl Decodable for DisconnectMessageData {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // TODO decode this properly...
        let reason = buf[buf.len() - 1];
        let msg_data = DisconnectMessageData { reason };
        Ok(msg_data)
    }
}

impl DisconnectMessageData {
    pub fn new(reason: Reason) -> Self {
        Self {
            reason: reason as u8,
        }
    }

    pub fn reason(&self) -> Result<Reason, HandshakeError> {
        let reason = self.reason;
        Reason::try_from(reason)
    }
}

impl From<DisconnectMessageData> for Frame {
    fn from(val: DisconnectMessageData) -> Self {
        let mut message_data = vec![];
        val.encode(&mut message_data);

        Frame {
            msg_id: DISCONNECT_MSG_ID,
            msg_data: message_data,
        }
    }
}

impl TryFrom<Frame> for DisconnectMessageData {
    type Error = HandshakeError;

    fn try_from(value: Frame) -> Result<Self, Self::Error> {
        let mut msg_data = value.msg_data.as_slice();
        let msg_data = DisconnectMessageData::decode(&mut msg_data)
            .map_err(|_| HandshakeError::RlpDecodeError)?;
        Ok(msg_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_disconnect_msg_data() {
        let encodable = DisconnectMessageData { reason: 4 };
        let mut rlp_bytes = vec![];
        encodable.encode(&mut rlp_bytes);
        let mut rlp_bytes = rlp_bytes.as_slice();
        let decoded = DisconnectMessageData::decode(&mut rlp_bytes)
            .expect("RLP bytes should be decodable into a disconnect message");
        assert_eq!(decoded, encodable);
    }
}
