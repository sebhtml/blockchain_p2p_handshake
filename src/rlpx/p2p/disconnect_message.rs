use alloy_rlp::{RlpDecodable, RlpEncodable};

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct DisconnectMessageData {
    reason: u32,
}
