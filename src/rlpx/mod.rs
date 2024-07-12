pub mod ack_message;
pub mod auth_message;
pub mod ecies;
pub mod enode;
pub mod handshake_error;
pub mod nonce;
pub mod rlpx_handshake;
pub mod secrets;

pub trait IntoRlpList {
    fn into_rlp_list(&self) -> Vec<u8>;
}
