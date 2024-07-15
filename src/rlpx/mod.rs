pub mod ecies_handshake;
pub mod enode;
pub mod handshake_error;
pub mod node;
pub mod p2p;

pub trait IntoRlpList {
    fn into_rlp_list(&self) -> Vec<u8>;
}
