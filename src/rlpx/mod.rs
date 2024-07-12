pub mod ecies_handshake;
pub mod enode;
pub mod handshake_error;
pub mod p2p;
pub mod rlpx_handshake;

pub trait IntoRlpList {
    fn into_rlp_list(&self) -> Vec<u8>;
}
