use secp256k1::PublicKey;

use super::{enode::ENode, handshake_error::HandshakeError};

pub struct Peer {
    static_pk: PublicKey,
}

impl Peer {
    pub fn new(recipient_enode: &ENode) -> Result<Self, HandshakeError> {
        let static_pk: PublicKey = recipient_enode.try_into().unwrap();
        let peer = Self { static_pk };

        Ok(peer)
    }

    pub fn static_pk(&self) -> &PublicKey {
        &self.static_pk
    }
}
