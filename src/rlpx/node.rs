use secp256k1::{generate_keypair, PublicKey, SecretKey};

use super::{connection::Connection, enode::ENode, handshake_error::HandshakeError};

pub struct EthereumNode {
    static_seck: SecretKey,
    static_pk: PublicKey,
}

impl EthereumNode {
    pub fn new() -> Self {
        let mut rng = secp256k1::rand::thread_rng();
        let (static_seck, static_pk) = generate_keypair(&mut rng);

        Self {
            static_seck,
            static_pk,
        }
    }

    pub fn add_peer(&self, recipient_enode: &ENode) -> Result<bool, HandshakeError> {
        let mut connection = Connection::new(recipient_enode)?;
        connection.handshake(&self.static_seck, &self.static_pk)
    }
}
