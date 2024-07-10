use crate::handshake_error::HandshakeError;
use rlp::RlpStream;
use secp256k1::{ecdh::SharedSecret, Message, PublicKey, Secp256k1, SecretKey};

#[derive(Debug)]
pub struct AuthMessage {
    pub signature: Vec<u8>,
    pub initiator_pub_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub version: u32,
}

impl AuthMessage {
    pub fn try_new(
        initiator_sk: &SecretKey,
        initiator_pk: &PublicKey,
        recipient_pk: &PublicKey,
    ) -> Result<AuthMessage, HandshakeError> {
        let auth_vsn = 4;

        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let shared_secret = SharedSecret::new(&recipient_pk, &initiator_sk)
            .secret_bytes()
            .to_vec();
        // TODO send the nonce to the context directly
        let msg: Vec<u8> = shared_secret
            .iter()
            .zip(nonce.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        let msg: [u8; 32] = msg.try_into().unwrap();
        let msg = Message::from_digest(msg);

        let context = Secp256k1::new();
        let recoverable_signature = context.sign_ecdsa_recoverable(&msg, &initiator_sk);
        let (recovery_id, signature_bytes) = recoverable_signature.serialize_compact();
        let recovery_id = u8::try_from(recovery_id.to_i32()).unwrap();
        let signature = vec![signature_bytes.to_vec(), vec![recovery_id]].concat();

        let auth = AuthMessage {
            signature,
            initiator_pub_key: initiator_pk.serialize_uncompressed()[1..].to_vec(),
            nonce,
            version: auth_vsn,
        };
        println!("initiator_pk len: {}", auth.initiator_pub_key.len());
        Ok(auth)
    }

    pub fn as_rlp_list(&self) -> Vec<u8> {
        let mut auth_body = RlpStream::new_list(4);
        println!("Signature len {}", self.signature.len());
        auth_body.append(&self.signature);
        auth_body.append(&self.initiator_pub_key);
        auth_body.append(&self.nonce);
        auth_body.append(&self.version);
        let auth_body = auth_body.out();
        auth_body.to_vec()
    }
}
