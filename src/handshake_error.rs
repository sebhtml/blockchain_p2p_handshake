use std::fmt::Display;

#[derive(Debug)]
pub enum HandshakeError {
    BadENodeId,
    BadENodeIdPubKeyLength,
    BadRegex(String),
    BadRecipientNodeAddress,
    BadRecipientPortInteger,
    IOError(String),
    Secp256k1Error(String),
    HmacValidationFailure,
    HexError(String),
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::BadRecipientNodeAddress => write!(f, "BadTargetNodeAddress"),
            HandshakeError::BadRecipientPortInteger => write!(f, "BadTargetPortInteger"),
            HandshakeError::IOError(err) => write!(f, "IOError: {}", err),
            HandshakeError::BadENodeId => write!(f, "BadENodeId"),
            HandshakeError::HmacValidationFailure => write!(f, "HmacValidationFailure"),
            HandshakeError::BadENodeIdPubKeyLength => write!(f, "BadENodeIdPubKeyLength"),
            HandshakeError::BadRegex(err) => write!(f, "BadRegex: {}", err),
            HandshakeError::Secp256k1Error(err) => write!(f, "Secp256k1Error: {}", err),
            HandshakeError::HexError(err) => write!(f, "HexError: {}", err),
        }
    }
}
