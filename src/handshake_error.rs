use std::{fmt::Display, io};

#[derive(Debug)]
pub enum HandshakeError {
    BadENodeId,
    BadENodeIdPubKeyLength,
    BadRegex(regex::Error),
    BadRecipientNodeAddress,
    BadRecipientPortInteger,
    IOError(io::Error),
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::BadRecipientNodeAddress => write!(f, "BadTargetNodeAddress"),
            HandshakeError::BadRecipientPortInteger => write!(f, "BadTargetPortInteger"),
            HandshakeError::IOError(err) => write!(f, "IOError: {}", err),
            HandshakeError::BadENodeId => write!(f, "BadENodeId"),
            HandshakeError::BadENodeIdPubKeyLength => write!(f, "BadENodeIdPubKeyLength"),
            HandshakeError::BadRegex(err) => write!(f, "BadRegex: {}", err),
        }
    }
}
