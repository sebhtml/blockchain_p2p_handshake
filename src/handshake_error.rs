use std::{fmt::Display, io::Error};

pub enum HandshakeError {
    BadTargetNodeAddress,
    BadTargetPortInteger,
    IOError(Error),
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::BadTargetNodeAddress => write!(f, "BadTargetNodeAddress"),
            HandshakeError::BadTargetPortInteger => write!(f, "BadTargetPortInteger"),
            HandshakeError::IOError(err) => write!(f, "IOError: {}", err),
        }
    }
}
