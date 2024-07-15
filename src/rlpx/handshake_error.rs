use std::fmt::Display;

#[derive(Debug)]
pub enum HandshakeError {
    BadENodeId,
    CryptoKeyError,
    BadRegex(String),
    BadRecipientNodeAddress,
    BadRecipientPortInteger,
    IOError(String),
    Secp256k1Error(String),
    HmacValidationFailure,
    HmacGenerationError,
    HexError(String),
    RlpDecodeError,
    BadRecipientHelloMsgId,
    RecipientHelloP2pProtocolMismatch,
    RecipientHelloNodeIdMismatch,
    RecipientDoesNotSupportP2pCapability,
    RecipientDisconnected,
    RecipientDidNotDisconnect,
    InvalidDisconnectReason,
    RecipientReturnedUndesiredBytes,
    FrameSizeTooLarge,
    FailedToPrepareCryptoMaterial,
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::BadRecipientNodeAddress => write!(f, "BadTargetNodeAddress"),
            HandshakeError::BadRecipientPortInteger => write!(f, "BadTargetPortInteger"),
            HandshakeError::IOError(err) => write!(f, "IOError: {}", err),
            HandshakeError::BadENodeId => write!(f, "BadENodeId"),
            HandshakeError::HmacValidationFailure => write!(f, "HmacValidationFailure"),
            HandshakeError::HmacGenerationError => write!(f, "HmacGenerationError"),
            HandshakeError::CryptoKeyError => write!(f, "CryptoKeyError"),
            HandshakeError::BadRegex(err) => write!(f, "BadRegex: {}", err),
            HandshakeError::Secp256k1Error(err) => write!(f, "Secp256k1Error: {}", err),
            HandshakeError::HexError(err) => write!(f, "HexError: {}", err),
            HandshakeError::RlpDecodeError => write!(f, "RlpDecodeError"),
            HandshakeError::BadRecipientHelloMsgId => write!(f, "BadRecipientHelloMsgId"),
            HandshakeError::RecipientHelloP2pProtocolMismatch => {
                write!(f, "RecipientHelloP2pProtocolMismatch")
            }
            HandshakeError::RecipientHelloNodeIdMismatch => {
                write!(f, "RecipientHelloNodeIdMismatch")
            }
            HandshakeError::FailedToPrepareCryptoMaterial => {
                write!(f, "FailedToPrepareCryptoMaterial")
            }
            HandshakeError::RecipientDisconnected => {
                write!(f, "RecipientDisconnected")
            }
            HandshakeError::RecipientDidNotDisconnect => {
                write!(f, "RecipientDidNotDisconnect")
            }
            HandshakeError::InvalidDisconnectReason => {
                write!(f, "InvalidDisconnectReason")
            }
            HandshakeError::RecipientDoesNotSupportP2pCapability => {
                write!(f, "RecipientDoesNotSupportP2pCapability")
            }
            HandshakeError::RecipientReturnedUndesiredBytes => {
                write!(f, "RecipientReturnedUndesiredBytes")
            }
            HandshakeError::FrameSizeTooLarge => write!(f, "FrameSizeTooLarge"),
        }
    }
}
