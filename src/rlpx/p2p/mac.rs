use sha3::{Digest, Keccak256};

pub struct FrameMacTags {
    pub header_mac: [u8; 32],
    pub frame_mac: [u8; 32],
}

pub trait MacDigest {
    fn digest_frame(&self, header_ciphertext: &[u8; 16], frame_ciphertext: &[u8]) -> FrameMacTags;
}

pub struct CommMacState {
    #[allow(unused)]
    state: Keccak256,
}

impl CommMacState {
    pub fn new() -> Self {
        // TODO do proper initialization
        Self {
            state: Keccak256::new(),
        }
    }
}

impl MacDigest for CommMacState {
    fn digest_frame(
        &self,
        _header_ciphertext: &[u8; 16],
        _frame_ciphertext: &[u8],
    ) -> FrameMacTags {
        // TODO updates
        FrameMacTags {
            header_mac: Default::default(),
            frame_mac: Default::default(),
        }
    }
}
