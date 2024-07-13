use aes::{
    cipher::{block_padding::NoPadding, BlockEncrypt, KeyInit},
    Aes256Enc,
};
use sha3::{Digest, Keccak256};

use crate::rlpx::ecies_handshake::xor;

pub struct FrameMacTags {
    pub header_mac: [u8; 16],
    pub frame_mac: [u8; 16],
}

pub struct MacState {
    mac_secret: [u8; 32],
    state: Keccak256,
}

impl MacState {
    pub fn new(mac_secret: &[u8; 32]) -> Self {
        Self {
            mac_secret: mac_secret.to_owned(),
            state: Keccak256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data)
    }

    pub fn mac(&self) -> [u8; 16] {
        self.state.clone().finalize().to_vec()[..16]
            .to_vec()
            .try_into()
            .unwrap()
    }

    pub fn update_with_frame(
        &mut self,
        header_ciphertext: &[u8; 16],
        _frame_ciphertext: &[u8],
    ) -> FrameMacTags {
        // Process header
        let mac = self.mac();

        let mac_secret = self.mac_secret.as_slice();
        let cipher = Aes256Enc::new_from_slice(mac_secret.into()).unwrap();

        let mut aes_mac = mac.to_vec();
        let msg_len = aes_mac.len();
        println!("msg_len {}", msg_len);
        println!("input {:?}", mac);
        cipher
            .encrypt_padded::<NoPadding>(&mut aes_mac, msg_len)
            .unwrap();
        println!("output {:?}", aes_mac);

        println!("aes_mac len {}", aes_mac.len());
        println!("header_ciphertext len {}", header_ciphertext.len());

        let header_mac_seed: Vec<u8> = xor(&aes_mac, header_ciphertext);
        self.state.update(&header_mac_seed);

        let header_mac = self.mac();

        let tags = FrameMacTags {
            header_mac: header_mac,
            frame_mac: Default::default(),
        };
        tags
    }
}
