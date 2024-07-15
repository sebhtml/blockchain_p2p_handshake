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
    state: Keccak256,
    cipher: Aes256Enc,
}

impl MacState {
    pub fn new(mac_secret: &[u8; 32]) -> Self {
        let cipher = Aes256Enc::new_from_slice(mac_secret).unwrap();
        Self {
            state: <Keccak256 as Digest>::new(),
            cipher,
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

    pub fn update_with_ciphertexts(
        &mut self,
        header_ciphertext: &[u8; 16],
        frame_ciphertext: &[u8],
    ) -> FrameMacTags {
        let header_mac = self.update_with_header_ciphertext(header_ciphertext);
        let frame_mac = self.update_with_frame_ciphertext(frame_ciphertext);

        let tags = FrameMacTags {
            header_mac,
            frame_mac,
        };
        tags
    }

    fn update_with_header_ciphertext(&mut self, header_ciphertext: &[u8; 16]) -> [u8; 16] {
        let mac = self.mac();

        let mut aes_mac = mac.to_vec();
        let msg_len = aes_mac.len();

        self.cipher
            .encrypt_padded::<NoPadding>(&mut aes_mac, msg_len)
            .unwrap();

        let header_mac_seed: Vec<u8> = xor(&aes_mac, header_ciphertext);
        self.update(&header_mac_seed);
        let header_mac = self.mac();
        header_mac
    }

    fn update_with_frame_ciphertext(&mut self, frame_ciphertext: &[u8]) -> [u8; 16] {
        self.update(frame_ciphertext);

        let mac = self.mac();

        let mut aes_mac = mac.to_vec();
        let msg_len = aes_mac.len();

        self.cipher
            .encrypt_padded::<NoPadding>(&mut aes_mac, msg_len)
            .unwrap();

        let mac = self.mac();

        let frame_mac_seed: Vec<u8> = xor(&aes_mac, &mac);
        self.update(&frame_mac_seed);
        let frame_mac = self.mac();
        frame_mac
    }
}
