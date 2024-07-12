use aes::{
    cipher::{block_padding::NoPadding, BlockEncryptMut, KeyInit},
    Aes256,
};
use ecb::Encryptor;
use sha3::{Digest, Keccak256};

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

    pub fn digest_frame(
        &mut self,
        header_ciphertext: &[u8; 16],
        _frame_ciphertext: &[u8],
    ) -> FrameMacTags {
        // Process header
        let mac = &self.state.clone().finalize().to_vec()[..16];

        let mac_secret = self.mac_secret.as_slice();
        let cipher = Encryptor::<Aes256>::new_from_slice(mac_secret.into()).unwrap();

        let mut aes_mac = mac.to_vec();
        let msg_len = aes_mac.len();
        println!("msg_len {}", msg_len);
        println!("input {:?}", mac);
        cipher
            .encrypt_padded_mut::<NoPadding>(&mut aes_mac, msg_len)
            .unwrap();
        println!("output {:?}", aes_mac);

        println!("aes_mac len {}", aes_mac.len());
        println!("header_ciphertext len {}", header_ciphertext.len());

        let header_mac_seed: Vec<u8> = aes_mac
            .iter()
            .zip(header_ciphertext.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        self.state.update(&header_mac_seed);
        let header_mac = &self.state.clone().finalize().to_vec()[..16];

        let tags = FrameMacTags {
            header_mac: header_mac.try_into().unwrap(),
            frame_mac: Default::default(),
        };
        tags
    }
}
