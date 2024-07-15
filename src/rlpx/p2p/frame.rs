use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr64BE;
use rlp::RlpStream;

use crate::rlpx::handshake_error::HandshakeError;

use super::mac::MacState;

pub struct FrameCipherTexts {
    pub header_ciphertext: [u8; 16],
    pub frame_ciphertext: Vec<u8>,
}
pub struct Frame {
    pub msg_id: u64,
    pub msg_data: Vec<u8>,
}

impl Frame {
    /// Generate a frame.
    /// See section "Framing" on the web page https://github.com/ethereum/devp2p/blob/master/rlpx.md
    pub fn generate_frame_cipher_texts(
        &self,
        aes_secret: &[u8; 32],
    ) -> Result<FrameCipherTexts, HandshakeError> {
        let msg_id = self.msg_id;
        let msg_data = self.msg_data.as_slice();

        // Cipher
        let iv = [0 as u8; 16].as_slice();
        let aes_secret = aes_secret.as_slice();
        let mut cipher = Ctr64BE::<Aes256>::new(aes_secret.into(), iv.into());

        // frame-data = msg-id || msg-data
        let msg_id = rlp::encode(&msg_id);
        let frame_data = vec![&msg_id, msg_data].concat();

        // frame-size = length of frame-data, encoded as a 24bit big-endian integer
        let frame_size = (frame_data.len() as u32).to_be_bytes();
        let (probably_0, frame_size) = frame_size.split_at(1);
        if probably_0[0] != 0 {
            return Err(HandshakeError::FrameSizeTooLarge);
        }

        // frame-padding = zero-fill frame-data to 16-byte boundary
        let frame_data_modulo = frame_data.len() % 16;
        let frame_padding_len = if frame_data_modulo != 0 {
            16 - frame_data_modulo
        } else {
            0
        };
        let frame_padding = vec![0 as u8; frame_padding_len];

        // capability-id = integer, always zero
        let capability_id: u32 = 0;

        // context-id = integer, always zero
        let context_id: u32 = 0;

        // header-data = [capability-id, context-id]
        let mut header_data = RlpStream::new_list(2);
        header_data.append(&capability_id);
        header_data.append(&context_id);
        let header_data = header_data.out();

        // header-padding = zero-fill header to 16-byte boundary
        let header_modulo = (frame_size.len() + header_data.len()) % 16;
        let header_padding_len = if header_modulo != 0 {
            16 - header_modulo
        } else {
            0
        };
        let header_padding = vec![0 as u8; header_padding_len];

        // header = frame-size || header-data || header-padding
        let header = vec![frame_size, &header_data, &header_padding].concat();

        // header-ciphertext = aes(aes-secret, header)
        let mut header_ciphertext = header.to_vec();
        cipher.apply_keystream(&mut header_ciphertext);

        // frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
        let frame_data_and_padding = vec![frame_data, frame_padding].concat();

        let mut frame_ciphertext = frame_data_and_padding.to_vec();
        cipher.apply_keystream(&mut frame_ciphertext);

        let texts = FrameCipherTexts {
            header_ciphertext: header_ciphertext.try_into().unwrap(),
            frame_ciphertext,
        };
        Ok(texts)
    }

    pub fn write_frame(
        &self,
        aes_secret: &[u8; 32],
        egress_mac: &mut MacState,
    ) -> Result<Vec<u8>, HandshakeError> {
        let cipher_texts = self.generate_frame_cipher_texts(aes_secret)?;
        let header_ciphertext = &cipher_texts.header_ciphertext;
        let frame_ciphertext = &cipher_texts.frame_ciphertext;

        let mac_tags = egress_mac.update_with_ciphertexts(header_ciphertext, frame_ciphertext);
        let header_mac = &mac_tags.header_mac;
        let frame_mac = &mac_tags.frame_mac;

        // frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac
        let frame = vec![
            header_ciphertext.as_slice(),
            header_mac,
            frame_ciphertext,
            frame_mac,
        ]
        .concat();

        Ok(frame)
    }

    /// See https://github.com/ethereum/devp2p/blob/master/rlpx.md
    pub fn read_frame(
        frame: &[u8],
        cipher: &mut impl StreamCipher,
        ingress_mac: &mut MacState,
    ) -> Result<Frame, HandshakeError> {
        // frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac
        let (header_ciphertext, rest) = frame.split_at(16);
        let (header_mac, rest) = rest.split_at(16);
        let (frame_ciphertext, frame_mac) = rest.split_at(rest.len() - 16);

        let header_ciphertext: [u8; 16] = header_ciphertext.try_into().unwrap();
        let header_mac: [u8; 16] = header_mac.try_into().unwrap();

        // Do the MAC check
        let mac_tags = ingress_mac.update_with_ciphertexts(&header_ciphertext, frame_ciphertext);
        if header_mac != mac_tags.header_mac {
            return Err(HandshakeError::HmacValidationFailure);
        }
        if frame_mac != mac_tags.frame_mac {
            return Err(HandshakeError::HmacValidationFailure);
        }

        // header-ciphertext = aes(aes-secret, header)

        let mut header = header_ciphertext.to_vec();
        cipher.apply_keystream(&mut header);

        // frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
        let mut frame_data_and_padding = frame_ciphertext.to_vec();
        cipher.apply_keystream(&mut frame_data_and_padding);

        // frame-data = msg-id || msg-data
        let msg_id = rlp::decode(&frame_data_and_padding).unwrap();

        // Re-encode the msg_id to know how many RLP bytes it needs.
        let encoded = rlp::encode(&msg_id);
        let (_, msg_data) = frame_data_and_padding.split_at(encoded.len());

        let message = Frame {
            msg_id,
            msg_data: msg_data.to_owned(),
        };
        Ok(message)
    }
}
