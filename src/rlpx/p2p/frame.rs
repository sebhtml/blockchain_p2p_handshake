use crate::rlpx::handshake_error::HandshakeError;
use aes::cipher::StreamCipher;
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};

use super::mac::MacState;

pub struct FrameCipherTexts {
    pub header_ciphertext: [u8; 16],
    pub frame_ciphertext: Vec<u8>,
}
pub struct Frame {
    pub msg_id: u64,
    pub msg_data: Vec<u8>,
}

#[derive(RlpEncodable, RlpDecodable)]
#[derive(Default)]
pub struct HeaderData {
    capability_id: u32,
    context_id: u32,
}


impl Frame {
    /// Generate a frame.
    /// See section "Framing" on the web page https://github.com/ethereum/devp2p/blob/master/rlpx.md
    pub fn generate_frame_cipher_texts(
        &self,
        cipher: &mut impl StreamCipher,
    ) -> Result<FrameCipherTexts, HandshakeError> {
        let msg_id = self.msg_id;
        let msg_data = self.msg_data.as_slice();

        // frame-data = msg-id || msg-data
        let mut msg_id_bytes = vec![];
        msg_id.encode(&mut msg_id_bytes);
        let frame_data = [&msg_id_bytes, msg_data].concat();

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
        let frame_padding = vec![0_u8; frame_padding_len];

        // header-data = [capability-id, context-id]
        let mut header_data_bytes = vec![];
        let header_data = HeaderData::default();
        header_data.encode(&mut header_data_bytes);

        // header-padding = zero-fill header to 16-byte boundary
        let header_modulo = (frame_size.len() + header_data_bytes.len()) % 16;
        let header_padding_len = if header_modulo != 0 {
            16 - header_modulo
        } else {
            0
        };
        let header_padding = vec![0_u8; header_padding_len];

        // header = frame-size || header-data || header-padding
        let header = [frame_size, &header_data_bytes, &header_padding].concat();

        // header-ciphertext = aes(aes-secret, header)
        let mut header_ciphertext = header.clone();
        cipher.apply_keystream(&mut header_ciphertext);

        // frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
        let frame_data_and_padding = [frame_data, frame_padding].concat();

        let mut frame_ciphertext = frame_data_and_padding.clone();
        cipher.apply_keystream(&mut frame_ciphertext);

        let texts = FrameCipherTexts {
            header_ciphertext: header_ciphertext
                .try_into()
                .map_err(|_| HandshakeError::FrameReadError)?,
            frame_ciphertext,
        };
        Ok(texts)
    }

    pub fn write_frame(
        &self,
        cipher: &mut impl StreamCipher,
        egress_mac: &mut MacState,
    ) -> Result<Vec<u8>, HandshakeError> {
        let cipher_texts = self.generate_frame_cipher_texts(cipher)?;
        let header_ciphertext = &cipher_texts.header_ciphertext;
        let frame_ciphertext = &cipher_texts.frame_ciphertext;

        let mac_tags = egress_mac.update_with_ciphertexts(header_ciphertext, frame_ciphertext)?;
        let header_mac = &mac_tags.header_mac;
        let frame_mac = &mac_tags.frame_mac;

        // frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac
        let frame = [header_ciphertext.as_slice(),
            header_mac,
            frame_ciphertext,
            frame_mac]
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

        let header_ciphertext: [u8; 16] = header_ciphertext
            .try_into()
            .map_err(|_| HandshakeError::FrameReadError)?;
        let header_mac: [u8; 16] = header_mac
            .try_into()
            .map_err(|_| HandshakeError::FrameReadError)?;

        // Do the MAC check
        let mac_tags = ingress_mac.update_with_ciphertexts(&header_ciphertext, frame_ciphertext)?;
        if header_mac != mac_tags.header_mac {
            return Err(HandshakeError::MacValidationFailure);
        }
        if frame_mac != mac_tags.frame_mac {
            return Err(HandshakeError::MacValidationFailure);
        }

        // header-ciphertext = aes(aes-secret, header)
        let mut header = header_ciphertext;
        cipher.apply_keystream(&mut header);

        // header = frame-size || header-data || header-padding
        let frame_size_bytes: [u8; 4] = [&[0], &header[..3]]
            .concat()
            .try_into()
            .map_err(|_| HandshakeError::FrameReadError)?;
        let frame_size = u32::from_be_bytes(frame_size_bytes);

        // frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
        let mut frame_data_and_padding = frame_ciphertext.to_owned();
        cipher.apply_keystream(&mut frame_data_and_padding);

        let frame_data = &frame_data_and_padding[..frame_size as usize];
        // frame-data = msg-id || msg-data
        let mut buffer = frame_data;
        let msg_id = u64::decode(&mut buffer).map_err(|_| HandshakeError::RlpDecodeError)?;

        let msg_data = buffer;

        let message = Frame {
            msg_id,
            msg_data: msg_data.to_owned(),
        };
        Ok(message)
    }
}
