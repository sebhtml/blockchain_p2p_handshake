use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr128BE;
use rlp::RlpStream;

use super::{mac::MacDigest, message::Message};

pub struct FrameCipherTexts {
    pub header_ciphertext: [u8; 16],
    pub frame_ciphertext: Vec<u8>,
}

/// Generate a frame.
/// See section "Framing" on the web page https://github.com/ethereum/devp2p/blob/master/rlpx.md
fn generate_frame_cipher_texts(
    msg_id: u64,
    msg_data: &[u8],
    aes_secret: &[u8; 32],
) -> FrameCipherTexts {
    // frame-data = msg-id || msg-data
    let msg_id = rlp::encode(&msg_id);
    let frame_data = vec![&msg_id, msg_data].concat();

    // frame-size = length of frame-data, encoded as a 24bit big-endian integer
    let frame_size = &(frame_data.len() as u32).to_be_bytes()[0..3];

    // frame-padding = zero-fill frame-data to 16-byte boundary
    let frame_data_modulo = frame_data.len() % 16;
    let frame_padding_len = if frame_data_modulo != 0 {
        16 - frame_data_modulo
    } else {
        0
    };
    let frame_padding = vec![0 as u8; frame_padding_len];

    // frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
    let iv = [0 as u8; 16].as_slice();
    let aes_secret = aes_secret.as_slice();
    let mut cipher = Ctr128BE::<Aes256>::new(aes_secret.into(), iv.into());
    let msg = vec![frame_data, frame_padding].concat();
    let mut frame_ciphertext = msg.to_vec();
    cipher.apply_keystream(&mut frame_ciphertext);

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
    let mut cipher = Ctr128BE::<Aes256>::new(aes_secret.into(), iv.into());
    let mut header_ciphertext = header.to_vec();
    cipher.apply_keystream(&mut header_ciphertext);

    println!("header_ciphertext len: {}", header_ciphertext.len());

    FrameCipherTexts {
        header_ciphertext: header_ciphertext.try_into().unwrap(),
        frame_ciphertext,
    }
}

pub fn write_frame(
    msg: &Message,
    aes_secret: &[u8; 32],
    egress_mac: &mut impl MacDigest,
) -> Vec<u8> {
    let msg_id = msg.msg_id;
    let msg_data = &msg.msg_data;
    let cipher_texts = generate_frame_cipher_texts(msg_id, msg_data, aes_secret);
    let header_ciphertext = &cipher_texts.header_ciphertext;
    let frame_ciphertext = &cipher_texts.frame_ciphertext;

    let mac_tags = egress_mac.digest_frame(header_ciphertext, frame_ciphertext);
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

    frame
}

pub fn read_frame(
    _frame: &[u8],
    _aes_secret: &[u8; 32],
    _ingress_mac: &mut impl MacDigest,
) -> Message {
    // TODO read frame into Message
    let msg_id = 99;
    let msg_data = vec![];
    // TODO do the MAC check
    Message { msg_id, msg_data }
}
