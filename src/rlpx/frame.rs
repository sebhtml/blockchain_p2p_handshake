use super::secrets::FrameSecrets;

/// Generate a frame.
/// See section "Framing" on the web page https://github.com/ethereum/devp2p/blob/master/rlpx.md
pub fn generate_frame(
    _rlp_msg_id: &[u8],
    _message_data: &[u8],
    _frame_secret: &FrameSecrets,
) -> Vec<u8> {
    // frame-data = msg-id || msg-data

    // frame-size = length of frame-data, encoded as a 24bit big-endian integer

    // frame-padding = zero-fill frame-data to 16-byte boundary

    // frame-ciphertext = aes(aes-secret, frame-data || frame-padding)

    // capability-id = integer, always zero

    // context-id = integer, always zero

    // header-data = [capability-id, context-id]

    // header-padding = zero-fill header to 16-byte boundary

    // header = frame-size || header-data || header-padding

    // header-ciphertext = aes(aes-secret, header)

    // frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac

    vec![]
}
