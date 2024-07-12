pub const NONCE_LENGTH: usize = 32;

pub fn make_nonce() -> [u8; NONCE_LENGTH] {
    // TODO don't use unwrap.
    let nonce: [u8; NONCE_LENGTH] = (0..NONCE_LENGTH)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    nonce
}
