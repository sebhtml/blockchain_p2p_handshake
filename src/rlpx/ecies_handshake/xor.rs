pub fn xor<const SIZE: usize>(x: &[u8; SIZE], y: &[u8]) -> [u8; SIZE] {
    let mut out: [u8; SIZE] = [0; SIZE];
    for i in 0..SIZE {
        out[i] = x[i] ^ y[i];
    }
    out
}
