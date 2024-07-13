pub mod ack_message;
pub mod auth_message;
pub mod ecies;
pub mod nonce;
pub mod secrets;

// TODO use trait to check that the len is the same
pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    if x.len() != y.len() {
        panic!("len mismatch");
    }
    let xored: Vec<u8> = x.iter().zip(y.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
    xored
}
