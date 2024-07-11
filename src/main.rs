use clap::Parser;
use rlpx::{enode::ENode, rlpx_handshake::do_rlpx_handshake_as_initiator};
use secp256k1::generate_keypair;
pub mod rlpx;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    recipient: String,
}

fn main() {
    let args = Args::parse();
    let recipient = args.recipient;
    let recipient: ENode = recipient.as_str().try_into().unwrap();

    let mut rng = secp256k1::rand::thread_rng();
    let (initiator_static_sk, initiator_static_pk) = generate_keypair(&mut rng);

    let result =
        do_rlpx_handshake_as_initiator(&initiator_static_sk, &initiator_static_pk, &recipient);
    match result {
        Ok(result) => println!(
            "Handshake with {}:{} was successful: {}",
            recipient.ip_addr, recipient.port, result
        ),
        Err(err) => println!("Handshake failed with error {}", err),
    }
}
