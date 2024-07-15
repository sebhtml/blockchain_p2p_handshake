// TODOs
// - remove calls to unwrap
// - remove calls to panic

use clap::Parser;
use rlpx::{enode::ENode, rlpx_handshake::EthereumNode};
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

    let initiator = EthereumNode::new();
    let result = initiator.do_handshake(&recipient);
    match result {
        Ok(_ephemeral_secrets) => println!(
            "Handshake with {}:{} was successful",
            recipient.ip_addr, recipient.port,
        ),
        Err(err) => println!("Handshake failed with error {}", err),
    }
}
