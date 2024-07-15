// - TODO remove calls to unwrap

use clap::Parser;
use rlpx::{enode::ENode, node::EthereumNode};
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

    let node = EthereumNode::new();
    let result = node.add_peer(&recipient);

    match result {
        Ok(_ephemeral_secrets) => println!(
            "Handshake with {}:{} was successful",
            recipient.ip_addr, recipient.port,
        ),
        Err(err) => println!("Handshake failed with error {}", err),
    }
}
