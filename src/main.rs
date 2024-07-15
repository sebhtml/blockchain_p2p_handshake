// - TODO remove calls to unwrap

use std::process::ExitCode;

use clap::Parser;
use rlpx::{enode::ENode, handshake_error::HandshakeError, node::EthereumNode};
pub mod rlpx;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    recipient: String,
}

fn main() -> Result<ExitCode, HandshakeError> {
    let args = Args::parse();
    let recipient = args.recipient;
    let recipient_enode: ENode = recipient
        .as_str()
        .try_into()
        .map_err(|_| HandshakeError::BadENodeId)?;

    let node = EthereumNode::new();
    let result = node.add_peer(&recipient_enode);

    match result {
        Ok(_ephemeral_secrets) => {
            println!("Handshake with {} was successful", recipient,)
        }
        Err(err) => {
            println!("Handshake failed with error {}", err);
            return Err(err);
        }
    }

    Ok(ExitCode::SUCCESS)
}
