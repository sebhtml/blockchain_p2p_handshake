use clap::Parser;
use rlpx::{enode::ENode, rlpx_handshake::do_rlpx_handshake_as_initiator};
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
    let result = do_rlpx_handshake_as_initiator(&recipient);
    match result {
        Ok(result) => println!(
            "Handshake with {}:{} was successful: {}",
            recipient.ip_addr, recipient.port, result
        ),
        Err(err) => println!("Handshake failed with error {}", err),
    }
}
