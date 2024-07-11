use clap::Parser;
use enode::ENode;
use rlpx_handshake::do_rlpx_handshake;
pub mod auth_message;
pub mod ecies;
pub mod enode;
pub mod handshake_error;
pub mod rlpx_handshake;

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
    let result = do_rlpx_handshake(&recipient);
    match result {
        Ok(result) => println!(
            "Handshake with {}:{} was successful: {}",
            recipient.ip_addr, recipient.port, result
        ),
        Err(err) => println!("Handshake failed with error {}", err),
    }
}
