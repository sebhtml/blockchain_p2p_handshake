
Part 1: start the target node

1. Install Go lang
2. Clone the Geth project `git clone https://github.com/ethereum/go-ethereum.git`
3. Go to go-ethereum and type `make geth`
4. Start the node: `./build/bin/geth`

Part 2: do the handshake

1. Install Rust using "rustup" (see https://www.rust-lang.org/tools/install )
2. Untar blockchain_p2p_handshake.tar.gz
3. Go to blockchain_p2p_handshake
4. Type `cargo run --release -- --target-node 127.0.0.1 --target-port 30303`
5. You can also do the handshake with `cargo make handshake`
