
Technical Challenge for applying for the Senior Rust Engineer at Eiger.

Challenge: https://github.com/eqlabs/recruitment-exercises/blob/master/node-handshake.md

== Publicly available P2P node (e.g. a blockchain one) implementation ==

I choose Ethereum: https://github.com/ethereum/go-ethereum

== Specification ==

Documentation:
- https://github.com/ethereum/devp2p/blob/master/rlpx.md

- There is a ECIES handshake for the RLPx transport protocol with auth and ack.
- Then, to complete the initial handshake, Hello messages have to be exchanged using the 'p2p' capability.

== Implementation decisions ==

- unwrap() is banned.
- prinln!() is banned.
- The capability 'eth' is not implemented.
- Ping and Pong messages from the 'p2p' capability are not implemented since go-ethereum sends a Disconnect when the 'eth' capability is not present.

== Rust code Style ==

- Use `cargo fmt`
- Use `cargo fix`
- Use `cargo clippy`
