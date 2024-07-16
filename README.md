
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

== Rough edges ==

- The RLPx spec says ephemeral_key = edch.agree(ephemeral-privkey, remote-ephemeral-pubk), so in auth, I sent initiator-ephemeral-pubk and not initiator-static-pubk.
- Since I send initiator-ephemeral-pubk and not initiator-static-pubk, I put initiator-ephemeral-pubk in node_id in initiator_Hello instead of initiator-static-pubk
to avoid "Unexpected identity in handshake. I am not sure what is the correct thing to do.
- Go Ethereum responds with Disconnect with reason = [1, 0, 3], in the Go Ethereum, I logged the reason and it is 3. 0x03 is for reason = "Useless peer". The RLP bytes should be simply [3]...