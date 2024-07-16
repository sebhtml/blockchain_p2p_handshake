# Challenge for applying for the Senior Rust Engineer at Eiger.

Challenge: https://github.com/eqlabs/recruitment-exercises/blob/master/node-handshake.md

# Selected  Publicly available P2P node (e.g. a blockchain one) implementation

I choose Ethereum: https://github.com/ethereum/go-ethereum

# Specification

Documentation:
- https://github.com/ethereum/devp2p/blob/master/rlpx.md

- There is a ECIES handshake for the RLPx transport protocol with auth and ack.
- Then, to complete the initial handshake, Hello messages have to be exchanged using the 'p2p' capability.

# Implementation decisions

- unwrap() is banned.
- prinln!() is banned.
- The capability 'eth' is not implemented.
- Ping and Pong messages from the 'p2p' capability are not implemented since go-ethereum sends a Disconnect when the 'eth' capability is not present.
- The eth wire protocol is not implemented since it's not part of the handshake. https://github.com/ethereum/devp2p/blob/master/caps/eth.md

# Rust code Style

- Use `cargo fmt`
- Use `cargo fix`
- Use `cargo clippy`

# Instructions

Tested on Debian GNU/Linux 12 (bookworm) with bash and rustc 1.81.0-nightly.

1. Start a Ethereum node using Docker:
```bash
docker run -d --name ethereum-node -v $HOME/Users/alice/ethereum:/root \
    -p 30303:30303 \
    ethereum/client-go:v1.14.7
```
2. Run `docker logs <container-id>`. (The container ID is the last line in the terminal.)
3. In the output, locate the line with enode:// This is the Ethereum node ID.
4. Install Rust using "rustup" (see https://www.rust-lang.org/tools/install )
5. Untar blockchain_p2p_handshake.tar.gz
6. Go to blockchain_p2p_handshake
7. Run the RLPx p2p client (you need to change the enode to use the id from step 3)
```bash
RECIPIENT="enode://2d02bb84cbe2bbc45867b497a4a70892f3656ca796303d53839293c8a90b279b3356e10de96483ea49072df54ba6e66c9fd38fef76ca4364b36ae366ba385eaa@127.0.0.1:30303"
RUST_LOG=info cargo run --release -- --recipient $RECIPIENT
```

# How to verify that the handshake has concluded ?

- The Hello messages from the initiator and the Hello message from the recipient are logged in the terminal.
- The recipient should send a Disconnect with reason "Useless peer" (3) because the initiator does not implement the capability "eth".
- The last line should say that the handshake was successful.
- There should be no error.

# Rough edges

- The RLPx spec says ephemeral_key = edch.agree(ephemeral-privkey, remote-ephemeral-pubk), so in auth, I sent initiator-ephemeral-pubk and not initiator-static-pubk.
- Since I send initiator-ephemeral-pubk and not initiator-static-pubk, I put initiator-ephemeral-pubk in node_id in initiator_Hello instead of initiator-static-pubk
to avoid "Unexpected identity in handshake. I am not sure what is the correct thing to do. The handshake works, but initiator-ephemeral-pubk is not a node-id.
- Go Ethereum responds with Disconnect with reason = [1, 0, 3], in the Go Ethereum log, I logged the reason and it is 3. 0x03 is for reason = "Useless peer". The RLP bytes should be simply [3], not [1, 0, 3]. alloy-rlp fails to decode it.
