# Instructions

Tested on Debian GNU/Linux 12 (bookworm) with bash.

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
