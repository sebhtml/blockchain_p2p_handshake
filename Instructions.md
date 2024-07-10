
Part 1: start the target node

1. Start a Ethereum node using Docker:
```bash
docker run -d --name ethereum-node -v /Users/alice/ethereum:/root \
    -p 30303:30303 \
    ethereum/client-go
```
2. Run `docker ps` to get the identifier of the Docker container.
3. Run `docker logs <identifier>`.
4. In the output, locate the line with enode:// This is the Ethereum node ID.

Part 2: do the handshake

1. Install Rust using "rustup" (see https://www.rust-lang.org/tools/install )
2. Untar blockchain_p2p_handshake.tar.gz
3. Go to blockchain_p2p_handshake
4. Type (you need to change the enode to use the id from step 4 in part 1.)
```bash
cargo run --release -- --recipient \
  enode://113575d657ca12f9c350994b6d0b30fc211e269c0be6b8f0a840add85c179f0c74fbc35125c5cd219ce3b60e9c65d78607ef00ddb1ccc6667bd7a9df936f444e@127.0.0.1:30303
```
