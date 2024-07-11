
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
  enode://edd46ce2368c4fecd13749968699bbaaec190acaf296616354b4d9284a78be17a2b9a0be2c5ca1d55ca3d22588d59efe680505aeb36c10776ecccbb38395ee3b@127.0.0.1:30303
```
