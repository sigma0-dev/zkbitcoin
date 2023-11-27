# zkBitcoin

## Set up bitcoind

Both users and nodes need access to Bitcoin.

1. download latest release on https://bitcoincore.org/en/releases/ (for example `wget https://bitcoincore.org/bin/bitcoin-core-25.1/bitcoin-25.1-x86_64-linux-gnu.tar.gz`)
2. configure `bitcoin.conf` to serve a JSON-RPC API:
    - `server=1`
    - `rpcuser=root`
    - `rpcpassword=hellohello`
3. you can run bitcoind with `./bin/bitcoind -testnet`
4. you can query it for testing with `./bin/bitcoin-cli -rpcport=18332 -rpcuser=root -rpcpass^Crd=hellohello getinfo`

