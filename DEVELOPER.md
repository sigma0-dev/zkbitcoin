# Developer Guide

## Set up Bitcoin CLI

This is needed to interact with a Bitcoin node.

If you are on Mac:

```shell
brew install bitcoin
```

## Set up a bitcoind node

Users and MPC nodes need access to a Bitcoin node to query the blockchain.

1. download latest release on https://bitcoincore.org/en/releases/ (for example `wget https://bitcoincore.org/bin/bitcoin-core-25.1/bitcoin-25.1-x86_64-linux-gnu.tar.gz`)
2. you can run bitcoind with `./bin/bitcoind -testnet -server=1 -rpcuser=root -rpcpassword=hello`
    - or you can set these in `bitcoin.conf` and copy that file in `~/.bitcoin/bitcoin.conf`
3. you can query it for testing with `./bin/bitcoin-cli -rpcport=18332 -rpcuser=root -rpcpassword=hellohello getblock`

You can also use curl to query it:

```console
curl --user root --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblock", "params": ["00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"]}' -H 'content-type: text/plain;' http://127.0.0.1:18332/
```

If you want to expose this to the internet, you can setup a reverse proxy like nginx. This is the config I use (in `/etc/nginx/sites-enabled/bitcoind-proxy.conf`):

```
server {
    listen 18331;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:18332;
    }
}
```

## Our own bitcoind

We're running one on digitalocean at [146.190.33.39](http://146.190.33.39). You can query it with:

```console
curl --user root:hellohello --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockchaininfo", "params": []}' -H 'content-type: text/plain;' http://146.190.33.39:18331
```

### Our wallets

I created a wallet called `mywallet` via:

```shell
bitcoin-cli -testnet -rpcconnect=146.190.33.39 -rpcport=18331 -rpcuser=root -rpcpassword=hellohello createwallet mywallet
```

Created another wallet `wallet2`:

```shell
bitcoin-cli -testnet -rpcconnect=146.190.33.39 -rpcport=18331 -rpcuser=root -rpcpassword=hellohello createwallet wallet2
```

You can get information about a wallet using:

```shell
bitcoin-cli -testnet -rpcconnect=146.190.33.39 -rpcport=18331 -rpcuser=root -rpcpassword=hellohello -rpcwallet=mywallet getwalletinfo
```

Obtain a new address via:

```shell
bitcoin-cli -testnet -rpcconnect=146.190.33.39 -rpcport=18331 -rpcuser=root -rpcpassword=hellohello -rpcwallet=mywallet getnewaddress
```

(I believe we can switch wallets by using the `loadwallet` command.)

The addresses I've been using:

* `tb1pxggs3tg09877hzqy6fhrg3wjat8c6jue83r3surjtwpgtsqwp5wqe5xpj5`: the zkBitcoin address, where zkapps have to be sent to.
* `tb1pv7auuumlqm9kehlep4y83xcthyma5yvprvlx39k7xvveh48976sq7e6sr5`: the zkBitcoin fund, where fees are being paid to when using zkapps (deploying is free).
* `tb1q6vjawwska63qxf77rrm5uwqev0ma8as8d0mkrt`: Bob address.

It's a good idea to fund them from times to times using [a faucet](https://bitcoinfaucet.uo1.net/send.php).

Note that you can get their associated public keys via:

```shell
bitcoin-cli -testnet -rpcconnect=146.190.33.39 -rpcport=18331 -rpcuser=root -rpcpassword=hellohello -rpcwallet=mywallet getaddressinfo "tb1q5pxn428emp73saglk7ula0yx5j7ehegu6ud6ad"
```

## Non-user nodes

### Generate committee with trusted dealer

```shell
cargo run --bin cli -- generate-committee --num 3 --threshold 2 --output-dir tests/
```

### Start a committee node 

```shell
RPC_WALLET="mywallet" RPC_ADDRESS="http://146.190.33.39:18331" RPC_AUTH="root:hellohello" cargo run -- start-committee-node --key-path examples/committee/key-0.json --publickey-package-path examples/committee/publickey-package.json --address "127.0.0.1:8891"
```

### Start an orchestrator/coordinator?

```shell
RPC_WALLET="mywallet" RPC_ADDRESS="http://146.190.33.39:18331" RPC_AUTH="root:hellohello" cargo run  -- start-orchestrator --threshold 2 --publickey-package-path examples/committee/publickey-package.json --committee-cfg-path examples/committee/committee-cfg.json
```

then you can query it like so:

```shell
curl -X POST http://127.0.0.1:8888 -H 'Content-Type: application/json' -d '{"jsonrpc": "2.0", "id": "thing", "method":"unlock_funds","params": [{"txid": "...", "vk": "...", "proof":"...", "public_inputs": []}]}'
```

or with the unlock funds CLI command.
