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

If you want to expose this to the internet, you can setup a reverse proxy like [nginx](https://www.nginx.com/). This is the config I use (in `/etc/nginx/sites-enabled/bitcoind-proxy.conf`):

```
server {
    listen 18331;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:18332;
    }
}
```

## Non-user nodes

### Generate committee with trusted dealer

```shell
cargo run -- generate-committee --num 3 --threshold 2 --output-dir tests/
```

### Start a committee node 

```shell
RUST_LOG=debug cargo run -- start-committee-node --key-path examples/committee/key-0.json --publickey-package-path examples/committee/publickey-package.json --address "127.0.0.1:8891"
```

### Start an orchestrator/coordinator

```shell
RUST_LOG=debug cargo run  -- start-orchestrator --publickey-package-path examples/committee/publickey-package.json --committee-cfg-path examples/committee/committee-cfg.json
```

then you can query it like so:

```shell
curl -X POST http://127.0.0.1:8888 -H 'Content-Type: application/json' -d '{"jsonrpc": "2.0", "id": "thing", "method":"unlock_funds","params": [{"txid": "...", "vk": "...", "proof":"...", "public_inputs": []}]}'
```

or with the unlock funds CLI command.

### Minimal setup for a node

* setup a server somewhere
  * the digital ocean regular $12/month is the minimal requirement (2GB of memory)
* ssh into it
* install essential tools 
  * `sudo apt install build-essential pkg-config`
* install rustup (https://rustup.rs/) and proceed with default installation
  * `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
  * you might have to restart your shell or do `source "$HOME/.cargo/env"`
* install snarkjs (https://github.com/iden3/snarkjs)
  * `apt install nodejs npm`
  * `npm install -g snarkjs@latest`
* setup nginx () to expose our node to the internet
  * `sudo apt install nginx`
  * `sudo nano /etc/nginx/sites-available/mpc-node.conf`
  * with the following content:
    ```
    server {
        listen 18332 default_server;
        listen [::]:18332 default_server;

        server_name _;

        location / {
            proxy_pass http://127.0.0.1:8891;
        }
    }
    ```
    * `sudo ln -s /etc/nginx/sites-available/mpc-node.conf /etc/nginx/sites-enabled/mpc-node.conf`
    * `sudo nginx -t` <-- test if the config is ok
    * `sudo systemctl restart nginx`
* `git clone https://github.com/sigma0-xyz/zkbitcoin`
* `cd zkbitcoin`
* `RUST_LOG=debug cargo run -- start-committee-node --key-path examples/committee/key-0.json --publickey-package-path examples/committee/publickey-package.json --address "127.0.0.1:8891"`
