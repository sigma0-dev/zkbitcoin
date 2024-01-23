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

## Run an MPC node with Docker

If you're using the DigitalOcean Docker droplet (or any Linux server protected with UFW), you need to open the port first:

```shell
sudo ufw allow 8891
```

1. Fetch the image:

```shell
docker pull imikushin/zkbitcoin
```

2. Create the zkBitcoin node container (creates the `keys` Docker volume if you don't already have it):

```shell
docker create --restart=always -v keys:/keys --name zkbtc-node -p 8891:8891 imikushin/zkbitcoin \
  zkbtc start-committee-node \
  --key-path=/keys/key.json --publickey-package-path=/keys/publickey-package.json \
  --address=0.0.0.0:8891
```

3. Create the keys (`./key.json`, `./publickey-package.json`) and copy them into the `keys` volume:

```shell
docker cp ./key.json zkbtc-node:/keys/key.json
docker cp ./publickey-package.json zkbtc-node:/keys/publickey-package.json
```

4. Start the node:

```shell
docker start zkbtc-node
```

You should now see the container show up in the printout from running the `docker ps -a` shell command:

```
CONTAINER ID   IMAGE                 COMMAND                  CREATED             STATUS          PORTS                    NAMES
b3d2e7c028ce   imikushin/zkbitcoin   "zkbtc start-committ…"   About an hour ago   Up 55 minutes   0.0.0.0:8891->8891/tcp   zkbtc-node
```

Follow its logs with `docker logs -f zkbtc-node`:
```
[2024-01-20T22:28:35Z INFO  zkbtc] - zkbitcoin_address: tb1p5sfstsnt9akcqf9zkm6ulke8ujwakjd8kdk5krws2th4ds238meqq4awtv
[2024-01-20T22:28:35Z INFO  zkbtc] - zkbitcoin_fund_address: tb1pv7auuumlqm9kehlep4y83xcthyma5yvprvlx39k7xvveh48976sq7e6sr5
[2024-01-20T22:28:35Z INFO  zkbitcoin::committee::node] - starting node for identifier Identifier("0000000000000000000000000000000000000000000000000000000000000001") at address http://0.0.0.0:8891
```

The node is now running in the background and listening on port 8891, and you can verify if that's the case (from your local machine):
```shell
nc -zv ${SERVER_IP} 8891
```

### Updating the MPC node software

```shell
docker pull imikushin/zkbitcoin
docker rm -f zkbtc-node
```

Now re-run steps 2 and 4 from above: create the container and then start it (the `keys` volume is re-used).

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
