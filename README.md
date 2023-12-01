# zkBitcoin

## Set up Bitcoin CLI

```shell
brew install bitcoin
```

## Set up bitcoind

Both users and nodes need access to Bitcoin.

1. download latest release on https://bitcoincore.org/en/releases/ (for example `wget https://bitcoincore.org/bin/bitcoin-core-25.1/bitcoin-25.1-x86_64-linux-gnu.tar.gz`)
2. you can run bitcoind with `./bin/bitcoind -testnet -server=1 -rpcuser=root -rpcpassword=hello`
    - or you can set these in `bitcoin.conf` and copy that file in `~/.bitcoin/bitcoin.conf`
3. you can query it for testing with `./bin/bitcoin-cli -rpcport=18332 -rpcuser=root -rpcpassword=hellohello getblock`

you can also use curl to query it:

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

I'm running one on digitalocean at [146.190.33.39](http://146.190.33.39)

You can query it with:

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

Some addresses I've been using:

* `tb1q5pxn428emp73saglk7ula0yx5j7ehegu6ud6ad` <-- I put some bitcoins in there from [this faucet](https://bitcoinfaucet.uo1.net/send.php) (you can see the wallet on [this explorer](https://blockstream.info/testnet/address/tb1q5pxn428emp73saglk7ula0yx5j7ehegu6ud6ad) where 141 satoshis were paid as fee)
* `tb1q6nkpv2j9lxrm6h3w4skrny3thswgdcca8cx9k6`

Note that you can get their associated public keys via:

```shell
bitcoin-cli -testnet -rpcconnect=146.190.33.39 -rpcport=18331 -rpcuser=root -rpcpassword=hellohello -rpcwallet=mywallet getaddressinfo "tb1q5pxn428emp73saglk7ula0yx5j7ehegu6ud6ad"
```

## Use circom/snarkjs

The following script creates a `vk.json` which you can also see in [`fixtures/vk.json`](fixtures/vk.json)

```shell
# phase1
snarkjs powersoftau new bn128 14 phase1_start.ptau -v
snarkjs powersoftau contribute phase1_start.ptau phase1_end.ptau --name="First contribution" -v

# start of phase 2 (but don't do the phase 2)
snarkjs powersoftau prepare phase2 phase1_end.ptau phase2_start.ptau -v

# compile
circom circuit.circom --r1cs --wasm --sym

# create zkey
snarkjs plonk setup circuit.r1cs phase2_start.ptau circuit_final.zkey

# export vk
snarkjs zkey export verificationkey circuit_final.zkey vk.json
```

## CLI

### Deploy smart contract command

Alice can deploy a smart contract with verifier key `examples/circuit/vk.json` and with value `1000` with the following command:

```shell
RPC_WALLET="mywallet" RPC_ADDRESS="http://146.190.33.39:18331" RPC_AUTH="root:hellohello" cargo run --bin cli -- deploy-transaction --verifier-key-path examples/circuit/vk.json --public-inputs-path examples/circuit/public_inputs.json --satoshi-amount 1000
```

note that `examples/circuit/public_inputs.json` is also passed to fix inputs `a` and `b` in the circuit. At the moment you can also not fix any inputs, or fix the `a` input, or fix `a, b, c`, but you can't just fix `b` or `c` or `b, c` (basically we can fix a prefix since we don't pass indexes for the public inputs).

### Unlock funds command

```
TODO
```

### Generate committee with trusted dealer

```shell
cargo run --bin cli -- generate-committee --num 3 --threshold 2 --output-dir tests/
```

### Start a committee node 

```shell
cargo run  -- start-committee-node --key-path tests/key-0.json --publickey-package-path tests/publickey-package.json
```

### Start an orchestrator/coordinator??

TODO: do we need this 