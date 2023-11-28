# Serialization

The Bitcoin RPC API returns and expects transactions in some hex format. For example, if I use `createrawtransaction` to create some transaction with no inputs and one output::

```
./bin/bitcoin-cli -testnet -rpcport=18332 -rpcuser=root -rpcpassword=hellohello createrawtransaction "[]" "{\"tb1q6nkpv2j9lxrm6h3w4skrny3thswgdcca8cx9k6\":0.01}"
```

I get the following hex string as response:

```
02000000000140420f0000000000160014d4ec162a45f987bd5e2eac2c39922bbc1c86e31d00000000
```

The implementation of the encoding is [here in bitcoind](https://github.com/bitcoin/bitcoin/blob/535424a10b4462a813b9797f3c607b97a0ca9b19/src/rpc/rawtransaction.cpp#L454C12-L454C23), which sets `without_witness=false`, to use the latest [segwite update]() which, IIUC, moves some witness data (needed to validate the transaction) outside of the transaction.

It is also [here in rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin/blob/2b0e85863f3200598515440d697fc0e5429cbdec/bitcoin/src/blockdata/transaction.rs#L1062).

It seems like things get encoded in this order without segwit: `version|inputs|outputs|lock_time`. And it seems like things get encoded in this order with segwite: `version|segwit_marker|segwit_flag|inputs|outputs|witnesses|lock_time`.

If I pass it to `decoderawtransaction` or an online decoder like https://btc.com/tools/tx/decode I get:

```json
{
    "txid": "078883f990a287d6f64576f17b869fe664204485909c929404d95a88caff965d",
    "hash": "078883f990a287d6f64576f17b869fe664204485909c929404d95a88caff965d",
    "version": 2,
    "size": 41,
    "vsize": 41,
    "weight": 164,
    "locktime": 0,
    "vin": [],
    "vout": [
        {
            "value": 0.01,
            "n": 0,
            "scriptPubKey": {
                "asm": "0 d4ec162a45f987bd5e2eac2c39922bbc1c86e31d",
                "desc": "addr(bc1q6nkpv2j9lxrm6h3w4skrny3thswgdccad7akdf)#fhmjzx3q",
                "hex": "0014d4ec162a45f987bd5e2eac2c39922bbc1c86e31d",
                "address": "bc1q6nkpv2j9lxrm6h3w4skrny3thswgdccad7akdf",
                "type": "witness_v0_keyhash"
            }
        }
    ]
}
```

It seems important to understand where the witness goes