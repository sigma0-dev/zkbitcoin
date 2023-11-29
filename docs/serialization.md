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

[This article](https://github.com/jimmysong/programmingbitcoin/blob/master/ch13.asciidoc) has a similar explanation on the serialization.

Also this has a nice visualization: https://bc-2.jp/tools/txeditor2.html

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

## There be dragons

Interestingly, the segwit serialization (done with Bitcoin rust) doesn't seem to work with what bitcoind expects. 

The transaction serialized in hex without segwit:

020000000001e8030000000000004076a914000000000000000000000000000000000000000088ac6a200000000000000000000000000000000000000000000000000000000000000000040000000000000000

The default, serialized with segwit:

0200000000010001e8030000000000004076a914000000000000000000000000000000000000000088ac6a200000000000000000000000000000000000000000000000000000000000000000040000000000000000

It seems like the only difference is 2 bytes `0x0001` which represent the segwit_marker (`0x00`) and the segwit_flag (`0x01`).

If we sent the segwit serialized one, we get the following error:

```
{"result":null,"error":{"code":-22,"message":"TX decode failed"},"id":"whatevs"}
```

[decoderawtransaction](https://github.com/bitcoin/bitcoin/blob/16b5b4b674414c41f34b0d37e15a16521fb08013/src/rpc/rawtransaction.cpp#L459) has the following comment:

> iswitness: depends on heuristic tests, Whether the transaction hex is a serialized witness transaction.
>
> If iswitness is not present, heuristic tests will be used in decoding.
> If true, only witness deserialization will be tried.
> If false, only non-witness deserialization will be tried.
> This boolean should reflect whether the transaction has inputs
> (e.g. fully valid, or on-chain transactions), if known by the caller."

The function logic calls [DecodeHexTx](https://github.com/bitcoin/bitcoin/blob/master/src/core_read.cpp#L194) which calls [DecodeTx](https://github.com/bitcoin/bitcoin/blob/master/src/core_read.cpp#L123) which has the following comment:

```rust
// General strategy:
// - Decode both with extended serialization (which interprets the 0x0001 tag as a marker for
//   the presence of witnesses) and with legacy serialization (which interprets the tag as a
//   0-input 1-output incomplete transaction).
//   - Restricted by try_no_witness (which disables legacy if false) and try_witness (which
//     disables extended if false).
//   - Ignore serializations that do not fully consume the hex string.
// - If neither succeeds, fail.
```

so if we're not passing anything it should detect the special serialization... so I'm not sure why it's failing.

Turns out I believe there's a bug in the lib we're using https://github.com/rust-bitcoin/rust-bitcoin/pull/2239
