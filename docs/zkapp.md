# zkApps

We want to offer two functionnalities:

* **Stateless zkapps**: lock some funds and whoever can create a proof can spend _all_ the funds.
* **Stateful zkapps**: initialize some authenticated state on-chain and update it by providing a proof.

Let's see how both system works:

## Stateless zkapps

A stateless zkapp can be deployed with a transaction to `0xzkBitcoin` that contains only one data field: 

1. Then digest of a verifier key.

In order to spend such a transaction Bob needs to produce:

1. The verifier key that hashes to that digest.
2. Their Bitcoin address.
4. A proof that verifies with a single public input: a truncated SHA-256 hash of their bitcoin address (so that the proof authenticates their address).

When observing such a _valid_ request, the MPC committee will produce a transaction that:

1. Spends the zkapp as first input.
2. Creates an output of `ZKBITCOIN_FEE` for `0xzkBitcoin`.
3. Creates an output for the whole amount (minus Bitcoin fees) to Bob's address.

## Stateful zkapps

A statefull zkapp can be deployed with a transaction to `0xzkBitcoin` that contains two data field: 

1. The digest of a verifier key.
2. $N$ field elements that represent the initial state of the zkapp. If there's 0, the zkapp is treated as a stateless zkapp!

In order to spend such a transaction Bob needs to produce:

1. The verifier key that hashes to that digest.
2. A Bitcoin public address
3. A number of public inputs in this order:
   1. The previous state as $N$ field elements. (TODO: do we want to replace this with a poseidon hash? heh)
   2. The new state as $N$ field elements (TODO: same question)
   3. A truncated SHA-256 hash of a recipient bitcoin address. This can be derived automatically from the Bitcoin public address given previously and does not need to be sent.
   4. An amount `amount_out` to withdraw.
   5. An amount `amount_in`to deposit.
4. A proof that verifies for the verifier key and the previous public inputs.

```
PI = [prev_state | new_state | recipient_address_hash | amount_out | amount_in ]
```

When receiving such a _valid_ request (e.g. proof verifies), the MPC committee will produce a transaction that:

1. Creates an output of `ZKBITCOIN_FEE` for `0xzkBitcoin`.
2. Creates an output of `amount_out` satoshis to the given recipient address, if $A$ is not 0.
3. Moves the remaining funds (minus fees for the Bitcoin network) to zkBitcoin's address, with the following data:
   1. The same verifier key digest that was used previously.
   2. The new state as $N$ field elements.

TODO: How is a zkapp funded?

idea: bob sends a request that contains inputs that can be used to fund the transaction

## zkapp data format

Currently, the bitcoin rpc node will mess with the order of UTXO when we create zkapp transactions.

Specifically, and only for Alice's transaction, the change will be created as an output that can be situated anywhere (or something like that).

For this reason, when an MPC node retrieves a zkapp from a txid, it needs to look at all the first two UTXO to ensure that one of them is to the 0xzkBitcoin address:

```rust
    let mut vout_of_zkbitcoin_utxo = 0;
    let mut outputs = raw_tx.output.iter();
    let locked_value = {
        let output = outputs.next().context("tx has no output")?;
        if output.script_pubkey != expected_script {
            // the first output must have been the change, moving on to the second output
            let output = outputs.next().context("tx has no output")?;
            if output.script_pubkey != expected_script {
                bail!("Transaction's first or second output must be for 0xzkBitcoin");
            }
            vout_of_zkbitcoin_utxo = 1;
            output.value
        } else {
            output.value
        }
    };
```

This should not be a problem for updates of stateful zkapps as these updates don't use the bitcoin rpc to fund the transaction (the transaction is funded via $ contained in the smart contract).
