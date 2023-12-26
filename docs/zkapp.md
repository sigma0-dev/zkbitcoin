# zkApps

We want to offer two functionnalities:

* **Stateless zkapps**: lock some funds and whoever can create a proof can spend _all_ the funds.
* **Stateful zkapps**: initialize some authenticated state on-chain and update it by providing a proof.

Let's see how both system works:

## Stateless zkapps

A stateless zkapp can be deployed by anyone (e.g. Alice) with a transaction to `0xzkBitcoin` that contains only one data field: 

1. Then digest of a verifier key.

In more detail, the transaction should look like this:

```rust
Transaction {
   version: Version::TWO,
   lock_time: absolute::LockTime::ZERO,
   input: vec![/* alice's funding */],
   output: vec![
      // one of the outputs is the stateless zkapp
      TxOut {
         value: /* amount locked */,
         script_pubkey: /* p2tr script to zkBitcoin pubkey */,
      },
      // the first OP_RETURN output is the vk hash
      TxOut {
         value: /* dust value */,
         script_pubkey: /* OP_RETURN of VK hash */,
      },
      // any other outputs...
   ],
}
```

In order to spend such a transaction, someone (e.g. Bob) needs to produce:

1. The verifier key that hashes to that digest.
2. An unsigned transaction that consumes a stateless zkapp (as input), and produces a fee to the zkBitcoin fund (as output). All other inputs and outputs are free.
3. A proof that verifies with a single public input: a truncated transaction (so that the proof authenticates that specific transaction).

To reiterate, the public input is structured as follows:

```python
PI = [truncated_tixd]
```

When observing such a _valid_ request, the MPC committee will sign the zkapp input and return it to Bob.

In more detail, the following transaction is produced by Bob and sent to the MPC committee:

```rust
Transaction {
   version: Version::TWO,
   lock_time: absolute::LockTime::ZERO,
   input: vec![
      // one of the inputs contains the stateless zkapp
      TxIn {
         previous_output: OutPoint {
               txid: /* the zkapp txid */,
               vout: /* the output id of the zkapp */,
         },
         script_sig: /* p2tr script to zkBitcoin */,
         sequence: Sequence::MAX,
         witness: Witness::new(),
      }
      // any other inputs...
   ],
   output: vec![
      // one of the outputs contains a fee to zkBitcoinFund
      TxOut {
         value: /* ZKBITCOIN_FEE */,
         script_pubkey: /* locked for zkBitcoinFund */,
      }
      // any other outputs...
   ],
}
```

## Stateful zkapps

A statefull zkapp can be deployed with a transaction to `0xzkBitcoin` that contains two data field: 

1. The digest of a verifier key.
2. $N$ field elements that represent the initial state of the zkapp. If there's 0, the zkapp is treated as a stateless zkapp!

In more detail, the transaction should look like this:

```rust
Transaction {
   version: Version::TWO,
   lock_time: absolute::LockTime::ZERO,
   input: vec![/* alice's funding */],
   output: vec![
      // one of the outputs contain the stateful zkapp
      TxOut {
         value: /* amount locked */,
         script_pubkey: /* p2tr script to zkBitcoin */,
      },
      // the first OP_RETURN output is the vk hash
      TxOut {
         value: /* dust value */,
         script_pubkey: /* OP_RETURN of VK hash */,
      },
      // further OP_RETURN outputs contain the initial state
      // arbitrary spendable outputs are also allowed...
   ],
}
```

In order to spend such a transaction Bob needs to produce:

1. The verifier key that hashes to that digest.
2. An unsigned transaction that consumes a stateful zkapp (as input), and produces a fee to the zkBitcoin fund as well as a new stateful zkapp (as outputs). All other inputs and outputs are free.
3. A number of public inputs in this order:
   1. The previous state as $N$ field elements. (TODO: do we want to replace this with a poseidon hash? heh)
   2. The new state as $N$ field elements (TODO: same question)
   3. A truncated SHA-256 hash of the transaction id (authenticating the transaction).
   4. An amount `amount_out` to withdraw.
   5. An amount `amount_in`to deposit.
4. A proof that verifies for the verifier key and the previous public inputs.

To reiterate, the public input is structured as follows:

```python
PI = [new_state | prev_state | truncated_txid | amount_out | amount_in ]
```

> Note: we place `new_state` first, because outputs in Circom are placed first (see [this tweet](https://twitter.com/tjade273/status/1732067115190956085)).

Because Bob's transaction will contain the new state, Bob needs to run a proof with `truncated_txid=0` first in order to obtain the new state, then run it again with the `txid` obtained. For this reason, **it is important that the output of the circuit is not impacted by the value of `truncated_tixd`**.

When receiving such a _valid_ request (e.g. proof verifies), the MPC committee signs the zkapp input of the transaction and returns it to Bob.

In more detail:

```rust
Transaction {
   version: Version::TWO,
   lock_time: absolute::LockTime::ZERO,
   input: vec![
      // one of the inputs contains the stateful zkapp
      TxIn {
         previous_output: OutPoint {
               txid: /* the zkapp txid */,
               vout: /* the output id of the zkapp */,
         },
         script_sig: ScriptBuf::new(),
         sequence: Sequence::MAX,
         witness: Witness::new(),
      }
      // other inputs are allowed...
   ],
   output: vec![
      // one of the outputs is a fee to the zkBitcoin fund
      TxOut {
         value: /* ZKBITCOIN_FEE */,
         script_pubkey: /* locked for zkBitcoinFund */,
      }
      // one of the outputs contain the new stateful zkapp
      TxOut {
         value: /* the zkapp value updated to reflect amount_out and amount_in */,
         script_pubkey: /* locked for zkBitcoin */,
      },
      // the first OP_RETURN output is the vk hash
      TxOut {
         value: /* dust value */,
         script_pubkey: /* OP_RETURN of VK hash */,
      },
      // further OP_RETURN outputs contain the new state
      // arbitrary spendable outputs are also allowed...
   ],
}
```
