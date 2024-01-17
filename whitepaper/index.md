# zkBitcoin: zero-knowledge applications for Bitcoin

Authors: David Wong and Ivan Mikushin

## Abstract

We introduce a light multi-party computation protocol to verify zero-knowledge proof circuits on Bitcoin. This unlocks two use-cases: stateless zero-knowledge applications that lock funds on Bitcoin until users unlock them using zero-knowledge proofs, and stateful zero-knowledge applications that allow users to update, deposit, and withdraw from a zero-knowledge application using zero-knowledge proofs. Since zero-knowledge proofs can't be verified directly on Bitcoin (for lack of optimized opcodes) we use a multi-party committee to verify them off-chain and compute a single on-chain signature. The particularity of the protocol is that it is akin to a minimal layer 2 on top of Bitcoin that uses Bitcoin as a data-availability layer. Specifically, the committee in charge of verifying zero-knowledge proofs does not have to be connected to the chain as hashes of circuits (verifier keys) are stored in UTXOs on-chain, and the latest state of a (stateful) application is also stored and kept on-chain.

keywords: zero-knowledge proofs, ZKP, multi-party computation, MPC, L2

## 1. Introduction

[It is documented](https://cointelegraph.com/magazine/satoshi-nakamoto-zk-proofs-bitcoin/) that the first time Satoshi (the inventor of Bitcoin) [mentioned zero-knowledge proofs](https://bitcointalk.org/index.php?topic=770.0), he found the technology interesting but did not know how to apply it.

![satoshi on zk](https://hackmd.io/_uploads/H1lKsnp8p.png)

3 years later, the [Zerocoin paper from Miers et al.](https://ieeexplore.ieee.org/document/6547123) was published at the 2013 IEEE Symposium on Security and Privacy, introducing a way to implement a cryptocurrency using zero-knowledge proofs. The paper was novel in that it successfuly managed to hide the sender, recipient, and amount being transfered in each transaction. 3 more years and a new cryptocurrency implementing the ideas from the Zerocoin paper and forking the codebase of Bitcoin was launching: [Zcash](https://z.cash/).

Today, Zcash still has no programmability (so-called smart contracts), and Bitcoin still has no support for zero-knowledge proofs. As cryptocurrencies are slow to make progress, new ones had to take advantage of all the recent advances in the field of zero-knowledge proofs. Cryptocurrencies like [Mina](https://minaprotocol.com/) and [Aleo](https://aleo.org/) were proposed as cryptocurrencies that provide programmable constructs augmented with zero-knowledge proofs (allowing applications to have privacy), other projects like [Aztec Network](https://aztec.network/) built on top of existing cryptocurrencies like Ethereum (as so-called "layer 2s") to provide similar privacy-enhance smart contracts.

While Zcash and the other technologies mentioned were big departure in design from Bitcoin, is it sensible that today Bitcoin could still benefit from zero-knowledge proofs without considerably changing its design. Bitcoin's scripting language is too limited to verify zero-knowledge proofs, but one could consider adding new opcodes to provide such a functionality (we discuss this further in the next section on related work). Unfortunately, this would be quite an important change that would require a hard-fork, and if previous history tells us anything such hard-forks often ends up splitting the community in two different versions of Bitcoin (the one that accepted the change, and the one that refused the change).

In this paper we introduce a different path: an extremely light service sitting on top of Bitcoin (so-called layer 2), and with no knowledge of the actual canonical blockchain of Bitcoin. The service splits the ownership of a Bitcoin wallet between a multi-party committee. The committee is then in charge of unlocking or updating a zero-knowledge application by signing user-provided transactions in the presence of valid user-provided proofs.

We released the code behind this paper in https://github.com/sigma0-xyz/zkbitcoin, and we are running a version of this project on the testnet (TODO: explorer + launch page link).

TODO: mention who is the committee that we are using?

The rest of this paper goes like this: section 2 talks about related work, section 3 gives an overview of the protocol, section 4 gives a more detailed specification of the protocol, section 5 discusses security, section 6 gives benchmarks, section 7 concludes and discusses future work.

## 2. Related work

In this section we survey zero-knowledge projects related to Bitcoin.

[ZeroSync](https://zerosync.org/zerosync.pdf) is a project that attempts to provide a verifiable light client for Bitcoin. That is, its goal is to create a zero-knowledge proof that verifies the integrity of the entirety of the canonical chain of Bitcoin at some point in time (also called "state proofs"). As such, it does not offer additional functionalities on top of Bitcoin, but can help external applications to make use of Bitcoin. 

[BitVM](https://bitvm.org/bitvm.pdf) is a proposal that does not use zero-knowledge proofs but is worth mentioning as it augments Bitcoin programmability with fraud proofs. That is, it allows users to lock funds using binary circuits, and unlock funds based on the execution of such circuits. If a user provides an incorrect execution, another user can then provide a fraud proof. The upside is that, like our proposal, it increases the size of what's possible in terms of smart contracts on Bitcoin. Unlike our proposal it does not provide any privacy. The downsides are also that it is quite an inefficient protocol as fraud proofs look unrealistic in practice, spanning over a number of transactions linear in size of the circuit.

[Alpen Labs](https://alpenlabs.io/) is a Layer 2 that settles on Bitcoin using a zero-knowledge proof of its state transitions (so-called "zk rollups"). Its proposition is the most straight-forward one: introducing a new op code (`OP_VERIFYSTARKPROOF`) to verify zero-knowledge proofs on Bitcoin. As we discussed in the introduction, this solution is the most elegant one, but it requires a hard-fork of Bitcoin.

![OP_VERIFYSTARKPROOF](https://hackmd.io/_uploads/Hkyh33pUT.png)

[Chainway](https://chainway.xyz/) is another "zk rollup" which settles on Bitcoin. There is currently little information about the project so it is not clear who verifies proofs and how funds go in and out of the layer 2.

TODO: https://github.com/boltlabs-inc/zeekoe

TODO: https://iohk.io/en/research/library/papers/zendoo-a-zk-snark-verifiable-cross-chain-transfer-protocol-enabling-decoupled-and-decentralized-sidechains/

TODO: block stream also? (https://blog.blockstream.com/bulletproofs-a-step-towards-fully-anonymous-transactions-with-multiple-asset-types/)

## 3. Overview

The zkBitcoin protocol works with the assumption that there exists a committee of participants that are willing to verify zero-knowledge proofs for users. This committee controls a Bitcoin address, that we'll call `0xzkBitcoin`, using a threshold signature scheme. This way, no member of the committee knows the private key of the wallet, and UTXOs can only be spent with the agreement of a threshold of committee members.

We support two types of zero-knowledge applications (zkapps): _stateless_ and _stateful_ zkapps. Let's first explain how stateless zkapps work.

Stateless zkapps are simply an augmentation of the Bitcoin scripting language, that allows a user to lock funds using a zero-knowledge circuit instead of a Bitcoin script. A user can _deploy_ such a stateless zkapp by sending a transaction to the Bitcoin network containing a UTXO spendable by `0xzkBitcoin`. In addition, the transaction must also have an unspendable UTXO containing the hash of the verifier key associated to the zero-knowledge proof circuit.

The transaction ID of this transaction represents the stateless zkapp. To unlock funds from this zkapp/UTXO, another user can provide the committee with a transaction that spends the UTXO. If the request is accompanied with a valid zero-knowledge proof that the user could execute the circuit authenticated by the unspendable UTXO, the committee will perform a multi-party computation to sign the transaction and return it to the user. The user can then broadcast the transaction to the Bitcoin network and unlock the funds.

It is important to note that the committee members did not need access to the Bitcoin blockchain to perform their duty: they simply had to verify that the UTXO being spent was part of a transaction matching the previous description of a deployment transaction.

Stateful zkapps are similar, except that the second UTXO containing a hash of the verifier key also contains the state of the zkapp. For the deploy transaction, this means that the second UTXO must also contain the initial state.

Users who want to use a stateful zkapp must create a transaction that spends the zkapp and produce a new zkapp as a new UTXO to `0xzkBitcoin` and a UTXO of the hashed verifier key and new state. The funds locked in the updated zkapp must match the following formula: 

$$b_{\text{new}} = b_{\text{old}} + b_{\text{amount_in}} - b_{\text{amount_out}}$$

In other words, the new balance is the old balance plus anything that was deposited and minus anything that was withdrawn.

For the previously discussed mechanisms to work, a stateful zkapp must be linked to a zero-knowledge circuit that takes 4 public inputs in this order: the new state, the previous state, the amount out and the amount in.

In addition, to ensure that a proof is strongly tied to a specific transaction, one additional public input is added to both stateless and stateful zero-knowledge circuits: the transaction ID spending the zkapp.

In the next section we give a more detailed specification of the protocol.

## 4. Protocol

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
2. 1 field element that represent the initial state of the zkapp. (If there's none the zkapp is treated as a stateless zkapp.)

> Note: we are limited to 1 field element as Bitcoin nodes don't forward transactions with more than one `OP_RETURN` output. An `OP_RETURN` seems to be limited to pushing 80 bytes of data, as such we are quite limited here.

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
      // an OP_RETURN output containing the vk hash concatenated with the state
      TxOut {
         value: /* dust value */,
         script_pubkey: /* OP_RETURN of VK hash and new state */,
      },
      // arbitrary spendable outputs are also allowed...
   ],
}
```

In order to spend such a transaction Bob needs to produce:

1. The verifier key that hashes to that digest.
2. An unsigned transaction that consumes a stateful zkapp (as input), and produces a fee to the zkBitcoin fund as well as a new stateful zkapp (as outputs). All other inputs and outputs are free.
3. A number of public inputs in this order:
   1. The previous state as 1 field element.
   2. The new state as 1 field element.
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
      // an OP_RETURN output containing the vk hash as well as the new state
      TxOut {
         value: /* dust value */,
         script_pubkey: /* OP_RETURN of VK hash and new state */,
      },
      // arbitrary spendable outputs are also allowed...
   ],
}
```

## 5. Security

* Key refresh from https://github.com/cronokirby/cait-sith/blob/main/docs/key-generation.md
* Committee could be a trusted set of entities (we're trying to figure out who would be interested)
* run MPC in SGX, and we could publish the SGX attestation that the shares were generated correctly
* after that, liveness could still be an issue, as currently the network might not have the best incentives to run (future work?)

## 6. Benchmarks

* we should try to run the protocol with like 100 participants and a threshold of 51? see how efficient it is (to me it looks like FROST is a very efficient protocol)
* maybe the FROST paper already has benchmarks?

## 7. Conclusion and Future work

## 8. References