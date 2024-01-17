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

$$
b_{\text{new}} = b_{\text{old}} + b_{\text{amount-in}} - b_{\text{amount-out}}
$$

In other words, the new balance is the old balance plus anything that was deposited and minus anything that was withdrawn.

For the previously discussed mechanisms to work, a stateful zkapp must be linked to a zero-knowledge circuit that takes 4 public inputs in this order: the new state, the previous state, the amount out and the amount in.

In addition, to ensure that a proof is strongly tied to a specific transaction, one additional public input is added to both stateless and stateful zero-knowledge circuits: the transaction ID spending the zkapp.

In the next section we give a more detailed specification of the protocol.

## 4. The zkBitcoin Protocol

In this section we fully review how the protocol works from the point of view of users, from the point of view of the service and the committee members. In addition, we also explain how to modify the [FROST]() threshold signature scheme in order to support Bitcoin taproot's schnorr signatures.

To recap, zkBitcoin offers two functionnalities:

* **Stateless zkapps**: lock some funds and whoever can create a proof can spend _all_ the funds.
* **Stateful zkapps**: initialize some authenticated state on-chain and update it by providing a proof.

In the next two subsection, we see how both system works.

### Stateless zkapps

A stateless zkapp can be deployed by anyone (e.g. Alice) with a transaction to `0xzkBitcoin` that contains only one data field: 

1. The digest of a verifier key.

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

### Stateful zkapps

A statefull zkapp can be deployed with a transaction to `0xzkBitcoin` that contains the following data: 

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

1. The verifier key that hashes to the digest of the verifier key.
2. An unsigned transaction that consumes a stateful zkapp (as input), and produces a fee to the zkBitcoin fund as well as a new stateful zkapp (as outputs). All other inputs and outputs are free.
3. A number of public inputs in this order:
   1. The new state as 1 field element.
   2. The previous state as 1 field element.
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

### MPC orchestrator

Characters:

* Alice, she locks fund in a "smart contract"
* Bob, he unlocks fund from the smart contract
* MPC members, a committee of N members, of which T < N needs to be online to unlock the funds by signing a transaction collaboratively (using [FROST](https://eprint.iacr.org/2020/852))
* Orchestrator, an endpoint that Bob can query to unlock the funds, the orchestrator literally "orchestrates" the signature by talking to the MPC members (MPC members don't talk to one another).

Flow:

The current proposed flow is the following:

- Bob sends a request to an orchestrator:

```rust
pub struct BobRequest {
    /// The transaction authenticated by the proof, and that Bob wants to sign.
    /// This transaction should contain the zkapp as input, and a fee as output.
    /// It might also contain a new zkapp as output, in case the input zkapp was stateful.
    pub tx: Transaction,

    /// The transaction that deployed the zkapp.
    /// Technically we could just pass a transaction ID, but this would require nodes to fetch the transaction from the blockchain.
    /// Note that for this optimization to work, we need the full transaction,
    /// as we need to deconstruct the txid of the input of `tx`.
    pub zkapp_tx: Transaction,

    /// The index of the input that contains the zkapp being used.
    // TODO: we should be able to infer this!
    pub zkapp_input: usize,

    /// The verifier key authenticated by the deployed transaction.
    pub vk: plonk::VerifierKey,

    /// A proof of execution.
    pub proof: plonk::Proof,

    /// In case of stateful zkapps, the update that can be converted as public inputs.
    pub update: Option<Update>,

    /// List of all the [TxOut] pointed out by the inputs.
    /// (This is needed to sign the transaction.)
    /// We can trust this because if Bob sends us wrong data the signature we create simply won't verify.
    pub prev_outs: Vec<TxOut>,
```

- The orchestrator validates the request and aborts if the request is not valid (proof does not verify, or txid has been spent, etc.)
- The orchestrator then hits the `/round_1_signing` endpoint of each MPC member (or a threshold of it) forwarding Bob's request as is.
- A member that receives such a request verifies the request as well, then starts a `LocalSigningTask` with a message set to the transaction to sign (which they can create deterministically, so that everyone has the same)

```rust
pub struct LocalSigningTask {
    /// So we know if we're processing the same request twice.
    pub proof_hash: [u8; 32],
    /// The smart contract that locked the value.
    pub smart_contract: SmartContract,
    /// transaction to sign.
    pub tx: Transaction,
    /// The previous outputs that are being spent by the transaction (needed to sign).
    pub prev_outs: Vec<TxOut>,
    /// The nonces behind these commitments
    pub nonces: round1::SigningNonces,
    // TODO: should we keep track of commitments here also to double check?
}
```

Members keep track of such signing tasks in a local hashmap:

```rust
signing_tasks: RwLock<HashMap<Txid, LocalSigningTask>>
```

The commitments created at this point are sent back to the orchestrator:

```rust
pub struct Round1Response {
    pub commitments: frost_secp256k1_tr::round1::SigningCommitments,
}
```

Note that a committee member doesn't necessarily care about seeing different local tasks for the same `txid`. They'll just keep track of the last one. If they see a new request for the same txid incoming, they will ignore it if the request's proof matches, or go through the flow again if its a new proof (keeping track of the last proof they've seen).

They also do not need to keep track of what round they are in. The existe of a LocalSigningTask means that there has been a proof that was verified, and that a transaction is being signed. If the `commitments` vector is not empty, then the first round has been completed. (But since the `LocalSigningTask` still exists the second round hasn't been completed, otherwise the member would have pruned it.)

> TODO: are there any issues with not keeping track of nonces and stuff for the same message? Similar attacks to nonce-reuse?

- The orchestrator continues until they collect a threshold of `SigningCommitments`, which they can convert into a `SigningPackage`. They will then send the `SigningCommitments` to all the participants in that signature by hitting their `/round_2_signing` endpoint.

```rust
pub struct Round2Request {
    /// The txid that we're referring to.
    pub txid: Txid,

    /// Hash of the proof. Useful to make sure that we're signing the request/proof.
    pub proof_hash: [u8; 32],

    /// The FROST data needed by the MPC participants in the second round.
    pub commitments_map:
        BTreeMap<frost_secp256k1_tr::Identifier, frost_secp256k1_tr::round1::SigningCommitments>,

    /// Digest to hash.
    /// While not necessary as nodes will recompute it themselves, it is good to double check that everyone is on the same page.
    pub message: [u8; 32],
}

pub struct Round2Response {
    pub signature_share: frost_secp256k1_tr::round2::SignatureShare,
}
```

- A member that receives such a request can recreate the `SigningPackage`, and perform the second round of the signature protocol, delete their `LocalSigningTask` and respond to the orchestrator with their signature share.
- The orchestrator will collect a threshold of signature shares, and will then send the aggregated signature back to Bob.

> TODO: what to do if the orchestrator gets time outs from their request? Or can't meet a threshold?
  
> TODO: what happens if the orchestrator crash at some point? Restart the protocol right?

### Making Bitcoin compatible with taproot

FROST is not compatible with Bitcoin Schnorr's standard (BIP 340 and BIP 341) because of two additions in the Bitcoin scheme: elliptic curve points lose information (they only carry the x coordinate) and public keys can be tweaked (this is due to the taproot design).

Some recap and notation:

* the keypair is $(s, Y)$ such that $Y = [s]G$
* the signature is $(R, z)$ such that $R = [k]G$ and $z = k + s \cdot c$

From page 6 of the FROST paper this is their notation for the simple Schnorr protocol:

![Screenshot 2023-12-06 at 1.27.51 PM](https://hackmd.io/_uploads/HymPwPRSa.png)

In addition, FROST has the MPC committee compute additive shares for $R$ and $z$, so that they can be computed by using a sum of the computed shares ($R = \sum R_i$ and $z = \sum z_i$).

## Discussion

The verifier ends up checking this equation:

$$
R == [z]G - [c]Y
$$

but in reality, they are checking the equation with $Y' = Y + [\text{tweak}] G$ which is the tweaked public key:

$$
R == [z]G - [c]Y'
$$

And due to that, the aggregator uses $z' = z + c \cdot \text{tweak}$ to cancel out the tweak:

$$
R == [z']G - [c]Y'
$$

On top of this:

1. the verifier uses $R'$ which could be $-R$  or $R$ depending on the parity of $R$ (this is due to only having access to the x coordinate of $R$)
2. $Y'$ is actually computed using $-Y$ or $Y$ depending on the parity of $Y$ (for the same reasons)

So the equation sort of looks like this if we open things up:

$$
[+-k]G == [k + s \cdot c + c \cdot \text{tweak}]G - [c]Y - [c \cdot \text{tweak}]Y
$$

![IMG_F5F98452A39B-1](https://hackmd.io/_uploads/BkL2IvP86.jpg)

Issues can arise in three locations:

* MPC signers might not compute the right value to cancel terms
* The orchestrator might not aggregate the right things
* The verification equation might not use the right values

## 5. Proof systems supported

In the initial version of zkBitcoin we support plonk proofs built using [Circom](https://github.com/iden3/circom) and [Snarkjs](https://github.com/iden3/snarkjs) with parameters supporting circuits of $2^{16}$ constraints maximum.

We ignore proof systems like Groth16 which are heavily used on other networks like Ethereum, as it would mean supporting different parameters for different circuits.

In practice, we could support different parameter sizes, as well as different proof systems, with the addition of a flag to the data field of zkapp transactions. This is something that we will explore in the future.

## 6. Security Considerations

Our system's security relies on the security of the MPC committee. 

* as long as a threshold of the committee is honest, and live, the funds are safe
* if the threshold is not met, liveness issues
* if an adversary can corrupt an entire threshold, then safety issue: the funds can be drained
* Committee could be a trusted set of entities (we're trying to figure out who would be interested)
* after that, we could add more security: run MPC in SGX, and we could publish the SGX attestation that the shares were generated correctly

* Key refresh from https://github.com/cronokirby/cait-sith/blob/main/docs/key-generation.md
* after that, liveness could still be an issue, as currently the network might not have the best incentives to run (future work?)

## 7. Benchmarks

* we should try to run the protocol with like 100 participants and a threshold of 51? see how efficient it is (to me it looks like FROST is a very efficient protocol)
* maybe the FROST paper already has benchmarks?

## 8. Conclusion and Future work

## 9. References

