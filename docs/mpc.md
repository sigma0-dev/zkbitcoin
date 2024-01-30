# MPC flow

## Characters

* Alice, she locks fund in a "smart contract"
* Bob, he unlocks fund from the smart contract
* MPC members, a committee of N members, of which T < N needs to be online to unlock the funds by signing a transaction collaboratively (using [FROST](https://eprint.iacr.org/2020/852))
* Orchestrator, an endpoint that Bob can query to unlock the funds, the orchestrator literally "orchestrates" the signature by talking to the MPC members (MPC members don't talk to one another).

## Flow

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
signing_tasks: RwLock<CappedHashMap<Txid, LocalSigningTask>>
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
