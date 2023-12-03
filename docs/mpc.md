# MPC flow

## Characters

* Alice, she locks fund in a "smart contract"
* Bob, he unlocks fund from the smart contract
* MPC members, a committee of N members, of which T < N needs to be online to unlock the funds by signing a transaction collaboratively (using [FROST]())
* Orchestrator, an endpoint that Bob can query to unlock the funds, the orchestrator literally "orchestrates" the signature by talking to the MPC members (MPC members don't talk to one another).

## Flow

The current proposed flow is the following:

- Bob sends a request to an orchestrator:

```rust
pub struct BobRequest {
    /// The transaction ID that deployed the smart contract.
    pub txid: bitcoin::Txid,

    /// The verifier key authenticated by the deployed transaction.
    pub vk: plonk::VerifierKey,

    /// A proof.
    pub proof: plonk::Proof,

    /// All public inputs used in the proof (if any).
    pub public_inputs: Vec<String>,
}
```

- The orchestrator validates the request and aborts if the request is not valid (proof does not verify, or txid has been spent, etc.)
- If the request is valid, the orchestrator creates a signing task:

```rust
pub struct SigningTask {
    /// The message to sign.
    message: Vec<u8>,

    /// The commitments collected during round 1.
    commitments: BTreeMap<frost_secp256k1::Identifier, frost_secp256k1::round1::SigningCommitments>,

    /// The signing package formed at the end of round 1.
    signing_package: Option<frost_secp256k1::SigningPackage>,

    /// The signature shares at the end of round 2.
    signature_shares:
        BTreeMap<frost_secp256k1::Identifier, frost_secp256k1::round2::SignatureShare>,
}
```

- The orchestrator then hits the `/verify_proof` endpoint of each MPC member (or a threshold of it)
- A member that receives such a request verifies the request in a similar way, then starts a `LocalSigningTask` with a message set to the transaction to sign (which they can create deterministically, so that everyone has the same)

```rust
pub struct LocalSigningTask {
    /// So we know if we're processing the same request twice.
    pub proof_hash: [u8; 32],
    /// The smart contract that locked the value.
    pub smart_contract: SmartContract,
    /// The commitments we produced to start the signature (round 1).
    pub commitments: frost_secp256k1::round1::SigningCommitments,
    /// The nonces behind these commitments
    pub nonces: frost_secp256k1::round1::SigningNonces,
}
```

The commitments created at this point are sent back to the orchestrator.
Members keep track of such signing tasks in a local hashmap:

```rust
pub struct LocalSigningTasks {
    tasks: HashMap<Txid, LocalSigningTask>,
}
```

Note that a committee member doesn't necessarily care about seeing different local tasks for the same `txid`. They'll just keep track of the last one. If they see a new request for the same txid incoming, they will ignore it if the request's proof matches, or go through the flow again if its a new proof (keeping track of the last proof they've seen).

They also do not need to keep track of what round they are in. The existe of a LocalSigningTask means that there has been a proof that was verified, and that a transaction is being signed. If the `commitments` vector is not empty, then the first round has been completed. (But since the `LocalSigningTask` still exists the second round hasn't been completed, otherwise the member would have pruned it.)

> TODO: are there any issues with not keeping track of nonces and stuff for the same message? Similar attacks to nonce-reuse?

- The orchestrator continues until they collect a threshold of `SigningCommitments`, which they can convert into a `SigningPackage`. They will then send the `SigningCommitments` to all the participants in that signature by hitting their `/round2_sign` endpoint.
- A member that receives such a request can recreate the `SigningPackage`, and perform the second round of the signature protocol, delete their `LocalSigningTask` and respond to the orchestrator with their signature share.
- The orchestrator will collect a threshold of signature shares, and will then send the aggregated signature back to Bob.

> TODO: what to do if the orchestrator gets time outs from their request? Or can't meet a threshold?
  
> TODO: what happens if the orchestrator crash at some point? Restart the protocol right?
