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

When observing such a _valid_ request, the MPC committee will produce a transaction that spends the whole UTXO (minus fees for the Bitcoin network AND zkBitcoin) and sends it to Bob's address.

## Stateful zkapps

A statefull zkapp can be deployed with a transaction to `0xzkBitcoin` that contains two data field: 

1. The digest of a verifier key.
2. $N$ field elements that represent the initial state of the zkapp. If there's 0, the zkapp is treated as a stateless zkapp!

In order to spend such a transaction Bob needs to produce:

1. The verifier key that hashes to that digest.
2. A Bitcoin public address
3. A number of public inputs in this order:
   1. The previous state as $N$ field elements (TODO: do we want to replace this with a poseidon hash? heh)
   2. The new state as $N$ field elements (TODO: same question)
   3. A truncated SHA-256 hash of a recipient bitcoin address. This can be derived automatically from the Bitcoin public address given previously and does not need to be sent.
   4. An amount $A$ to withdraw.
4. A proof that verifies for the verifier key and the previous public inputs.

When receiving such a _valid_ request, the MPC committee will produce a transaction that:

1. spends $A$ satoshis to the given recipient address, if $A$ is not 0.
2. moves the remaining funds (minus fees for the Bitcoin network AND zkBitcoin) to zkBitcoin's address, with the following data:
   1. The same verifier key digest that was used previously.
   2. The new state as $N$ field elements.
