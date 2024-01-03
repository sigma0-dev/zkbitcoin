# zkBitcoin

Use ZK applications on Bitcoin!

How does it work? Write your ZK application in [circom](https://github.com/iden3/circom), compile it to a circuit, and deploy it on Bitcoin by sending a transaction to our multi-party wallet run by a committee of nodes.

To use a zkapp, anyone who can provide a proof of correct execution to our committee which will trigger a threshold signature, eventually allowing funds to move out of the zkapp.

## Usage

### Requirements

On top of knowing what circom circuits you want to deploy or use, you'll need your own Bitcoin node/wallet running locally. This application will perform queries to your node/wallet in order to deposit or withdraw funds from zkapps.

### Stateless zkapps

A stateless zkapp is a zkapp that can be unlocked (its funds can be unlocked) by anyone who can provide a proof of correct execution. An example of a stateless zkapp is in [`examples/circuit/stateless.circom`](examples/circuit/stateless.circom). A stateless zkapp always contains one public input that authenticates the transaction that spends it:

```circom
template Main() {
    signal input truncated_txid;
```

The zkapp does not have to do anything with this (although it can if it wants to).

Alice can deploy such a stateless zkapp with the following command:

```shell
RPC_WALLET="mywallet" RPC_ADDRESS="http://146.190.33.39:18331" RPC_AUTH="root:hellohello" cargo run --bin cli -- deploy-transaction --circom-circuit-path examples/circuit/stateless.circom --satoshi-amount 1000
```

This will lock 1,000 satoshis in the zkapp and return the transaction ID of the transaction that deployed the zkapp. A stateless zkapp can be referenced by that transaction ID, which handily also contains an output authenticating the compiled smart contract (more specifically, an `OP_RETURN` output of the verifier key).

Bob can then unlock the funds from the stateless zkapp (by specifying its transaction ID) with the following command:

```shell
ENDPOINT="http://127.0.0.1:6666" RPC_WALLET="mywallet" RPC_ADDRESS="http://146.190.33.39:18331" RPC_AUTH="root:hellohello" cargo run --bin cli -- unlock-funds-request --txid "e793bdd8dfdd9912d971790a5f385ad3f1215dce97e25dbefe5449faba632836" --circom-circuit-path examples/circuit/stateless.circom --proof-inputs '{"preimage":["1"]}' --recipient-address "tb1q6nkpv2j9lxrm6h3w4skrny3thswgdcca8cx9k6"
```

The `ENDPOINT` environment variable is the URL of the orchestrator.

### Stateful zkapps

A stateful zkapp is a zkapp that can be updated without consuming the zkapp (unlike stateless zkapps). 

An example of a stateful zkapp is in [`examples/circuit/stateful.circom`](examples/circuit/stateful.circom). A stateful zkapp always contains a number of additional public inputs, allowing an execution to authenticate the zkapp state transition, as well as the amounts being withdrawn and deposited:

```circom
template Main() {
    signal output new_state;
    signal input prev_state;
    signal input truncated_txid; // this should not affect output
    signal input amount_out;
    signal input amount_in;
```

Alice can deploy a stateful zkapp with the following command:

```shell
RPC_WALLET="mywallet" RPC_ADDRESS="http://146.190.33.39:18331" RPC_AUTH="root:hellohello" cargo run --bin cli -- deploy-transaction --circom-circuit-path examples/circuit/stateful.circom --initial-state "1" --satoshi-amount 1000     
```

Bob can then use the stateful zkapps with the following command:

```shell
ENDPOINT="http://127.0.0.1:6666" RPC_WALLET="mywallet" RPC_ADDRESS="http://146.190.33.39:18331" RPC_AUTH="root:hellohello" cargo run --bin cli -- unlock-funds-request --circom-circuit-path examples/circuit/stateful.circom --proof-inputs '{"amount_in":["1000"], "amount_out":["1000"]}' --recipient-address "tb1q6vjawwska63qxf77rrm5uwqev0ma8as8d0mkrt" --txid "76763d6130ee460ede2739e0f38ea4d61cc940b00af5eab83e5afb0fcc837b91"
```

specifying the following inputs:

* `amount_out`: amount being withdrawn
* `amount_in`: amount being deposited

Other inputs will be automatically filled in (for example, it will use the zkapp's state as `prev_state` input).

The `ENDPOINT` environment variable is the URL of the orchestrator.

## Tell me more

You can read more about zkBitcoin in [our documentation](docs/), and about advanced usage in [our developer documentation](DEVELOPER.md).
