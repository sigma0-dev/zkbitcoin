# zkBIP-001: Tokens as App Data (ToAD 🐸)

We propose a change to zkBitcoin so that a zkapp instance (UTXO) could fit in a single Bitcoin UTXO, utilizing Taproot capabilities. A single transaction will be able to spend and/or create multiple zkapp UTXOs. We also propose transaction-level validation predicates. This will allow for more expressive zkapps and zkapp composability.

We want to use Bitcoin UTXOs as units of on-chain data (zkapp instances). We want to minimize the number of assumptions about internal structure of a zkapp, while still keeping it useful. For example, it should still be possible to create zkapps that only deal with native BTC. At the same time, we want to enable custom tokens using the same model.

## Motivation

In the initial zkBitcoin design, in order to create a zkapp instance, one has to submit a transaction creating two outputs:

- the first one -- funds to lock in the zkBitcoin Taproot script, 
- the second one -- a dust amount of BTC with an `OP_RETURN` script containing the zkapp VK (_verification key_) hash and state.

There are some shortcomings to this approach.

1. It's wasteful: an entire Bitcoin transaction is used to create or spend a single zkapp instance.
2. Limited expressiveness. Conceptually zkapps could be viewed as UTXOs with more expressive validation scripts. Because we are limited to a single zkapp instance per transaction, we are limited to a single zkapp validation script per transaction.
3. Because of the above, zkapps are not composable. We cannot create a token zkapp interacting with a DEX zkapp, for example.

Goals:

1. Allow for multiple zkapp UTXOs to be created and spent in a single Bitcoin transaction.
2. Enable zkapp composability.
3. Enable custom tokens.

## High-Level Design

### Core Model
The core of the proposal is a *validation function* (or *validation predicate*), that is used to validate a transaction involving zkapp UTXOs. The validation predicate is a function of the following shape:
$$F: (ins, outs, x, w) → Bool$$
, where
- $ins$ — set of outputs spent by the transaction,
- $outs$ — set of outputs created by the transaction,
- $x$ — public *redeeming* (or *spending*) data necessary to validate the transaction (a great example would be a set of *spending signatures*).
- $w$ — private *witness* data necessary to validate the transaction (e.g. pre-images of hashes in the public data).

Each zkapp UTXO should have
- a map of: *validation predicate → state data*
    - e.g. *token policy → amount*:
        - $T_1 → a_1$
        - $T_2 → a_2$
        - $T_3 → a_3$
    - e.g. *smart-contract validator → smart-contract data*
        - $S_1 → d_1$
        - $S_2 → d_2$

If a transaction spends or creates any number of zkapp UTXOs, then all zkapp validation predicates need to be satisfied to validate a transaction.

### Adding ZK to the Core Model

*Validation predicates* are represented by their *VK*s (verification keys).

In practice, an output can only store hashes of these (perhaps even just one hash of them combined):
- *VK hash → state data* mapping.

The signature of a validation predicate is:
$$(ins, outs, x, w) → Bool$$
, where
- $ins$, $outs$, $x$ — public data described above: *spent* and *created* outputs, *redeeming data*,
- $w$ — private data (e.g. pre-images of hashes in the public data).

### Submitting a transaction

When submitting a transaction for signing by the MPC committee, the user provides (in addition to the transaction to sign):
- for each spent and created zkapp UTXO individually:
    - preimage of the hash stored in the zkapp UTXO:
        - mapping of *VK hash → state data*
- for the whole transaction (for all spent and created zkapp UTXOs collectively):
    - mapping of *VK hash → (VK, predicate evaluation proof, redeeming data)*
- any existing (signed) transactions (named *pre-requisite* transactions) that created the zkapps being spent by the user's transaction (this prevents creating tokens out of thin air, for example).

### Validating a transaction

In order to verify the transaction, each MPC node:

- Verifies that pre-requisite transactions, for all zkapps being spent, have a valid zkBitcoin MPC committee signature.
- Verifies hash pre-images for each spent and created zkapp UTXO. For each zkapp UTXO, these hashes are supposed to be computed from:
    - mapping of *VK hash → state data*
- Verifies predicate evaluation proofs for the transaction.
    - To do this, a set of all VK hashes from zkapp UTXOs in the transaction, both being spent and created, is taken.
    - Then, for each *VK hash* from this set, the predicate evaluation proof is verified against the following data:
        - *(VK, predicate evaluation proof, redeeming data, ins, outs)*, where each of *ins* and *outs*, carries:
            - satoshi amount — amount of BTC (in sats) in the zkapp UTXO,
            - (if it is a zkapp UTXO) mapping of *VK hash → state data*
                - the key in this mapping is zeroed out if VK hash is the same as the one being proven, so that the predicate could easily recognize its own state data

Upon successful verification, the MPC node produces its share of the user transaction signature and returns it back to the client.

### Tokens
Tokens are represented by special validation predicates called *token policies*. They are special in that they are **necessarily satisfied** by transactions **where** $\sum amount_{in} = \sum amount_{out}$, i.e. *the total amount of the token in spent outputs equals the total amount of the token in created outputs*. They work exactly the same as other validation predicates otherwise. Token amounts are simply positive integer state values corresponding to these predicates in zkapp UTXOs.

The purpose of token policies is to maintain integrity of token quantities participating in transactions. Since tokens are at the core of digital asset economies, these predicates indeed deserve a special name.

Because of this property (satisfied when token quantity is preserved), a very useful optimization can be applied: we don't need the proof of its evaluation if we know for sure the total amounts of the token are equal between transactions inputs and outputs.

For this to work, we need to tag such validation predicate VKs in a special way. (TODO: propose a way of tagging token policy VKs).

Of course, when total amounts *are* different, we do need the proof, so tokens can be minted and burned in a controlled way. For example, by using some secret value as a witness.

Tokens cannot be created out of thin air, since to validate a transaction involving zkapps, the user must provide signed transactions producing any zkapps being spent.

### Examples

Let's look at some examples of zkapp validation predicates (in Rust). The following code is not circuit-friendly, but it should give an idea of what validation predicates do.

Some type and const definitions used in the examples below:

```rust
// Arbitrary data.
pub struct Data {
    data: Box<[u8]>,
}

// VK hash is a byte array of length 32. 
type VkHash = [u8; 32];

// Every UTXOs that already exists (has been created by a transaction) 
// has an ID, consisting of the transaction ID and the index if the UTXO 
// in the transaction outputs.
struct UtxoId {
    txid: [u8; 32],
    vout: u32,
}

// A zkapp UTXO as presented to the validator function.
pub struct Utxo {
    id: Option<UtxoId>,
    satoshi_amount: u64,
    state_map: HashMap<VkHash, Data>,
}

// Zeroed out array of 32 bytes.
// Used in a validator function, refers to the current validator's
// own VK hash in the UTXO (as presented to the current validator).
// In an actual UTXO, the hash of the validator's VK is used instead.
pub const OWN_VK_HASH: VkHash = [0u8; 32];
```

### Send Bitcoin to an email address

Even UTXOs with a single validation predicate can be useful. In this example, a rather simple smart contract checks the proof of email address ownership by the spender:

```rust
pub fn spender_owns_email_contract(
    ins: &[Utxo],
    outs: &[Utxo],
    x: &Data,
    w: &Data,
) -> Result<bool> {

    // Make sure the spender owns the email addresses in the input UTXOs.
    for utxo in ins {
        // Retrieve the state for this zkapp.
        // OWN_VK_HASH (always zeroed out) refers to the current validator's
        // own VK hash in the UTXO.
        // In an actual UTXO, this would be the hash of the validator's VK.
        // Also, we only care about UTXOs that have a state for the current
        // validator.
        if let Some(state) = utxo.state_map.get(&OWN_VK_HASH) {
            // If the state is not even a string, the UTXO is invalid.
            let email: String = state.try_into()?;
            // Check if the spender owns the email address.
            if !owns_email(&email, x, w)? {
                return Ok(false);
            }
        }
    }

    // Make sure our own state in output UTXOs is an email address.
    for utxo in outs {
        // Again, we only care about UTXOs that have a state for the current
        // validator.
        if let Some(state) = utxo.state_map.get(&OWN_VK_HASH) {
            // There needs to be an `impl TryFrom<&Data> for String`
            // for this to work.
            let email: String = state.try_into()?;
            // Check if the email address is valid XD
            if !email.contains('@') {
                return Ok(false);
            }
        }
    }

    Ok(true)
}


fn owns_email(email: &str, x: &Data, w: &Data) -> Result<bool> {
    todo!("Implement!")
}
```

### Meme Token

In addition to Bitcoin, we can create a custom meme token with this token policy validator and add it to any zkBitcoin UTXOs.

```rust
pub fn zk_meme_token_policy(
    ins: &[Utxo],
    outs: &[Utxo],
    x: &Data,
    w: &Data
) -> Result<bool> {
    let in_amount = sum_token_amount(ins)?;
    let out_amount = sum_token_amount(outs)?;

    // is_meme_token_creator is a function that checks that
    // the spender is the creator of this meme token.
    // In our policy, the token creator can mint and burn tokens at will.
    Ok(in_amount == out_amount || is_meme_token_creator(x, w)?)
}

fn sum_token_amount(utxos: &[Utxo]) -> Result<u64> {
    let mut in_amount: u64 = 0;
    for utxo in utxos {
        // We only care about UTXOs that have our token.
        if let Some(state) = utxo.state_map.get(&OWN_VK_HASH) {
            // There needs to be an `impl TryFrom<&Data> for u64`
            // for this to work.
            let utxo_amount: u64 = state.try_into()?;
            in_amount += utxo_amount;
        }
    }
    Ok(in_amount)
}

fn is_meme_token_creator(x: &Data, w: &Data) -> Result<bool> {
    // TODO should be a real public key instead of a bunch of zeros
    const CREATOR_PUBLIC_KEY: [u8; 64] = [0u8; 64];
    todo!("check the signature in the witness against CREATOR_PUBLIC_KEY")
}
```

We can, of course, combine the above validators, and now we can send meme coins to an email address! By "combine" we mean create UTXOs that have VK hashes and states for both validators.

### Order-Book DEX
A simple example of how this model would be used is a minimal "order book" DEX enabling users to trade tokens. An order in such a DEX would be a UTXO with two predicate→state mappings:
- "base" token policy VK hash → amount
- DEX smart-contract VK hash → limit order data, including
    - "quote" token policy VK hash
    - limit (min) price (in the "quote" token) per "base" token
    - owner's public key (where to send "quote" tokens)
    - matching fee rate (percentage of the amount of quote tokens received above the limit price the trader is willing to pay for making the match)

Anyone willing to take the matching fee is free to submit transactions to match and settle these orders. In such transactions, all these validation predicates must be satisfied:
- the "base" and "quote" token policies — these make sure the amount of tokens stays the same between spent and created UTXOs,
- the DEX smart contract — makes sure all conditions of the orders are met and fees are paid accordingly.

## Benefits

The above structure has several properties enabling interesting applications:
- Uniformity — everything is a validation predicate: token policies, ownership, smart contracts, combinations thereof.
- Zkapps can be as minimal (a single VK with empty state) or as sophisticated (a full blown DEX or an L2 on/off ramp working with multiple tokens) as users would please.
- We can store several different tokens in a single UTXO.
- Minting/burning tokens is just a matter of increasing/decreasing token amounts in the created outputs (vs spent outputs).
    - Whether a token can be minted, for example, can be controlled by a certain private input and the proof it has indeed been provided.
- The transaction is validated by a validation predicate as a whole, so there's no "split brain" present in other UTXO based systems (e.g. Bitcoin and clones, Cardano).
- With (possibly in the future) addition of arbitrary composition, flexibility in how the UTXO can be spent. For example,
    - A UTXO can represent a limit order in an order book DEX, waiting for a good match to happen.
    - At the same time, the tokens in the order are spendable at any moment if the owner finds a better use for them — no need for a separate transaction to cancel the order.
    - One can authorize a third party to manage their funds for them (e.g. trade), while maintaining full spending control themselves — no need to deposit and withdraw to the management firm's wallet.
