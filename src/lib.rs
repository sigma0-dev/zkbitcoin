//! zkBitcoin.

pub mod constants;
pub mod json_rpc_stuff;
pub mod plonk;

/// 1. Alice signs a transaction to deploy a smart contract.
pub mod alice_sign_tx;

/// 2. Bob sends a request to the zkBitcoin committee to unlock funds from a smart contract.
pub mod bob_request;

/// 3. The zkBitcoin committee produce a collaborative schnorr signature to unlock the funds for Bob,
/// given that Bob's proof verifies.
//pub mod mpc_sign_tx;
