// https://github.com/rust-bitcoin/rust-bitcoin/issues/294
//!
//! MPC-part of the flow.

use std::str::FromStr;

use bitcoin::{
    hashes::{hash160, Hash},
    psbt::raw,
    Amount, PubkeyHash, PublicKey, ScriptBuf, Transaction,
};

use crate::constants::ZKBITCOIN_PUBKEY;

/// All the metadata that describes a smart contract.
pub struct SmartContract {
    pub locked_value: Amount,
    pub vk_hash: [u8; 32],
    pub vk: Option<()>, // TODO: replace with actual VK type
}

/// A request from Bob to unlock funds from a smart contract should look like this.
pub struct BobRequest {
    /// The transaction ID that deployed the smart contract.
    pub txid: bitcoin::Txid,

    /// The verifier key authenticated by the deployed transaction.
    pub vk: (),

    /// A proof.
    pub proof: (),

    /// Any additional public inputs used in the proof (if any).
    pub public_inputs: Vec<()>,
}

/// Extracts smart contract information as a [SmartContract] from a transaction.
pub fn parse_transaction(raw_tx: &Transaction) -> Result<SmartContract, &'static str> {
    let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();

    // ensure that the first output is to 0xzkBitcoin
    if raw_tx.output.is_empty() {
        return Err("Transaction has no outputs");
    }

    // validate the first output and extract amount
    let zkbitcoin_output = &raw_tx.output[0];
    if zkbitcoin_output.script_pubkey.as_script().p2pk_public_key() != Some(zkbitcoin_pubkey) {
        return Err("Transaction's first output is not to 0xzkBitcoin");
    }
    let locked_value = zkbitcoin_output.value;

    // create a list of all the outputs following that one that are OP_RETURN outputs
    let mut op_return_outputs = vec![];
    for output in raw_tx.output.iter().skip(1) {
        if output.script_pubkey.is_op_return() {
            let unlock_script = output.script_pubkey.as_bytes();
            let data = unlock_script[1..].to_vec();
            op_return_outputs.push(data);
        }
    }

    // ensure that the list at least contains the VK hash
    // other elements in the list are presumed to contain public inputs
    if op_return_outputs.is_empty() {
        return Err("Transaction has no OP_RETURN outputs");
    }

    // TODO: extract validate the vk hash against the given vk
    let vk_hash = op_return_outputs[0].clone();
    let vk_hash: [u8; 32] = vk_hash
        .try_into()
        .map_err(|_| "first OP_RETURN data is not a 32-byte vk hash")?;

    let smart_contract = SmartContract {
        locked_value,
        vk_hash,
        vk: None,
    };
    Ok(smart_contract)
}

/// Validates a request received from Bob.
pub fn validate_request(request: BobRequest) -> Result<(), &'static str> {
    // fetch transaction based on txid
    let transaction = todo!();

    // parse transaction
    let smart_contract = parse_transaction(&transaction)?;

    // TODO: ensure that number public inputs <= vk.num_public_inputs

    // TODO: ensure that the hash of the VK correctly gives us the vk_hash
}
