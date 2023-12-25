use std::{
    fs::{remove_dir_all, File},
    process::Command,
    str::FromStr,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::{
    opcodes::all::OP_RETURN, script::Instruction, Address, Amount, PublicKey, Transaction,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tempdir::TempDir;

use crate::{
    alice_sign_tx::p2tr_script_to,
    constants::{FEE_BITCOIN_SAT, FEE_ZKBITCOIN_SAT, MINIMUM_CONFIRMATIONS, ZKBITCOIN_PUBKEY},
    get_network,
    json_rpc_stuff::json_rpc_request,
    zkp::verify_proof,
};
use crate::{json_rpc_stuff::RpcCtx, plonk};

//
// Bob's side: form a request and send it to an endpoint
//

/// A request from Bob to unlock funds from a smart contract should look like this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BobRequest {
    /// Bob's address. This is insecure and we should move it to the public inputs.
    // TODO: move this to public input.
    pub bob_address: String,

    /// The transaction ID that deployed the smart contract.
    pub txid: bitcoin::Txid,

    /// The verifier key authenticated by the deployed transaction.
    pub vk: plonk::VerifierKey,

    /// A proof.
    pub proof: plonk::Proof,

    /// All public inputs used in the proof (if any).
    pub public_inputs: Vec<String>,
}

impl BobRequest {
    // TODO: does an address fit in a public input/field element?
    pub fn get_bob_address(&self) -> Result<Address> {
        let address = Address::from_str(&self.bob_address)?.require_network(get_network())?;
        Ok(address)
        // if self.public_inputs.len() < 1 {
        //     bail!("public input should at least be of size 1 (as first public input is bob's address)");
        // }

        // let address_str = &self.public_inputs[0];
        // let bob_pubkey = bitcoin::PublicKey::from_slice(todo!());
        // let bob_address = bitcoin::Address::from_str(address_str)
        //     .context("failed to deserialize the first public input as a bitcoin address")?;
        // let bob_address = bob_address.require_network(get_network()).context({
        //     "network of bitcoin address needs to be testnet or bitcoin (depending on cfg)"
        // })?;

        // Ok(bob_address)
    }

    pub fn get_hash_bob_address(&self) -> Result<Vec<u8>> {
        // TODO: maybe we want to be in a world where Bob can give us a script pubkey directly? (instead of an address)
        let bob_address = self.get_bob_address()?;
        let bob_address = bob_address.script_pubkey();
        let bob_address = bob_address.to_bytes();

        let mut hasher = Sha3_256::new();
        hasher.update(bob_address);
        let res = hasher.finalize().to_vec();
        Ok(res)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BobResponse {
    //pub txid: bitcoin::Txid,
    pub commitments: frost_secp256k1_tr::round1::SigningCommitments,
}

pub async fn send_bob_request(address: &str, request: BobRequest) -> Result<BobResponse> {
    let ctx = RpcCtx {
        version: Some("2.0"),
        wallet: None,
        address: Some(address.to_string()),
        auth: None,
    };

    let resp = json_rpc_request(
        &ctx,
        "unlock_funds",
        &[serde_json::value::to_raw_value(&request).unwrap()],
    )
    .await
    .context("couldn't send unlock_funds request to orchestrator")?;

    // TODO: get rid of unwrap in here
    let response: bitcoincore_rpc::jsonrpc::Response =
        serde_json::from_str(&resp).context("couldn't deserialize orchestrator's response")?;
    let bob_response: BobResponse = response.result().context("bob request failed")?;

    Ok(bob_response)
}

//
// Everything at this point is to parse and validate Bob's request.
//

/// All the metadata that describes a smart contract.
#[derive(Clone)]
pub struct SmartContract {
    pub locked_value: Amount,
    pub vk_hash: [u8; 32],
    pub public_inputs: Vec<Vec<u8>>,
    pub vout_of_zkbitcoin_utxo: u32,

    /// _All_ the outputs of the deploy transaction.
    /// (needed to sign a transaction to unlock the funds).
    pub prev_outs: Vec<bitcoin::TxOut>,
}

impl SmartContract {
    /// Returns true if the smart contract is stateless.
    fn is_stateless(&self) -> bool {
        // a stateless contract expects no public input
        self.public_inputs.is_empty()
    }

    /// Returns true if the smart contract is stateful.
    fn is_stateful(&self) -> bool {
        !self.is_stateless()
    }

    /// Returns the amount that is being withdrawn from the smart contract, and the remaining amount in the contract (0 if stateless).
    fn calculate_split_funds(&self, request: &BobRequest) -> Result<(Amount, Amount)> {
        if self.is_stateless() {
            return Ok((self.locked_value, Amount::from_sat(0)));
        }

        let len_state = self.public_inputs.len();
        let amount_offset = len_state * 2 + 1;
        let zero = "0".to_string();
        let amount = request.public_inputs.get(amount_offset).unwrap_or(&zero);

        let bob_amount = {
            // TODO: need to write a test here
            let big = BigUint::from_str(amount).context("amount is not a u64 (err_code: 1)")?;
            let big_u64s = big.to_u64_digits();
            ensure!(big_u64s.len() == 1, "amount is not a u64 (err_code: 2)");
            let u64res = amount
                .parse::<u64>()
                .context("amount is not a u64 (err_code: 3)")?;
            ensure!(big_u64s[0] == u64res, "amount is not a u64 (err_code: 4)");
            Amount::from_sat(u64res)
        };

        let remaining = self.locked_value - bob_amount;

        Ok((bob_amount, remaining))
    }

    fn check_remaining_funds(&self, request: &BobRequest) -> Result<()> {
        // TODO: bitcoin fee shouldn't be a constant
        // TODO: use https://crates.io/crates/bitcoin-fees or https://lib.rs/crates/bitcoinwallet-fees
        let fees = Amount::from_sat(FEE_BITCOIN_SAT) + Amount::from_sat(FEE_ZKBITCOIN_SAT);

        let remaining = if self.is_stateless() {
            self.locked_value
        } else {
            let len_state = self.public_inputs.len();
            let amount_offset = len_state * 2 + 1;
            let zero = "0".to_string();
            let amount = request.public_inputs.get(amount_offset).unwrap_or(&zero);
            let bob_amount = {
                // TODO: need to write a test here
                let big = BigUint::from_str(amount).context("amount is not a u64 (err_code: 1)")?;
                let big_u64s = big.to_u64_digits();
                ensure!(big_u64s.len() == 1, "amount is not a u64 (err_code: 2)");
                let u64res = amount
                    .parse::<u64>()
                    .context("amount is not a u64 (err_code: 3)")?;
                ensure!(big_u64s[0] == u64res, "amount is not a u64 (err_code: 4)");
                Amount::from_sat(u64res)
            };

            ensure!(
                self.locked_value >= bob_amount,
                "there is not enough funds in the zkapp to cover for the withdrawal amount"
            );

            self.locked_value - bob_amount
        };

        ensure!(
            remaining > fees,
            "there is not enough funds in the zkapp to cover for bitcoin and zkBitcoin fees"
        );

        Ok(())
    }
}

pub fn parse_op_return_data(script: &bitcoin::ScriptBuf) -> Result<Vec<u8>> {
    // we expect [OP_RETURN, OP_PUSHBYTES]
    // anything else we won't accept
    let mut instructions = script.instructions();
    let inst = instructions
        .next()
        .expect("caller should have checked that this is an OP_RETURN")
        .expect("not sure why there are two layers of result")
        .opcode()
        .expect("come on");
    assert_eq!(
        inst, OP_RETURN,
        "caller should have checked that this is an OP_RETURN"
    );

    let inst = instructions
        .next()
        .context("no data was pushed as the last instruction of the script")?;

    let res = if let Ok(Instruction::PushBytes(bytes)) = inst {
        bytes.as_bytes().to_vec()
    } else {
        bail!("last instruction of the script was not a pushdata");
    };

    ensure!(
        instructions.next().is_none(),
        "we only expect one pushdata in an OP_RETURN"
    );

    Ok(res)
}

/// Extracts smart contract information as a [SmartContract] from a transaction.
pub fn extract_smart_contract_from_tx(
    raw_tx: &Transaction,
    zkbitcoin_pubkey: &PublicKey,
) -> Result<SmartContract> {
    let zkbitcoin_pubkey = zkbitcoin_pubkey.to_owned();

    // ensure that the first or second output is to 0xzkBitcoin and extract amount
    let expected_script = p2tr_script_to(zkbitcoin_pubkey);
    let mut vout_of_zkbitcoin_utxo = 0;
    let mut outputs = raw_tx.output.iter();
    let locked_value = {
        let output = outputs.next().context("tx has no output")?;
        if output.script_pubkey != expected_script {
            // the first output must have been the change, moving on to the second output
            let output = outputs.next().context("tx has no output")?;
            if output.script_pubkey != expected_script {
                bail!("Transaction's first or second output must be for 0xzkBitcoin");
            }
            vout_of_zkbitcoin_utxo = 1;
            output.value
        } else {
            output.value
        }
    };

    // create a list of all the outputs following that one that are OP_RETURN outputs
    let mut op_return_outputs = vec![];
    for output in outputs {
        if output.script_pubkey.is_op_return() {
            let data = parse_op_return_data(&output.script_pubkey)?;
            println!(
                "- extracted {data:?} from OP_RETURN {:?}",
                output.script_pubkey.as_script()
            );
            op_return_outputs.push(data);
        }
    }

    // ensure that the list at least contains the VK hash
    // other elements in the list are presumed to contain public inputs
    ensure!(
        !op_return_outputs.is_empty(),
        "Transaction has no OP_RETURN outputs"
    );

    // TODO: extract validate the vk hash against the given vk
    let vk_hash = op_return_outputs[0].clone();
    println!("- first op_return is vk hash: {:?}", vk_hash);
    ensure!(
        vk_hash.len() == 32,
        "first OP_RETURN data is not a 32-byte vk hash"
    );
    let vk_hash: [u8; 32] = vk_hash.try_into().unwrap();

    let public_inputs = op_return_outputs[1..].to_vec();

    let smart_contract = SmartContract {
        locked_value,
        vk_hash,
        public_inputs,
        vout_of_zkbitcoin_utxo,
        prev_outs: raw_tx.output.clone(),
    };
    Ok(smart_contract)
}

/// Fetch the smart contract on-chain from the txid.
pub async fn fetch_smart_contract(ctx: &RpcCtx, txid: bitcoin::Txid) -> Result<SmartContract> {
    // fetch transaction + metadata based on txid
    let (transaction, confirmations) = {
        println!("- fetching txid {txid}", txid = txid);

        let response = json_rpc_request(
            ctx,
            "gettransaction",
            &[
                serde_json::value::to_raw_value(&serde_json::Value::String(txid.to_string()))
                    .unwrap(),
            ],
        )
        .await
        .context("gettransaction error")?;

        // TODO: get rid of unwrap in here
        let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&response).unwrap();
        let parsed: bitcoincore_rpc::json::GetTransactionResult = response.result().unwrap();
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex).unwrap();
        let actual_hex = hex::encode(&parsed.hex);

        //println!("- tx found: {tx:?}");
        println!("- tx found: (in hex): {actual_hex}");

        (tx, parsed.info.confirmations)
    };

    // enforce that the smart contract was confirmed
    ensure!(
        confirmations >= MINIMUM_CONFIRMATIONS,
        "Smart contract has not been confirmed yet"
    );

    // parse transaction
    let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
    extract_smart_contract_from_tx(&transaction, &zkbitcoin_pubkey)
}

/// Validates a request received from Bob.
pub async fn validate_request(
    ctx: &RpcCtx,
    request: &BobRequest,
    smart_contract: Option<SmartContract>,
) -> Result<SmartContract> {
    // fetch the smart contract if not given
    let smart_contract = if let Some(x) = smart_contract {
        x
    } else {
        fetch_smart_contract(ctx, request.txid).await?
    };

    // ensure that the hash of the VK correctly gives us the vk_hash
    ensure!(
        smart_contract.vk_hash[..] == request.vk.hash(),
        "VK does not match the VK hash in the smart contract"
    );

    // ensure that the vk makes sense with public inputs that are fixed
    ensure!(smart_contract.public_inputs.len() <= request.vk.nPublic,"number of public inputs that are fixed is greater than the number of public inputs in the vk");

    // retrieve amount to be moved
    if smart_contract.is_stateful() {
        // ensure that the smart contract expects the correct number of public inputs
        let expected_len = smart_contract.public_inputs.len() * 2 /* prev state + new state */ + 1 /* truncated hash of bob address */ + 1 /* amount */;
        ensure!(
            request.vk.nPublic == expected_len,
            "the smart contract is malformed"
        );

        // ensure that number public inputs == vk.num_public_inputs
        ensure!(
            request.vk.nPublic == request.public_inputs.len(),
            "number of public input don't match"
        );

        // ensure that the public input (prefix) matches what's on chain
        // any other public input is decided by Bob (the prover)
        // TODO: we should get that from the smart contract instead of getting it from Bob's
        for (pi1, pi2) in smart_contract
            .public_inputs
            .iter()
            .zip(&request.public_inputs)
        {
            println!("pi1: {:?}", pi1);
            println!("pi2: {:?}", pi2);
            println!("pi2 as bytes: {:?}", pi2.as_bytes());
            ensure!(pi1 == pi2.as_bytes(), "public inputs don't match");
        }

        // withdraw-related public inputs
        let len_state = smart_contract.public_inputs.len();
        // TODO: we should derive that hashed address ourselves instead of receiving it from Bob
        let address_offset = len_state * 2;
        let hashed_bob_address = &request.public_inputs[address_offset];
        let expected = request.get_hash_bob_address()?;
        ensure!(
            hashed_bob_address.as_bytes() == expected,
            "Bob's address should match the truncated digest present in the public inputs given"
        );
    }

    // ensure that there's enough funds remaining to cover for bitcoin and zkBitcoin fee
    smart_contract.check_remaining_funds(&request)?;

    // verify proof using snarkjs
    verify_proof(&request)?;

    //
    Ok(smart_contract)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use secp256k1::hashes::Hash;

    use crate::plonk;

    use super::*;

    #[tokio::test]
    async fn test_validate_bob_request() {
        // read circuit example files
        let circuit_files = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/circuit");

        // get proof, vk, and inputs
        let proof: plonk::Proof = {
            let proof_path = circuit_files.join("proof.json");
            let file = File::open(proof_path).expect("file not found");
            serde_json::from_reader(file).expect("error while reading file")
        };
        let vk: plonk::VerifierKey = {
            let vk_path = circuit_files.join("vk.json");
            let file = File::open(vk_path).expect("file not found");
            serde_json::from_reader(file).expect("error while reading file")
        };
        let public_inputs: plonk::ProofInputs = {
            let proof_inputs_path = circuit_files.join("proof_inputs.json");
            let file = File::open(proof_inputs_path).expect("file not found");
            serde_json::from_reader(file).expect("error while reading file")
        };

        // truncate a portion (let's say 10) of the public inputs
        assert_eq!(public_inputs.0.len(), 96);
        let truncated_pi = public_inputs
            .0
            .iter()
            .map(|x| x.as_bytes().to_vec())
            .take(32)
            .collect();

        // create smart contract
        let vk_hash = vk.hash();
        let smart_contract = SmartContract {
            locked_value: Amount::from_sat(10),
            vk_hash,
            public_inputs: truncated_pi,
            vout_of_zkbitcoin_utxo: 0,
            prev_outs: vec![],
        };

        // create bob request
        let bob_request = BobRequest {
            bob_address: "".to_string(),
            txid: bitcoin::Txid::all_zeros(),
            vk,
            proof,
            public_inputs: public_inputs.0,
        };

        // try to validate the request
        let ctx = RpcCtx::for_testing();

        validate_request(&ctx, &bob_request, Some(smart_contract))
            .await
            .unwrap();
    }
}
