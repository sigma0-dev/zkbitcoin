use std::{
    fs::{remove_dir_all, File},
    process::Command,
    str::FromStr,
};

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{
    opcodes::all::OP_RETURN, script::Instruction, Address, Amount, PublicKey, Transaction,
};
use serde::{Deserialize, Serialize};
use tempdir::TempDir;

use crate::{
    alice_sign_tx::p2tr_script_to,
    constants::{MINIMUM_CONFIRMATIONS, ZKBITCOIN_PUBKEY},
    get_network,
    json_rpc_stuff::json_rpc_request,
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

    // ensure that the vk makes sense with public input that are fixed
    ensure!(smart_contract.public_inputs.len() <= request.vk.nPublic,"number of public inputs that are fixed is greater than the number of public inputs in the vk");

    // ensure that number public inputs <= vk.num_public_inputs
    ensure!(
        request.vk.nPublic == request.public_inputs.len(),
        "number of public input don't match"
    );

    // ensure that the hash of the VK correctly gives us the vk_hash
    ensure!(
        smart_contract.vk_hash[..] == request.vk.hash(),
        "VK does not match the VK hash in the smart contract"
    );

    // ensure that the public input (prefix) matches what's on chain
    // any other public input is decided by Bob (the prover)
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

    // write vk, inputs, proof to file
    let tmp_dir = TempDir::new("zkbitcoin_").expect("couldn't create tmp dir");

    let proof_path = tmp_dir.path().join("proof.json");
    let mut tmp_file = File::create(proof_path).expect("file creation failed");
    serde_json::to_writer(&mut tmp_file, &request.proof).expect("write failed");

    let public_inputs_path = tmp_dir.path().join("public_inputs.json");
    let mut tmp_file = File::create(public_inputs_path).expect("file creation failed");
    serde_json::to_writer(&mut tmp_file, &request.public_inputs).expect("write failed");

    let verification_key = tmp_dir.path().join("verification_key.json");
    let mut tmp_file = File::create(verification_key).expect("file creation failed");
    serde_json::to_writer(&mut tmp_file, &request.vk).expect("write failed");

    // verify proof using snarkjs
    let output = Command::new("snarkjs")
        .current_dir(&tmp_dir)
        .arg("plonk")
        .arg("verify")
        .arg("verification_key.json")
        .arg("public_inputs.json")
        .arg("proof.json")
        .output()
        .expect("failed to execute process");

    println!("{}", String::from_utf8_lossy(&output.stdout));

    if !output.status.success() {
        bail!("failed to verify proof");
    }

    // clean up
    remove_dir_all(tmp_dir).expect("failed to remove temp dir");

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
