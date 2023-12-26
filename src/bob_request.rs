use std::str::FromStr;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{
    absolute::LockTime, opcodes::all::OP_RETURN, script::Instruction, transaction::Version,
    Address, Amount, Denomination, OutPoint, PublicKey, Script, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use itertools::Itertools;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    alice_sign_tx::p2tr_script_to,
    constants::{
        FEE_BITCOIN_SAT, FEE_ZKBITCOIN_SAT, MINIMUM_CONFIRMATIONS, ZKBITCOIN_FEE_PUBKEY,
        ZKBITCOIN_PUBKEY,
    },
    json_rpc_stuff::json_rpc_request,
    snarkjs::verify_proof,
};
use crate::{json_rpc_stuff::RpcCtx, plonk};

// note to self:
//
// the flow from Bob will be:
// 1. create the transaction that uses zkapp, if it's stateless it's easy, if it's stateful we need the following vars:
//   - prev_state = zkapp.public_inputs
//   - truncated_txid = truncate(hash(txid))
//   - amount_out = hint
//   - amount_in = hint
// 2. create the proof and produce new_state as well as full public inputs

//
// Helpers
//

fn string_to_amount(amount: &str) -> Result<Amount> {
    // TODO: need to write a test here, once we have tested this we need to figure out which one to keep :D
    let big = BigUint::from_str(amount).context("amount is not a u64 (err_code: 1)")?;
    let big_u64s = big.to_u64_digits();
    ensure!(big_u64s.len() == 1, "amount is not a u64 (err_code: 2)");
    let u64res = amount
        .parse::<u64>()
        .context("amount is not a u64 (err_code: 3)")?;
    ensure!(big_u64s[0] == u64res, "amount is not a u64 (err_code: 4)");
    let res = Amount::from_sat(u64res);
    let res2 = Amount::from_str_in(amount, Denomination::Satoshi)?;
    assert_eq!(res, res2);

    Ok(res)
}

//
// Bob's side: form a request and send it to an endpoint
//

/// A request from Bob to unlock funds from a smart contract should look like this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BobRequest {
    /// The transaction authenticated by the proof, and that Bob wants to sign.
    /// This transaction should contain the zkapp as input, and a fee as output.
    /// It might also contain a new zkapp as output, in case the input zkapp was stateful.
    pub tx: Transaction,

    /// The index of the input that contains the zkapp being used.
    pub zkapp_input: usize,

    /// The verifier key authenticated by the deployed transaction.
    pub vk: plonk::VerifierKey,

    /// A proof.
    pub proof: plonk::Proof,

    /// All public inputs used in the proof (if any).
    pub public_inputs: Vec<String>,
}

impl BobRequest {
    async fn new(
        rpc_ctx: &RpcCtx,
        bob_address: Address,
        txid: bitcoin::Txid, // of zkapp
        vk: plonk::VerifierKey,
        proof: plonk::Proof,
        public_inputs: Vec<String>,
    ) -> Result<Self> {
        let tx = {
            ensure!(
                vk.nPublic == public_inputs.len(),
                "sanity check failed: the verifier key does not match the public inputs given"
            );
            let mut inputs = vec![];

            // fetch smart contract we want to use
            let smart_contract = fetch_smart_contract(&rpc_ctx, txid).await?;

            // first input is the zkapp being used
            {
                inputs.push(TxIn {
                    previous_output: OutPoint {
                        txid,
                        vout: smart_contract.vout_of_zkbitcoin_utxo,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                });
            }

            let mut outputs = vec![];

            // first output is to zkBitcoinFund
            {
                let zkbitcoin_pubkey: PublicKey =
                    PublicKey::from_str(ZKBITCOIN_FEE_PUBKEY).unwrap();
                outputs.push(TxOut {
                    value: Amount::from_sat(FEE_ZKBITCOIN_SAT),
                    script_pubkey: p2tr_script_to(zkbitcoin_pubkey),
                });
            }

            // second output is to ourselves
            {
                let script_pubkey = bob_address.script_pubkey();
                let value = if smart_contract.is_stateful() {
                    let amount = public_inputs.get(state_len)
                } else {
                    smart_contract.locked_value - ZKBITCOIN_FEE_PUBKEY
                };
                outputs.push(TxOut {
                    value,
                    script_pubkey,
                });
            }

            // if it's a stateful zkapp, we need to add a new zkapp as output
            if smart_contract.stateful() {
                outputs.push(TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: p2tr_script_to(vk.to_public_key()),
                })
            }

            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO, // no lock time
                input: inputs,
                output: outputs,
            }
        };

        let res = Self {
            tx,
            zkapp_input: 0,
            vk,
            proof,
            public_inputs,
        };
        Ok(res)
    }

    fn new_state(&self, state_len: usize) -> Result<&[String]> {
        self.public_inputs
            .get(0..state_len)
            .context("can't find previous state in public inputs")
    }

    fn prev_state(&self, state_len: usize) -> Result<&[String]> {
        self.public_inputs
            .get(state_len..state_len * 2)
            .context("can't find previous state in public inputs")
    }

    /// This should only be called on stateful smart contracts.
    fn amount_in(&self, state_len: usize) -> Result<Amount> {
        let offset = state_len * 2 + 1 /* txid */ + 1 /* amount_out */;
        let amount_in = self
            .public_inputs
            .get(offset)
            .context("can't find amount_in in public inputs")?;
        string_to_amount(amount_in)
    }

    /// This should only be called on stateful smart contracts.
    fn amount_out(&self, state_len: usize) -> Result<Amount> {
        let offset = state_len * 2 + 1 /* txid */;
        let amount_in = self
            .public_inputs
            .get(offset)
            .context("can't find amount_in in public inputs")?;
        string_to_amount(amount_in)
    }

    /// The transaction ID and output index of the zkapp used in the request.
    fn zkapp_outpoint(&self) -> Result<OutPoint> {
        let txin = self
            .tx
            .input
            .get(self.zkapp_input)
            .context("the transaction ID that was passed in the request does not exist")?;
        Ok(txin.previous_output)
        // TODO: do we care about other fields in txin and previous_output?
    }

    pub fn txid(&self) -> Result<Txid> {
        Ok(self.zkapp_outpoint()?.txid)
    }

    /// Validate the unsigned transaction contained in Bob's request.
    /// It checks outputs, but not inputs.
    /// The caller will be in charge of retrieving the smart contract and verifying its execution.
    fn validate_transaction(&self, smart_contract: &SmartContract) -> Result<()> {
        // it must contain an output fee paid to zkBitcoinFund
        self.tx
            .output
            .iter()
            .find(|x| {
                x.script_pubkey
                    == p2tr_script_to(PublicKey::from_str(ZKBITCOIN_FEE_PUBKEY).unwrap())
            })
            .context("the transaction does not contain an output fee paid to zkBitcoinFund")?;

        if smart_contract.is_stateful() {
            // if the zkapp is stateful, it must also produce a new stateful zkapp as output
            let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
            let new_zkapp = extract_smart_contract_from_tx(&self.tx, &zkbitcoin_pubkey)
                .context("the transaction does not contain a new stateful zkapp as output")?;

            // it contains the same VK
            ensure!(
                new_zkapp.vk_hash == smart_contract.vk_hash,
                "the updated zkapp is not the same as the previous zkapp"
            );

            // it contains the correct new state
            let state_len = smart_contract.state_len();
            let new_state = self.new_state(state_len)?;
            let new_state_bytes = new_state
                .iter()
                .map(|x| x.as_bytes().to_vec())
                .collect_vec();
            ensure!(
                new_zkapp.public_inputs == new_state_bytes,
                "the updated zkapp does not contain the correct new state"
            );

            // ensure that it contains the correct locked value after withdrawl and funding
            let new_value = new_zkapp.locked_value;
            let expected_value = smart_contract.updated_value(self)?;
            ensure!(expected_value == new_value, "the updated zkapp does not contain the correct locked value after withdrawl and funding");
        }

        //
        Ok(())
    }

    /// Validates a request received from Bob.
    pub async fn validate_request(
        &self,
        ctx: &RpcCtx,
        smart_contract: Option<SmartContract>,
    ) -> Result<SmartContract> {
        // fetch the smart contract if not given
        let smart_contract = if let Some(x) = smart_contract {
            x
        } else {
            fetch_smart_contract(ctx, self.txid()?).await?
        };

        // validate the unsigned transaction
        self.validate_transaction(&smart_contract)?;

        // ensure that the hash of the VK correctly gives us the vk_hash
        ensure!(
            smart_contract.vk_hash[..] == self.vk.hash(),
            "VK does not match the VK hash in the smart contract"
        );

        // ensure that the vk makes sense with public inputs that are fixed
        ensure!(smart_contract.public_inputs.len() <= self.vk.nPublic,"number of public inputs that are fixed is greater than the number of public inputs in the vk");

        // retrieve amount to be moved
        if smart_contract.is_stateful() {
            // ensure that the smart contract expects the correct number of public inputs
            let expected_len = smart_contract.public_inputs.len() * 2 /* prev state + new state */ + 1 /* truncated hash of bob address */ + 1 /* amount */;
            ensure!(
                self.vk.nPublic == expected_len,
                "the smart contract is malformed"
            );

            // ensure that number public inputs == vk.num_public_inputs
            ensure!(
                self.vk.nPublic == self.public_inputs.len(),
                "number of public input don't match"
            );

            // ensure that the previous state used is correctly used
            // TODO: we don't need Bob to send us that information
            let state_len = smart_contract.state_len();
            for (pi1, pi2) in smart_contract
                .public_inputs
                .iter()
                .zip(self.prev_state(state_len)?)
            {
                println!("pi1: {:?}", pi1);
                println!("pi2: {:?}", pi2);
                println!("pi2 as bytes: {:?}", pi2.as_bytes());
                ensure!(pi1 == pi2.as_bytes(), "public inputs don't match");
            }
        }

        // ensure that there's enough funds remaining to cover for bitcoin and zkBitcoin fee
        smart_contract.check_remaining_funds(&self)?;

        // verify proof using snarkjs
        verify_proof(&self)?;

        //
        Ok(smart_contract)
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
    fn state_len(&self) -> usize {
        self.public_inputs.len()
    }

    fn updated_value(&self, request: &BobRequest) -> Result<Amount> {
        ensure!(
            self.is_stateful(),
            "smart contract is stateless, so has no new value"
        );
        let state_len = self.state_len();
        let amount_in = request.amount_in(state_len)?;
        let amount_out = request.amount_out(state_len)?;
        let res = self.locked_value + amount_in - amount_out;
        Ok(res)
    }

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
    // fn calculate_split_funds(&self, request: &BobRequest) -> Result<(Amount, Amount)> {
    //     if self.is_stateless() {
    //         return Ok((self.locked_value, Amount::from_sat(0)));
    //     }

    //     let len_state = self.public_inputs.len();
    //     let amount_offset = len_state * 2 + 1;
    //     let zero = "0".to_string();
    //     let amount = request.public_inputs.get(amount_offset).unwrap_or(&zero);

    //     let bob_amount = {
    //         // TODO: need to write a test here
    //         let big = BigUint::from_str(amount).context("amount is not a u64 (err_code: 1)")?;
    //         let big_u64s = big.to_u64_digits();
    //         ensure!(big_u64s.len() == 1, "amount is not a u64 (err_code: 2)");
    //         let u64res = amount
    //             .parse::<u64>()
    //             .context("amount is not a u64 (err_code: 3)")?;
    //         ensure!(big_u64s[0] == u64res, "amount is not a u64 (err_code: 4)");
    //         Amount::from_sat(u64res)
    //     };

    //     let remaining = self.locked_value - bob_amount;

    //     Ok((bob_amount, remaining))
    // }

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

#[cfg(test)]
mod tests {
    use std::{fs::File, path::PathBuf};

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

        // create bob tx
        let tx = todo!();

        // create bob request
        let bob_request = BobRequest {
            tx,
            zkapp_input: 0,
            vk,
            proof,
            public_inputs: public_inputs.0,
        };

        // try to validate the request
        let ctx = RpcCtx::for_testing();

        bob_request
            .validate_request(&ctx, Some(smart_contract))
            .await
            .unwrap();
    }
}
