use std::{collections::HashMap, path::Path, str::FromStr, vec};

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{
    consensus::Decodable, opcodes::all::OP_RETURN, script::Instruction, Address, Amount,
    Denomination, OutPoint, PublicKey, Transaction, Txid,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    circom_field_from_bytes, circom_field_to_bytes,
    constants::{FEE_ZKBITCOIN_SAT, MINIMUM_CONFIRMATIONS, ZKBITCOIN_FEE_PUBKEY, ZKBITCOIN_PUBKEY},
    json_rpc_stuff::{fund_raw_transaction, json_rpc_request, TransactionOrHex},
    p2tr_script_to,
    plonk::PublicInputs,
    snarkjs::{self, verify_proof},
    taproot_addr_from, truncate_txid,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Update {
    pub new_state: String,
    pub prev_state: String,

    /// The truncated txid should be rederived by the verifier.
    #[serde(skip)]
    pub truncated_txid: Option<String>,

    pub amount_out: String,
    pub amount_in: String,
}

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

    /// In case of stateful zkapps, the update that can be converted as public inputs.
    pub update: Option<Update>,
}

impl BobRequest {
    pub async fn new(
        rpc_ctx: &RpcCtx,
        bob_address: Address,
        txid: bitcoin::Txid, // of zkapp
        circom_circuit_path: &Path,
        mut proof_inputs: HashMap<String, Vec<String>>,
    ) -> Result<Self> {
        // fetch smart contract we want to use
        let smart_contract = fetch_smart_contract(&rpc_ctx, txid).await?;

        println!(
            "Bob's trying to use this smart contract: {:#?}",
            smart_contract
        );

        // create a proof with a 0 txid
        // (we expect the proof to give the same `new_state` with the correct `truncated_txid` later)
        // we need to do this because we need to include the `new_state` in a stateful zkapp transaction
        // and then we can compute the transaction ID
        // and then we can compute the proof on the correct public inputs (which include the transaction ID).

        let new_state = if let Some(prev_state) = &smart_contract.state {
            // truncated_txid = 0
            proof_inputs.insert("truncated_txid".to_string(), vec!["0".to_string()]);
            proof_inputs.insert("prev_state".to_string(), vec![prev_state.to_string()]);

            // prove
            let (_proof, public_inputs, _vk) =
                snarkjs::prove(&circom_circuit_path, &proof_inputs).await?;

            // extract new_state
            let new_state = public_inputs
                .0
                .get(0)
                .cloned()
                .context("the full public input does not contain a new state")?;

            Some(new_state)
        } else {
            None
        };

        // create a transaction to spend that input
        // let tx = {
        //     let mut inputs = vec![];

        //     // first input is the zkapp being used
        //     {
        //         inputs.push(TxIn {
        //             previous_output: OutPoint {
        //                 txid,
        //                 vout: smart_contract.vout_of_zkbitcoin_utxo,
        //             },
        //             script_sig: ScriptBuf::new(),
        //             sequence: Sequence::MAX,
        //             witness: Witness::new(),
        //         });
        //     }

        //     let mut outputs = vec![];

        //     // first output is to zkBitcoinFund
        //     {
        //         let zkbitcoin_pubkey: PublicKey =
        //             PublicKey::from_str(ZKBITCOIN_FEE_PUBKEY).unwrap();
        //         outputs.push(TxOut {
        //             value: Amount::from_sat(FEE_ZKBITCOIN_SAT),
        //             script_pubkey: p2tr_script_to(zkbitcoin_pubkey),
        //         });
        //     }

        //     // second output is to ourselves
        //     {
        //         let script_pubkey = bob_address.script_pubkey();
        //         let value = if smart_contract.is_stateful() {
        //             string_to_amount(
        //                 proof_inputs
        //                     .get("amount_out")
        //                     .and_then(|x| x.get(0))
        //                     .context("amount_out in proof inputs must be of length 1")?,
        //             )?
        //         } else {
        //             smart_contract.locked_value - Amount::from_sat(FEE_ZKBITCOIN_SAT)
        //         };
        //         outputs.push(TxOut {
        //             value,
        //             script_pubkey,
        //         });
        //     }

        //     // if it's a stateful zkapp, we need to add a new zkapp as output
        //     if smart_contract.is_stateful() {
        //         // the new locked value to zkBitcoin
        //         let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
        //         let amount_in = string_to_amount(
        //             proof_inputs
        //                 .get("amount_in")
        //                 .and_then(|x| x.get(0))
        //                 .context("amount_in in proof inputs must be of length 1")?,
        //         )?;
        //         let amount_out = string_to_amount(
        //             proof_inputs
        //                 .get("amount_out")
        //                 .and_then(|x| x.get(0))
        //                 .context("amount_out in proof inputs must be of length 1")?,
        //         )?;
        //         let new_value = smart_contract.locked_value + amount_in - amount_out;
        //         outputs.push(TxOut {
        //             value: new_value,
        //             script_pubkey: p2tr_script_to(zkbitcoin_pubkey),
        //         });

        //         // the vk + new state
        //         outputs.push(TxOut {
        //             value: Amount::from_sat(0),
        //             script_pubkey: op_return_script_for(
        //                 &smart_contract.vk_hash,
        //                 new_state.as_ref(),
        //             )?,
        //         });
        //     }

        //     Transaction {
        //         version: Version::TWO,
        //         lock_time: LockTime::ZERO, // no lock time
        //         input: inputs,
        //         output: outputs,
        //     }
        // };

        // if true {
        // println!("tx1: {:?}", tx);
        // let mut tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
        // tx_hex.push_str("00000000");
        // println!("tx_hex: {}", tx_hex);
        // let tx2: Transaction =
        //     bitcoin::consensus::encode::deserialize(&hex::decode(&tx_hex).unwrap()).unwrap();
        // println!("tx2: {:?}", tx2);
        // let params = &[
        //     // tx
        //     serde_json::value::to_raw_value(&serde_json::Value::String(tx_hex)).unwrap(),
        //     // permitsigdata
        //     //serde_json::value::to_raw_value(&serde_json::Value::Bool(false)).unwrap(),
        //     // iswitness
        //     //serde_json::value::to_raw_value(&serde_json::Value::Bool(false)).unwrap(),
        // ];
        // println!("{}", serde_json::to_string(params).unwrap());
        // let response = json_rpc_request(rpc_ctx, "converttopsbt", params)
        //     .await
        //     .context("converttopsbt error")?;

        // // TODO: get rid of unwrap in here
        // let response: bitcoincore_rpc::jsonrpc::Response =
        //     serde_json::from_str(&response).unwrap();
        // println!("{:?}", response);
        // panic!("yo!");
        // }

        // TODO: trying to use PSBT instead
        let tx = {
            // let's try to create the same transaction but using `walletcreatefundedpsbt`
            /*
            walletcreatefundedpsbt ( [{"txid":"hex","vout":n,"sequence":n},...] ) [{"address":amount},{"data":"hex"},...] ( locktime options bip32derivs )
             */
            let inputs = vec![
                // the zkapp being used
                serde_json::json!({
                    "txid": txid.to_string(),
                    "vout": smart_contract.vout_of_zkbitcoin_utxo,
                }),
            ];

            let fee_address = taproot_addr_from(ZKBITCOIN_FEE_PUBKEY)?;

            let mut outputs = vec![
                // first output is to zkBitcoinFund
                // TODO: we need to create a taproot address here
                serde_json::json!({
                    fee_address.to_string(): Amount::from_sat(FEE_ZKBITCOIN_SAT).to_string_in(Denomination::Bitcoin),
                }),
            ];

            if smart_contract.is_stateless() {
                // move all the funds to Bob's address
                outputs.push(
                serde_json::json!({
                    bob_address.to_string(): smart_contract.locked_value.to_string_in(Denomination::Bitcoin),
                }));
            } else {
                // the new locked value to zkBitcoin
                let amount_in = string_to_amount(
                    proof_inputs
                        .get("amount_in")
                        .and_then(|x| x.get(0))
                        .context("amount_in in proof inputs must be of length 1")?,
                )?;
                let amount_out = string_to_amount(
                    proof_inputs
                        .get("amount_out")
                        .and_then(|x| x.get(0))
                        .context("amount_out in proof inputs must be of length 1")?,
                )?;
                let new_value = smart_contract.locked_value + amount_in - amount_out;

                // Bob can only withdraw amount_out
                outputs.push(serde_json::json!({
                    bob_address.to_string(): amount_out.to_string_in(Denomination::Bitcoin),
                }));

                // the updated zkapp
                let zkbitcoin_address = taproot_addr_from(ZKBITCOIN_PUBKEY)?;
                outputs.push(serde_json::json!({
                    // TODO: this is incorrect as it's not a taproot address
                    zkbitcoin_address.to_string(): new_value.to_string_in(Denomination::Bitcoin)
                }));

                // its vk + new state
                let new_state = new_state.as_ref().context("no new state")?;
                let mut data = smart_contract.vk_hash.to_vec();
                data.extend(circom_field_to_bytes(new_state).context("incorrect new state given")?);
                outputs.push(serde_json::json!({
                    "data": hex::encode(data),
                }));
            }

            // call createrawtransaction
            let change_position = outputs.len(); // place change at the end of the outputs
            let params = &[
                // inputs
                serde_json::value::to_raw_value(&serde_json::Value::Array(inputs)).unwrap(),
                // outputs
                serde_json::value::to_raw_value(&serde_json::Value::Array(outputs)).unwrap(),
                // lock time
                serde_json::value::to_raw_value(&serde_json::Number::from(0)).unwrap(),
                // params
                // serde_json::value::to_raw_value(&serde_json::json!({
                //     "add_inputs": true,
                //     "changePosition": change_position,
                // }))
                // .unwrap(),
            ];
            println!("{}", serde_json::to_string(params).unwrap());
            let response = json_rpc_request(rpc_ctx, "createrawtransaction", params)
                .await
                .context("createrawtransaction error")?;

            // TODO: get rid of unwrap in here
            let response: bitcoincore_rpc::jsonrpc::Response =
                serde_json::from_str(&response).unwrap();
            println!("{:?}", response);

            #[derive(Debug, Clone, Deserialize)]
            struct CreateRawTransactionResult {
                #[serde(with = "bitcoincore_rpc::json::serde_hex")]
                hex: Vec<u8>,
            }
            let tx_hex: String = response.result().unwrap();
            println!("{:?}", tx_hex);

            println!(
                "decoded raw tx: {:?}",
                Transaction::consensus_decode(&mut &hex::decode(&tx_hex).unwrap()[..]).unwrap()
            );

            // fund that transaction
            let (tx_hex, tx) = fund_raw_transaction(rpc_ctx, TransactionOrHex::Hex(tx_hex)).await?;

            tx
        };

        // println!(
        //     "- created transaction, will now ask wallet to fund it ({})",
        //     bitcoin::consensus::encode::serialize_hex(&tx)
        // );

        // // add truncated txid to proof inputs
        // {
        //     let txid = tx.txid();
        //     let truncated_txid = truncate_txid(txid);
        //     proof_inputs.insert("truncated_txid".to_string(), vec![truncated_txid]);
        // }

        // // fund it using BITCOIN RPC
        // let (_raw_tx_with_inputs_hex, funded_tx) =
        //     fund_raw_transaction(rpc_ctx, TransactionOrHex::Transaction(&tx)).await?;

        // create a proof with the correct txid this time
        let (proof, public_inputs, vk) =
            snarkjs::prove(&circom_circuit_path, &proof_inputs).await?;

        // sanity check
        ensure!(
            vk.hash() == smart_contract.vk_hash,
            "the zkapp being used does not match the circuit passed"
        );

        // and ensure it created the same new_state
        let update = if smart_contract.is_stateful() {
            let new_state = new_state.unwrap();
            ensure!(
                public_inputs.0.len()
                    == 1 * 2 /* prev/new_state */ + 1 /* truncated txid */ + 1 /* amount_out */ + 1, /* amount_in */
                "the number of public inputs is not correct"
            );

            let new_state2 = &public_inputs.0[0];
            ensure!(
                &new_state == new_state2,
                "the circuit must return the same output given different txid"
            );

            Some(public_inputs.to_update())
        } else {
            None
        };

        //
        let res = Self {
            tx,
            zkapp_input: 0,
            vk,
            proof,
            update,
        };

        println!("Bob's request: {:#?}", res);

        Ok(res)
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
        // TODO: we need to make sure that amount_out < smart_contract.locked_value

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
            let update = self.update.as_ref().unwrap();

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
            let new_state_observed = new_zkapp.state.context(
                "the zkapp created as output is not stateful, but the consumed zkapp was stateful",
            )?;
            ensure!(
                new_state_observed == update.new_state,
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
        bob_txid: Txid,
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

        // TODO: do we need to check that vk.nPublic makes sense?

        // create truncated txid of Bob's transaction
        let truncated_txid = truncate_txid(bob_txid);

        // retrieve amount to be moved
        let public_inputs = if let Some(prev_state) = &smart_contract.state {
            // ensure that we have an update
            let update = self
                .update
                .as_ref()
                .context("an update was expected as the smart contract is stateful")?;

            // ensure that the smart contract expects the correct number of public inputs
            let expected_len = 1 * 2 /* prev state + new state */ + 1 /* truncated hash of bob address */ + 1 /* amount */;
            ensure!(
                self.vk.nPublic == expected_len,
                "the smart contract is malformed"
            );

            // ensure that the previous state used is correctly used
            ensure!(prev_state == &update.prev_state);

            //
            PublicInputs::from_update(update, 1, truncated_txid)?.0
        } else {
            vec![truncated_txid]
        };

        // ensure that there's enough funds remaining to cover for bitcoin and zkBitcoin fee
        //smart_contract.check_remaining_funds(&self)?;

        // verify proof using snarkjs
        verify_proof(&self.vk, &public_inputs, &self.proof)?;

        //
        Ok(smart_contract)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BobResponse {
    pub unlocked_tx: Transaction,
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
#[derive(Clone, Debug)]
pub struct SmartContract {
    pub locked_value: Amount,
    pub vk_hash: [u8; 32],
    pub state: Option<String>,
    pub vout_of_zkbitcoin_utxo: u32,

    /// _All_ the outputs of the deploy transaction.
    /// (needed to sign a transaction to unlock the funds).
    pub prev_outs: Vec<bitcoin::TxOut>,
}

impl SmartContract {
    fn updated_value(&self, request: &BobRequest) -> Result<Amount> {
        ensure!(
            self.is_stateful(),
            "smart contract is stateless, so has no new value"
        );
        let update = request.update.as_ref().context("no update present")?;
        let amount_out = Amount::from_str_in(&update.amount_out, Denomination::Satoshi)?;
        let amount_in = Amount::from_str_in(&update.amount_in, Denomination::Satoshi)?;
        let res = self.locked_value + amount_in - amount_out;
        Ok(res)
    }

    /// Returns true if the smart contract is stateless.
    fn is_stateless(&self) -> bool {
        // a stateless contract expects no public input
        self.state.is_none()
    }

    /// Returns true if the smart contract is stateful.
    fn is_stateful(&self) -> bool {
        self.state.is_some()
    }

    // Returns the amount that is being withdrawn from the smart contract, and the remaining amount in the contract (0 if stateless).
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

    // Ensures that there is enough $$ to cover for fees
    // TODO: wait, is this relevant anymore? The transaction won't go through if there's not enough funds anyway
    // fn check_remaining_funds(&self, request: &BobRequest) -> Result<()> {
    //     // TODO: bitcoin fee shouldn't be a constant
    //     // TODO: use https://crates.io/crates/bitcoin-fees or https://lib.rs/crates/bitcoinwallet-fees
    //     let fees = Amount::from_sat(FEE_BITCOIN_SAT) + Amount::from_sat(FEE_ZKBITCOIN_SAT);

    //     let remaining = if self.is_stateless() {
    //         self.locked_value
    //     } else {
    //         let update = request
    //             .update
    //             .as_ref()
    //             .context("no update present for a request using a stateful contract")?;

    //         let len_state = self.public_inputs.len();
    //         let amount_offset = len_state * 2 + 1;
    //         let zero = "0".to_string();
    //         let amount = request.public_inputs.get(amount_offset).unwrap_or(&zero);
    //         let bob_amount = {
    //             // TODO: need to write a test here
    //             let big = BigUint::from_str(amount).context("amount is not a u64 (err_code: 1)")?;
    //             let big_u64s = big.to_u64_digits();
    //             ensure!(big_u64s.len() == 1, "amount is not a u64 (err_code: 2)");
    //             let u64res = amount
    //                 .parse::<u64>()
    //                 .context("amount is not a u64 (err_code: 3)")?;
    //             ensure!(big_u64s[0] == u64res, "amount is not a u64 (err_code: 4)");
    //             Amount::from_sat(u64res)
    //         };

    //         ensure!(
    //             self.locked_value >= bob_amount,
    //             "there is not enough funds in the zkapp to cover for the withdrawal amount"
    //         );

    //         self.locked_value - bob_amount
    //     };

    //     ensure!(
    //         remaining > fees,
    //         "there is not enough funds in the zkapp to cover for bitcoin and zkBitcoin fees"
    //     );

    //     Ok(())
    // }
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

    // we expect an OP_RETURN output containing both the vk and the state (if any)
    let (vk_hash, state) = {
        // find the first OP_RETURN
        let output = outputs
            .find(|x| x.script_pubkey.is_op_return())
            .context("Transaction has no OP_RETURN")?;

        // parse it
        let data = parse_op_return_data(&output.script_pubkey)?;
        println!(
            "- extracted {data:?} from OP_RETURN {:?}",
            output.script_pubkey.as_script()
        );

        // ensure that the list at least contains the VK hash
        // other elements in the list are presumed to contain public inputs
        ensure!(data.len() >= 32, "OP_RETURN output is too small, it should at least contain the 32-byte hash of the verifier key");

        // TODO: extract validate the vk hash against the given vk
        let (vk_hash, state) = data.split_at(32);
        println!("- vk hash extracted: {:?}", vk_hash);
        let vk_hash: [u8; 32] = vk_hash.try_into().unwrap();

        // parse state
        let state = if state.is_empty() {
            None
        } else {
            let res = circom_field_from_bytes(state)?;
            println!("state extracted: {}", res);
            Some(res)
        };

        (vk_hash, state)
    };

    let smart_contract = SmartContract {
        locked_value,
        vk_hash,
        state,
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

    use crate::plonk;

    use super::*;

    // #[tokio::test]
    // async fn test_validate_bob_request() {
    //     // read circuit example files
    //     let circuit_files = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/circuit");

    //     // get proof, vk, and inputs
    //     let proof: plonk::Proof = {
    //         let proof_path = circuit_files.join("proof.json");
    //         let file = File::open(proof_path).expect("file not found");
    //         serde_json::from_reader(file).expect("error while reading file")
    //     };
    //     let vk: plonk::VerifierKey = {
    //         let vk_path = circuit_files.join("vk.json");
    //         let file = File::open(vk_path).expect("file not found");
    //         serde_json::from_reader(file).expect("error while reading file")
    //     };
    //     let public_inputs: plonk::PublicInputs = {
    //         let proof_inputs_path = circuit_files.join("proof_inputs.json");
    //         let file = File::open(proof_inputs_path).expect("file not found");
    //         serde_json::from_reader(file).expect("error while reading file")
    //     };

    //     // truncate a portion (let's say 10) of the public inputs
    //     assert_eq!(public_inputs.0.len(), 96);
    //     let truncated_pi = public_inputs
    //         .0
    //         .iter()
    //         .map(|x| x.as_bytes().to_vec())
    //         .take(32)
    //         .collect();

    //     // create smart contract
    //     let vk_hash = vk.hash();
    //     let smart_contract = SmartContract {
    //         locked_value: Amount::from_sat(10),
    //         vk_hash,
    //         state: truncated_pi,
    //         vout_of_zkbitcoin_utxo: 0,
    //         prev_outs: vec![],
    //     };

    //     // create bob tx
    //     let tx = todo!();

    //     // create bob request
    //     let bob_request = BobRequest {
    //         tx,
    //         zkapp_input: 0,
    //         vk,
    //         proof,
    //         update: None,
    //     };

    //     // try to validate the request
    //     let ctx = RpcCtx::for_testing();

    //     bob_request
    //         .validate_request(&ctx, Some(smart_contract), tx.txid())
    //         .await
    //         .unwrap();
    // }
}
