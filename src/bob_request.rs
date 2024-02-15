use std::{collections::HashMap, path::Path, str::FromStr, sync::Arc, vec};

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{
    opcodes::all::OP_RETURN, script::Instruction, Address, Amount, Denomination, OutPoint,
    PublicKey, Transaction, TxOut, Txid, Witness,
};
use log::{debug, info};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    circom_field_from_bytes, circom_field_to_bytes,
    compliance::Compliance,
    constants::{
        FEE_ZKBITCOIN_SAT, MINIMUM_CONFIRMATIONS, STATEFUL_ZKAPP_PUBLIC_INPUT_LEN,
        ZKBITCOIN_FEE_PUBKEY, ZKBITCOIN_PUBKEY,
    },
    get_network,
    json_rpc_stuff::{
        createrawtransaction, fund_raw_transaction, get_transaction, json_rpc_request,
        TransactionOrHex,
    },
    p2tr_script_to,
    plonk::PublicInputs,
    snarkjs::{self, verify_proof},
    taproot_addr_from, truncate_txid,
};
use crate::{json_rpc_stuff::RpcCtx, plonk};

//
// Helpers
//

/// Converts a string to some Bitcoin [Amount].
fn string_to_amount(amount: &str) -> Result<Amount> {
    // TODO: need to write a test here, once we have tested this we need to figure out which one to keep :D
    if amount == "0" {
        return Ok(Amount::ZERO);
    }
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

/// An update to a _stateful_ zkapp.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Update {
    /// The new state after update.
    pub new_state: String,

    /// The state of the zkapp being used.
    pub prev_state: String,

    /// The truncated txid should be rederived by the verifier.
    #[serde(skip)]
    pub truncated_txid: Option<String>,

    /// The amount being withdrawn from the zkapp.
    pub amount_out: String,

    /// The amount being deposited into the zkapp.
    pub amount_in: String,
}

/// A request from Bob to unlock funds from a smart contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BobRequest {
    /// The transaction authenticated by the proof, and that Bob wants to sign.
    /// This transaction should contain the zkapp as input, and a fee as output.
    /// It might also contain a new zkapp as output, in case the input zkapp was stateful.
    pub tx: Transaction,

    /// The transaction that deployed the zkapp.
    /// Technically we could just pass a transaction ID, but this would require nodes to fetch the transaction from the blockchain.
    /// Note that for this optimization to work, we need the full transaction,
    /// as we need to deconstruct the txid of the input of `tx`.
    pub zkapp_tx: Transaction,

    /// The verifier key authenticated by the deployed transaction.
    pub vk: plonk::VerifierKey,

    /// A proof of execution.
    pub proof: plonk::Proof,

    /// In case of stateful zkapps, the update that can be converted as public inputs.
    pub update: Option<Update>,

    /// List of all the [TxOut] pointed out by the inputs.
    /// (This is needed to sign the transaction.)
    /// We can trust this because if Bob sends us wrong data the signature we create simply won't verify.
    pub prev_outs: Vec<TxOut>,
}

impl BobRequest {
    #[allow(clippy::absurd_extreme_comparisons)]
    pub async fn new(
        rpc_ctx: &RpcCtx,
        bob_address: Address,
        txid: bitcoin::Txid, // of zkapp
        circom_circuit_path: &Path,
        mut proof_inputs: HashMap<String, Vec<String>>,
    ) -> Result<Self> {
        // fetch transaction + metadata based on txid
        debug!("- fetching txid {txid}");
        let (_, zkapp_tx, confirmations) = get_transaction(rpc_ctx, txid).await?;

        // enforce that the smart contract was confirmed
        ensure!(
            confirmations >= MINIMUM_CONFIRMATIONS,
            "Smart contract has not been confirmed yet"
        );

        // fetch smart contract we want to use
        let smart_contract = extract_smart_contract_from_tx(&zkapp_tx)?;
        debug!("- smart contract being used: {smart_contract:?}",);

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
                snarkjs::prove(circom_circuit_path, &proof_inputs).await?;

            // extract new_state
            let new_state = public_inputs
                .0
                .first()
                .cloned()
                .context("the full public input does not contain a new state")?;

            Some(new_state)
        } else {
            None
        };

        // create funded transaction
        let tx = {
            let inputs = vec![
                // the zkapp being used
                serde_json::json!({
                    "txid": txid.to_string(),
                    "vout": smart_contract.vout_of_zkbitcoin_utxo,
                }),
            ];

            let fee_address = taproot_addr_from(ZKBITCOIN_FEE_PUBKEY)?;
            let fee = Amount::from_sat(FEE_ZKBITCOIN_SAT).to_string_in(Denomination::Bitcoin);
            debug!(
                "- first output is to zkBitcoinFund: {} for {} BTC",
                fee_address, fee
            );

            let mut outputs = vec![
                // first output is to zkBitcoinFund
                serde_json::json!({
                    fee_address.to_string(): fee,
                }),
            ];

            if smart_contract.is_stateless() {
                // move all the funds to Bob's address
                let amount_out = smart_contract
                    .locked_value
                    .to_string_in(Denomination::Bitcoin);
                debug!(
                    "- stateless: second output is to ourselves: {} for {} BTC",
                    bob_address, amount_out
                );
                outputs.push(serde_json::json!({
                    bob_address.to_string(): amount_out,
                }));
            } else {
                // the new locked value to zkBitcoin
                let amount_in = string_to_amount(
                    proof_inputs
                        .get("amount_in")
                        .and_then(|x| x.first())
                        .context("amount_in in proof inputs must be of length 1")?,
                )?;
                let amount_out = string_to_amount(
                    proof_inputs
                        .get("amount_out")
                        .and_then(|x| x.first())
                        .context("amount_out in proof inputs must be of length 1")?,
                )?;
                let new_value = smart_contract.locked_value + amount_in - amount_out;

                let withdraw_happening = amount_out != Amount::ZERO;

                // convert to BTC as expected by API
                let amount_in = amount_in.to_string_in(Denomination::Bitcoin);
                let new_value = new_value.to_string_in(Denomination::Bitcoin);
                let amount_out = amount_out.to_string_in(Denomination::Bitcoin);
                let locked = smart_contract
                    .locked_value
                    .to_string_in(Denomination::Bitcoin);

                debug!("- stateful: Bob is attempting to deposit {amount_in} BTC, and withdraw {amount_out} BTC, from the zkapp's {locked} BTC");
                debug!(
                    "- there will be {new_value} BTC locked in the zkapp after this transaction"
                );

                // the updated zkapp
                let zkbitcoin_address = taproot_addr_from(ZKBITCOIN_PUBKEY)?;
                debug!(
                    "- stateful: second output is to zkBitcoin: {} for {} BTC",
                    zkbitcoin_address, new_value
                );
                outputs.push(serde_json::json!({
                    zkbitcoin_address.to_string(): new_value
                }));

                // Bob can only withdraw amount_out
                if withdraw_happening {
                    debug!("- Bob is receiving amount_out: {}", amount_out);
                    outputs.push(serde_json::json!({
                        bob_address.to_string(): amount_out,
                    }));
                }

                // its vk + new state
                let new_state = new_state.as_ref().context("no new state")?;
                let mut data = smart_contract.vk_hash.to_vec();
                data.extend(circom_field_to_bytes(new_state).context("incorrect new state given")?);
                outputs.push(serde_json::json!({
                    "data": hex::encode(data),
                }));
            }

            // call createrawtransaction
            let (tx_hex, tx) = createrawtransaction(rpc_ctx, inputs, outputs, 0).await?;
            debug!("- tx created: {tx:?}");

            // fund that transaction
            let (_tx_hex, tx, fee) =
                fund_raw_transaction(rpc_ctx, TransactionOrHex::Hex(tx_hex)).await?;

            info!("- funded tx with fee {fee}");
            debug!("- tx funded: {tx:?}");

            tx
        };

        // create a proof with the correct txid this time
        let truncated_txid = truncate_txid(tx.txid());
        proof_inputs.insert("truncated_txid".to_string(), vec![truncated_txid]);

        let (proof, public_inputs, vk) = snarkjs::prove(circom_circuit_path, &proof_inputs).await?;
        debug!(
            "- public_inputs used to create the proof: {:?}",
            public_inputs.0
        );

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
                    == 2 /* prev/new_state */ + 1 /* truncated txid */ + 1 /* amount_out */ + 1, /* amount_in */
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

        // compute zkapp input as the input that uses the zkapp
        let zkapp_inputs = tx
            .input
            .iter()
            .filter(|x| x.previous_output.txid == txid)
            .collect::<Vec<_>>();

        ensure!(
            zkapp_inputs.len() == 1,
            "internal error: the transaction does not contain the zkapp being used or it contains duplicate inputs"
        );

        // compute prev_outs as all the TxOut pointed out by the inputs
        let mut prev_outs = vec![];
        for (input_idx, input) in tx.input.iter().enumerate() {
            let (_, tx, confirmations) =
                get_transaction(rpc_ctx, input.previous_output.txid).await?;
            // TODO: this is not useful as the transaction itself has received enough confirmation at this point
            ensure!(
                confirmations >= MINIMUM_CONFIRMATIONS,
                "one of the input ({}) is not confirmed yet",
                input.previous_output.txid
            );

            prev_outs.push(
                tx.output
                    .get(input.previous_output.vout as usize)
                    .context(format!("the input {input_idx} does not exist"))?
                    .clone(),
            );
        }

        // create request
        let res = Self {
            tx,
            zkapp_tx,
            vk,
            proof,
            update,
            prev_outs,
        };

        debug!("- Bob's request: {res:?}");

        Ok(res)
    }

    pub fn unlocked_tx(&self, witness: Witness) -> Result<Transaction> {
        let mut transaction = self.tx.clone();

        transaction
            .input
            .iter_mut()
            .find(|tx| tx.previous_output.txid == self.zkapp_tx.txid())
            .context("couldn't find zkapp input in transaction")?
            .witness = witness;

        Ok(transaction)
    }

    /// The transaction ID and output index of the zkapp used in the request.
    fn zkapp_outpoint(&self) -> Result<OutPoint> {
        let outpoint = self
            .tx
            .input
            .iter()
            .find(|tx| tx.previous_output.txid == self.zkapp_tx.txid())
            .context("the transaction ID that was passed in the request does not exist")?
            .previous_output;

        Ok(outpoint)

        // TODO: do we care about other fields in txin and previous_output?
    }

    pub fn txid(&self) -> Result<Txid> {
        Ok(self.zkapp_outpoint()?.txid)
    }

    /// Validate the unsigned transaction contained in Bob's request.
    /// It checks outputs, but not inputs.
    /// The caller will be in charge of retrieving the smart contract and verifying its execution.
    fn validate_transaction(
        tx: &Transaction,
        smart_contract: &SmartContract,
        update: Option<&Update>,
    ) -> Result<()> {
        // TODO: we need to make sure that amount_out < smart_contract.locked_value

        // it must contain an output fee paid to zkBitcoinFund
        {
            let pay_to_zkbitcoin_fund_script =
                p2tr_script_to(PublicKey::from_str(ZKBITCOIN_FEE_PUBKEY).unwrap());
            debug!(
                "- pay_to_zkbitcoin_fund_script: {:?}",
                pay_to_zkbitcoin_fund_script
            );
            let fee_output = tx
                .output
                .iter()
                .find(|x| x.script_pubkey == pay_to_zkbitcoin_fund_script)
                .context("the transaction does not contain an output fee paid to zkBitcoinFund")?;

            // check fee amount
            ensure!(
            fee_output.value >= Amount::from_sat(FEE_ZKBITCOIN_SAT),
            "the transaction fee paid to zkBitcoinFund needs to be {ZKBITCOIN_FEE_PUBKEY} satoshis at the very least, come on"
        );
        }

        if let Some(update) = update {
            // ensure we are updating because it's a stateful zkapp
            ensure!(
                smart_contract.is_stateful(),
                "Bob sent an update but the zkapp used is stateless"
            );

            // if the zkapp is stateful, it must also produce a new stateful zkapp as output
            let new_zkapp = extract_smart_contract_from_tx(tx)?;

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
            let expected_value = {
                let amount_out = Amount::from_str_in(&update.amount_out, Denomination::Satoshi)?;
                let amount_in = Amount::from_str_in(&update.amount_in, Denomination::Satoshi)?;
                smart_contract.locked_value + amount_in - amount_out
            };
            ensure!(expected_value == new_value, "the updated zkapp does not contain the correct locked value after withdrawl and funding");
        }

        //
        Ok(())
    }

    /// Check that the zkapp input transactions are compliant
    pub async fn check_compliance(&self, compliance: Arc<Compliance>) -> Result<()> {
        for (index, zkapp_txin) in self.zkapp_tx.input.iter().enumerate() {
            let addr = Address::from_script(
                &zkapp_txin.script_sig.clone().into_boxed_script(),
                get_network(),
            )?;

            ensure!(
                !compliance.is_sanctioned(&addr).await,
                format!("ZkApp input #{index} is sanctioned"),
            );
        }

        Ok(())
    }

    /// Validates a request received from Bob.
    pub async fn validate_request(&self) -> Result<SmartContract> {
        // extract smart contract from tx
        let smart_contract = extract_smart_contract_from_tx(&self.zkapp_tx)?;

        // ensure that the zkapp_tx given is the one being used
        let zkapp_outpoint = self.zkapp_outpoint()?;
        ensure!(
            smart_contract.txid == zkapp_outpoint.txid,
            "the zkapp_tx given is not the one being used"
        );

        // validate the unsigned transaction
        Self::validate_transaction(&self.tx, &smart_contract, self.update.as_ref())?;

        // ensure that the hash of the VK correctly gives us the vk_hash
        ensure!(
            smart_contract.vk_hash[..] == self.vk.hash(),
            "VK does not match the VK hash in the smart contract"
        );

        // TODO: do we need to check that vk.nPublic makes sense?

        // create truncated txid of Bob's transaction
        let bob_txid = self.tx.txid();
        let truncated_txid = truncate_txid(bob_txid);

        // retrieve amount to be moved
        let public_inputs = if let Some(prev_state) = &smart_contract.state {
            // ensure that we have an update
            let update = self
                .update
                .as_ref()
                .context("an update was expected as the smart contract is stateful")?;

            // ensure that the smart contract expects the correct number of public inputs
            ensure!(
                self.vk.nPublic == STATEFUL_ZKAPP_PUBLIC_INPUT_LEN,
                "the smart contract is malformed, we observed {nPublic} public inputs, but expected {STATEFUL_ZKAPP_PUBLIC_INPUT_LEN} for a stateful zkapp", nPublic=self.vk.nPublic
            );

            // ensure that the previous state used is correctly used
            ensure!(prev_state == &update.prev_state);

            //
            PublicInputs::from_update(update, truncated_txid)?.0
        } else {
            vec![truncated_txid]
        };
        debug!("- using public inputs: {public_inputs:?}");

        // TODO: ensure that there's enough funds remaining to cover for bitcoin and zkBitcoin fee
        // TODO: we need to make sure that new_locked = prev_locked + amount_in - amount_out and that amount_out < prev_locked + amount_in
        //smart_contract.check_remaining_funds(&self)?;

        // verify proof using snarkjs
        debug!("- attempting to verify proof");
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
    let ctx = RpcCtx::new(Some("2.0"), None, Some(address.to_string()), None, None);

    let resp = json_rpc_request(
        &ctx,
        "unlock_funds",
        &[serde_json::value::to_raw_value(&request).unwrap()],
    )
    .await
    .context("couldn't send unlock_funds request to orchestrator")?;

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
    pub txid: Txid,
    pub locked_value: Amount,
    pub vk_hash: [u8; 32],
    pub state: Option<String>,
    pub vout_of_zkbitcoin_utxo: u32,
}

impl std::fmt::Display for SmartContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let &SmartContract {
            txid,
            locked_value,
            vk_hash,
            state,
            vout_of_zkbitcoin_utxo,
        } = &self;

        write!(
            f,
            "- txid: {txid} (output #{vout}), locked_value: {locked_value}, vk_hash: {vk_hash}, {state}",
            vk_hash=hex::encode(vk_hash),
            vout=vout_of_zkbitcoin_utxo,
            state=state.as_ref().map(|s| format!("state: {s}")).unwrap_or("stateless".to_string())
        )
    }
}

impl SmartContract {
    /// Returns true if the smart contract is stateless.
    fn is_stateless(&self) -> bool {
        // a stateless contract expects no public input
        self.state.is_none()
    }

    /// Returns true if the smart contract is stateful.
    fn is_stateful(&self) -> bool {
        self.state.is_some()
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
pub fn extract_smart_contract_from_tx(raw_tx: &Transaction) -> Result<SmartContract> {
    // extract zkapp locked amount
    let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
    let expected_script = p2tr_script_to(zkbitcoin_pubkey);
    let (vout, output) = raw_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, x)| x.script_pubkey == expected_script)
        .context("Transaction does not contain an output for 0xzkBitcoin")?;
    let locked_value = output.value;

    // extract OP_RETURN data
    let (vk_hash, state) = {
        let output = raw_tx
            .output
            .iter()
            .find(|x| x.script_pubkey.is_op_return())
            .context("Transaction has no OP_RETURN")?;
        let data = parse_op_return_data(&output.script_pubkey)?;

        // ensure that the list at least contains the VK hash
        // other elements in the list are presumed to contain public inputs
        ensure!(data.len() >= 32, "OP_RETURN output is too small, it should at least contain the 32-byte hash of the verifier key");

        let (vk_hash, state) = data.split_at(32);
        let vk_hash: [u8; 32] = vk_hash.try_into().unwrap();

        // parse state
        let state = if state.is_empty() {
            None
        } else {
            let res = circom_field_from_bytes(state)?;
            Some(res)
        };

        (vk_hash, state)
    };

    let smart_contract = SmartContract {
        txid: raw_tx.txid(),
        locked_value,
        vk_hash,
        state,
        vout_of_zkbitcoin_utxo: vout as u32,
    };
    Ok(smart_contract)
}

/// Fetch the smart contract on-chain from the txid.
#[allow(clippy::absurd_extreme_comparisons)]
pub async fn fetch_smart_contract(ctx: &RpcCtx, txid: bitcoin::Txid) -> Result<SmartContract> {
    // fetch transaction + metadata based on txid
    debug!("- fetching txid {txid}", txid = txid);
    let (_tx_hex, transaction, confirmations) = get_transaction(ctx, txid).await?;

    // enforce that the smart contract was confirmed
    ensure!(
        confirmations >= MINIMUM_CONFIRMATIONS,
        "Smart contract has not been confirmed yet"
    );

    // parse transaction
    extract_smart_contract_from_tx(&transaction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero() {
        let amount_in = string_to_amount("0").unwrap();
        let amount_in = amount_in.to_string_in(Denomination::Bitcoin);
        assert_eq!(&amount_in, "0");
    }
}
