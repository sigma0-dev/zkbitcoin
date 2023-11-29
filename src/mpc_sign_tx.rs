use std::str::FromStr;

use bitcoin::{sighash, Amount, PublicKey, Transaction};

use crate::{
    bob_request::BobRequest,
    constants::{MINIMUM_CONFIRMATIONS, ZKBITCOIN_PUBKEY},
    json_rpc_stuff::json_rpc_request,
};

/// All the metadata that describes a smart contract.
pub struct SmartContract {
    pub locked_value: Amount,
    pub vk_hash: [u8; 32],
    pub vk: Option<()>, // TODO: replace with actual VK type
}

/// Extracts smart contract information as a [SmartContract] from a transaction.
pub fn parse_transaction(raw_tx: &Transaction) -> Result<SmartContract, &'static str> {
    let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();

    // ensure that the first or second output is to 0xzkBitcoin and extract amount
    let mut outputs = raw_tx.output.iter();
    let locked_value = {
        let output = outputs.next().ok_or("tx has no output")?;
        if output.script_pubkey.as_script().p2pk_public_key() != Some(zkbitcoin_pubkey) {
            // the first output must have been the change, moving on to the second output
            let output = outputs.next().ok_or("tx has no output")?;
            if output.script_pubkey.as_script().p2pk_public_key() != Some(zkbitcoin_pubkey) {
                return Err("Transaction's first or second output must be for 0xzkBitcoin");
            }
            output.value
        } else {
            output.value
        }
    };

    // create a list of all the outputs following that one that are OP_RETURN outputs
    let mut op_return_outputs = vec![];
    for output in outputs {
        if output.script_pubkey.is_op_return() {
            let unlock_script = output.script_pubkey.as_bytes();
            let data = unlock_script[1..].to_vec();
            op_return_outputs.push(data);
        } else {
            // break at the first non-OP_RETURN output
            break;
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
pub async fn validate_request(request: BobRequest) -> Result<(), &'static str> {
    // fetch transaction + metadata based on txid
    let (transaction, confirmations) = {
        println!("- fetching txid {txid}", txid = request.txid);

        let response = json_rpc_request(
            None,
            "gettransaction",
            &[serde_json::value::to_raw_value(&serde_json::Value::String(
                request.txid.to_string(),
            ))
            .unwrap()],
        )
        .await
        .map_err(|_| "TODO: real error")?;

        // TODO: get rid of unwrap in here
        let response: jsonrpc::Response = serde_json::from_str(&response).unwrap();
        let parsed: bitcoincore_rpc::json::GetTransactionResult = response.result().unwrap();
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex).unwrap();
        let actual_hex = hex::encode(&parsed.hex);

        //println!("- tx found: {tx:?}");
        println!("- tx found: (in hex): {actual_hex}");

        (tx, parsed.info.confirmations)
    };

    // enforce that the smart contract was confirmed
    if confirmations < MINIMUM_CONFIRMATIONS {
        return Err("Smart contract has not been confirmed yet");
    }

    // parse transaction
    let smart_contract = parse_transaction(&transaction)?;

    // TODO: ensure that number public inputs <= vk.num_public_inputs

    // TODO: ensure that the hash of the VK correctly gives us the vk_hash

    // TODO: verify proof
    Ok(())
}

pub fn sign_transaction_ecdsa(
    sk: &secp256k1::SecretKey,
    tx: &Transaction,
) -> secp256k1::ecdsa::Signature {
    // TODO: figure out how to get the digest to sign
    // the C++ code: https://github.com/bitcoin/bitcoin/blob/16b5b4b674414c41f34b0d37e15a16521fb08013/src/script/sign.cpp#L784
    let msg = {
        let mut cache = sighash::SighashCache::new(tx);
        // let sighash = cache
        //     .p2wpkh_signature_hash(inp_idx, &spk, Amount::from_sat(value), sig.hash_ty)
        //     .expect("failed to compute sighash");

        // println!("Segwit p2wpkh sighash: {:x}", sighash);

        // secp256k1::Message::from_digest(sighash.to_byte_array())

        todo!()
    };

    let secp = secp256k1::Secp256k1::signing_only();
    let sig = secp.sign_ecdsa(&msg, &sk);

    let pubkey = sk.public_key(&secp);

    let secp = secp256k1::Secp256k1::verification_only();
    secp.verify_ecdsa(&msg, &sig, &pubkey).unwrap();

    sig
}
