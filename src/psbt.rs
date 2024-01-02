#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, Psbt, PublicKey, ScriptBuf,
        Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };

    use crate::{alice_sign_tx::p2tr_script_to, constants::ZKBITCOIN_PUBKEY};

    use super::*;

    #[test]
    fn test_psbt() {
        // create transaction
        let zkbitcoin_pubkey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO, // no lock time
            // one input containing some zkapp UTXO
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "cf3476aeb9a4e0d94f7aa2f8fe58c931e8ac44474ea4e3ce63c48ce15f6e5a4a",
                    )
                    .unwrap(),
                    vout: 1,
                },
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            // one output spending it to zkbitcoin pubkey
            output: vec![TxOut {
                value: Amount::from_sat(500),
                script_pubkey: p2tr_script_to(zkbitcoin_pubkey),
            }],
        };

        // create PSBT
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // fund the transaction
        let params = &[
            // inputs
            serde_json::value::to_raw_value(&serde_json::Value::Array(inputs)).unwrap(),
            // outputs
            serde_json::value::to_raw_value(&serde_json::Value::Array(outputs)).unwrap(),
            // lock time
            serde_json::value::to_raw_value(&serde_json::Number::from(0)).unwrap(),
            // params
            serde_json::value::to_raw_value(&serde_json::json!({
                "add_inputs": true,
                "changePosition": change_position,
            }))
            .unwrap(),
        ];
        println!("{}", serde_json::to_string(params).unwrap());
        let response = json_rpc_request(rpc_ctx, "walletcreatefundedpsbt", params)
            .await
            .context("walletcreatefundedpsbt error")?;

        // TODO: get rid of unwrap in here
        let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&response).unwrap();
        println!("{:?}", response);
        let res: bitcoincore_rpc::json::WalletCreateFundedPsbtResult = response.result().unwrap();
        println!("{:?}", res);
        panic!("yo!");
    }
}
