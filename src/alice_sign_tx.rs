use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, PublicKey, ScriptBuf, Transaction, TxOut,
};
use std::str::FromStr;

use crate::{constants::ZKBITCOIN_PUBKEY, json_rpc_stuff::json_rpc_request};

/// Generates and broadcasts a transaction to the network.
/// Specifically, this sends a transaction to 0xzkBitcoin, for some given amount in satoshis,
/// and authenticates the verifier key `vk` that can unlock the founds.
pub async fn generate_and_broadcast_transaction(
    wallet: Option<String>,
    vk: &[u8; 32],
    satoshi_amount: u64,
) -> Result<bitcoin::Txid, &'static str> {
    // 1. create transaction based on VK + amount
    // https://developer.bitcoin.org/reference/rpc/createrawtransaction.html
    //
    let (_tx, tx_hex) = {
        let mut outputs = vec![];
        // first output is a P2PK to 0xzkBitcoin
        let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
        outputs.push(TxOut {
            value: Amount::from_sat(satoshi_amount),
            script_pubkey: ScriptBuf::new_p2pk(&zkbitcoin_pubkey),
        });
        // second output is VK
        {
            let script_pubkey = ScriptBuf::new_op_return(&vk);
            let value = script_pubkey.dust_value();
            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }
        // TODO: other outputs are public input

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO, // no lock time
            // we don't need to specify inputs at this point, the wallet will fill that for us
            input: vec![],
            output: outputs,
        };
        let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);

        //println!("- Alice's raw tx for 0xzkBitcoin: {tx:?}");
        println!("- Alice's raw tx for 0xzkBitcoin (in hex): {tx_hex}");

        (tx, tx_hex)
    };

    // 2. ask wallet to add inputs to fund the transaction
    // https://developer.bitcoin.org/reference/rpc/fundrawtransaction.html
    //
    let (raw_tx_with_inputs_hex, _raw_tx_with_inputs) = {
        let response = json_rpc_request(
            wallet.as_deref(),
            "fundrawtransaction",
            &[serde_json::value::to_raw_value(&serde_json::Value::String(tx_hex)).unwrap()],
        )
        .await
        .map_err(|_| "TODO: real error")?;

        // TODO: get rid of unwrap in here
        let response: jsonrpc::Response = serde_json::from_str(&response).unwrap();
        let parsed: bitcoincore_rpc::json::FundRawTransactionResult = response.result().unwrap();
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex).unwrap();
        let actual_hex = hex::encode(&parsed.hex);
        //println!("- funded tx: {tx:?}");
        println!("- funded tx (in hex): {actual_hex}");

        (actual_hex, tx)
    };

    // 3. sign transaction
    // https://developer.bitcoin.org/reference/rpc/signrawtransactionwithwallet.html
    //
    let (signed_tx_hex, _signed_tx) = {
        let response = json_rpc_request(
            wallet.as_deref(),
            "signrawtransactionwithwallet",
            &[
                serde_json::value::to_raw_value(&serde_json::Value::String(raw_tx_with_inputs_hex))
                    .unwrap(),
            ],
        )
        .await
        .map_err(|_| "TODO: real error")?;

        let response: jsonrpc::Response = serde_json::from_str(&response).unwrap();
        let parsed: bitcoincore_rpc::json::SignRawTransactionResult = response.result().unwrap();
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex).unwrap();
        let actual_hex = hex::encode(&parsed.hex);
        //println!("- signed tx: {tx:?}");
        println!("- signed tx (in hex): {actual_hex}");

        (actual_hex, tx)
    };

    // 4. broadcast transaction
    // https://developer.bitcoin.org/reference/rpc/sendrawtransaction.html
    //
    let txid = {
        let response = json_rpc_request(
            wallet.as_deref(),
            "sendrawtransaction",
            &[serde_json::value::to_raw_value(&serde_json::Value::String(signed_tx_hex)).unwrap()],
        )
        .await
        .map_err(|_| "TODO: real error")?;
        println!("{:?}", response);

        let response: jsonrpc::Response = serde_json::from_str(&response).unwrap();
        let txid: bitcoin::Txid = response.result().unwrap();
        println!("- txid broadcast to the network: {txid}");
        println!("- on an explorer: https://blockstream.info/testnet/tx/{txid}");

        txid
    };

    //
    Ok(txid)
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::RpcApi;

    use crate::json_rpc_stuff::JSON_RPC_ENDPOINT;

    use super::*;

    /// Simple test to see if we can reach our bitcoind full node.
    #[tokio::test]
    async fn test_json_rpc_connection_with_bitcoind() {
        // you can run the test with `RUST_LOG=trace`
        env_logger::init();

        let wallet = Some("mywallet".to_string());
        let response = json_rpc_request(wallet.as_deref(), "getblockchaininfo", &[])
            .await
            .unwrap();

        println!("{:?}", response);
    }

    /// Simple test to see if the same thing work with bitcoincore-rpc.
    /// We actually don't use bitcoincore-rpc atm,
    /// this is because it doesn't have great errors when we get error 500s from the server
    /// it also doesn't support async so it's shit anyway?
    #[test]
    fn test_bitcoin_rpc_lib() {
        // you can run the test with `RUST_LOG=trace`
        env_logger::init();

        let wallet = Some("mywallet".to_string());
        let url = match &wallet {
            Some(w) => format!("{}/wallet/{}", JSON_RPC_ENDPOINT, w),
            None => JSON_RPC_ENDPOINT.to_string(),
        };
        println!("now trying with bitcoin core rpc:");
        let rpc = bitcoincore_rpc::Client::new(
            &url,
            bitcoincore_rpc::Auth::UserPass("root".to_string(), "hellohello".to_string()),
        )
        .unwrap();
        let tx = "0200000000010001e8030000000000004076a914000000000000000000000000000000000000000088ac6a200000000000000000000000000000000000000000000000000000000000000000040000000000000000";
        let response = rpc.fund_raw_transaction(tx, None, Some(true));
        println!("{:?}", response);
    }

    /// Test the actual flow.
    #[tokio::test]
    async fn test_generate_transaction_flow() {
        // you can run the test with `RUST_LOG=trace`
        env_logger::init();

        let vk = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let wallet = Some("mywallet".to_string());
        let response = generate_and_broadcast_transaction(wallet, &vk, 1000)
            .await
            .unwrap();

        println!("{:?}", response);
    }
}
