use base64::{engine::general_purpose, Engine};
use bitcoin::{
    absolute::LockTime,
    hashes::{hash160, Hash},
    opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_RETURN},
    transaction::Version,
    Amount, PubkeyHash, ScriptBuf, Transaction, TxOut,
};
use bitcoincore_rpc::{RawTx, RpcApi};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const JSON_RPC_ENDPOINT: &str = "http://146.190.33.39:18331";
const JSON_RPC_AUTH: &str = "root:hellohello";

#[derive(Serialize)]
struct Request {
    jsonrpc: &'static str,
    id: String,
    method: &'static str,
    // TODO: this is not going to work, for example if there's a bool we need to pass it as a bool directly
    // e.g. "true" -> true
    params: Vec<String>,
}

// TODO: perhaps this will help https://github.com/rust-bitcoin/rust-bitcoin/issues/294

pub async fn generate_transaction(
    wallet: Option<String>,
    vk: &[u8; 32],
    satoshi_amount: u64,
) -> Result<(), &'static str> {
    // TODO: replace with our actual public key hash
    let zkbitcoin_pubkey_hash: PubkeyHash = PubkeyHash::from_raw_hash(hash160::Hash::all_zeros());

    // 1. create transaction based on VK + amount
    // https://developer.bitcoin.org/reference/rpc/createrawtransaction.html
    let script_pubkey = ScriptBuf::builder().
    // P2PKH
    push_opcode(OP_DUP)
    .push_opcode(OP_HASH160)
    .push_slice(zkbitcoin_pubkey_hash)
    .push_opcode(OP_EQUALVERIFY)
    .push_opcode(OP_CHECKSIG)
    // METADATA
    .push_opcode(OP_RETURN)
    // VK
    .push_slice(&vk)
    // TODO: public input
    .push_slice(&[0, 0, 0, 0])
    // to script
    .into_script();

    let output = TxOut {
        value: Amount::from_sat(satoshi_amount),
        script_pubkey,
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        // we don't need to specify inputs at this point, the wallet will fill that for us
        input: vec![],
        output: vec![output],
    };
    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);

    //println!("- Alice's raw tx for 0xzkBitcoin: {tx:?}");
    println!("- Alice's raw tx for 0xzkBitcoin (in hex): {tx_hex}");

    // 2. ask wallet to add inputs to fund the transaction
    // https://developer.bitcoin.org/reference/rpc/fundrawtransaction.html
    let response = json_rpc_request(&wallet, "fundrawtransaction", vec![tx_hex])
        .await
        .map_err(|_| "TODO: real error")?;

    // TODO: get rid of unwrap in here
    let (raw_tx_with_inputs_hex, raw_tx_with_inputs) = {
        let response: jsonrpc::Response = serde_json::from_str(&response).unwrap();
        let parsed: bitcoincore_rpc::json::FundRawTransactionResult = response.result().unwrap();
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex).unwrap();
        let actual_hex = hex::encode(&parsed.hex);
        //println!("- funded tx: {tx:?}");
        println!("- funded tx (in hex): {actual_hex}");

        (actual_hex, tx)
    };

    // 3. sign transaction
    // signrawtransactionwithwallet
    let response = json_rpc_request(
        &wallet,
        "signrawtransactionwithwallet",
        vec![raw_tx_with_inputs_hex],
    )
    .await
    .map_err(|_| "TODO: real error")?;

    let (signed_tx_hex, signed_tx) = {
        let response: jsonrpc::Response = serde_json::from_str(&response).unwrap();
        let parsed: bitcoincore_rpc::json::SignRawTransactionResult = response.result().unwrap();
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex).unwrap();
        let actual_hex = hex::encode(&parsed.hex);
        //println!("- signed tx: {tx:?}");
        println!("- signed tx (in hex): {actual_hex}");

        (actual_hex, tx)
    };

    // 4. broadcast transaction
    // sendrawtransaction
    let response = json_rpc_request(&wallet, "sendrawtransaction", vec![signed_tx_hex])
        .await
        .map_err(|_| "TODO: real error")?;
    println!("{:?}", response);

    let response: jsonrpc::Response = serde_json::from_str(&response).unwrap();
    let txid: bitcoin::Txid = response.result().unwrap();
    println!("- txid broadcast to the network: {txid}");
    println!("- on an explorer: https://blockstream.info/testnet/tx/{txid}");

    //
    Ok(())
}

/// Implements a JSON RPC request to the bitcoind node.
/// Following the [JSON RPC 1.0 spec](https://www.jsonrpc.org/specification_v1).
pub async fn json_rpc_request(
    wallet: &Option<String>,
    method: &'static str,
    params: Vec<String>,
) -> Result<String, reqwest::Error> {
    let request = Request {
        // bitcoind doesn't seem to support anything else but json rpc 1.0
        jsonrpc: "1.0",
        // I don't think that field is useful (https://www.jsonrpc.org/specification_v1)
        id: "whatevs".to_string(),
        method,
        params,
    };
    let body = serde_json::to_string(&request).unwrap();

    let user_n_pw = general_purpose::STANDARD.encode(JSON_RPC_AUTH);

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {}", user_n_pw)).unwrap(),
    );
    let client = Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(10))
        .build()?;

    let url = match wallet {
        Some(wallet) => format!("{}/wallet/{}", JSON_RPC_ENDPOINT, wallet),
        None => JSON_RPC_ENDPOINT.to_string(),
    };

    let response = client
        .post(url)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await?;

    println!("- status_code: {:?}", &response.status().as_u16());

    response.text().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_json_rpc_connection_with_bitcoind() {
        // you can run the test with `RUST_LOG=trace`
        env_logger::init();

        let wallet = Some("mywallet".to_string());
        let response = json_rpc_request(&wallet, "getblockchaininfo", vec![])
            .await
            .unwrap();

        println!("{:?}", response);
    }

    /// We actually don't use bitcoincore-rpc atm,
    /// this is because it doesn't have great errors when we get error 500s from the server
    /// it also doesn't support async so it's shit anyway
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

    #[tokio::test]
    async fn test_generate_transaction_flow() {
        // you can run the test with `RUST_LOG=trace`
        env_logger::init();

        let wallet = Some("mywallet".to_string());
        let response = generate_transaction(
            wallet,
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            1000,
        )
        .await
        .unwrap();

        println!("{:?}", response);
    }
}
