//! Code related to the Bitcoind JSON RPC interface.
//! It heavily relies on the jsonrpc and bitcoincore_rpc crates (and its dependencies).
//! It does not directly make use of these crates due to some issues (loss of information when getting 500 errors from bitcoind).

use base64::{engine::general_purpose, Engine};
use bitcoin::{Transaction, Txid};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client,
};
use std::time::Duration;

//
// Main JSON RPC request function
//

/// The endpoint for our bitcoind full node.
pub const JSON_RPC_ENDPOINT: &str = "http://146.190.33.39:18331";

/// The RPC authentication our bitcoind node uses (user + password).
// TODO: obviously we're using poor's man authentication :))
const JSON_RPC_AUTH: &str = "root:hellohello";

/// Implements a JSON RPC request to the bitcoind node.
/// Following the [JSON RPC 1.0 spec](https://www.jsonrpc.org/specification_v1).
pub async fn json_rpc_request<'a>(
    wallet: Option<&str>,
    method: &'static str,
    params: &'a [Box<serde_json::value::RawValue>],
) -> Result<String, reqwest::Error> {
    // create the request
    let request = jsonrpc::Request::<'a> {
        // bitcoind doesn't seem to support anything else but json rpc 1.0
        jsonrpc: Some("1.0"),
        // I don't think that field is useful (https://www.jsonrpc.org/specification_v1)
        id: serde_json::Value::String("whatevs".to_string()),
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

//
// Helpers around useful Bitcoin RPC functions
//

pub enum TransactionOrHex<'a> {
    Hex(String),
    Transaction(&'a Transaction),
}

pub async fn fund_raw_transaction<'a>(
    tx: TransactionOrHex<'a>,
    wallet: Option<&str>,
) -> Result<(String, Transaction), &'static str> {
    let tx_hex = match tx {
        TransactionOrHex::Hex(hex) => hex,
        TransactionOrHex::Transaction(tx) => bitcoin::consensus::encode::serialize_hex(tx),
    };

    let response = json_rpc_request(
        wallet,
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

    Ok((actual_hex, tx))
}

pub async fn sign_transaction<'a>(
    tx: TransactionOrHex<'a>,
    wallet: Option<&str>,
) -> Result<(String, Transaction), &'static str> {
    let tx_hex = match tx {
        TransactionOrHex::Hex(hex) => hex,
        TransactionOrHex::Transaction(tx) => bitcoin::consensus::encode::serialize_hex(tx),
    };

    let response = json_rpc_request(
        wallet,
        "signrawtransactionwithwallet",
        &[serde_json::value::to_raw_value(&serde_json::Value::String(tx_hex)).unwrap()],
    )
    .await
    .map_err(|_| "TODO: real error")?;

    // TODO: get rid of unwrap in here
    let response: jsonrpc::Response = serde_json::from_str(&response).unwrap();
    let parsed: bitcoincore_rpc::json::SignRawTransactionResult = response.result().unwrap();
    let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex).unwrap();
    let actual_hex = hex::encode(&parsed.hex);
    //println!("- signed tx: {tx:?}");
    println!("- signed tx (in hex): {actual_hex}");

    Ok((actual_hex, tx))
}

pub async fn send_raw_transaction<'a>(tx: TransactionOrHex<'a>) -> Result<Txid, &'static str> {
    let tx_hex = match tx {
        TransactionOrHex::Hex(hex) => hex,
        TransactionOrHex::Transaction(tx) => bitcoin::consensus::encode::serialize_hex(tx),
    };

    let response = json_rpc_request(
        None,
        "sendrawtransaction",
        &[serde_json::value::to_raw_value(&serde_json::Value::String(tx_hex)).unwrap()],
    )
    .await
    .map_err(|_| "TODO: real error")?;

    // TODO: get rid of unwrap in here
    let response: jsonrpc::Response = serde_json::from_str(&response).unwrap();
    let txid: bitcoin::Txid = response.result().unwrap();
    println!("- txid broadcast to the network: {txid}");
    println!("- on an explorer: https://blockstream.info/testnet/tx/{txid}");

    Ok(txid)
}
