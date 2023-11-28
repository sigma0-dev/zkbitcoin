use base64::{engine::general_purpose, Engine};
use bitcoin::{
    absolute::LockTime,
    hashes::{hash160, Hash},
    opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_RETURN},
    transaction::Version,
    Amount, PubkeyHash, ScriptBuf, Transaction, TxOut,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client,
};
use serde::Serialize;
use std::time::Duration;

pub const JSON_RPC_ENDPOINT: &str = "http://146.190.33.39:18331";
const JSON_RPC_AUTH: &str = "root:hellohello";

#[derive(Serialize)]
struct Request {
    jsonrpc: &'static str,
    id: String,
    method: &'static str,
    params: Vec<String>,
}

// TODO: perhaps this will help https://github.com/rust-bitcoin/rust-bitcoin/issues/294

pub async fn generate_transaction(vk: &[u8; 32], satoshi_amount: u64) -> Result<(), &'static str> {
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
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        // we don't need to specify inputs at this point, the wallet will fill that for us
        input: vec![],
        output: vec![output],
    };
    let tx_hex_str = hex::encode(&serde_json::to_string(&tx).unwrap());

    // 2. fund transaction
    // https://developer.bitcoin.org/reference/rpc/fundrawtransaction.html
    let response = json_rpc_request("fundrawtransaction", vec![tx_hex_str])
        .await
        .map_err(|_| "TODO: real error")?;
    println!("{:?}", response);

    // 3. sign transaction
    // signrawtransactionwithwallet

    // 4. broadcast transaction
    // sendrawtransaction

    //
    Ok(())
}

/// Implements a JSON RPC request to the bitcoind node.
/// Following the [JSON RPC 1.0 spec](https://www.jsonrpc.org/specification_v1).
pub async fn json_rpc_request(
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

    let response = client
        .post(JSON_RPC_ENDPOINT)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await?;
    println!("status_code: {:?}", &response.status().as_u16());

    response.text().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_json_rpc() {
        env_logger::init();

        let response = json_rpc_request("getblockchaininfo", vec![]).await.unwrap();

        println!("{:?}", response);
    }
}
