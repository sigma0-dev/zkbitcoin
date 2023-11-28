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
use serde::Serialize;
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
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        // we don't need to specify inputs at this point, the wallet will fill that for us
        input: vec![],
        output: vec![output],
    };

    // we now have to encode the transaction as a hex string
    // bitcoind has an API to decode it: https://developer.bitcoin.org/reference/rpc/decoderawtransaction.html
    // with implementation here: https://github.com/bitcoin/bitcoin/blob/master/src/rpc/rawtransaction.cpp#L459
    // that leads to this DecodeTx function https://github.com/bitcoin/bitcoin/blob/master/src/core_read.cpp#L123
    // let tx_hex_str = hex::encode(&serde_json::to_string(&tx).unwrap());
    // println!("naive: {tx_hex_str}");

    let tx_hex_str = bitcoin::consensus::encode::serialize_hex(&tx);
    println!("consensus::encode::serialize_hex: {tx_hex_str}");

    // let mut bytes = Vec::new();
    // let mut serializer = serde_json::Serializer::new(&mut bytes);
    // bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>::serialize(
    //     &tx,
    //     &mut serializer,
    // )
    // .unwrap();
    // let tx_hex_str = hex::encode(bytes);
    // println!("other: {tx_hex_str}");

    // let tx_hex_str = tx.raw_hex();
    // println!("the bitcoin rpc one: {tx_hex_str}");

    // 2. fund transaction
    // https://developer.bitcoin.org/reference/rpc/fundrawtransaction.html
    let response = json_rpc_request(
        "fundrawtransaction",
        vec![tx_hex_str, "{}".to_string(), "false".to_string()],
    )
    .await
    .map_err(|_| "TODO: real error")?;
    println!("our own way: {:?}", response);

    // try the same thing with bitcoin rpc:
    println!("now trying with bitcoin core rpc:");
    let rpc = bitcoincore_rpc::Client::new(
        JSON_RPC_ENDPOINT,
        bitcoincore_rpc::Auth::UserPass("root".to_string(), "hellohello".to_string()),
    )
    .unwrap();
    let response = rpc.fund_raw_transaction(&tx, None, Some(true));
    if response.is_err() {
        println!("err: {}", response.unwrap_err());
    } else {
        println!("response: {:?}", response.unwrap());
    }

    // TODO: deserialize the response
    let raw_tx_with_inputs = todo!();

    // 3. sign transaction
    // signrawtransactionwithwallet
    let response = json_rpc_request("signrawtransactionwithwallet", vec![raw_tx_with_inputs])
        .await
        .map_err(|_| "TODO: real error")?;
    println!("{:?}", response);

    // TODO: deserialize the response
    let signed_tx = todo!();

    // 4. broadcast transaction
    // sendrawtransaction
    let response = json_rpc_request("sendrawtransaction", vec![signed_tx])
        .await
        .map_err(|_| "TODO: real error")?;
    println!("{:?}", response);

    // check status of response
    todo!();

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
    async fn test_json_rpc_connection_with_bitcoind() {
        // you can run the test with `RUST_LOG=trace`
        env_logger::init();

        let response = json_rpc_request("getblockchaininfo", vec![]).await.unwrap();

        println!("{:?}", response);
    }

    #[tokio::test]
    async fn test_generate_transaction_flow() {
        // you can run the test with `RUST_LOG=trace`
        env_logger::init();

        let response = generate_transaction(
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
