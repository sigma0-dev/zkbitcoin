//! Code related to the Bitcoind JSON RPC interface.
//! It heavily relies on the jsonrpc and bitcoincore_rpc crates (and its dependencies).
//! It does not directly make use of these crates due to some issues (loss of information when getting 500 errors from bitcoind).

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine};
use bitcoin::{Amount, Transaction, Txid};
use log::{debug, info, log_enabled, Level};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client,
};
use std::time::Duration;

use crate::constants::BITCOIN_JSON_RPC_VERSION;

/// Timeout (in seconds) for json rpc requests.
const JSON_RPC_TIMEOUT: u64 = 10;

//
// Context
//

#[derive(Default)]
pub struct RpcCtx {
    pub version: Option<&'static str>,
    pub wallet: Option<String>,
    pub address: Option<String>,
    pub auth: Option<String>,
    pub timeout: Duration,
}

impl RpcCtx {
    pub fn new(
        version: Option<&'static str>,
        wallet: Option<String>,
        address: Option<String>,
        auth: Option<String>,
        timeout: Option<Duration>,
    ) -> Self {
        let ctx = Self {
            version,
            wallet,
            address,
            auth,
            timeout: timeout.unwrap_or(Duration::from_secs(JSON_RPC_TIMEOUT)),
        };

        debug!("- using RPC node at address {}", ctx.address());

        if ctx.auth().is_some() {
            debug!("- using given RPC credentials");
        } else {
            debug!("- using no RPC credentials");
        }

        if let Some(wallet) = ctx.wallet() {
            debug!("- using wallet {wallet}");
        } else {
            debug!("- using default wallet");
        }

        ctx
    }

    pub fn wallet(&self) -> Option<&str> {
        self.wallet.as_deref()
    }

    pub fn address(&self) -> &str {
        self.address.as_deref().unwrap_or("http://127.0.0.1:18331")
    }

    pub fn auth(&self) -> Option<&str> {
        self.auth.as_deref()
        /*.map(|s| {
            s.split('.')
                .map(str::to_string)
                .collect_tuple()
                .expect("auth was incorrectly passed (expected `user:pw`)")
        })*/
    }

    pub fn for_testing() -> Self {
        let endpoint = std::env::var("BITCOIN_JSON_RPC_ENDPOINT").unwrap();
        let auth = std::env::var("BITCOIN_JSON_RPC_AUTH").unwrap_or("root:hellohello".to_string());
        let wallet = std::env::var("BITCOIN_JSON_RPC_WALLET").unwrap_or("mywallet".to_string());

        Self::new(
            Some(BITCOIN_JSON_RPC_VERSION),
            Some(wallet),
            Some(endpoint),
            Some(auth),
            None,
        )
    }
}

//
// Main JSON RPC request function
//

/// Implements a JSON RPC request to the bitcoind node.
/// Following the [JSON RPC 1.0 spec](https://www.jsonrpc.org/specification_v1).
pub async fn json_rpc_request<'a>(
    ctx: &RpcCtx,
    method: &'static str,
    params: &'a [Box<serde_json::value::RawValue>],
) -> Result<String> {
    // create the request
    let request = bitcoincore_rpc::jsonrpc::Request::<'a> {
        // bitcoind doesn't seem to support anything else but json rpc 1.0
        jsonrpc: ctx.version,
        // I don't think that field is useful (https://www.jsonrpc.org/specification_v1)
        id: serde_json::Value::String("whatevs".to_string()),
        method,
        params,
    };

    let mut headers = HeaderMap::new();
    if let Some(auth) = ctx.auth() {
        let user_n_pw = general_purpose::STANDARD.encode(auth);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", user_n_pw))?,
        );
    }

    let body = serde_json::to_string(&request)?;

    let client = Client::builder()
        .default_headers(headers)
        .timeout(ctx.timeout)
        .build()?;

    let endpoint = ctx.address();
    let url = match &ctx.wallet {
        Some(wallet) => format!("{}/wallet/{}", endpoint, wallet),
        None => endpoint.to_string(),
    };

    if log_enabled!(Level::Debug) {
        let body = serde_json::to_string_pretty(&request)?;
        debug!("- sending request to {url} with body: {body}");
    }

    let response = client
        .post(url)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await?;

    let res = response.text().await?;
    Ok(res)
}

//
// Helpers around useful Bitcoin RPC functions
//

pub enum TransactionOrHex<'a> {
    Hex(String),
    Transaction(&'a Transaction),
}

pub async fn fund_raw_transaction<'a>(
    ctx: &RpcCtx,
    tx: TransactionOrHex<'a>,
) -> Result<(String, Transaction, Amount)> {
    let tx_hex = match tx {
        TransactionOrHex::Hex(hex) => hex,
        TransactionOrHex::Transaction(tx) => bitcoin::consensus::encode::serialize_hex(tx),
    };

    let response = json_rpc_request(
        ctx,
        "fundrawtransaction",
        &[serde_json::value::to_raw_value(
            &serde_json::Value::String(tx_hex),
        )?],
    )
    .await
    .context("fundrawtransaction error")?;

    let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&response)?;
    let parsed: bitcoincore_rpc::json::FundRawTransactionResult = response.result()?;
    let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex)?;
    let actual_hex = hex::encode(&parsed.hex);

    Ok((actual_hex, tx, parsed.fee))
}

pub async fn sign_transaction<'a>(
    ctx: &RpcCtx,
    tx: TransactionOrHex<'a>,
) -> Result<(String, Transaction)> {
    let tx_hex = match tx {
        TransactionOrHex::Hex(hex) => hex,
        TransactionOrHex::Transaction(tx) => bitcoin::consensus::encode::serialize_hex(tx),
    };

    let response = json_rpc_request(
        ctx,
        "signrawtransactionwithwallet",
        &[serde_json::value::to_raw_value(
            &serde_json::Value::String(tx_hex),
        )?],
    )
    .await
    .context("signrawtransactionwithwallet error")?;

    let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&response)?;
    let parsed: bitcoincore_rpc::json::SignRawTransactionResult = response.result()?;
    let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex)?;
    let actual_hex = hex::encode(&parsed.hex);

    Ok((actual_hex, tx))
}

pub async fn send_raw_transaction<'a>(ctx: &RpcCtx, tx: TransactionOrHex<'a>) -> Result<Txid> {
    let tx_hex = match tx {
        TransactionOrHex::Hex(hex) => hex,
        TransactionOrHex::Transaction(tx) => bitcoin::consensus::encode::serialize_hex(tx),
    };

    let response = json_rpc_request(
        ctx,
        "sendrawtransaction",
        &[serde_json::value::to_raw_value(
            &serde_json::Value::String(tx_hex),
        )?],
    )
    .await
    .context("sendrawtransaction error")?;

    let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&response)?;
    let txid: bitcoin::Txid = response.result()?;

    Ok(txid)
}

pub async fn createrawtransaction<'a>(
    ctx: &RpcCtx,
    inputs: Vec<serde_json::Value>,
    outputs: Vec<serde_json::Value>,
    lock_time: usize,
) -> Result<(String, Transaction)> {
    let response = json_rpc_request(
        ctx,
        "createrawtransaction",
        &[
            // inputs
            serde_json::value::to_raw_value(&serde_json::Value::Array(inputs))?,
            // outputs
            serde_json::value::to_raw_value(&serde_json::Value::Array(outputs))?,
            // lock time
            serde_json::value::to_raw_value(&serde_json::Number::from(lock_time))?,
        ],
    )
    .await
    .context("createrawtransaction error")?;

    let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&response)?;
    let tx_hex: String = response.result()?;
    let bytes = hex::decode(&tx_hex)?;
    let tx: Transaction = bitcoin::consensus::encode::deserialize(&bytes)?;

    Ok((tx_hex, tx))
}

pub async fn get_transaction<'a>(ctx: &RpcCtx, txid: Txid) -> Result<(String, Transaction, usize)> {
    let response = json_rpc_request(
        ctx,
        "gettransaction",
        &[serde_json::value::to_raw_value(&serde_json::Value::String(txid.to_string())).unwrap()],
    )
    .await
    .context("gettransaction error")?;

    let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&response)?;
    let parsed: bitcoincore_rpc::json::GetTransactionResult = response.result()?;
    let tx: Transaction = bitcoin::consensus::encode::deserialize(&parsed.hex)?;
    let tx_hex = hex::encode(&parsed.hex);

    Ok((tx_hex, tx, parsed.info.confirmations as usize))
}

pub async fn scan_txout_set<'a>(
    ctx: &RpcCtx,
    address: &str,
) -> Result<bitcoincore_rpc::json::ScanTxOutResult> {
    let req = format!("addr({address})");
    let response = json_rpc_request(
        ctx,
        "scantxoutset",
        &[
            serde_json::value::to_raw_value(&serde_json::Value::String("start".to_string()))?,
            serde_json::value::to_raw_value(&serde_json::Value::Array(vec![
                serde_json::Value::String(req),
            ]))?,
        ],
    )
    .await
    .context("scantxoutset error")?;

    // TODO: this can return "Scan already in progress" in which case we might want to wait for it to finish

    let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&response)?;
    let result: bitcoincore_rpc::json::ScanTxOutResult = response.result()?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::bob_request::fetch_smart_contract;

    use super::*;

    #[tokio::test]
    async fn get_zkapps() {
        let mut rpc_ctx = RpcCtx::for_testing();
        rpc_ctx.timeout = Duration::from_secs(20); // scan takes 13s from what I can see
        let res = scan_txout_set(
            &rpc_ctx,
            "tb1p5sfstsnt9akcqf9zkm6ulke8ujwakjd8kdk5krws2th4ds238meqq4awtv",
        )
        .await
        .unwrap();
        for unspent in &res.unspents {
            let txid = unspent.txid;
            if let Ok(smart_contract) = fetch_smart_contract(&rpc_ctx, txid).await {
                println!("{:?}", smart_contract);
            }
        }
    }
}
