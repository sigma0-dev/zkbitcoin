//! Code related to the Bitcoind JSON RPC interface.
//! It heavily relies on the jsonrpc and bitcoincore_rpc crates (and its dependencies).
//! It does not directly make use of these crates due to some issues (loss of information when getting 500 errors from bitcoind).

use base64::{engine::general_purpose, Engine};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client,
};
use std::time::Duration;

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
