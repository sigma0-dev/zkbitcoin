use std::str::FromStr;

use anyhow::Result;
use bitcoin::{absolute::LockTime, transaction::Version, Amount, PublicKey, Transaction, TxOut};
use log::{debug, info};

use crate::constants::ZKBITCOIN_PUBKEY;
use crate::json_rpc_stuff::{
    fund_raw_transaction, send_raw_transaction, sign_transaction, RpcCtx, TransactionOrHex,
};
use crate::{op_return_script_for, p2tr_script_to};

/// Generates and broadcasts a transaction to the network.
/// Specifically, this sends a transaction to 0xzkBitcoin, for some given amount in satoshis,
/// and authenticates the verifier key `vk` that can unlock the founds.
pub async fn generate_and_broadcast_transaction(
    ctx: &RpcCtx,
    vk_hash: &[u8; 32],
    initial_state: Option<&String>,
    satoshi_amount: u64,
) -> Result<bitcoin::Txid> {
    // 1. create transaction based on VK + amount
    // https://developer.bitcoin.org/reference/rpc/createrawtransaction.html
    //
    let (_tx, tx_hex) = {
        let mut outputs = vec![];
        // first output is a P2PK to 0xzkBitcoin
        {
            let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
            outputs.push(TxOut {
                value: Amount::from_sat(satoshi_amount),
                script_pubkey: p2tr_script_to(zkbitcoin_pubkey),
            });
        }

        // second output is VK + initial state
        {
            let script_pubkey = op_return_script_for(vk_hash, initial_state)?;
            let value = script_pubkey.dust_value();
            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }

        // build tx
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO, // no lock time
            // we don't need to specify inputs at this point, the wallet will fill that for us
            input: vec![],
            output: outputs,
        };
        let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);

        debug!("- Alice's raw tx for 0xzkBitcoin (in hex): {tx_hex}");

        (tx, tx_hex)
    };

    // 2. ask wallet to add inputs to fund the transaction
    // https://developer.bitcoin.org/reference/rpc/fundrawtransaction.html
    //
    let (raw_tx_with_inputs_hex, _raw_tx_with_inputs, fee) =
        fund_raw_transaction(ctx, TransactionOrHex::Hex(tx_hex)).await?;
    info!("- funded transaction with fee: {fee}");

    // 3. sign transaction
    // https://developer.bitcoin.org/reference/rpc/signrawtransactionwithwallet.html
    //
    let (signed_tx_hex, _signed_tx) =
        sign_transaction(ctx, TransactionOrHex::Hex(raw_tx_with_inputs_hex)).await?;

    // 4. broadcast transaction
    // https://developer.bitcoin.org/reference/rpc/sendrawtransaction.html
    //
    let txid = send_raw_transaction(ctx, TransactionOrHex::Hex(signed_tx_hex)).await?;

    //
    Ok(txid)
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::RpcApi;

    use crate::json_rpc_stuff::{json_rpc_request, JSON_RPC_ENDPOINT};

    use super::*;

    /// Simple test to see if we can reach our bitcoind full node.
    #[tokio::test]
    async fn test_json_rpc_connection_with_bitcoind() {
        // you can run the test with `RUST_LOG=trace`
        env_logger::init();

        let ctx = RpcCtx::for_testing();
        let response = json_rpc_request(&ctx, "getblockchaininfo", &[])
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
        let satoshi_amount = 1000;

        let ctx = RpcCtx::for_testing();

        let response = generate_and_broadcast_transaction(&ctx, &vk, None, satoshi_amount)
            .await
            .unwrap();

        println!("{:?}", response);
    }
}
