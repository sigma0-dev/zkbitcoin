use std::str::FromStr;

use anyhow::{ensure, Result};
use bitcoin::key::UntweakedPublicKey;
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, PublicKey, ScriptBuf, Transaction, TxOut,
};
use num_traits::{FromPrimitive, Num, One, PrimInt, ToPrimitive, Zero};

use crate::constants::{CIRCOM_ETH_PRIME, ZKBITCOIN_PUBKEY};
use crate::json_rpc_stuff::{
    fund_raw_transaction, send_raw_transaction, sign_transaction, RpcCtx, TransactionOrHex,
};

/// Creates a P2TR script from a public key.
pub fn p2tr_script_to(zkbitcoin_pubkey: PublicKey) -> ScriptBuf {
    let secp = secp256k1::Secp256k1::default();
    let internal_key = UntweakedPublicKey::from(zkbitcoin_pubkey);
    ScriptBuf::new_p2tr(&secp, internal_key, None)
}

pub fn circom_field_to_bytes(field: &str) -> Result<Vec<u8>> {
    let big = num_bigint::BigUint::from_str_radix(field, 10).unwrap();
    // sanity check
    let prime_p = num_bigint::BigUint::from_str_radix(CIRCOM_ETH_PRIME, 10).unwrap(); // TODO: cache that value
    ensure!(
        prime_p > big,
        "the field element given was bigger than the Circom prime"
    );
    Ok(big.to_bytes_be())
}

pub fn circom_field_from_bytes(bytes: &[u8]) -> Result<String> {
    let prime_p = num_bigint::BigUint::from_str_radix(CIRCOM_ETH_PRIME, 10).unwrap(); // TODO: cache that value
    let big = num_bigint::BigUint::from_bytes_be(bytes);
    ensure!(
        prime_p > big,
        "the bytes given can't be deserialized as a Circom field element"
    );
    Ok(big.to_str_radix(10))
}

pub fn op_return_script_for(
    vk_hash: &[u8; 32],
    initial_state: Option<String>,
) -> Result<ScriptBuf> {
    let mut data = vk_hash.to_vec();
    if let Some(initial_state) = initial_state {
        data.extend(circom_field_to_bytes(&initial_state)?);
        assert!(data.len() < 64);
    }
    let thing: &bitcoin::script::PushBytes = data.as_slice().try_into().unwrap();
    Ok(ScriptBuf::new_op_return(&thing))
}

/// Generates and broadcasts a transaction to the network.
/// Specifically, this sends a transaction to 0xzkBitcoin, for some given amount in satoshis,
/// and authenticates the verifier key `vk` that can unlock the founds.
pub async fn generate_and_broadcast_transaction(
    ctx: &RpcCtx,
    vk_hash: &[u8; 32],
    initial_state: Option<String>,
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

        //println!("- Alice's raw tx for 0xzkBitcoin: {tx:?}");
        println!("- Alice's raw tx for 0xzkBitcoin (in hex): {tx_hex}");

        (tx, tx_hex)
    };

    // 2. ask wallet to add inputs to fund the transaction
    // https://developer.bitcoin.org/reference/rpc/fundrawtransaction.html
    //
    let (raw_tx_with_inputs_hex, _raw_tx_with_inputs) =
        fund_raw_transaction(ctx, TransactionOrHex::Hex(tx_hex)).await?;

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
