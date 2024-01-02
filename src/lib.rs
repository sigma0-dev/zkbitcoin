//! zkBitcoin.

use secp256k1::hashes::Hash;

pub mod committee;
pub mod constants;
pub mod frost;
pub mod json_rpc_stuff;
pub mod plonk;
//pub mod psbt;
pub mod snarkjs;
pub mod srs;

/// 1. Alice signs a transaction to deploy a smart contract.
pub mod alice_sign_tx;

/// 2. Bob sends a request to the zkBitcoin committee to unlock funds from a smart contract.
/// The MPC committee can verify that request.
pub mod bob_request;

/// 3. The zkBitcoin committee produce a collaborative schnorr signature to unlock the funds for Bob.
pub mod mpc_sign_tx;

//
// Helpers
//

/// Returns the path to the local zkBitcoin folder,
/// and creates it if it doesn't exist.
pub fn zkbitcoin_folder() -> std::path::PathBuf {
    let zkbitcoin_dir = home::home_dir()
        .expect("couldn't get home dir")
        .join(".zkbitcoin");
    if !zkbitcoin_dir.exists() {
        std::fs::create_dir(&zkbitcoin_dir)
            .expect("couldn't create .zkbitcoin dir in home directory");
    }
    zkbitcoin_dir
}

/// Returns the current network (mainnet or testnet).
pub fn get_network() -> bitcoin::Network {
    if std::env::var("MAINNET").is_ok() {
        bitcoin::Network::Bitcoin
    } else {
        bitcoin::Network::Testnet
    }
}

/// Truncates a transaction ID so that it can fit in a field element in Circom.
pub fn truncate_txid(txid: bitcoin::Txid) -> String {
    //    let mut bytes = vec![];
    //    tx.consensus_encode(&mut bytes)?;
    // TODO: what's the exact size of the field?

    let mut bytes = txid.as_byte_array().to_vec();
    // TODO: think more about that
    // 256-bit -> 240-bit
    bytes.truncate(30.min(bytes.len()));
    let big = num_bigint::BigUint::from_bytes_be(&bytes);
    big.to_str_radix(10)
}
