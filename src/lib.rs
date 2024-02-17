//! zkBitcoin.

use anyhow::Context;
use secp256k1::hashes::Hash;

pub mod capped_hashmap;
pub mod committee;
pub mod compliance;
pub mod constants;
pub mod frost;
pub mod json_rpc_stuff;
pub mod plonk;
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

/// Creates a P2TR script from a public key.
pub fn p2tr_script_to(zkbitcoin_pubkey: bitcoin::PublicKey) -> bitcoin::ScriptBuf {
    let secp = secp256k1::Secp256k1::default();
    let internal_key = bitcoin::key::UntweakedPublicKey::from(zkbitcoin_pubkey);
    bitcoin::ScriptBuf::new_p2tr(&secp, internal_key, None)
}

pub fn circom_field_to_bytes(field: &str) -> anyhow::Result<Vec<u8>> {
    let big = <num_bigint::BigUint as num_traits::Num>::from_str_radix(field, 10)?;
    // sanity check
    let prime_p =
        <num_bigint::BigUint as num_traits::Num>::from_str_radix(constants::CIRCOM_ETH_PRIME, 10)
            .unwrap(); // TODO: cache that value
    anyhow::ensure!(
        prime_p > big,
        "the field element given was bigger than the Circom prime"
    );
    Ok(big.to_bytes_be())
}

pub fn circom_field_from_bytes(bytes: &[u8]) -> anyhow::Result<String> {
    let prime_p =
        <num_bigint::BigUint as num_traits::Num>::from_str_radix(constants::CIRCOM_ETH_PRIME, 10)
            .unwrap(); // TODO: cache that value
    let big = num_bigint::BigUint::from_bytes_be(bytes);
    anyhow::ensure!(
        prime_p > big,
        "the bytes given can't be deserialized as a Circom field element"
    );
    Ok(big.to_str_radix(10))
}

pub fn op_return_script_for(
    vk_hash: &[u8; 32],
    initial_state: Option<&str>,
) -> anyhow::Result<bitcoin::ScriptBuf> {
    let mut data = vk_hash.to_vec();
    if let Some(initial_state) = initial_state {
        data.extend(circom_field_to_bytes(initial_state).context("incorrect initial state given")?);
        assert!(data.len() < 64);
    }
    let thing: &bitcoin::script::PushBytes = data.as_slice().try_into().unwrap();
    Ok(bitcoin::ScriptBuf::new_op_return(thing))
}

pub fn taproot_addr_from(pubkey_str: &str) -> anyhow::Result<bitcoin::Address> {
    let pubkey = <bitcoin::PublicKey as std::str::FromStr>::from_str(pubkey_str)?;
    let internal_key = bitcoin::key::UntweakedPublicKey::from(pubkey);
    let secp = secp256k1::Secp256k1::default();
    let taproot_address = bitcoin::Address::p2tr(&secp, internal_key, None, get_network());
    Ok(taproot_address)
}
