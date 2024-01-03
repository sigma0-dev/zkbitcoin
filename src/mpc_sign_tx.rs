use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::{
    absolute::LockTime,
    key::{TweakedPublicKey, UntweakedPublicKey},
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Address, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TapSighashType, TapTweakHash,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use secp256k1::{hashes::Hash, All, Secp256k1, XOnlyPublicKey};

use crate::{
    bob_request::SmartContract,
    constants::{FEE_ZKBITCOIN_SAT, ZKBITCOIN_FEE_PUBKEY},
    json_rpc_stuff::{
        fund_raw_transaction, send_raw_transaction, sign_transaction, TransactionOrHex,
    },
    p2tr_script_to,
};
use crate::{constants::ZKBITCOIN_PUBKEY, json_rpc_stuff::RpcCtx};

pub fn get_digest_to_hash(
    transaction: &bitcoin::Transaction,
    smart_contract: &SmartContract,
) -> [u8; 32] {
    // TODO: return Result
    // the sighash flag is always ALL
    let hash_ty = TapSighashType::All;

    // sighash
    let mut cache = SighashCache::new(transaction);
    let mut sig_msg = Vec::new();

    // TODO: only keep track of one prev_outs in the smart contract
    let thing = [smart_contract.prev_outs[smart_contract.vout_of_zkbitcoin_utxo as usize].clone()];
    let prev_outs = Prevouts::All(&thing);

    cache
        .taproot_encode_signing_data_to(&mut sig_msg, 0, &prev_outs, None, None, hash_ty)
        .unwrap();
    let sighash = cache
        .taproot_signature_hash(0, &prev_outs, None, None, hash_ty)
        .unwrap();
    sighash.to_byte_array()
}

pub fn create_transaction(
    smart_contract: &SmartContract,
    txid: Txid,
    bob_address: Address,
) -> Transaction {
    // there's only one input: the zkapp we're using
    let inputs = {
        let input = TxIn {
            previous_output: OutPoint {
                txid,
                vout: smart_contract.vout_of_zkbitcoin_utxo,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        vec![input]
    };

    // create outputs
    let mut outputs = vec![];

    // first output is to

    // second output is to zkBitcoin fund
    {
        let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_FEE_PUBKEY).unwrap();
        outputs.push(TxOut {
            value: Amount::from_sat(FEE_ZKBITCOIN_SAT),
            script_pubkey: p2tr_script_to(zkbitcoin_pubkey),
        });
    }

    // we need to subtract the amount to cover for the fee
    let amount_for_bob = smart_contract.locked_value - Amount::from_sat(FEE_ZKBITCOIN_SAT);

    {
        // first output is a P2TR to Bob
        outputs.push(TxOut {
            value: amount_for_bob,
            script_pubkey: bob_address.script_pubkey(),
        });

        // second output is to zkBitcoin
        // TODO: obviously we shouldn't send it to this address no? This is controlled by an MPC instead of by us
        let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
        outputs.push(TxOut {
            value: Amount::from_sat(FEE_ZKBITCOIN_SAT),
            script_pubkey: p2tr_script_to(zkbitcoin_pubkey),
        });
    }

    // create final transaction
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO, // no lock time
        input: inputs,
        output: outputs,
    }
}

pub fn sign_transaction_schnorr(
    sk: &secp256k1::SecretKey,
    tx: &Transaction,
    prevouts: &[TxOut],
) -> secp256k1::schnorr::Signature {
    // key
    let secp = &secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(secp, sk);

    // the first input is the taproot UTXO we want to spend
    let tx_ind = 0;

    // the sighash flag is always ALL
    let hash_ty = TapSighashType::All;

    // sighash
    let mut cache = SighashCache::new(tx);
    let mut sig_msg = Vec::new();
    cache
        .taproot_encode_signing_data_to(
            &mut sig_msg,
            tx_ind,
            &Prevouts::All(prevouts),
            None,
            None,
            hash_ty,
        )
        .unwrap();
    let sighash = cache
        .taproot_signature_hash(tx_ind, &Prevouts::All(prevouts), None, None, hash_ty)
        .unwrap();
    let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
    secp.sign_schnorr_with_aux_rand(&msg, &keypair, &[0u8; 32])
}

async fn send_to_p2tr_pubkey(
    ctx: &RpcCtx,
    secp: &Secp256k1<All>,
    xonly_pubkey: XOnlyPublicKey,
    amount: u64,
) -> (Txid, TxOut) {
    // create empty transaction that sends to a p2tr from our wallet
    let tx_out = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: ScriptBuf::new_p2tr(secp, xonly_pubkey, None),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO, // no lock time
        input: vec![],
        output: vec![tx_out.clone()],
    };

    // fund that transaction with our wallet
    let (tx_hex, _) = fund_raw_transaction(&ctx, TransactionOrHex::Transaction(&tx))
        .await
        .unwrap();

    // sign that transaction with our wallet
    let (tx_hex, _) = sign_transaction(&ctx, TransactionOrHex::Hex(tx_hex))
        .await
        .unwrap();

    // broadcast it
    let txid = send_raw_transaction(&ctx, TransactionOrHex::Hex(tx_hex))
        .await
        .unwrap();

    // return the tx id and the output created for the P2TR pubkey
    (txid, tx_out)
}

#[cfg(test)]
mod tests {

    use bitcoin::{taproot, Network, PrivateKey};
    use rand::prelude::*;
    use std::str::FromStr;

    use rand_chacha::ChaCha20Rng;

    use crate::frost::{gen_frost_keys, sign_transaction_frost, to_xonly_pubkey};
    use crate::json_rpc_stuff::{send_raw_transaction, TransactionOrHex};
    use crate::taproot_addr_from;

    use super::*;
    /*
    - privkey: b2f7f581d6de3c06a822fd6e7e8265fbc00f8401696a5bdc34f5a6d2ff3f922f
    - status_code: 200
    - funded tx (in hex): 0200000001ea94c02f7ab26326aa459d5000416285313fdbab95c85b78dcefa41b2d35380a0200000000fdffffff02e803000000000000225120814c57829b8c1af9956a23a9d687779469b1d7c06ebecac01f81922761331ea41e120000000000002251201d6f50ea71d3a10bd02e206a319b7e300d73363c8aa38de70e61857f1992d91c00000000
    - status_code: 200
    - signed tx (in hex): 02000000000101ea94c02f7ab26326aa459d5000416285313fdbab95c85b78dcefa41b2d35380a0200000000fdffffff02e803000000000000225120814c57829b8c1af9956a23a9d687779469b1d7c06ebecac01f81922761331ea41e120000000000002251201d6f50ea71d3a10bd02e206a319b7e300d73363c8aa38de70e61857f1992d91c014098abe19b55ab3fb450c75f1cbead91a6eb55c130c7c8162d26e882ead282a34181b929628a1a165eacb7b4942dc43ccdaa6c57192a6e7f947b7c5d31f683a94f00000000
    - status_code: 200
    - txid broadcast to the network: 02fcc5b458ff032d4c82b12ce8c1c4c5b88c91bd7953bb2cdbb212f3219e91c3
    - on an explorer: https://blockstream.info/testnet/tx/02fcc5b458ff032d4c82b12ce8c1c4c5b88c91bd7953bb2cdbb212f3219e91c3
    - txid: 02fcc5b458ff032d4c82b12ce8c1c4c5b88c91bd7953bb2cdbb212f3219e91c3
     */

    #[tokio::test]
    #[ignore = "I used this to send a p2tr transaction on the network to a known private key"]
    async fn test_p2tr() {
        // let's create a keypair and expose the privkey and pubkey
        let secp = secp256k1::Secp256k1::default();
        // seeded rand with 0
        let rng = &mut ChaCha20Rng::seed_from_u64(0);

        let sk = secp256k1::SecretKey::new(rng);
        //let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let private_key = PrivateKey::new(sk, Network::Testnet);
        let pubkey = PublicKey::from_private_key(&secp, &private_key);
        let xonly_pubkey = UntweakedPublicKey::from(pubkey);
        //        let tweaked = untweaked.add_tweak(&secp, &secp256k1::Scalar::ONE);

        // make sure we can recover the private key
        {
            println!("- privkey: {}", hex::encode(sk.secret_bytes()));
            let sk2 = secp256k1::SecretKey::from_str(
                "b2f7f581d6de3c06a822fd6e7e8265fbc00f8401696a5bdc34f5a6d2ff3f922f",
            )
            .unwrap();
            assert_eq!(sk, sk2);
        }

        let amount = 1000;

        //        let (tx, prevouts) = create_dummy_tx();
        //        let sig = sign_transaction_schnorr(&sk, &tx, &prevouts);
        //        println!("{sig:?}");
        let ctx = RpcCtx::for_testing();
        let (txid, _tx_out) = send_to_p2tr_pubkey(&ctx, &secp, xonly_pubkey, amount).await;

        println!("- txid: {txid}");
    }

    #[tokio::test]
    #[ignore = "This creates 2 transactions: 1) send to the frost pubkey, 2) spend from the frost (signed by all frost participants)"]
    async fn test_send_and_spend_with_frost() {
        // let's create a keypair and expose the privkey and pubkey
        let secp = secp256k1::Secp256k1::default();

        let max_signers = 5;
        let min_signers = 3;

        let (key_packages, pubkey_package) = gen_frost_keys(max_signers, min_signers).unwrap();
        println!("- FROST pubkey: {:#?}", pubkey_package.verifying_key());

        let pubkey = to_xonly_pubkey(pubkey_package.verifying_key());
        println!("- XOnly pubkey: {:#?}", pubkey);

        let xonly_pubkey = UntweakedPublicKey::from(pubkey);
        //        let tweaked = untweaked.add_tweak(&secp, &secp256k1::Scalar::ONE);

        let amount = 1000;

        //        let (tx, prevouts) = create_dummy_tx();
        //        let sig = sign_transaction_schnorr(&sk, &tx, &prevouts);
        //        println!("{sig:?}");
        let ctx = RpcCtx::for_testing();
        let (txid, tx_out) = send_to_p2tr_pubkey(&ctx, &secp, xonly_pubkey, amount).await;

        println!("- txid: {txid}");

        // Spend this fucker now
        let vout = 0;
        let satoshi_amount = Amount::from_sat(amount);

        let bob_address = taproot_addr_from(ZKBITCOIN_PUBKEY).unwrap();

        let fee_bitcoin_sat = 400;
        let fee_zkbitcoin_sat = 100;
        let smart_contract = SmartContract {
            locked_value: satoshi_amount,
            vk_hash: [0; 32],
            state: None,
            vout_of_zkbitcoin_utxo: 0,
            prev_outs: vec![],
        };
        let mut tx = create_transaction(&smart_contract, txid, bob_address);

        // prevouts
        let prevouts = &[tx_out];

        // sign
        let sig = sign_transaction_frost(&key_packages, &pubkey_package, &tx, prevouts);

        // place signature in witness
        let hash_ty = TapSighashType::All;
        let final_signature = taproot::Signature { sig, hash_ty };
        let mut witness = Witness::new();
        witness.push(final_signature.to_vec());
        tx.input[0].witness = witness;

        println!("{tx:#?}");

        // broadcast transaction
        let ctx = RpcCtx::for_testing();
        let _txid = send_raw_transaction(&ctx, TransactionOrHex::Transaction(&tx))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "I'm trying to use this to spend the p2tr created in the previous test"]
    async fn test_real_tx() {
        // txid from https://blockstream.info/testnet/tx/02fcc5b458ff032d4c82b12ce8c1c4c5b88c91bd7953bb2cdbb212f3219e91c3?expand
        let txid =
            Txid::from_str("02fcc5b458ff032d4c82b12ce8c1c4c5b88c91bd7953bb2cdbb212f3219e91c3")
                .unwrap();
        let vout = 0;
        let satoshi_amount = Amount::from_sat(1000);

        let bob_address = taproot_addr_from(ZKBITCOIN_PUBKEY).unwrap();

        let smart_contract = SmartContract {
            locked_value: satoshi_amount,
            vk_hash: [0; 32],
            state: None,
            vout_of_zkbitcoin_utxo: 0,
            prev_outs: vec![],
        };
        let mut tx = create_transaction(&smart_contract, txid, bob_address);

        // prevouts
        let prevouts = vec![TxOut {
            value: satoshi_amount,
            script_pubkey: ScriptBuf::from_hex(
                "5120814c57829b8c1af9956a23a9d687779469b1d7c06ebecac01f81922761331ea4",
            )
            .unwrap(),
        }];

        // sign
        let sk = secp256k1::SecretKey::from_str(
            "b2f7f581d6de3c06a822fd6e7e8265fbc00f8401696a5bdc34f5a6d2ff3f922f",
        )
        .unwrap();
        let sig = sign_transaction_schnorr(&sk, &tx, &prevouts);

        // place signature in witness
        let hash_ty = TapSighashType::All;
        let final_signature = taproot::Signature { sig, hash_ty };
        let mut witness = Witness::new();
        witness.push(final_signature.to_vec());
        tx.input[0].witness = witness;

        println!("{tx:#?}");

        // broadcast transaction
        let ctx = RpcCtx::for_testing();
        let _txid = send_raw_transaction(&ctx, TransactionOrHex::Transaction(&tx))
            .await
            .unwrap();
    }

    #[test]
    fn can_we_deserialize_taproot_addresses() {
        let address =
            Address::from_str("bc1p0dq0tzg2r780hldthn5mrznmpxsxc0jux5f20fwj0z3wqxxk6fpqm7q0va")
                .expect("a valid address")
                .require_network(Network::Bitcoin)
                .expect("valid address for mainnet");

        println!("{:?}", address.address_type());

        println!("{:?}", address.script_pubkey());
    }
}
