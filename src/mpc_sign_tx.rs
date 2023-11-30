use std::str::FromStr;

use bitcoin::{
    absolute::LockTime,
    key::UntweakedPublicKey,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Address, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TapSighashType, TapTweakHash,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use secp256k1::{hashes::Hash, XOnlyPublicKey};

use crate::constants::ZKBITCOIN_PUBKEY;

pub fn create_transaction(
    utxo: (Txid, u32),
    satoshi_amount: u64,
    bob_address: Address,
    fee_bitcoin_sat: u64,
    fee_zkbitcoin_sat: u64,
) -> Transaction {
    // TODO: should we enforce that tx.value == amount?

    let inputs = {
        // the first input is the smart contract we're unlocking
        let input = TxIn {
            previous_output: OutPoint {
                txid: utxo.0,
                vout: utxo.1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        vec![input]
    };

    // we need to subtract the amount  to cover for the fee
    let amount_for_bob = satoshi_amount - fee_bitcoin_sat - fee_zkbitcoin_sat;

    let outputs = {
        let mut outputs = vec![];

        // first output is a P2TR to Bob
        outputs.push(TxOut {
            value: Amount::from_sat(amount_for_bob),
            script_pubkey: bob_address.script_pubkey(),
        });

        // second output is to us
        let secp = secp256k1::Secp256k1::default();
        let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
        let internal_key = UntweakedPublicKey::from(zkbitcoin_pubkey);
        outputs.push(TxOut {
            value: Amount::from_sat(fee_zkbitcoin_sat),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        });

        outputs
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO, // no lock time
        input: inputs,
        output: outputs,
    };
    tx
}

pub fn sign_transaction_schnorr(
    sk: &secp256k1::SecretKey,
    tx: &Transaction,
    prevouts: &[TxOut],
) -> secp256k1::schnorr::Signature {
    // key
    let secp = &secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(secp, &sk);
    let (internal_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);
    let tweak = TapTweakHash::from_key_and_tweak(internal_key, None);
    let tweaked_keypair = keypair.add_xonly_tweak(secp, &tweak.to_scalar()).unwrap();

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
    let key_spend_sig = secp.sign_schnorr_with_aux_rand(&msg, &tweaked_keypair, &[0u8; 32]);

    key_spend_sig
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{taproot, Network, PrivateKey, Script};
    use rand::prelude::*;
    use rand_chacha::ChaCha20Rng;

    use crate::{
        constants::{ZKBITCOIN_ADDRESS, ZKBITCOIN_PUBKEY},
        json_rpc_stuff::{
            fund_raw_transaction, json_rpc_request, send_raw_transaction, sign_transaction,
            TransactionOrHex,
        },
    };

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
        let untweaked = UntweakedPublicKey::from(pubkey);
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

        //        let (tx, prevouts) = create_dummy_tx();
        //        let sig = sign_transaction_schnorr(&sk, &tx, &prevouts);
        //        println!("{sig:?}");

        // create empty transaction that sends to a p2tr from our wallet
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO, // no lock time
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, untweaked, None),
            }],
        };

        // fund that transaction with our wallet
        let (tx_hex, _) =
            fund_raw_transaction(TransactionOrHex::Transaction(&tx), Some("mywallet"))
                .await
                .unwrap();

        // sign that transaction with our wallet
        let (tx_hex, _) = sign_transaction(TransactionOrHex::Hex(tx_hex), Some("mywallet"))
            .await
            .unwrap();

        // broadcast it
        let txid = send_raw_transaction(TransactionOrHex::Hex(tx_hex))
            .await
            .unwrap();

        println!("- txid: {txid}");
    }

    #[tokio::test]
    #[ignore = "I'm trying to use this to spend the p2tr created in the previous test"]
    async fn test_real_tx() {
        // txid from https://blockstream.info/testnet/tx/02fcc5b458ff032d4c82b12ce8c1c4c5b88c91bd7953bb2cdbb212f3219e91c3?expand
        let txid =
            Txid::from_str("02fcc5b458ff032d4c82b12ce8c1c4c5b88c91bd7953bb2cdbb212f3219e91c3")
                .unwrap();
        let vout = 0;
        let satoshi_amount = 1000;

        let bob_address = Address::from_str(ZKBITCOIN_ADDRESS)
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let fee_bitcoin_sat = 800;
        let fee_zkbitcoin_sat = 200;
        let mut tx = create_transaction(
            (txid, vout),
            satoshi_amount,
            bob_address,
            fee_bitcoin_sat,
            fee_zkbitcoin_sat,
        );

        // prevouts
        let prevouts = vec![TxOut {
            value: Amount::from_sat(satoshi_amount),
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
        let _txid = send_raw_transaction(TransactionOrHex::Transaction(&tx))
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
