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
    let utxos = &tx.output;
    cache
        .taproot_encode_signing_data_to(
            &mut sig_msg,
            tx_ind,
            &Prevouts::All(utxos),
            None,
            None,
            hash_ty,
        )
        .unwrap();
    let sighash = cache
        .taproot_signature_hash(tx_ind, &Prevouts::All(&utxos), None, None, hash_ty)
        .unwrap();

    let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
    let key_spend_sig = secp.sign_schnorr_with_aux_rand(&msg, &tweaked_keypair, &[0u8; 32]);

    key_spend_sig
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::Network;

    use crate::constants::{ZKBITCOIN_ADDRESS, ZKBITCOIN_PUBKEY};

    use super::*;

    fn create_dummy_tx() -> Transaction {
        let zkbitcoin_pubkey: PublicKey = PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();

        // first input is a P2TR
        let satoshi_amount = 1000;
        let secp = secp256k1::Secp256k1::default();
        let internal_key = UntweakedPublicKey::from(zkbitcoin_pubkey);
        let pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);
        let input = vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }];

        // first output is a P2TR as well
        let output = vec![TxOut {
            value: Amount::from_sat(satoshi_amount),
            script_pubkey: pubkey,
        }];

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO, // no lock time
            // we don't need to specify inputs at this point, the wallet will fill that for us
            input,
            output,
        };

        tx
    }

    #[test]
    fn test_sign_tx() {
        let sk = secp256k1::SecretKey::new(&mut rand::thread_rng());
        let tx = create_dummy_tx();
        let sig = sign_transaction_schnorr(&sk, &tx);
        println!("{sig:?}");
    }

    /// https://blockstream.info/testnet/tx/0a38352d1ba4efdc785bc895abdb3f3185624100509d45aa2663b27a2fc094ea?expand
    #[test]
    fn test_real_tx() {
        let txid =
            Txid::from_str("0a38352d1ba4efdc785bc895abdb3f3185624100509d45aa2663b27a2fc094ea")
                .unwrap();
        let vout = 0;
        let satoshi_amount = 1000;

        let bob_address = Address::from_str(ZKBITCOIN_ADDRESS)
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let fee_bitcoin_sat = 800;
        let fee_zkbitcoin_sat = 200;
        let tx = create_transaction(
            (txid, vout),
            satoshi_amount,
            bob_address,
            fee_bitcoin_sat,
            fee_zkbitcoin_sat,
        );

        println!("{tx:#?}");

        let sk = secp256k1::SecretKey::new(&mut rand::thread_rng());
        let tx = create_dummy_tx();
        let sig = sign_transaction_schnorr(&sk, &tx);
        println!("{sig:?}");

        // TODO: place signature in witness
    }
}
