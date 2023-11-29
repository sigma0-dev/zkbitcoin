use bitcoin::{
    sighash::{self, Prevouts, SighashCache},
    TapSighashType, TapTweakHash, Transaction,
};
use secp256k1::{hashes::Hash, XOnlyPublicKey};

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

    use bitcoin::{
        absolute::LockTime, key::UntweakedPublicKey, transaction::Version, Amount, OutPoint,
        PublicKey, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness,
    };

    use crate::constants::ZKBITCOIN_PUBKEY;

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
}
