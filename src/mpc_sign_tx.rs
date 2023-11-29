use bitcoin::{sighash, Transaction};

pub fn sign_transaction_ecdsa(
    sk: &secp256k1::SecretKey,
    tx: &Transaction,
) -> secp256k1::ecdsa::Signature {
    // TODO: figure out how to get the digest to sign
    // the C++ code: https://github.com/bitcoin/bitcoin/blob/16b5b4b674414c41f34b0d37e15a16521fb08013/src/script/sign.cpp#L784
    let msg = {
        let mut cache = sighash::SighashCache::new(tx);
        // let sighash = cache
        //     .p2wpkh_signature_hash(inp_idx, &spk, Amount::from_sat(value), sig.hash_ty)
        //     .expect("failed to compute sighash");

        // println!("Segwit p2wpkh sighash: {:x}", sighash);

        // secp256k1::Message::from_digest(sighash.to_byte_array())

        todo!()
    };

    let secp = secp256k1::Secp256k1::signing_only();
    let sig = secp.sign_ecdsa(&msg, &sk);

    let pubkey = sk.public_key(&secp);

    let secp = secp256k1::Secp256k1::verification_only();
    secp.verify_ecdsa(&msg, &sig, &pubkey).unwrap();

    sig
}
