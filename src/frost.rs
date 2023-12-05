use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{TapSighashType, TapTweakHash, Transaction, TxOut};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::{Signature, VerifyingKey};
use rand::{thread_rng, RngCore};
use secp256k1::XOnlyPublicKey;
use std::collections::{BTreeMap, HashMap};

pub use frost::keys::{KeyPackage, PublicKeyPackage};
use secp256k1::hashes::Hash;

//
// copy/paste from their example
//

fn example() -> Result<(), frost::Error> {
    let mut rng = thread_rng();
    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    // Verifies the secret shares from the dealer and store them in a BTreeMap.
    // In practice, the KeyPackages must be sent to its respective participants
    // through a confidential and authenticated channel.
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();

    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        key_packages.insert(identifier, key_package);
    }

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_index in 1..(min_signers as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        let (nonces, commitments) = frost::round1::commit(
            key_packages[&participant_identifier].signing_share(),
            &mut rng,
        );
        // In practice, the nonces must be kept by the participant to use in the
        // next round, while the commitment must be sent to the coordinator
        // (or to every other participant if there is no coordinator) using
        // an authenticated channel.
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = BTreeMap::new();
    let message = "message to sign".as_bytes();
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];

        let nonces = &nonces_map[participant_identifier];

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;

        // In practice, the signature share must be sent to the Coordinator
        // using an authenticated channel.
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    let is_signature_valid = pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok();
    assert!(is_signature_valid);

    Ok(())
}

//
// Functions to test our flow
//

pub fn gen_frost_keys(
    max_signers: u16,
    min_signers: u16,
) -> Result<
    (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ),
    frost::Error,
> {
    let mut rng = thread_rng();

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 1
    ////////////////////////////////////////////////////////////////////////////

    // Keep track of each participant's round 1 secret package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut round1_secret_packages = HashMap::new();

    // Keep track of all round 1 packages sent to the given participant.
    // This is used to simulate the broadcast; in practice the packages
    // will be sent through some communication channel.
    let mut received_round1_packages = HashMap::new();

    // For each participant, perform the first part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (round1_secret_package, round1_package) =
            frost::keys::dkg::part1(participant_identifier, max_signers, min_signers, &mut rng)?;

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round1_secret_packages.insert(participant_identifier, round1_secret_package);

        // "Send" the round 1 package to all other participants. In this
        // test this is simulated using a HashMap; in practice this will be
        // sent through some communication channel.
        for receiver_participant_index in 1..=max_signers {
            if receiver_participant_index == participant_index {
                continue;
            }
            let receiver_participant_identifier: frost::Identifier = receiver_participant_index
                .try_into()
                .expect("should be nonzero");
            received_round1_packages
                .entry(receiver_participant_identifier)
                .or_insert_with(BTreeMap::new)
                .insert(participant_identifier, round1_package.clone());
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 2
    ////////////////////////////////////////////////////////////////////////////

    // Keep track of each participant's round 2 secret package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut round2_secret_packages = HashMap::new();

    // Keep track of all round 2 packages sent to the given participant.
    // This is used to simulate the broadcast; in practice the packages
    // will be sent through some communication channel.
    let mut received_round2_packages = HashMap::new();

    // For each participant, perform the second part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let round1_secret_package = round1_secret_packages
            .remove(&participant_identifier)
            .unwrap();
        let round1_packages = &received_round1_packages[&participant_identifier];
        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, round1_packages)?;

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round2_secret_packages.insert(participant_identifier, round2_secret_package);

        // "Send" the round 2 package to all other participants. In this
        // test this is simulated using a HashMap; in practice this will be
        // sent through some communication channel.
        // Note that, in contrast to the previous part, here each other participant
        // gets its own specific package.
        for (receiver_identifier, round2_package) in round2_packages {
            received_round2_packages
                .entry(receiver_identifier)
                .or_insert_with(BTreeMap::new)
                .insert(participant_identifier, round2_package);
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, final computation
    ////////////////////////////////////////////////////////////////////////////

    // Keep track of each participant's long-lived key package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut key_packages = BTreeMap::new();

    // Keep track of each participant's public key package.
    // In practice, if there is a Coordinator, only they need to store the set.
    // If there is not, then all candidates must store their own sets.
    // All participants will have the same exact public key package.
    let mut pubkey_packages = HashMap::new();

    // For each participant, perform the third part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let round2_secret_package = &round2_secret_packages[&participant_identifier];
        let round1_packages = &received_round1_packages[&participant_identifier];
        let round2_packages = &received_round2_packages[&participant_identifier];
        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;
        key_packages.insert(participant_identifier, key_package);
        pubkey_packages.insert(participant_identifier, pubkey_package);
    }

    // With its own key package and the pubkey package, each participant can now proceed
    // to sign with FROST.

    Ok((
        key_packages,
        pubkey_packages.values().next().unwrap().clone(),
    ))
}

pub fn to_xonly_pubkey(verifying_key: &frost::VerifyingKey) -> XOnlyPublicKey {
    let serialized_pubkey = verifying_key.serialize();
    XOnlyPublicKey::from_slice(&serialized_pubkey[1..]).unwrap()
}

fn sign(
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pubkey_package: &frost::keys::PublicKeyPackage,
    message: &[u8],
) -> Result<Signature, frost::Error> {
    let rng = &mut thread_rng();
    let min_signers = 3;

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_index in 1..(min_signers as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        let (nonces, commitments) =
            frost::round1::commit(key_packages[&participant_identifier].signing_share(), rng);
        // In practice, the nonces must be kept by the participant to use in the
        // next round, while the commitment must be sent to the coordinator
        // (or to every other participant if there is no coordinator) using
        // an authenticated channel.
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = BTreeMap::new();
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];

        let nonces = &nonces_map[participant_identifier];

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;

        // In practice, the signature share must be sent to the Coordinator
        // using an authenticated channel.
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    let is_signature_valid = pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok();
    assert!(is_signature_valid);

    Ok(group_signature)
}

pub fn sign_transaction_frost(
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pubkey_package: &frost::keys::PublicKeyPackage,
    tx: &Transaction,
    prevouts: &[TxOut],
) -> secp256k1::schnorr::Signature {
    // key
    let secp = &secp256k1::Secp256k1::new();

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

    // secp.sign_schnorr_with_aux_rand(&msg, &tweaked_keypair, &[0u8; 32])

    let signature = sign(key_packages, pubkey_package, msg.as_ref()).unwrap();
    println!("- signature: {:#?}", signature);

    // TODO use FROST signature as a Bitcoin signature
    // TODO it may be 02 or 03, so make sure it's okay to truncate it like this
    secp256k1::schnorr::Signature::from_slice(signature.serialize()[1..].as_ref()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1_tr::VerifyingKey;
    use secp256k1::XOnlyPublicKey;

    pub fn get_private_and_public() -> (
        BTreeMap<frost::Identifier, frost::keys::SecretShare>,
        frost::SigningKey,
        frost::keys::PublicKeyPackage,
    ) {
        let rng = &mut thread_rng();
        let max_signers = 5;
        let min_signers = 3;

        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);

        let private_key = frost::SigningKey::new(rng);
        let (shares, pubkey_package) = frost::keys::split(
            &private_key,
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();

        (shares, private_key, pubkey_package)
    }

    /// Useful to see if we correctly convert types from the frost library to the bitcoin library.
    #[test]
    fn test_get_pubkey_out() {
        // keygen
        let (mut shares, mut private, mut pubkey_package) = get_private_and_public();
        let mut pubkey = pubkey_package.verifying_key().to_owned();

        loop {
            if pubkey.serialize()[0] == 2 {
                break;
            }

            (shares, private, pubkey_package) = get_private_and_public();
            pubkey = pubkey_package.verifying_key().to_owned();
        }

        // dump private
        let serialized_private = private.serialize();
        println!("private key: {}", hex::encode(&serialized_private));

        // dump pubkey
        let serialized_pubkey = pubkey.serialize();
        println!("{}", hex::encode(&serialized_pubkey));

        // deserialize pubkey
        let deserialized_pubkey = bitcoin::PublicKey::from_slice(&serialized_pubkey).unwrap();

        // convert pubkey directly
        let serialized_pubkey = pubkey.serialize();
        let pubkey_from_direct_type_conversion =
            XOnlyPublicKey::from_slice(&serialized_pubkey[1..]).unwrap();

        // try to get pubkey from deserialized privkey
        let privkey = secp256k1::SecretKey::from_slice(&serialized_private).unwrap();
        let secp = secp256k1::Secp256k1::default();
        let pubkey_from_deserialized_private = privkey.public_key(&secp);

        println!(
            "pubkey_from_direct_type_conversion: {}",
            pubkey_from_direct_type_conversion
        );
        println!(
            "pubkey_from_deserialized_private: {}",
            pubkey_from_deserialized_private
        );
        println!("deserialized_pubkey: {}", deserialized_pubkey);

        let msg = secp256k1::Message::from_digest([0u8; 32]);

        // now let's try to sign with the MPC
        let key_packages = shares
            .iter()
            .map(|(id, share)| {
                (
                    *id,
                    frost::keys::KeyPackage::try_from(share.clone()).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let sig_mpc = sign(&key_packages, &pubkey_package, msg.as_ref()).unwrap();

        // and verify
        let sig =
            secp256k1::schnorr::Signature::from_slice(sig_mpc.serialize()[1..].as_ref()).unwrap();
        let res = secp.verify_schnorr(&sig, &msg, &pubkey_from_direct_type_conversion);
        println!("verify signature: {:?}", res);

        let is_signature_valid = pubkey.verify(&[0u8; 32], &sig_mpc).is_ok();
        println!("verify with their method: {:?}", is_signature_valid);

        if false {
            // let's sign with the private key directly
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_secret_key(&secp, &privkey);
            let (internal_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let tweak = TapTweakHash::from_key_and_tweak(internal_key, None);
            let tweaked_keypair = keypair.add_xonly_tweak(&secp, &tweak.to_scalar()).unwrap();
            let sig_bitcoin_rs =
                secp.sign_schnorr_with_aux_rand(&msg, &tweaked_keypair, &[0u8; 32]);

            println!("signature via MPC: {:?}", sig_mpc.serialize());
            println!("signature via bitcoin-rs: {:?}", sig_bitcoin_rs);

            // verify a signature with secp256k1 schnorr
            let (tweaked_pubkey, _) = tweaked_keypair.x_only_public_key();
            let res = secp.verify_schnorr(&sig_bitcoin_rs, &msg, &tweaked_pubkey);
            println!("verify signature: {:?}", res);
        }
    }

    #[test]
    fn test_flow() {
        let (key_packages, pubkey_package) = gen_frost_keys(5, 3).unwrap();

        let message = "message to sign".as_bytes();
        sign(&key_packages, &pubkey_package, message).unwrap();
    }
}
