#[cfg(test)]
mod tests {
    use frost_secp256k1 as frost;
    use rand::{thread_rng, RngCore};

    pub fn get_private_and_public() -> (frost::SigningKey, frost::VerifyingKey) {
        let mut rng = &mut thread_rng();
        let max_signers = 5;
        let min_signers = 3;

        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);

        let private_key = frost::SigningKey::new(rng);
        let (_shares, pubkey_package) = frost::keys::split(
            &private_key,
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();

        (private_key, pubkey_package.verifying_key().to_owned())
    }

    #[test]
    fn test_get_pubkey_out() {
        let (private, pubkey) = get_private_and_public();

        let serialized_private = private.serialize();
        let serialized_pubkey = pubkey.serialize();
        println!("{}", hex::encode(&serialized_pubkey));

        let privkey = secp256k1::SecretKey::from_slice(&serialized_private).unwrap();
        let secp = secp256k1::Secp256k1::default();
        let pubkey2 = privkey.public_key(&secp);
        let pubkey3 = bitcoin::PublicKey::from_slice(&serialized_pubkey).unwrap();
        println!("2: {}", pubkey2);
        println!("3: {}", pubkey3);

        // TODO: why does this fail half of the time? Not anymore!
        let pubkey = bitcoin::XOnlyPublicKey::from_slice(&serialized_pubkey[1..]).unwrap();

        println!("1: {}", pubkey);
    }
}
