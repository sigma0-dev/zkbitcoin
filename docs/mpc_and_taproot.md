# Making zcash-FROST lib compatible with taproot

## Problem

FROST is not compatible with Bitcoin Schnorr's standard (BIP 340 and BIP 341) because of two additions in the Bitcoin scheme: elliptic curve points lose information (they only carry the x coordinate) and public keys can be tweaked (this is due to the taproot design).

Some recap and notation:

* the keypair is $(s, Y)$ such that $Y = [s]G$
* the signature is $(R, z)$ such that $R = [k]G$ and $z = k + s \cdot c$

From page 6 of the FROST paper this is their notation for the simple Schnorr protocol:

![Screenshot 2023-12-06 at 1.27.51 PM](https://hackmd.io/_uploads/HymPwPRSa.png)

In addition, FROST has the MPC committee compute additive shares for $R$ and $z$, so that they can be computed by using a sum of the computed shares ($R = \sum R_i$ and $z = \sum z_i$).

## Discussion

The verifier ends up checking this equation:

$$
R == [z]G - [c]Y
$$

but in reality, they are checking the equation with $Y' = Y + [\text{tweak}] G$ which is the tweaked public key:

$$
R == [z]G - [c]Y'
$$

And due to that, the aggregator uses $z' = z + c \cdot \text{tweak}$ to cancel out the tweak:

$$
R == [z']G - [c]Y'
$$

On top of this:

1. the verifier uses $R'$ which could be $-R$  or $R$ depending on the parity of $R$ (this is due to only having access to the x coordinate of $R$)
2. $Y'$ is actually computed using $-Y$ or $Y$ depending on the parity of $Y$ (for the same reasons)

So the equation sort of looks like this if we open things up:

$$
[+-k]G == [k + s \cdot c + c \cdot \text{tweak}]G - [c]Y - [c \cdot \text{tweak}]Y
$$

## How this is solved by FROST taproot lib

There's a PR: https://github.com/ZcashFoundation/frost/pull/584

The verification implementation is here:

```rust=
fn verify_signature(
        msg: &[u8],
        signature: &Signature<Self>,
        public_key: &VerifyingKey<Self>,
    ) -> Result<(), Error<Self>> {
        let c = <Self>::challenge(&signature.R, public_key, msg);

        public_key.verify_prehashed(c, signature)
    }

pub(crate) fn verify_prehashed(
        &self,
        challenge: Challenge<C>,
        signature: &Signature<C>,
    ) -> Result<(), Error<C>> {
        // Verify check is h * ( - z * B + R  + c * A) == 0
        //                 h * ( z * B - c * A - R) == 0
        //
        // where h is the cofactor
        let mut R = signature.R;
        let mut vk = self.element;
        if <C>::is_need_tweaking() {
            R = <C>::tweaked_R(&signature.R);
            vk = <C>::tweaked_public_key(&self.element);
        }
        let zB = C::Group::generator() * signature.z;
        let cA = vk * challenge.0;
        let check = (zB - cA - R) * C::Group::cofactor();

        if check == C::Group::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
```

Because we use the taproot-compatible library, the `is_need_tweaking` branch is always taken.

$R$ in Frost is the full point (with x and y coordinates), so here the implementation pretends that we can only see the x coordinate (and recovers the full point with an even y coordinate):

```rust=
fn tweaked_R(
        R: &<Self::Group as Group>::Element,
    ) -> <Self::Group as Group>::Element {
        AffinePoint::decompact(&R.to_affine().x()).unwrap().into()
    }
```

In addition, it creates the tweaked public key on the fly, using an empty data commitment:

```rust=
fn tweaked_public_key(
        public_key: &<Self::Group as Group>::Element,
    ) -> <Self::Group as Group>::Element {
        tweaked_public_key(public_key, &[])
    }

/// Create a BIP341 compliant tweaked public key
pub fn tweaked_public_key(
    public_key: &<<Secp256K1Sha256 as Ciphersuite>::Group as Group>::Element,
    merkle_root: &[u8],
) -> <<Secp256K1Sha256 as Ciphersuite>::Group as Group>::Element {
    let mut pk = public_key.clone();
    if public_key.to_affine().y_is_odd().into() {
        pk = -pk;
    }
    ProjectivePoint::GENERATOR * tweak(&pk, merkle_root) + pk
}
```

They also pretend that $Y$ is $-Y$ if its y coordinate is odd. This emulates what the real Bitcoin spender will be doing as they will only use the x coordinate of $Y$ when tweaking it.

Bitcoin defines their Schnorr protocol in [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#description), and touches on why it did this "x-coordinate only" thing:

![Screenshot 2023-12-06 at 1.41.41 PM](https://hackmd.io/_uploads/B14oqD0rp.png)

Due to that, signing is done differently:

![Screenshot 2023-12-06 at 1.43.49 PM](https://hackmd.io/_uploads/ryWQiwAHT.png)

Specifically:

* the private key $d = s$ is potentially negated to ensure that the public key $P = Y$ it produces has an even y coordinate.
* the nonce $k$ is potentially negated to ensure that the commitment point $R$ it produces has an even y coordinate.

This is solved by each MPC committee during the second round of a signing operation: they negate the nonce if it leads to the wrong $R$ ($R$ has an odd coordinate, and so it will be decoded with an even coordinate), and they negate the secret key if it leads to the wrong the public key (the correct public key, again, is the one that when decoded has an even y coordinate.):

```rust=
fn compute_tweaked_signature_share(
        signer_nonces: &round1::SigningNonces,
        binding_factor: frost::BindingFactor<S>,
        group_commitment: frost_core::GroupCommitment<S>,
        lambda_i: <<Self::Group as Group>::Field as Field>::Scalar,
        key_package: &frost::keys::KeyPackage<S>,
        challenge: Challenge<S>,
    ) -> round2::SignatureShare
    {
        let mut sn = signer_nonces.clone();
        if group_commitment.y_is_odd() {
            sn.negate_nonces();
        }

        let mut kp = key_package.clone();
        if key_package.verifying_key().y_is_odd() {
            kp.negate_signing_share();
        }

        frost::round2::compute_signature_share(
            &sn,
            binding_factor,
            lambda_i,
            &kp,
            challenge,
        )
    }
```

We have one last problem, the tweak of the public key will lead to a wrong verification equation if nothing cancels it out. Turns out that the FROST aggregator can cancel out the tweak by adding it to the nonce $z$, after aggregating. See the implementation:

```rust=
pub fn aggregate<C>(
    signing_package: &SigningPackage<C>,
    signature_shares: &BTreeMap<Identifier<C>, round2::SignatureShare<C>>,
    pubkeys: &keys::PublicKeyPackage<C>,
) -> Result<Signature<C>, Error<C>>
where
    C: Ciphersuite,
{
    // Check if signing_package.signing_commitments and signature_shares have
    // the same set of identifiers, and if they are all in pubkeys.verifying_shares.
    if signing_package.signing_commitments().len() != signature_shares.len() {
        return Err(Error::UnknownIdentifier);
    }
    if !signing_package.signing_commitments().keys().all(|id| {
        #[cfg(feature = "cheater-detection")]
        return signature_shares.contains_key(id) && pubkeys.verifying_shares().contains_key(id);
        #[cfg(not(feature = "cheater-detection"))]
        return signature_shares.contains_key(id);
    }) {
        return Err(Error::UnknownIdentifier);
    }

    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list: BindingFactorList<C> =
        compute_binding_factor_list(signing_package, &pubkeys.verifying_key, &[]);

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    //
    // Implements [`aggregate`] from the spec.
    //
    // [`aggregate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-5.3
    let mut z = <<C::Group as Group>::Field>::zero();

    for signature_share in signature_shares.values() {
        z = z + signature_share.share;
    }

    if <C>::is_need_tweaking() {
        let challenge = <C>::challenge(
            &group_commitment.0,
            &pubkeys.verifying_key,
            signing_package.message().as_slice(),
        );
        z = <C>::aggregate_tweak_z(z, &challenge, &pubkeys.verifying_key.element);
    }

    let signature = Signature {
        R: group_commitment.0,
        z,
    };

    // Verify the aggregate signature
    let verification_result = pubkeys
        .verifying_key
        .verify(signing_package.message(), &signature);

    // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
    // This approach is more efficient since we don't need to verify all shares
    // if the aggregate signature is valid (which should be the common case).
    #[cfg(feature = "cheater-detection")]
    if let Err(err) = verification_result {
        // Compute the per-message challenge.
        let challenge = <C>::challenge(
            &group_commitment.0,
            &pubkeys.verifying_key,
            signing_package.message().as_slice(),
        );

        // Verify the signature shares.
        for (signature_share_identifier, signature_share) in signature_shares {
            // Look up the public key for this signer, where `signer_pubkey` = _G.ScalarBaseMult(s[i])_,
            // and where s[i] is a secret share of the constant term of _f_, the secret polynomial.
            let signer_pubkey = pubkeys
                .verifying_shares
                .get(signature_share_identifier)
                .ok_or(Error::UnknownIdentifier)?;

            // Compute Lagrange coefficient.
            let lambda_i = derive_interpolating_value(signature_share_identifier, signing_package)?;

            let binding_factor = binding_factor_list
                .get(signature_share_identifier)
                .ok_or(Error::UnknownIdentifier)?;

            // Compute the commitment share.
            let R_share = signing_package
                .signing_commitment(signature_share_identifier)
                .ok_or(Error::UnknownIdentifier)?
                .to_group_commitment_share(binding_factor);

            // Compute relation values to verify this signature share.
            signature_share.verify(
                *signature_share_identifier,
                &R_share,
                signer_pubkey,
                lambda_i,
                &challenge,
                &group_commitment,
                &pubkeys.verifying_key,
            )?;
        }

        // We should never reach here; but we return the verification error to be safe.
        return Err(err);
    }

    #[cfg(not(feature = "cheater-detection"))]
    verification_result?;

    Ok(signature)
}
```

Notice that the `challenge` and the `z` part of the signature are computed differently: the challenge computation only uses the x coordinate of R, and the tweaked public key instead of the public key. Then the tweak is added to `z` to cancel out the one from the tweaked public key in the verification equation.

```rust=
fn challenge(R: &Element<S>, verifying_key: &VerifyingKey, msg: &[u8]) -> Challenge<S>
    {
        let mut preimage = vec![];
        let tweaked_public_key = tweaked_public_key(&verifying_key.to_element(), &[]);
        preimage.extend_from_slice(&R.to_affine().x());
        preimage.extend_from_slice(&tweaked_public_key.to_affine().x());
        preimage.extend_from_slice(msg);
        Challenge::from_scalar(S::H2(&preimage[..]))
    }

fn aggregate_tweak_z(
        z: <<Self::Group as Group>::Field as Field>::Scalar,
        challenge: &Challenge<S>,
        verifying_key: &Element<S>,
    ) -> <<Self::Group as Group>::Field as Field>::Scalar
    {
        let t = tweak(&verifying_key, &[]);
        z + t * challenge.clone().to_scalar()
    }
```

## Issues

The problem is that the previous code doesn't work :o)

To investigate this, we need to understand two things:

1. how exactly they implement signing and verification in the FROST library (this is what we've done here so far)
2. what are the different possibilities due to losing information about the y coordinate of the public key, the tweaked public key, and the commitment R in the signature

This led me to draw this wonderful diagram which shows exactly the different possibilities taken by each point during signing and verification:

![IMG_F5F98452A39B-1](https://hackmd.io/_uploads/BkL2IvP86.jpg)

Issues can arise in three locations:

* MPC signers might not compute the right value to cancel terms
* The orchestrator might not aggregate the right things
* The verification equation might not use the right values

It looks like the issues I found were a combination of these:

1. the verification equation could use the wrong tweaked public key, as it didn't check if the y coordinate was odd (if it was, then it should negate it)
2. signers negated their shares based on the public key, but they should also have taken the tweaked public key into account
3. the aggregator didn't correctly negate the tweak when added to the second part of the signature

the issues were pointed and a fix was proposed in the original PR: https://github.com/ZcashFoundation/frost/pull/584
