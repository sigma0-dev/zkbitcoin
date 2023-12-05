# MPC and taproot

* This document is motivated by a bug in our MPC signature.
* Currently, the MPC committee signs a transaction, but then the transaction fails to verify.
* Here's the current flow:
* We use the taproot library of FROST for the MPC.
* We used a trusted dealer (faster than DKG to prototype) to distribute the MPC private keys
* When Alice deploys a smart contract, she sends a taproot transaction to the zkBitcoin signature + a tweak. The tweak is added automatically via the `ScriptBuf::new_p2tr` function.
* This is necessary, because the group public key we obtained does not contain any tweak.
* Note that if we used the frost `verify` function, it would compute the tweak on the public key on the fly:

```rust
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
```

* When Bob wants to unlock funds, he will make a request to the orchestrator
* the orchestrator will then forward the request to the MPC committee, and help them advance through a 2-round MPC
* they will produce a schnorr signature as usual
* but the orchestrator will add the tweak when aggregating the signature shares
* This is because the original computation of s `z = k + s * c` now becomes `z = k + (s + tweak) * c = (k + s * c) + (tweak * c)`, so notice `tweak * c` can be added at the end
* The signature will be added to the transaction by the orchestrator, who will then try to send it to their bitcoin full node
* At this point, the signature is deemed invalid by the bitcoin full node
* We do not know why.

