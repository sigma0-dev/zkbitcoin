use std::collections::{BTreeMap, HashMap};

pub struct Member {
    /// e.g. "127.0.0.1:8887"
    address: String,
}

pub struct Orchestrator {
    pub pubkey_package: frost_secp256k1::keys::PublicKeyPackage,
    pub committee: HashMap<frost_secp256k1::Identifier, Member>,
}

/// The state throughout a single MPC signature.
pub struct SigningTask {
    /// The message to sign.
    message: Vec<u8>,

    /// The commitments collected during round 1.
    commitments: BTreeMap<frost_secp256k1::Identifier, frost_secp256k1::round1::SigningCommitments>,

    /// The signing package formed at the end of round 1.
    signing_package: Option<frost_secp256k1::SigningPackage>,

    /// The signature shares at the end of round 2.
    signature_shares:
        BTreeMap<frost_secp256k1::Identifier, frost_secp256k1::round2::SignatureShare>,
}

impl SigningTask {
    pub fn new(message: Vec<u8>) -> Self {
        Self {
            message,
            commitments: BTreeMap::new(),
            signing_package: None,
            signature_shares: BTreeMap::new(),
        }
    }

    pub fn step1_collect_commitments_from_round1(signing_task: &mut SigningTask) {
        // TODO: send messages in parallel to a threshold of committee member (what if we get a timeout or can't meet that threshold? loop? send to more members?)
    }

    pub fn step2_submit_commitments_for_round2() {
        // TODO: query some API to colllect the commitment from each of them
    }

    pub fn step3_finally_aggregate(&self, state: &Orchestrator) -> frost_secp256k1::Signature {
        let signing_package = self.signing_package.as_ref().unwrap();
        let group_signature = frost_secp256k1::aggregate(
            signing_package,
            &self.signature_shares,
            &state.pubkey_package,
        )
        .unwrap();
        group_signature
    }
}
