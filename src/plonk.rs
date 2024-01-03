#![allow(non_snake_case)]

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::bob_request::Update;

/// The snarkjs plonk verifier key format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierKey {
    protocol: String,   // "plonk",
    curve: String,      // "bn128",
    pub nPublic: usize, // 96,
    power: usize,       // 9,
    k1: String,         // "2",
    k2: String,         // "3",
    Qm: Vec<String>,
    Ql: Vec<String>,
    Qr: Vec<String>,
    Qo: Vec<String>,
    Qc: Vec<String>,
    S1: Vec<String>,
    S2: Vec<String>,
    S3: Vec<String>,
    X_2: Vec<Vec<String>>,
    w: String, //"6837567842312086091520287814181175430087169027974246751610506942214842701774"
}

impl VerifierKey {
    /// hashes a verifier key.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        // TODO: find a better way :D
        hasher.update(serde_json::to_string(&self).unwrap());
        let hash = hasher.finalize().to_vec();
        hash.try_into().unwrap()
    }
}

/// A snarkjs plonk proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    A: Vec<String>,
    B: Vec<String>,
    C: Vec<String>,
    Z: Vec<String>,
    T1: Vec<String>,
    T2: Vec<String>,
    T3: Vec<String>,
    Wxi: Vec<String>,
    Wxiw: Vec<String>,
    eval_a: String,
    eval_b: String,
    eval_c: String,
    eval_s1: String,
    eval_s2: String,
    eval_zw: String,
    protocol: String, // "plonk",
    curve: String,    //"bn128"
}

impl Proof {
    /// Hashes a proof.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        // TODO: find a better way :D ?
        hasher.update(serde_json::to_string(&self).unwrap());
        let hash = hasher.finalize().to_vec();
        hash.try_into().unwrap()
    }
}

/// The public input that has to be used by the verifier
// TODO: rename to public inputs, proof inputs should be about private inputs as well
#[derive(Serialize, Deserialize)]
pub struct PublicInputs(pub Vec<String>);

impl PublicInputs {
    /// Warning: might panic if the public inputs is malformed.
    pub fn new_state(&self) -> String {
        self.0[0].clone()
    }

    /// Warning: might panic if the public inputs is malformed.
    pub fn prev_state(&self) -> String {
        self.0[1].clone()
    }

    /// Warning: might panic if the public inputs is malformed.
    pub fn truncated_txid(&self) -> String {
        self.0[2].clone()
    }

    /// Warning: might panic if the public inputs is malformed.
    pub fn amount_out(&self) -> String {
        self.0[3].clone()
    }

    /// Warning: might panic if the public inputs is malformed.
    pub fn amount_in(&self) -> String {
        self.0[4].clone()
    }

    /// Recover the [Update] responsible for the given the public inputs.
    pub fn to_update(&self) -> Update {
        Update {
            new_state: self.new_state(),
            prev_state: self.prev_state(),
            truncated_txid: None, // doesn't get serialized
            amount_out: self.amount_out(),
            amount_in: self.amount_in(),
        }
    }

    /// Convert an [Update] into the public inputs that can be used by the verifier.
    pub fn from_update(update: &Update, truncated_txid: String) -> Result<Self> {
        let mut public_inputs = vec![update.new_state.clone()];
        public_inputs.push(update.prev_state.clone());
        public_inputs.push(truncated_txid);
        public_inputs.push(update.amount_out.clone());
        public_inputs.push(update.amount_in.clone());

        Ok(Self(public_inputs))
    }
}
