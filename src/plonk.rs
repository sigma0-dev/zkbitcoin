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
    /// Warning: will panic if the public inputs is malformed.
    pub fn new_state(&self, state_len: usize) -> Vec<String> {
        self.0[0..state_len].to_vec()
    }

    /// Warning: will panic if the public inputs is malformed.
    pub fn prev_state(&self, state_len: usize) -> Vec<String> {
        self.0[state_len..state_len * 2].to_vec()
    }

    /// Warning: will panic if the public inputs is malformed.
    pub fn truncated_txid(&self, state_len: usize) -> String {
        self.0[state_len * 2].clone()
    }

    /// Warning: will panic if the public inputs is malformed.
    pub fn amount_out(&self, state_len: usize) -> String {
        self.0[state_len * 2 + 1].clone()
    }

    /// Warning: will panic if the public inputs is malformed.
    pub fn amount_in(&self, state_len: usize) -> String {
        self.0[state_len * 2 + 2].clone()
    }

    /// Recover the [Update] responsible for the given the public inputs.
    pub fn to_update(&self, state_len: usize) -> Update {
        Update {
            new_state: self.new_state(state_len),
            prev_state: self.prev_state(state_len),
            truncated_txid: None, // doesn't get serialized
            amount_out: self.amount_out(state_len),
            amount_in: self.amount_in(state_len),
        }
    }

    /// Convert an [Update] into the public inputs that can be used by the verifier.
    pub fn from_update(update: &Update, state_len: usize, truncated_txid: String) -> Result<Self> {
        ensure!(
            update.prev_state.len() == update.new_state.len(),
            "the size of the given previous state and new state don't match"
        );
        ensure!(
            update.prev_state.len() == state_len,
            "the size of the given previous state doesn't match the expected state length of {state_len}");

        let mut public_inputs = update.new_state.clone();
        public_inputs.extend(update.prev_state.clone());
        public_inputs.push(truncated_txid);
        public_inputs.push(update.amount_out.clone());
        public_inputs.push(update.amount_in.clone());

        Ok(Self(public_inputs))
    }
}
