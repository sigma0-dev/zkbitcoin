use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// The snarkjs plonk verifier key format.
#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
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

/// The public input that has to be used by the verifier
#[derive(Serialize, Deserialize)]
pub struct ProofInputs(Vec<String>);

impl VerifierKey {
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        // I know, this is a really ugly way to hash a struct :D
        hasher.update(serde_json::to_string(&self).unwrap());
        hasher.finalize().to_vec()
    }
}
