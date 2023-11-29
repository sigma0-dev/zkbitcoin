use serde::{Deserialize, Serialize};

/// The snarkjs plonk verifier key format.
#[derive(Serialize, Deserialize)]
pub struct VerifierKey {
    protocol: String, // "plonk",
    curve: String,    // "bn128",
    nPublic: usize,   // 96,
    power: usize,     // 9,
    k1: String,       // "2",
    k2: String,       // "3",
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
pub struct Proof {}
