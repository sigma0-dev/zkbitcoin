use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use tempdir::TempDir;

use crate::plonk::{self, VerifierKey};

pub struct CompilationResult {
    pub verifier_key: VerifierKey,
    pub circuit_r1cs_path: PathBuf,
    pub prover_key_path: PathBuf,
}

/// Compiles a circom circuit to a wasm and r1cs file.
pub fn compile(tmp_dir: &TempDir, circom_circuit_path: &Path) -> Result<CompilationResult> {
    // SRS
    let circuit_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("examples")
        .join("circuit");
    let srs_path = circuit_dir.join("srs.ptau");

    // set up new paths for files that will be created
    let circuit_r1cs_path = tmp_dir.path().join("circuit_r1cs.json");
    let prover_key_path = tmp_dir.path().join("prover_key.zkey");
    let verifier_key_path = tmp_dir.path().join("verifier_key.json");

    // compile to wasm and r1cs
    {
        // circom circuit.circom --r1cs --wasm --sym
        let output = Command::new("circom")
            .current_dir(&tmp_dir)
            .arg(circom_circuit_path)
            .arg("--wasm")
            .arg("--r1cs")
            .output()
            .expect("failed to execute process");

        println!("{}", String::from_utf8_lossy(&output.stdout));

        if !output.status.success() {
            bail!("failed to verify proof");
        }
    }

    // create prover key
    {
        // snarkjs plonk setup circuit.r1cs phase2_start.ptau circuit_final.zkey
        let output = Command::new("snarkjs")
            .current_dir(&tmp_dir)
            .arg("plonk")
            .arg("setup")
            .arg(&circuit_r1cs_path)
            .arg(srs_path)
            .arg(&prover_key_path)
            .output()
            .expect("failed to execute process");

        println!("{}", String::from_utf8_lossy(&output.stdout));

        if !output.status.success() {
            bail!("failed to verify proof");
        }
    }

    // create verifier key
    {
        // snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
        let output = Command::new("snarkjs")
            .current_dir(&tmp_dir)
            .arg("zkey")
            .arg("export")
            .arg("verificationkey")
            .arg(&prover_key_path)
            .arg(&verifier_key_path)
            .output()
            .expect("failed to execute process");

        println!("{}", String::from_utf8_lossy(&output.stdout));

        if !output.status.success() {
            bail!("failed to verify proof");
        }
    }

    // deserialize vk
    let vk = {
        let vk_file = File::open(verifier_key_path).expect("file creation failed");
        let vk: plonk::VerifierKey = serde_json::from_reader(vk_file).expect("read failed");
        vk
    };

    Ok(CompilationResult {
        verifier_key: vk,
        circuit_r1cs_path,
        prover_key_path,
    })
}

// should we implement these things?
// perhaps I can just use snarkjs as a library directly?
pub fn prove(
    circom_circuit_path: &Path,
    public_inputs: &HashMap<String, Vec<String>>,
) -> Result<(plonk::Proof, plonk::ProofInputs, plonk::VerifierKey)> {
    // create tmp dir
    let tmp_dir = TempDir::new("zkbitcoin_").expect("couldn't create tmp dir");

    // compile
    let CompilationResult {
        verifier_key,
        circuit_r1cs_path: _,
        prover_key_path,
    } = compile(&tmp_dir, circom_circuit_path)?;

    // write inputs to file
    let public_inputs_path = tmp_dir.path().join("public_inputs.json");
    let mut tmp_file = File::create(&public_inputs_path).expect("file creation failed");
    serde_json::to_writer(&mut tmp_file, &public_inputs).expect("write failed");

    // set up new paths for files that will be created
    let witness_path = tmp_dir.path().join("witness.json");
    let proof_path = tmp_dir.path().join("proof.json");
    let full_public_inputs_path = tmp_dir.path().join("full_public_inputs.json");

    // create witness using circom
    {
        // node output/circuit_js/generate_witness.js output/circuit_js/circuit.wasm public_input.json output/witness.wtns
        let circuit_name = circom_circuit_path
            .file_stem()
            .context("failed to get circuit name from filename")?;
        let output_folder = tmp_dir
            .path()
            .join(format!("{}_js", circuit_name.to_string_lossy()));
        let generate_witness_path = output_folder.join("generate_witness.js");
        let circuit_wasm_path =
            output_folder.join(format!("{}_wasm.js", circuit_name.to_string_lossy()));

        let output = Command::new("node")
            .current_dir(&tmp_dir)
            .arg(generate_witness_path)
            .arg(circuit_wasm_path)
            .arg(&public_inputs_path)
            .arg(&witness_path)
            .output()
            .expect("failed to execute process");

        println!("{}", String::from_utf8_lossy(&output.stdout));

        if !output.status.success() {
            bail!("failed to verify proof");
        }
    }

    // create proof using snarkjs
    {
        let output = Command::new("snarkjs")
            .current_dir(&tmp_dir)
            .arg("plonk")
            .arg("prove")
            .arg(prover_key_path)
            .arg(&witness_path)
            .arg(&proof_path)
            .arg(&full_public_inputs_path)
            .output()
            .expect("failed to execute process");

        println!("{}", String::from_utf8_lossy(&output.stdout));

        if !output.status.success() {
            bail!("failed to verify proof");
        }
    }

    // parse proof and full public inputs
    let proof_file = File::open(proof_path).expect("file creation failed");
    let proof: plonk::Proof = serde_json::from_reader(proof_file).expect("read failed");

    let full_public_inputs_file =
        File::open(full_public_inputs_path).expect("file creation failed");
    let full_public_inputs: plonk::ProofInputs =
        serde_json::from_reader(full_public_inputs_file).expect("read failed");

    Ok((proof, full_public_inputs, verifier_key))
}

pub fn verify_proof(
    vk: &plonk::VerifierKey,
    public_inputs: &[String],
    proof: &plonk::Proof,
) -> Result<()> {
    // create tmp dir
    let tmp_dir = TempDir::new("zkbitcoin_").expect("couldn't create tmp dir");

    // write vk, inputs, proof to file
    {
        let proof_path = tmp_dir.path().join("proof.json");
        let mut tmp_file = File::create(proof_path).expect("file creation failed");
        serde_json::to_writer(&mut tmp_file, &proof).expect("write failed");

        let public_inputs_path = tmp_dir.path().join("public_inputs.json");
        let mut tmp_file = File::create(public_inputs_path).expect("file creation failed");
        serde_json::to_writer(&mut tmp_file, &public_inputs).expect("write failed");

        let verification_key = tmp_dir.path().join("verification_key.json");
        let mut tmp_file = File::create(verification_key).expect("file creation failed");
        serde_json::to_writer(&mut tmp_file, &vk).expect("write failed");
    }

    // verify proof using snarkjs
    {
        let output = Command::new("snarkjs")
            .current_dir(&tmp_dir)
            .arg("plonk")
            .arg("verify")
            .arg("verification_key.json")
            .arg("public_inputs.json")
            .arg("proof.json")
            .output()
            .expect("failed to execute process");

        println!("{}", String::from_utf8_lossy(&output.stdout));

        if !output.status.success() {
            bail!("failed to verify proof");
        }
    }

    //
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_and_verify() {
        // get circuit and others
        let circuit_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("examples")
            .join("circuit");
        let circom_circuit_path = circuit_dir.join("circuit.circom");

        // // compile to get VK
        // let vk = {
        //     let tmp_dir = TempDir::new("zkbitcoin_").expect("couldn't create tmp dir");
        //     let CompilationResult {
        //         verifier_key,
        //         circuit_r1cs_path: _,
        //         prover_key_path: _,
        //     } = compile(tmp_dir, &circom_circuit_path).unwrap();
        //     verifier_key
        // };

        // prove
        let mut public_inputs = HashMap::new();
        let (proof, full_inputs, vk) = prove(&circom_circuit_path, &public_inputs).unwrap();

        // verify
        verify_proof(&vk, &full_inputs.0, &proof).unwrap();
    }
}
