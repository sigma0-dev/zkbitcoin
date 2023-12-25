use std::{
    fs::{remove_dir_all, File},
    process::Command,
};

use anyhow::{bail, Result};
use tempdir::TempDir;

use crate::bob_request::BobRequest;

pub fn verify_proof(request: &BobRequest) -> Result<()> {
    // write vk, inputs, proof to file
    let tmp_dir = {
        let tmp_dir = TempDir::new("zkbitcoin_").expect("couldn't create tmp dir");

        let proof_path = tmp_dir.path().join("proof.json");
        let mut tmp_file = File::create(proof_path).expect("file creation failed");
        serde_json::to_writer(&mut tmp_file, &request.proof).expect("write failed");

        let public_inputs_path = tmp_dir.path().join("public_inputs.json");
        let mut tmp_file = File::create(public_inputs_path).expect("file creation failed");
        serde_json::to_writer(&mut tmp_file, &request.public_inputs).expect("write failed");

        let verification_key = tmp_dir.path().join("verification_key.json");
        let mut tmp_file = File::create(verification_key).expect("file creation failed");
        serde_json::to_writer(&mut tmp_file, &request.vk).expect("write failed");

        tmp_dir
    };

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

    // clean up
    remove_dir_all(tmp_dir).expect("failed to remove temp dir");

    //
    Ok(())
}
