use std::{collections::HashMap, env, path::PathBuf, str::FromStr};

use anyhow::{ensure, Context, Result};
use bitcoin::{Address, Txid};
use clap::{Parser, Subcommand};
use tempdir::TempDir;
use zkbitcoin::{
    alice_sign_tx::generate_and_broadcast_transaction,
    bob_request::{send_bob_request, BobRequest},
    committee::orchestrator::{CommitteeConfig, Member},
    constants::{
        BITCOIN_JSON_RPC_VERSION, ORCHESTRATOR_ADDRESS, ZKBITCOIN_FEE_PUBKEY, ZKBITCOIN_PUBKEY,
    },
    frost, get_network,
    json_rpc_stuff::{send_raw_transaction, sign_transaction, RpcCtx, TransactionOrHex},
    snarkjs::{self, CompilationResult},
    taproot_addr_from,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Alice can use this to deploy a circuit.
    DeployTransaction {
        /// The wallet name of the RPC full node.
        #[arg(env = "RPC_WALLET")]
        wallet: Option<String>,

        /// The `http(s)://address:port`` of the RPC full node.
        #[arg(env = "RPC_ADDRESS")]
        address: Option<String>,

        /// The `user:password`` of the RPC full node.
        #[arg(env = "RPC_AUTH")]
        auth: Option<String>,

        // /// The path to the verifier key in JSON format (see `examples/circuit/vk.json` for an example).
        // #[arg(short, long)]
        // verifier_key_path: Option<String>,
        // -----
        /// The path to the circom circuit to deploy.
        #[arg(short, long)]
        circom_circuit_path: PathBuf,

        /// Optionally, for stateful zkapps, an initial state.
        #[arg(short, long)]
        initial_state: Option<String>,

        /// The amount in satoshis to send to the smart contract.
        #[arg(short, long)]
        satoshi_amount: u64,
    },

    /// Bob can use this to unlock funds from a smart contract.
    UnlockFundsRequest {
        /// The wallet name of the RPC full node.
        #[arg(env = "RPC_WALLET")]
        wallet: Option<String>,

        /// The `http(s)://address:port`` of the RPC full node.
        #[arg(env = "RPC_ADDRESS")]
        address: Option<String>,

        /// The `user:password`` of the RPC full node.
        #[arg(env = "RPC_AUTH")]
        auth: Option<String>,

        /// The address of the orchestrator.
        #[arg(env = "ENDPOINT")]
        orchestrator_address: Option<String>,

        /// The transaction ID that deployed the smart contract.
        #[arg(short, long)]
        txid: String,

        /// The address of the recipient.
        #[arg(short, long)]
        recipient_address: String,

        // /// The path to the verifier key in JSON format (see `examples/circuit/vk.json` for an example).
        // #[arg(short, long)]
        // verifier_key_path: String,
        /// The path to the circom circuit to deploy.
        #[arg(short, long)]
        circom_circuit_path: PathBuf,

        /// A JSON string of the proof inputs in case of a stateful zkapp being used.
        /// We expect the following fields:
        /// `prev_state`, `amount_in`, `amount_out`.
        #[arg(short, long)]
        proof_inputs: Option<String>,
        // /// The path to the full proof public inputs
        // /// (see `examples/circuit/proof_inputs.json` for an example).
        // #[arg(short, long)]
        // inputs_path: Option<String>,

        // /// The path to the full proof.
        // /// (see `examples/circuit/proof.json` for an example).
        // #[arg(short, long)]
        // proof_path: String,
    },

    /// Generates an MPC committee via a trusted dealer.
    /// Ideally this is just used for testing as it is more secure to do a DKG.
    GenerateCommittee {
        /// Number of nodes in the committee.
        #[arg(short, long)]
        num: u16,

        /// Minimum number of committee member required for a signature.
        #[arg(short, long)]
        threshold: u16,

        /// Output directory to write the committee configuration files to.
        #[arg(short, long)]
        output_dir: String,
    },

    /// Starts an MPC node given a configuration
    StartCommitteeNode {
        /// The wallet name of the RPC full node.
        #[arg(env = "RPC_WALLET")]
        rpc_wallet: Option<String>,

        /// The `http(s)://address:port`` of the RPC full node.
        #[arg(env = "RPC_ADDRESS")]
        rpc_address: Option<String>,

        /// The `user:password`` of the RPC full node.
        #[arg(env = "RPC_AUTH")]
        rpc_auth: Option<String>,

        /// The address to run the node on.
        #[arg(short, long)]
        address: Option<String>,

        #[arg(short, long)]
        key_path: String,

        #[arg(short, long)]
        publickey_package_path: String,
    },

    /// Starts an orchestrator
    StartOrchestrator {
        /// The wallet name of the RPC full node.
        #[arg(env = "RPC_WALLET")]
        rpc_wallet: Option<String>,

        /// The `http(s)://address:port` of the RPC full node.
        #[arg(env = "RPC_ADDRESS")]
        rpc_address: Option<String>,

        /// The `user:password` of the RPC full node.
        #[arg(env = "RPC_AUTH")]
        rpc_auth: Option<String>,

        #[arg(short, long)]
        publickey_package_path: String,

        #[arg(short, long)]
        committee_cfg_path: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // init log
    env_logger::init();

    // debug info
    println!(
        "zkbitcoin_address: {}",
        taproot_addr_from(ZKBITCOIN_PUBKEY).unwrap().to_string()
    );
    println!(
        "zkbitcoin_fund_address: {}",
        taproot_addr_from(ZKBITCOIN_FEE_PUBKEY).unwrap().to_string()
    );

    // parse CLI
    let cli = Cli::parse();
    match &cli.command {
        // Alice's command
        Commands::DeployTransaction {
            wallet,
            address,
            auth,
            circom_circuit_path,
            initial_state,
            satoshi_amount,
        } => {
            let ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                wallet.clone(),
                address.clone(),
                auth.clone(),
            );

            let circom_circuit_path = env::current_dir()?.join(circom_circuit_path);

            // compile to get VK (and its digest)
            let (vk, vk_hash) = {
                let tmp_dir = TempDir::new("zkbitcoin_").context("couldn't create tmp dir")?;
                let CompilationResult {
                    verifier_key,
                    circuit_r1cs_path: _,
                    prover_key_path: _,
                } = snarkjs::compile(&tmp_dir, &circom_circuit_path).await?;

                // verifier_key

                // // open vk file
                // let full_path = PathBuf::from(verifier_key_path);
                // let file = std::fs::File::open(full_path).expect("file not found");
                // let vk: plonk::VerifierKey =
                //     serde_json::from_reader(file).expect("error while reading file");

                // hash
                let vk_hash = verifier_key.hash();

                (verifier_key, vk_hash)
            };

            // let mut public_inputs = vec![];
            // if let Some(path) = public_inputs_path {
            //     // open public_inputs file
            //     let full_path = PathBuf::from(path);
            //     let file = std::fs::File::open(&full_path)
            //         .unwrap_or_else(|_| panic!("file not found at path: {:?}", full_path));

            //     // recursively extract all strings from object
            //     fn recover_all_strings(acc: &mut Vec<String>, value: serde_json::Value) {
            //         match value {
            //             serde_json::Value::String(s) => acc.push(s),
            //             serde_json::Value::Array(arr) => {
            //                 for v in arr {
            //                     recover_all_strings(acc, v);
            //                 }
            //             }
            //             serde_json::Value::Object(obj) => {
            //                 for (_, v) in obj {
            //                     recover_all_strings(acc, v);
            //                 }
            //             }
            //             _ => (),
            //         }
            //     }
            //     let root: serde_json::Value =
            //         serde_json::from_reader(file).expect("error while reading file");
            //     recover_all_strings(&mut public_inputs, root);
            // }

            // sanity check
            let num_public_inputs = vk.nPublic;
            ensure!(
                num_public_inputs > 0,
                "the circuit must have at least one public input (the txid)"
            );

            // sanity check for stateful zkapps
            if num_public_inputs > 1 {
                let double_state_len = vk.nPublic - 3; /* txid, amount_in, amount_out */
                let state_len = double_state_len.checked_div(2).context("the VK")?;
                {
                    // TODO: does checked_div errors if its not a perfect division?
                    assert_eq!(state_len * 2, double_state_len);
                }

                // for now we only state of a single element
                ensure!(
                    state_len == 1,
                    "we only allow states of a single field element"
                );

                // check that the circuit makes sense for a stateful zkapp
                ensure!(num_public_inputs == 3 /* txid, amount_in, amount_out */ + state_len * 2, "the circuit passed does not expect the right number of public inputs for a stateful zkapp");

                // parse initial state
                ensure!(
                    initial_state.is_some(),
                    "an initial state should be passed for a stateful zkapp"
                );
            }

            // generate and broadcast deploy transaction
            let txid = generate_and_broadcast_transaction(
                &ctx,
                &vk_hash,
                initial_state.as_ref(),
                *satoshi_amount,
            )
            .await?;

            println!("txid: {}", txid);
        }

        // Bob's command
        Commands::UnlockFundsRequest {
            wallet,
            address,
            auth,
            orchestrator_address,
            txid,
            recipient_address,
            circom_circuit_path,
            proof_inputs,
        } => {
            let rpc_ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                wallet.clone(),
                address.clone(),
                auth.clone(),
            );

            // parse circom circuit path
            let circom_circuit_path = env::current_dir()?.join(circom_circuit_path);

            // parse proof inputs
            let proof_inputs: HashMap<String, Vec<String>> = if let Some(s) = &proof_inputs {
                serde_json::from_str(s)?
            } else {
                HashMap::new()
            };

            // parse Bob address
            let bob_address = Address::from_str(recipient_address)
                .unwrap()
                .require_network(get_network())
                .unwrap();

            // parse transaction ID
            let txid = Txid::from_str(txid)?;

            // create bob request
            let bob_request = BobRequest::new(
                &rpc_ctx,
                bob_address,
                txid,
                &circom_circuit_path,
                proof_inputs,
            )
            .await?;

            // send bob's request to the MPC committee.
            // TODO: we need a coordinator.
            let address = orchestrator_address
                .as_deref()
                .unwrap_or(ORCHESTRATOR_ADDRESS);
            let bob_response = send_bob_request(address, bob_request)
                .await
                .context("error while sending request to orchestrator")?;

            println!("{:?}", bob_response);

            // sign it
            let (signed_tx_hex, _signed_tx) = sign_transaction(
                &rpc_ctx,
                TransactionOrHex::Transaction(&bob_response.unlocked_tx),
            )
            .await?;

            // broadcast transaction
            let txid = send_raw_transaction(&rpc_ctx, TransactionOrHex::Hex(signed_tx_hex)).await?;

            // print useful msg
            println!("- txid broadcast to the network: {txid}");
            println!("- on an explorer: https://blockstream.info/testnet/tx/{txid}");
        }

        Commands::GenerateCommittee {
            num,
            threshold,
            output_dir,
        } => {
            let output_dir = PathBuf::from(output_dir);

            // deal until we get a public key starting with 0x02
            let (mut key_packages, mut pubkey_package) =
                frost::gen_frost_keys(*num, *threshold).unwrap();
            let mut pubkey = pubkey_package.verifying_key().to_owned();
            loop {
                if pubkey.serialize()[0] == 2 {
                    break;
                }
                (key_packages, pubkey_package) = frost::gen_frost_keys(*num, *threshold).unwrap();
                pubkey = pubkey_package.verifying_key().to_owned();
            }

            // all key packages
            {
                for (id, key_package) in key_packages.values().enumerate() {
                    let filename = format!("key-{id}.json");

                    let path = output_dir.join(filename);
                    let file = std::fs::File::create(&path)
                        .expect("couldn't create file given output dir");
                    serde_json::to_writer_pretty(file, key_package).unwrap();
                }
            }

            // public key package
            {
                let path = output_dir.join("publickey-package.json");
                let file =
                    std::fs::File::create(&path).expect("couldn't create file given output dir");
                serde_json::to_writer_pretty(file, &pubkey_package).unwrap();
            }

            // create the committee-cfg.json file
            {
                let ip = "http://127.0.0.1:889";
                let committee_cfg = CommitteeConfig {
                    threshold: *threshold as usize,
                    members: key_packages
                        .iter()
                        .enumerate()
                        .map(|(id, (member_id, _))| {
                            (
                                *member_id,
                                Member {
                                    address: format!("{}{}", ip, id),
                                },
                            )
                        })
                        .collect(),
                };
                let path = output_dir.join("committee-cfg.json");
                let file =
                    std::fs::File::create(&path).expect("couldn't create file given output dir");
                serde_json::to_writer_pretty(file, &committee_cfg).unwrap();
            }
        }

        Commands::StartCommitteeNode {
            rpc_wallet,
            rpc_address,
            rpc_auth,
            address,
            key_path,
            publickey_package_path,
        } => {
            let ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                rpc_wallet.clone(),
                rpc_address.clone(),
                rpc_auth.clone(),
            );

            let key_package = {
                let full_path = PathBuf::from(key_path);
                let file = std::fs::File::open(full_path).expect("file not found");
                let key: frost::KeyPackage =
                    serde_json::from_reader(file).expect("error while reading file");
                key
            };

            let pubkey_package = {
                let full_path = PathBuf::from(publickey_package_path);
                let file = std::fs::File::open(full_path).expect("file not found");
                let publickey_package: frost::PublicKeyPackage =
                    serde_json::from_reader(file).expect("error while reading file");
                publickey_package
            };

            zkbitcoin::committee::node::run_server(
                address.as_deref(),
                ctx,
                key_package,
                pubkey_package,
            )
            .await
            .unwrap();
        }

        Commands::StartOrchestrator {
            rpc_wallet,
            rpc_address,
            rpc_auth,
            publickey_package_path,
            committee_cfg_path,
        } => {
            let ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                rpc_wallet.clone(),
                rpc_address.clone(),
                rpc_auth.clone(),
            );

            let pubkey_package = {
                let full_path = PathBuf::from(publickey_package_path);
                let file = std::fs::File::open(full_path).expect("file not found");
                let publickey_package: frost::PublicKeyPackage =
                    serde_json::from_reader(file).expect("error while reading file");
                publickey_package
            };

            let committee_cfg = {
                let full_path = PathBuf::from(committee_cfg_path);
                let file = std::fs::File::open(full_path).expect("file not found");
                let publickey_package: CommitteeConfig =
                    serde_json::from_reader(file).expect("error while reading file");
                publickey_package
            };

            // sanity check (unfortunately the publickey_package doesn't contain this info)
            assert!(committee_cfg.threshold > 0);

            zkbitcoin::committee::orchestrator::run_server(
                Some(ORCHESTRATOR_ADDRESS),
                ctx,
                pubkey_package,
                committee_cfg,
            )
            .await
            .unwrap();
        }
    }

    Ok(())
}
