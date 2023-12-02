use std::{path::PathBuf, str::FromStr};

use clap::{Parser, Subcommand};
use zkbitcoin::{
    alice_sign_tx::generate_and_broadcast_transaction, bob_request::send_bob_request,
    constants::BITCOIN_JSON_RPC_VERSION, frost, json_rpc_stuff::RpcCtx, plonk,
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

        /// The path to the verifier key in JSON format (see `examples/circuit/vk.json` for an example).
        #[arg(short, long)]
        verifier_key_path: String,

        /// The path to the public input (see `examples/circuit/public_inputs.json` for an example).
        /// We assume that the JSON object is correctly ordered (in the order that the Circom circuit expects).
        #[arg(short, long)]
        public_inputs_path: Option<String>,

        /// The amount in satoshis to send to the smart contract.
        #[arg(short, long)]
        satoshi_amount: u64,
    },

    /// Bob can use this to unlock funds from a smart contract.
    UnlockFundsRequest {
        /// The wallet name of the RPC full node.
        #[arg(env = "MPC_ADDRESS")]
        mpc_address: Option<String>,

        /// The transaction ID that deployed the smart contract.
        #[arg(short, long)]
        txid: String,

        /// The path to the verifier key in JSON format (see `examples/circuit/vk.json` for an example).
        #[arg(short, long)]
        verifier_key_path: String,

        /// The path to the full proof public inputs
        /// (see `examples/circuit/proof_inputs.json` for an example).
        #[arg(short, long)]
        inputs_path: Option<String>,

        /// The path to the full proof.
        /// (see `examples/circuit/proof.json` for an example).
        #[arg(short, long)]
        proof_path: String,
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
        wallet: Option<String>,

        /// The `http(s)://address:port`` of the RPC full node.
        #[arg(env = "RPC_ADDRESS")]
        address: Option<String>,

        /// The `user:password`` of the RPC full node.
        #[arg(env = "RPC_AUTH")]
        auth: Option<String>,

        #[arg(short, long)]
        key_path: String,

        #[arg(short, long)]
        publickey_package_path: String,
    },
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::DeployTransaction {
            wallet,
            address,
            auth,
            verifier_key_path,
            public_inputs_path,
            satoshi_amount,
        } => {
            let ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                wallet.clone(),
                address.clone(),
                auth.clone(),
            );

            let (vk, vk_hash) = {
                // open vk file
                let full_path = PathBuf::from(verifier_key_path);
                let file = std::fs::File::open(full_path).expect("file not found");
                let vk: plonk::VerifierKey =
                    serde_json::from_reader(file).expect("error while reading file");

                // hash
                let vk_hash = vk.hash();

                (vk, vk_hash)
            };

            // TODO: this doesn't seem like a very user friendly way to pass public inputs. What if I want to pass a and c, but not b? It seems like I'd have to pass an order as well... well we might change this design so this is good enough for now.
            let mut public_inputs = vec![];
            if let Some(path) = public_inputs_path {
                // open public_inputs file
                let full_path = PathBuf::from(path);
                let file = std::fs::File::open(&full_path)
                    .unwrap_or_else(|_| panic!("file not found at path: {:?}", full_path));

                // recursively extract all strings from object
                fn recover_all_strings(acc: &mut Vec<String>, value: serde_json::Value) {
                    match value {
                        serde_json::Value::String(s) => acc.push(s),
                        serde_json::Value::Array(arr) => {
                            for v in arr {
                                recover_all_strings(acc, v);
                            }
                        }
                        serde_json::Value::Object(obj) => {
                            for (_, v) in obj {
                                recover_all_strings(acc, v);
                            }
                        }
                        _ => (),
                    }
                }
                let root: serde_json::Value =
                    serde_json::from_reader(file).expect("error while reading file");
                recover_all_strings(&mut public_inputs, root);

                // sanity check
                if public_inputs.len() > vk.nPublic {
                    panic!(
                        "Too many public inputs! Expected {}, got {}",
                        vk.nPublic,
                        public_inputs.len()
                    );
                }
            }

            // generate and broadcast deploy transaction
            let txid =
                generate_and_broadcast_transaction(&ctx, &vk_hash, public_inputs, *satoshi_amount)
                    .await
                    .unwrap();

            println!("txid: {}", txid);
        }

        Commands::UnlockFundsRequest {
            mpc_address,
            txid,
            verifier_key_path,
            inputs_path,
            proof_path,
        } => {
            // get proof, vk, and inputs
            let proof: plonk::Proof = {
                let full_path = PathBuf::from(proof_path);
                let file = std::fs::File::open(&full_path)
                    .unwrap_or_else(|_| panic!("file not found at path: {:?}", full_path));
                serde_json::from_reader(file).expect("error while reading file")
            };
            let vk: plonk::VerifierKey = {
                let full_path = PathBuf::from(verifier_key_path);
                let file = std::fs::File::open(&full_path)
                    .unwrap_or_else(|_| panic!("file not found at path: {:?}", full_path));
                serde_json::from_reader(file).expect("error while reading file")
            };
            let public_inputs: Vec<String> = if let Some(path) = inputs_path {
                let full_path = PathBuf::from(path);
                let file = std::fs::File::open(&full_path)
                    .unwrap_or_else(|_| panic!("file not found at path: {:?}", full_path));
                let proof_inputs: plonk::ProofInputs =
                    serde_json::from_reader(file).expect("error while reading file");
                proof_inputs.0
            } else {
                vec![]
            };

            // create bob request
            let bob_request = zkbitcoin::bob_request::BobRequest {
                txid: bitcoin::Txid::from_str(txid).unwrap(),
                vk,
                proof,
                public_inputs: public_inputs,
            };

            // send bob's request to the MPC committee.
            // TODO: we need a coordinator.
            const MPC_ADDRESS: &str = "http://127.0.0.1:6666";
            let mpc_address = mpc_address.as_deref().unwrap_or(MPC_ADDRESS);
            let bob_response = send_bob_request(mpc_address, bob_request).await.unwrap();

            println!("{:?}", bob_response);
        }

        Commands::GenerateCommittee {
            num,
            threshold,
            output_dir,
        } => {
            let output_dir = PathBuf::from(output_dir);
            //            output_dir.is_relative();

            let (key_packages, pubkey_package) = frost::gen_frost_keys(*num, *threshold).unwrap();

            // all key packages
            for (id, key_package) in key_packages.values().enumerate() {
                let filename = format!("key-{id}.json");

                let path = output_dir.join(filename);
                let file =
                    std::fs::File::create(&path).expect("couldn't create file given output dir");
                serde_json::to_writer_pretty(file, key_package).unwrap();
            }

            // public key package
            let path = output_dir.join("publickey-package.json");
            let file = std::fs::File::create(&path).expect("couldn't create file given output dir");
            serde_json::to_writer_pretty(file, &pubkey_package).unwrap();
        }

        Commands::StartCommitteeNode {
            wallet,
            address,
            auth,
            key_path,
            publickey_package_path,
        } => {
            let ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                wallet.clone(),
                address.clone(),
                auth.clone(),
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

            zkbitcoin::committee::node::run_server(None, ctx, key_package, pubkey_package)
                .await
                .unwrap();
        }
    }
}
