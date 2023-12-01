use std::{env, path::PathBuf, str::FromStr};

use clap::{Parser, Subcommand};
use zkbitcoin::{alice_sign_tx::generate_and_broadcast_transaction, json_rpc_stuff::RpcCtx, plonk};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // /// Optional name to operate on
    // name: Option<String>,

    // /// Sets a custom config file
    // #[arg(short, long, value_name = "FILE")]
    // config: Option<PathBuf>,

    // /// Turn debugging information on
    // #[arg(short, long, action = clap::ArgAction::Count)]
    // debug: u8,
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

        /// The path to the verifier key in JSON format (see `circuit_example/vk.json` for an example).
        #[arg(short, long)]
        verifier_key_path: String,

        /// The path to the public input (see `circuit_example/public_inputs.json` for an example).
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

        /// The path to the verifier key in JSON format (see `circuit_example/vk.json` for an example).
        #[arg(short, long)]
        verifier_key_path: String,

        /// The path to the full proof public inputs
        /// (see `circuit_example/proof_inputs.json` for an example).
        #[arg(short, long)]
        proof_inputs_path: Option<String>,

        /// The path to the full proof.
        /// (see `circuit_example/proof.json` for an example).
        #[arg(short, long)]
        proof_path: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // You can check the value provided by positional arguments, or option arguments
    // if let Some(name) = cli.name.as_deref() {
    //     println!("Value for name: {name}");
    // }

    // if let Some(config_path) = cli.config.as_deref() {
    //     println!("Value for config: {}", config_path.display());
    // }

    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences
    // match cli.debug {
    //     0 => println!("Debug mode is off"),
    //     1 => println!("Debug mode is kind of on"),
    //     2 => println!("Debug mode is on"),
    //     _ => println!("Don't be crazy"),
    // }

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::DeployTransaction {
            wallet,
            address,
            auth,
            verifier_key_path,
            public_inputs_path,
            satoshi_amount,
        } => {
            let ctx = RpcCtx::new(wallet.clone(), address.clone(), auth.clone());

            let (vk, vk_hash) = {
                // open vk file
                let full_path = PathBuf::from(env::current_dir().unwrap()).join(verifier_key_path);
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
                let full_path = PathBuf::from(env::current_dir().unwrap()).join(path);
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
        }

        Commands::UnlockFundsRequest {
            mpc_address,
            txid,
            verifier_key_path,
            proof_inputs_path,
            proof_path,
        } => {
            let current_dir = PathBuf::from(env::current_dir().unwrap());
            // get proof, vk, and inputs
            let proof: plonk::Proof = {
                let full_path = current_dir.join(proof_path);
                let file = std::fs::File::open(&full_path)
                    .unwrap_or_else(|_| panic!("file not found at path: {:?}", full_path));
                serde_json::from_reader(file).expect("error while reading file")
            };
            let vk: plonk::VerifierKey = {
                let full_path = current_dir.join(verifier_key_path);
                let file = std::fs::File::open(&full_path)
                    .unwrap_or_else(|_| panic!("file not found at path: {:?}", full_path));
                serde_json::from_reader(file).expect("error while reading file")
            };
            let public_inputs: Vec<String> = if let Some(path) = proof_inputs_path {
                let full_path = current_dir.join(path);
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
            const MPC_ADDRESS: &str = "TODO";
            let mpc_address = mpc_address.as_deref().unwrap_or(MPC_ADDRESS);
            todo!();
        }
    }
}
