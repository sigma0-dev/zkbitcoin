use std::path::PathBuf;

use clap::{Parser, Subcommand};
use zkbitcoin::{alice_sign_tx::generate_and_broadcast_transaction, json_rpc_stuff::RpcCtx};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Optional name to operate on
    name: Option<String>,

    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Alice can use this to deploy a circuit
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
        verifier_key: String,

        /// The path to the public input (see `circuit_example/public_inputs.json` for an example)
        #[arg(short, long)]
        public_inputs: Vec<String>,

        /// The amount in satoshis to send to the smart contract.
        #[arg(short, long)]
        satoshi_amount: u64,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // You can check the value provided by positional arguments, or option arguments
    if let Some(name) = cli.name.as_deref() {
        println!("Value for name: {name}");
    }

    if let Some(config_path) = cli.config.as_deref() {
        println!("Value for config: {}", config_path.display());
    }

    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences
    match cli.debug {
        0 => println!("Debug mode is off"),
        1 => println!("Debug mode is kind of on"),
        2 => println!("Debug mode is on"),
        _ => println!("Don't be crazy"),
    }

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Some(Commands::DeployTransaction {
            wallet,
            verifier_key,
            public_inputs,
            address,
            auth,
            satoshi_amount,
        }) => {
            let ctx = RpcCtx {
                wallet: wallet.clone(),
                address: address.clone(),
                auth: auth.clone(),
            };

            let vk_hash = todo!();
            let public_inputs = todo!();
            let txid =
                generate_and_broadcast_transaction(&ctx, vk_hash, public_inputs, *satoshi_amount)
                    .await
                    .unwrap();
        }
        None => {}
    }

    // Continued program logic goes here...
}
