use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Deploy a zkapp on Bitcoin.
    DeployZkapp {
        /// The wallet name of the RPC full node.
        #[arg(env = "RPC_WALLET")]
        wallet: Option<String>,

        /// The `http(s)://address:port`` of the RPC full node.
        #[arg(env = "RPC_ADDRESS")]
        address: Option<String>,

        /// The `user:password`` of the RPC full node.
        #[arg(env = "RPC_AUTH")]
        auth: Option<String>,

        /// The path to the Circom circuit to deploy.
        #[arg(short, long)]
        circom_circuit_path: PathBuf,

        /// Optionally, an initial state for stateful zkapps.
        #[arg(short, long)]
        initial_state: Option<String>,

        /// The amount in satoshis to send to the zkapp.
        #[arg(short, long)]
        satoshi_amount: u64,
    },

    /// Use a zkapp on Bitcoin.
    UseZkapp {
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

        /// The transaction ID that deployed the zkapp.
        #[arg(short, long)]
        txid: String,

        /// The address of the recipient.
        #[arg(short, long)]
        recipient_address: String,

        /// The path to the circom circuit to use.
        #[arg(short, long)]
        circom_circuit_path: PathBuf,

        /// A JSON string of the proof inputs.
        /// For stateful zkapps, we expect at least `amount_in` and `amount_out`.
        #[arg(short, long)]
        proof_inputs: Option<String>,
    },

    /// Check the status of a zkapp on Bitcoin.
    GetZkapp {
        /// The transaction ID that deployed the zkapp.
        #[arg(required = true)]
        txid: String,

        /// The wallet name of the RPC full node.
        #[arg(env = "RPC_WALLET")]
        wallet: Option<String>,

        /// The `http(s)://address:port`` of the RPC full node.
        #[arg(env = "RPC_ADDRESS")]
        address: Option<String>,

        /// The `user:password`` of the RPC full node.
        #[arg(env = "RPC_AUTH")]
        auth: Option<String>,
    },

    /// Get list of deployed zkapps on Bitcoin.
    ListZkapps {
        /// The wallet name of the RPC full node.
        #[arg(env = "RPC_WALLET")]
        wallet: Option<String>,

        /// The `http(s)://address:port`` of the RPC full node.
        #[arg(env = "RPC_ADDRESS")]
        address: Option<String>,

        /// The `user:password`` of the RPC full node.
        #[arg(env = "RPC_AUTH")]
        auth: Option<String>,
    }
}
