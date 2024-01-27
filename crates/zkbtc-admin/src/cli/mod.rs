use std::{collections::HashMap, env, path::PathBuf, str::FromStr};
use anyhow::{ensure, Context, Result};
use bitcoin::{Address, Txid};
use clap::{Parser, Subcommand};
use log::info;
use tempdir::TempDir;
use zkbitcoin::{
    alice_sign_tx::generate_and_broadcast_transaction,
    bob_request::{fetch_smart_contract, send_bob_request, BobRequest},
    committee::orchestrator::{CommitteeConfig, Member},
    constants::{
        BITCOIN_JSON_RPC_VERSION, ORCHESTRATOR_ADDRESS, ZKBITCOIN_FEE_PUBKEY, ZKBITCOIN_PUBKEY,
    },
    frost, get_network,
    json_rpc_stuff::{
        scan_txout_set, send_raw_transaction, sign_transaction, RpcCtx, TransactionOrHex,
    },
    snarkjs::{self, CompilationResult},
    taproot_addr_from,
};

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
        /// The address to run the node on.
        #[arg(short, long)]
        address: Option<String>,

        /// The path to the node's key package.
        #[arg(short, long)]
        key_path: String,

        /// The path to the MPC committee public key package.
        #[arg(short, long)]
        publickey_package_path: String,
    },

    /// Starts an orchestrator
    StartOrchestrator {
        /// The address to run the node on.
        #[arg(short, long)]
        address: Option<String>,

        #[arg(short, long)]
        publickey_package_path: String,

        #[arg(short, long)]
        committee_cfg_path: String,
    },
}
