use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
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
