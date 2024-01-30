use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use zkbitcoin::{
    committee::orchestrator::{CommitteeConfig, Member},
    constants::{
        ZKBITCOIN_FEE_PUBKEY, ZKBITCOIN_PUBKEY,
    },
    frost, taproot_addr_from,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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

#[tokio::main]
async fn main() -> Result<()> {
    // init default log level to info (unless RUST_LOG is set)
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // debug info
    info!(
        "- zkbitcoin_address: {}",
        taproot_addr_from(ZKBITCOIN_PUBKEY).unwrap().to_string()
    );
    info!(
        "- zkbitcoin_fund_address: {}",
        taproot_addr_from(ZKBITCOIN_FEE_PUBKEY).unwrap().to_string()
    );

    // parse CLI
    let cli = Cli::parse();
    match &cli.command {
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
                    std::fs::create_dir_all(path.clone().parent().unwrap())
                        .expect("Couldn't create directory");
                    let file = std::fs::File::create(&path)
                        .expect("couldn't create file given output dir");
                    serde_json::to_writer_pretty(file, key_package).unwrap();
                }
            }

            // public key package
            {
                let path = output_dir.join("publickey-package.json");
                let file =
                    std::fs::File::create(path).expect("couldn't create file given output dir");
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
                    std::fs::File::create(path).expect("couldn't create file given output dir");
                serde_json::to_writer_pretty(file, &committee_cfg).unwrap();
            }
        }

        Commands::StartCommitteeNode {
            address,
            key_path,
            publickey_package_path,
        } => {
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

            zkbitcoin::committee::node::run_server(address.as_deref(), key_package, pubkey_package)
                .await
                .unwrap();
        }

        Commands::StartOrchestrator {
            address,
            publickey_package_path,
            committee_cfg_path,
        } => {
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
                address.as_deref(),
                pubkey_package,
                committee_cfg,
            )
            .await
            .unwrap();
        }
    }

    Ok(())
}
