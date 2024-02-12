use anyhow::{ensure, Context, Result};
use bitcoin::{Address, Txid};
use clap::{Parser, Subcommand};
use log::info;
use std::{collections::HashMap, env, path::PathBuf, str::FromStr};
use tempdir::TempDir;
use zkbitcoin::{
    alice_sign_tx::generate_and_broadcast_transaction,
    bob_request::{fetch_smart_contract, send_bob_request, BobRequest},
    constants::{
        BITCOIN_JSON_RPC_VERSION, ORCHESTRATOR_ADDRESS, ZKBITCOIN_FEE_PUBKEY, ZKBITCOIN_PUBKEY,
    },
    get_network,
    json_rpc_stuff::{
        scan_txout_set, send_raw_transaction, sign_transaction, RpcCtx, TransactionOrHex,
    },
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

        /// The path to the srs file
        #[arg(short, long)]
        srs_path: PathBuf,

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

        /// The path to the srs file
        #[arg(short, long)]
        srs_path: PathBuf,

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
        // Alice's command
        Commands::DeployZkapp {
            wallet,
            address,
            auth,
            circom_circuit_path,
            initial_state,
            satoshi_amount,
            srs_path,
        } => {
            let ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                wallet.clone(),
                address.clone(),
                auth.clone(),
                None,
            );

            let circom_circuit_path = env::current_dir()?.join(circom_circuit_path);

            // compile to get VK (and its digest)
            let (vk, vk_hash) = {
                let tmp_dir = TempDir::new("zkbitcoin_").context("couldn't create tmp dir")?;
                let CompilationResult {
                    verifier_key,
                    circuit_r1cs_path: _,
                    prover_key_path: _,
                } = snarkjs::compile(&tmp_dir, &circom_circuit_path, srs_path).await?;
                let vk_hash = verifier_key.hash();
                (verifier_key, vk_hash)
            };

            // sanity check
            let num_public_inputs = vk.nPublic;
            ensure!(
                num_public_inputs > 0,
                "the circuit must have at least one public input (the txid)"
            );

            info!(
                "deploying circuit {} with {num_public_inputs} public inputs",
                hex::encode(vk_hash)
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

            info!("- txid broadcast to the network: {txid}");
            info!("- on an explorer: https://blockstream.info/testnet/tx/{txid}");
        }

        // Bob's command
        Commands::UseZkapp {
            wallet,
            address,
            auth,
            orchestrator_address,
            txid,
            recipient_address,
            circom_circuit_path,
            srs_path,
            proof_inputs,
        } => {
            let rpc_ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                wallet.clone(),
                address.clone(),
                auth.clone(),
                None,
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
                srs_path,
                proof_inputs,
            )
            .await?;

            // send bob's request to the orchestartor.
            let address = orchestrator_address
                .as_deref()
                .unwrap_or(ORCHESTRATOR_ADDRESS);
            let bob_response = send_bob_request(address, bob_request)
                .await
                .context("error while sending request to orchestrator")?;

            // sign it
            let (signed_tx_hex, _signed_tx) = sign_transaction(
                &rpc_ctx,
                TransactionOrHex::Transaction(&bob_response.unlocked_tx),
            )
            .await?;

            // broadcast transaction
            let txid = send_raw_transaction(&rpc_ctx, TransactionOrHex::Hex(signed_tx_hex)).await?;

            // print useful msg
            info!("- txid broadcast to the network: {txid}");
            info!("- on an explorer: https://blockstream.info/testnet/tx/{txid}");
        }

        Commands::GetZkapp {
            wallet,
            address,
            auth,
            txid,
        } => {
            let ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                wallet.clone(),
                address.clone(),
                auth.clone(),
                None,
            );

            // extract smart contract
            let zkapp = fetch_smart_contract(&ctx, Txid::from_str(txid)?).await?;

            println!("{zkapp}");
        }

        Commands::ListZkapps {
            wallet,
            address,
            auth,
        } => {
            let mut rpc_ctx = RpcCtx::new(
                Some(BITCOIN_JSON_RPC_VERSION),
                wallet.clone(),
                address.clone(),
                auth.clone(),
                None,
            );
            rpc_ctx.timeout = std::time::Duration::from_secs(20); // scan takes 13s from what I can see
            let zkbitcoin_addr = taproot_addr_from(ZKBITCOIN_PUBKEY).unwrap();
            let res = scan_txout_set(&rpc_ctx, &zkbitcoin_addr.to_string()).await?;
            for unspent in &res.unspents {
                let txid = unspent.txid;
                if let Ok(zkapp) = fetch_smart_contract(&rpc_ctx, txid).await {
                    println!("{zkapp}");
                }
            }
        }
    }

    Ok(())
}
