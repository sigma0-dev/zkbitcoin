use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::Arc,
};

use bitcoin::{taproot, TapSighashType, Txid, Witness};
use jsonrpsee::{server::Server, RpcModule};
use jsonrpsee_core::RpcResult;
use jsonrpsee_types::{ErrorObjectOwned, Params};
use serde::{Deserialize, Serialize};

use crate::{
    bob_request::{validate_request, BobRequest, BobResponse},
    constants::{FEE_BITCOIN_SAT, FEE_ZKBITCOIN_SAT},
    frost,
    json_rpc_stuff::{json_rpc_request, send_raw_transaction, RpcCtx, TransactionOrHex},
    mpc_sign_tx::{create_transaction, get_digest_to_hash},
};

use super::node::{Round2Request, Round2Response};

//
// Orchestration logic
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeConfig {
    pub threshold: usize,
    pub members: HashMap<frost_secp256k1::Identifier, Member>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    /// e.g. "127.0.0.1:8887"
    address: String,
}

pub struct Orchestrator {
    pub bitcoin_rpc_ctx: RpcCtx,
    pub pubkey_package: frost_secp256k1::keys::PublicKeyPackage,
    pub committee_cfg: CommitteeConfig,
}

impl Orchestrator {
    pub fn new(
        bitcoin_rpc_ctx: RpcCtx,
        pubkey_package: frost_secp256k1::keys::PublicKeyPackage,
        committee_cfg: CommitteeConfig,
    ) -> Self {
        Self {
            bitcoin_rpc_ctx,
            pubkey_package,
            committee_cfg,
        }
    }

    /// Handles bob request from A to Z.
    pub async fn handle_request(&self, bob_request: &BobRequest) -> Result<Txid, &'static str> {
        //
        // Validate transaction before forwarding it, and get smart contract
        //

        let smart_contract = validate_request(&self.bitcoin_rpc_ctx, &bob_request, None).await?;

        //
        // Round 1
        //

        let mut commitments_map = BTreeMap::new();

        // TODO: do this concurrently with async
        // TODO: take a random sample instead of the first `threshold` members
        // TODO: what if we get a timeout or can't meet that threshold? loop? send to more members?
        for (member_id, member) in self
            .committee_cfg
            .members
            .iter()
            .take(self.committee_cfg.threshold)
        {
            // send json RPC request
            let rpc_ctx = RpcCtx {
                version: Some("2.0"),
                wallet: None,
                address: Some(member.address.clone()),
                auth: None,
            };
            let resp = json_rpc_request(
                &rpc_ctx,
                "round_1_signing",
                &[serde_json::value::to_raw_value(&bob_request).unwrap()],
            )
            .await
            .map_err(|e| {
                println!("error: {e}");
                "unlock_funds error"
            })?;

            let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&resp).unwrap();
            let bob_response: BobResponse = response.result().unwrap();

            // store the commitment
            commitments_map.insert(*member_id, bob_response.commitments);
        }

        //
        // Round 2
        //

        let mut signature_shares = BTreeMap::new();

        let round2_request = Round2Request {
            txid: bob_request.txid,
            proof_hash: bob_request.proof.hash(),
            commitments_map: commitments_map.clone(),
        };

        // TODO: do this concurrently with async
        // TODO: take a random sample instead of the first `threshold` members
        // TODO: what if we get a timeout or can't meet that threshold? loop? send to more members?
        for (member_id, member) in self
            .committee_cfg
            .members
            .iter()
            .take(self.committee_cfg.threshold)
        {
            // send json RPC request
            let rpc_ctx = RpcCtx {
                version: Some("2.0"),
                wallet: None,
                address: Some(member.address.clone()),
                auth: None,
            };
            let resp = json_rpc_request(
                &rpc_ctx,
                "round_2_signing",
                &[serde_json::value::to_raw_value(&round2_request).unwrap()],
            )
            .await
            .map_err(|e| {
                println!("error: {e}");
                "unlock_funds error"
            })?;

            let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&resp).unwrap();
            let round2_response: Round2Response = response.result().unwrap();

            // store the commitment
            signature_shares.insert(*member_id, round2_response.signature_share);
        }

        //
        // Produce transaction and digest
        //

        let bob_address = bob_request.get_bob_address()?;
        let utxo = (bob_request.txid, smart_contract.vout_of_zkbitcoin_utxo);
        let mut transaction = create_transaction(
            utxo,
            smart_contract.locked_value,
            bob_address,
            FEE_BITCOIN_SAT,
            FEE_ZKBITCOIN_SAT,
        );
        let message = get_digest_to_hash(&transaction, &smart_contract);

        //
        // Aggregate signatures
        //

        let signing_package = frost_secp256k1::SigningPackage::new(commitments_map, &message);
        let group_signature =
            frost_secp256k1::aggregate(&signing_package, &signature_shares, &self.pubkey_package)
                .map_err(|_| "failed to aggregate signatures")?;

        //
        // Include signature in the witness of the transaction
        //
        let serialized = group_signature.serialize();
        println!("serialized: {:?}", serialized);
        let sig = secp256k1::schnorr::Signature::from_slice(&serialized)
            .map_err(|_| "couldn't convert signature type")?;

        let hash_ty = TapSighashType::All;
        let final_signature = taproot::Signature { sig, hash_ty };
        let mut witness = Witness::new();
        witness.push(final_signature.to_vec());
        transaction.input[0].witness = witness; // TODO: is it always the first input?

        //
        // Broadcast transaction
        //

        let txid = send_raw_transaction(
            &self.bitcoin_rpc_ctx,
            TransactionOrHex::Transaction(&transaction),
        )
        .await?;

        Ok(txid)
    }
}

//
// Server logic
//

/// Bob's request to unlock funds from a smart contract.
async fn unlock_funds(params: Params<'static>, context: Arc<Orchestrator>) -> RpcResult<Txid> {
    // get bob request
    let bob_request: [BobRequest; 1] = params.parse()?;
    let bob_request = &bob_request[0];
    println!("received request: {:?}", bob_request);

    let txid = context.handle_request(bob_request).await.map_err(|e| {
        ErrorObjectOwned::owned(
            jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
            "error while unlocking funds",
            Some(format!("the request didn't validate: {e}")),
        )
    })?;

    RpcResult::Ok(txid)
}

pub async fn run_server(
    address: Option<&str>,
    ctx: RpcCtx,
    pubkey_package: frost::PublicKeyPackage,
    committee_cfg: CommitteeConfig,
) -> anyhow::Result<SocketAddr> {
    let address = address.unwrap_or("127.0.0.1:6666");

    let ctx = Orchestrator {
        bitcoin_rpc_ctx: ctx,
        pubkey_package,
        committee_cfg,
    };

    let server = Server::builder()
        .build(address.parse::<SocketAddr>()?)
        .await?;
    let mut module = RpcModule::new(ctx);
    module.register_async_method("unlock_funds", unlock_funds)?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    handle.stopped().await;

    Ok(addr)
}
