use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result};
use bitcoin::{
    hex::DisplayHex,
    key::{TapTweak, UntweakedPublicKey},
    secp256k1, taproot, TapSighashType, Txid, Witness,
};
use frost_secp256k1_tr::Ciphersuite;
use frost_secp256k1_tr::Group;
use itertools::Itertools;
use jsonrpsee::{server::Server, RpcModule};
use jsonrpsee_core::RpcResult;
use jsonrpsee_types::{ErrorObjectOwned, Params};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    bob_request::BobRequest,
    committee::node::Round1Response,
    constants::ZKBITCOIN_PUBKEY,
    frost,
    json_rpc_stuff::{json_rpc_request, send_raw_transaction, RpcCtx, TransactionOrHex},
    mpc_sign_tx::get_digest_to_hash,
};

use super::node::{Round2Request, Round2Response};

//
// Orchestration logic
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeConfig {
    pub threshold: usize,
    pub members: HashMap<frost_secp256k1_tr::Identifier, Member>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    /// e.g. "127.0.0.1:8887"
    pub address: String,
}

pub struct Orchestrator {
    pub bitcoin_rpc_ctx: RpcCtx,
    pub pubkey_package: frost_secp256k1_tr::keys::PublicKeyPackage,
    pub committee_cfg: CommitteeConfig,
}

impl Orchestrator {
    pub fn new(
        bitcoin_rpc_ctx: RpcCtx,
        pubkey_package: frost_secp256k1_tr::keys::PublicKeyPackage,
        committee_cfg: CommitteeConfig,
    ) -> Self {
        Self {
            bitcoin_rpc_ctx,
            pubkey_package,
            committee_cfg,
        }
    }

    /// Handles bob request from A to Z.
    pub async fn handle_request(&self, bob_request: &BobRequest) -> Result<Txid> {
        //
        // Validate transaction before forwarding it, and get smart contract
        //

        let smart_contract = bob_request
            .validate_request(&self.bitcoin_rpc_ctx, None, bob_request.tx.txid())
            .await?;

        //
        // Round 1
        //

        let mut commitments_map = BTreeMap::new();

        // pick a threshold of members at random
        let threshold_of_members = self
            .committee_cfg
            .members
            .iter()
            .take(self.committee_cfg.threshold)
            .collect_vec();

        // TODO: do this concurrently with async
        // TODO: take a random sample instead of the first `threshold` members
        // TODO: what if we get a timeout or can't meet that threshold? loop? send to more members?
        for (member_id, member) in &threshold_of_members {
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
            .context("rpc request to committee didn't work");
            println!("{:?}", resp);
            let resp = resp?;

            let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&resp)?;
            let resp: Round1Response = response.result()?;

            // store the commitment
            commitments_map.insert(**member_id, resp.commitments.clone());
        }

        //
        // Produce transaction and digest
        //
        let message = get_digest_to_hash(&bob_request.tx, &smart_contract)?;

        //
        // Round 2
        //

        let mut signature_shares = BTreeMap::new();

        let round2_request = Round2Request {
            txid: bob_request.txid()?,
            proof_hash: bob_request.proof.hash(),
            commitments_map: commitments_map.clone(),
            message: message.clone(),
        };

        // TODO: do this concurrently with async
        // TODO: take a random sample instead of the first `threshold` members
        // TODO: what if we get a timeout or can't meet that threshold? loop? send to more members?
        for (member_id, member) in &threshold_of_members {
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
                &[serde_json::value::to_raw_value(&round2_request)?],
            )
            .await;
            println!("resp to 2nd request: {:?}", resp);

            let resp = resp.context("second rpc request to committee didn't work")?;

            let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&resp)?;
            let round2_response: Round2Response = response.result()?;

            // store the commitment
            signature_shares.insert(**member_id, round2_response.signature_share.clone());
        }

        //
        // Aggregate signatures
        //

        println!("- aggregate signature shares");
        let signing_package = frost_secp256k1_tr::SigningPackage::new(commitments_map, &message);
        let group_signature = {
            let res = frost_secp256k1_tr::aggregate(
                &signing_package,
                &signature_shares,
                &self.pubkey_package,
            );
            if let Some(err) = res.err() {
                println!("error: {}", err);
            }
            res.context("failed to aggregate signatures")?
        };

        #[cfg(debug_assertions)]
        {
            // verify using FROST
            let group_pubkey = self.pubkey_package.verifying_key();
            assert!(group_pubkey.verify(&message, &group_signature).is_ok());
            println!("- the signature verified locally with FROST lib");

            // assert that the pubkey is the same
            let deserialized_pubkey =
                bitcoin::PublicKey::from_slice(&group_pubkey.serialize()).unwrap();
            let zkbitcoin_pubkey: bitcoin::PublicKey =
                bitcoin::PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
            assert_eq!(deserialized_pubkey, zkbitcoin_pubkey);

            // let's compare pubkeys
            {
                // from hardcoded
                let secp = secp256k1::Secp256k1::default();
                let zkbitcoin_pubkey: bitcoin::PublicKey =
                    bitcoin::PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
                let internal_key = UntweakedPublicKey::from(zkbitcoin_pubkey);
                let (tweaked, _) = internal_key.tap_tweak(&secp, None);
                let tweaked = tweaked.to_string();
                println!("tweaked: {}", tweaked);

                // from FROST
                let xone = XOnlyPublicKey::from_slice(&group_pubkey.serialize()[1..]).unwrap();
                let (tweaked2, _) = xone.tap_tweak(&secp, None);
                let tweaked2 = tweaked2.to_string();
                println!("tweaked2: {}", tweaked2);
                assert_eq!(tweaked, tweaked2);

                // twaked
                let tweaked3 =
                    frost_secp256k1_tr::Secp256K1Sha256::tweaked_public_key(group_pubkey.element());
                let s = <frost_secp256k1_tr::Secp256K1Sha256 as Ciphersuite>::Group::serialize(
                    &tweaked3,
                );
                let tweaked3 = s.to_lower_hex_string();
                println!("tweaked3: {}", tweaked3);
                //assert_eq!(tweaked2, tweaked3);
            }

            // verify using bitcoin lib
            let sig = secp256k1::schnorr::Signature::from_slice(&group_signature.serialize()[1..])
                .unwrap();
            let zkbitcoin_pubkey: bitcoin::PublicKey =
                bitcoin::PublicKey::from_str(ZKBITCOIN_PUBKEY).unwrap();
            let internal_key = UntweakedPublicKey::from(zkbitcoin_pubkey);
            let secp = secp256k1::Secp256k1::default();
            let (tweaked, _) = internal_key.tap_tweak(&secp, None);
            let msg = secp256k1::Message::from_digest(message);
            assert!(secp.verify_schnorr(&sig, &msg, &tweaked.into()).is_ok());
            println!("- the signature verified locally with bitcoin lib");
        }

        //
        // Include signature in the witness of the transaction
        //

        println!("- include signature in witness of transaction");
        let serialized = group_signature.serialize();
        println!("- serialized: {:?}", serialized);
        let sig = secp256k1::schnorr::Signature::from_slice(&serialized[1..])
            .context("couldn't convert signature type")?;

        let hash_ty = TapSighashType::All;
        let final_signature = taproot::Signature { sig, hash_ty };
        let mut witness = Witness::new();
        witness.push(final_signature.to_vec());

        let mut transaction = bob_request.tx.clone();
        transaction
            .input
            .get_mut(bob_request.zkapp_input)
            .context("couldn't find zkapp input in transaction")?
            .witness = witness;

        //
        // Broadcast transaction
        //

        println!("- attempting to broadcast transaction");
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
) -> Result<SocketAddr> {
    let address = address.unwrap_or("127.0.0.1:6666");
    println!("- starting orchestrator at address http://{address}");

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
