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
    secp256k1, taproot, TapSighashType, Witness,
};

use frost_secp256k1_tr::Ciphersuite;
use frost_secp256k1_tr::Group;
use itertools::Itertools;
use jsonrpsee::{server::Server, RpcModule};
use jsonrpsee_core::RpcResult;
use jsonrpsee_types::{ErrorObjectOwned, Params};
use log::{debug, error, info};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    bob_request::{BobRequest, BobResponse},
    committee::node::Round1Response,
    constants::ZKBITCOIN_PUBKEY,
    frost,
    json_rpc_stuff::{json_rpc_request, RpcCtx},
    mpc_sign_tx::get_digest_to_hash,
};

use super::node::{Round2Request, Round2Response};

use futures::future::{join_all, try_join_all};
use rand::seq::SliceRandom;
use rand::thread_rng;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tokio_stream::StreamExt as _;

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
    pub pubkey_package: frost_secp256k1_tr::keys::PublicKeyPackage,
    pub committee_cfg: CommitteeConfig,
}

impl Orchestrator {
    pub fn new(
        pubkey_package: frost_secp256k1_tr::keys::PublicKeyPackage,
        committee_cfg: CommitteeConfig,
    ) -> Self {
        Self {
            pubkey_package,
            committee_cfg,
        }
    }

    /// Handles bob request from A to Z.
    pub async fn handle_request(&self, bob_request: &BobRequest) -> Result<BobResponse> {
        // Validate transaction before forwarding it, and get smart contract
        let smart_contract = bob_request.validate_request().await?;

        // TODO: we might want to check that the zkapp/UTXO is unspent here, but this requires us to have access to a bitcoin node, so for now we don't do it :o)

        //
        // Round 1
        //

        // Round 1 - Randomly pick some members
        let results = Arc::new(Mutex::new(vec![]));
        let mut all_members = self.committee_cfg.members.iter().collect_vec();

        all_members.shuffle(&mut rand::thread_rng());

        // Take a random sample of members, up to the threshold
        let selected_members = all_members
            .choose_multiple(&mut rand::thread_rng(), self.committee_cfg.threshold)
            .cloned()
            .collect::<Vec<_>>();

        let mut stream = tokio_stream::iter(selected_members);

        // Sending requests to the selected members concurrently
        while let Some((member_id, member)) = stream.next().await {
            // stop now when reached enough responses
            {
                if results.lock().await.len() >= self.committee_cfg.threshold {
                    break;
                }
            }

            // send json RPC request
            let rpc_ctx = RpcCtx::new(Some("2.0"), None, Some(member.address.clone()), None, None);
            let round1_response = json_rpc_request(
                &rpc_ctx,
                "round_1_signing",
                &[serde_json::value::to_raw_value(&bob_request).unwrap()],
            )
            .await
            .and_then(|resp| {
                serde_json::from_str::<bitcoincore_rpc::jsonrpc::Response>(&resp)
                    .map_err(anyhow::Error::new)
            })
            .and_then(|parsed_resp| {
                parsed_resp
                    .result::<Round1Response>()
                    .map_err(anyhow::Error::new)
            });

            match round1_response {
                Ok(round1_actual_response) => {
                    // store the commitment
                    results.lock().await.push((
                        member_id,
                        member,
                        round1_actual_response.commitments,
                    ));
                }
                Err(err) => {
                    info!("Error: member {member_id:?} in round 1: {err}");
                    continue;
                }
            };
        }

        //
        // Produce transaction and digest
        //
        let message = get_digest_to_hash(&bob_request.prev_outs, &bob_request.tx, &smart_contract)?;
        let commitments_map: BTreeMap<_, _> = results
            .lock()
            .await
            .iter()
            .map(|(member_id, _, commitments)| ((*member_id).clone(), commitments.clone()))
            .collect();

        //
        // Round 2
        //
        let mut futures = Vec::new();

        // Preparing for round 2
        let round2_request = Round2Request {
            txid: bob_request.txid()?,
            proof_hash: bob_request.proof.hash(),
            commitments_map: commitments_map.clone(),
            message,
        };

        // Concurrently send round 2 requests
        for (member_id, member, _) in results.lock().await.iter() {
            let rpc_ctx = RpcCtx::new(Some("2.0"), None, Some(member.address.clone()), None, None);
            let round2_request_clone = round2_request.clone();
            let member_id_clone = member_id.clone();
            let future = async move {
                json_rpc_request(
                    &rpc_ctx,
                    "round_2_signing",
                    &[serde_json::value::to_raw_value(&round2_request_clone)?],
                )
                .await
                .and_then(|response| {
                    serde_json::from_str::<bitcoincore_rpc::jsonrpc::Response>(&response)
                        .map_err(anyhow::Error::new)
                })
                .and_then(|round2_response| {
                    round2_response
                        .result::<Round2Response>()
                        .map_err(anyhow::Error::new)
                })
                .map(|round2_results_response| {
                    (member_id_clone, round2_results_response.signature_share)
                })
            };
            futures.push(future);
        }

        // Wait for all futures to complete
        let results = join_all(futures).await;

        let mut signature_shares = BTreeMap::new();
        for result in results {
            match result {
                Ok((member_id, signature_share)) => {
                    signature_shares.insert(member_id.clone(), signature_share);
                }
                Err(e) => {
                    // Handle errors (e.g., log them)
                    error!("Error in round 2: {:?}", e);
                }
            }
        }

        //
        // Aggregate signatures
        //

        debug!("- aggregate signature shares");
        let signing_package = frost_secp256k1_tr::SigningPackage::new(commitments_map, &message);
        let group_signature = {
            let res = frost_secp256k1_tr::aggregate(
                &signing_package,
                &signature_shares,
                &self.pubkey_package,
            );
            if let Some(err) = res.err() {
                error!("Error: {}", err);
            }
            res.context("failed to aggregate signatures")?
        };

        #[cfg(debug_assertions)]
        {
            // verify using FROST
            let group_pubkey = self.pubkey_package.verifying_key();
            assert!(group_pubkey.verify(&message, &group_signature).is_ok());
            debug!("- the signature is verified locally with FROST lib");

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
                debug!("tweaked from hardcoded: {}", tweaked);

                // from FROST
                let xone = XOnlyPublicKey::from_slice(&group_pubkey.serialize()[1..]).unwrap();
                let (tweaked2, _) = xone.tap_tweak(&secp, None);
                let tweaked2 = tweaked2.to_string();
                debug!("tweaked2 from FROST: {}", tweaked2);
                assert_eq!(tweaked, tweaked2);

                // tweaked
                let tweaked3 =
                    frost_secp256k1_tr::Secp256K1Sha256::tweaked_public_key(group_pubkey.element());
                let s = <frost_secp256k1_tr::Secp256K1Sha256 as Ciphersuite>::Group::serialize(
                    &tweaked3,
                );
                let tweaked3 = s.to_lower_hex_string();
                debug!("tweaked3: {}", tweaked3);
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
            debug!("- the signature verified locally with bitcoin lib");
        }

        //
        // Include signature in the witness of the transaction
        //

        debug!("- include signature in witness of transaction");
        let serialized = group_signature.serialize();
        debug!("- serialized: {:?}", serialized);
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

        // return the signed transaction
        Ok(BobResponse {
            unlocked_tx: transaction,
        })
    }
}

//
// Server logic
//

/// Bob's request to unlock funds from a smart contract.
async fn unlock_funds(
    params: Params<'static>,
    context: Arc<Orchestrator>,
) -> RpcResult<BobResponse> {
    // get bob request
    let bob_request: [BobRequest; 1] = params.parse()?;
    let bob_request = &bob_request[0];
    info!("received request: {:?}", bob_request);

    let bob_response = context.handle_request(bob_request).await.map_err(|e| {
        ErrorObjectOwned::owned(
            jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
            "error while unlocking funds",
            Some(format!("the request didn't validate: {e}")),
        )
    })?;

    RpcResult::Ok(bob_response)
}

pub async fn run_server(
    address: Option<&str>,
    pubkey_package: frost::PublicKeyPackage,
    committee_cfg: CommitteeConfig,
) -> Result<SocketAddr> {
    let address = address.unwrap_or("127.0.0.1:6666");
    info!("- starting orchestrator at address http://{address}");

    let ctx = Orchestrator {
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
