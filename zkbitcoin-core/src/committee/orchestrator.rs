use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use bitcoin::{
    hex::DisplayHex,
    key::{TapTweak, UntweakedPublicKey},
    secp256k1, taproot, TapSighashType, Witness,
};
use frost_secp256k1_tr::Ciphersuite;
use frost_secp256k1_tr::Group;
use futures::future::join_all;
use itertools::Itertools;
use jsonrpsee::{server::Server, RpcModule};
use jsonrpsee_core::RpcResult;
use jsonrpsee_types::{ErrorObjectOwned, Params};
use log::{debug, error, info, warn};
use rand::seq::SliceRandom;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::{
    bob_request::{BobRequest, BobResponse},
    committee::node::Round1Response,
    constants::{KEEPALIVE_MAX_RETRIES, KEEPALIVE_WAIT_SECONDS, ZKBITCOIN_PUBKEY},
    frost,
    json_rpc_stuff::{json_rpc_request, RpcCtx},
    mpc_sign_tx::get_digest_to_hash,
};

use super::node::{Round2Request, Round2Response};

//
// Orchestration logic
//

type RpcOrchestratorContext = Arc<(Orchestrator, Arc<RwLock<MemberStatusState>>)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeConfig {
    pub threshold: usize,
    // TODO: We could use a Vec instead of a HashMap for the members, since it would be more efficient.
    // We do not currently need hashmap functionality, but we might later, so left unchanged.
    pub members: HashMap<frost_secp256k1_tr::Identifier, Member>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum MemberStatus {
    Online,
    /// Disconnected members contain a tuple with the next connect retry time and the last retry number
    Disconnected((u64, u8)),
    /// Will no longer retry
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub online_members: Vec<frost_secp256k1_tr::Identifier>,
    pub offline_members: Vec<frost_secp256k1_tr::Identifier>,
}

// This will be the second part in the RpcModule context wrapped in a RwLock.
// I think this is better than including it in the actual CommitteeConfig since handlers will need
// to wait for a read lock every time an rpc handler needs to access the config.
// This way, handlers will only wait for read locks when they need the status of the members.
pub struct MemberStatusState {
    pub key_to_addr: HashMap<frost_secp256k1_tr::Identifier, String>,
    pub status: HashMap<frost_secp256k1_tr::Identifier, MemberStatus>,
}

impl MemberStatusState {
    pub async fn new(config: &CommitteeConfig) -> Self {
        let mut key_to_addr = HashMap::new();
        let mut status = HashMap::new();
        let mut futures = Vec::with_capacity(config.members.len());

        for (key, member) in config.members.iter() {
            let _ = key_to_addr.insert(key.clone(), member.address.clone());
            futures.push((
                key.clone(),
                Self::check_alive(member.address.clone()),
                member.address.clone(),
            ));
        }

        for (key, future, address) in futures.into_iter() {
            let new_status = if future.await == true {
                info!("{address} is online");
                MemberStatus::Online
            } else {
                let delay = Self::get_next_fibonacci_backoff_delay(0);
                warn!(
                    "{address} is offline. Re-trying in {delay} seconds... (1/{KEEPALIVE_MAX_RETRIES})"
                );
                MemberStatus::Disconnected((Self::get_current_time_secs() + delay, 1))
            };

            let _ = status.insert(key, new_status);
        }

        Self {
            key_to_addr,
            status,
        }
    }

    pub fn get_member_status(&self, key: &frost_secp256k1_tr::Identifier) -> MemberStatus {
        *self.status.get(key).unwrap()
    }

    pub fn mark_as_disconnected(&mut self, key: &frost_secp256k1_tr::Identifier) {
        let m_status = self.status.get_mut(key).unwrap();
        *m_status = MemberStatus::Disconnected((
            Self::get_current_time_secs() + Self::get_next_fibonacci_backoff_delay(0),
            1,
        ))
    }

    pub fn mark_as_offline(&mut self, key: &frost_secp256k1_tr::Identifier) {
        let m_status = self.status.get_mut(key).unwrap();
        *m_status = MemberStatus::Offline;
    }

    pub fn get_status(
        &self,
    ) -> (
        Vec<frost_secp256k1_tr::Identifier>,
        Vec<frost_secp256k1_tr::Identifier>,
    ) {
        let mut online = Vec::new();
        let mut offline = Vec::new();

        for (member, status) in self.status.iter() {
            match *status {
                MemberStatus::Online => online.push(member.clone()),
                MemberStatus::Offline | MemberStatus::Disconnected(_) => {
                    offline.push(member.clone())
                }
            };
        }

        (online, offline)
    }

    fn get_current_time_secs() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn fib(n: u64) -> u64 {
        if n <= 0 {
            return 0;
        } else if n == 1 {
            return 1;
        } else {
            return Self::fib(n - 1) + Self::fib(n - 2);
        }
    }

    fn get_next_fibonacci_backoff_delay(retry: u8) -> u64 {
        // Offset fib sequence by 5 to get better backoff times
        Self::fib(retry as u64 + 5)
    }

    async fn check_alive(address: String) -> bool {
        let data = Self::get_current_time_secs();
        let rpc_ctx = RpcCtx::new(Some("2.0"), None, Some(address.clone()), None, None);
        match json_rpc_request(
            &rpc_ctx,
            "ping",
            &[serde_json::value::to_raw_value(&data).unwrap()],
        )
        .await
        {
            Err(_) => false,
            Ok(resp_str) => {
                // Sanity check
                if let Ok(resp) =
                    serde_json::from_str::<bitcoincore_rpc::jsonrpc::Response>(&resp_str)
                {
                    if let Some(resp_data) = resp.result {
                        resp_data.get().parse::<u64>().unwrap_or_default() == data
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    pub async fn keepalive_thread(state: Arc<RwLock<Self>>) {
        debug!("Keepalive thread started");
        loop {
            // Sleep
            sleep(Duration::from_secs(KEEPALIVE_WAIT_SECONDS)).await;
            // Get array of members which are not *permanently* offline

            let members_to_check = {
                let r_lock = state.read().unwrap();
                r_lock
                    .key_to_addr
                    .iter()
                    .map(|(key, addr)| {
                        let status = r_lock.status.get(key).unwrap().clone();
                        (key.clone(), addr.clone(), status)
                    })
                    .filter(|(_, _, status)| match *status {
                        MemberStatus::Online => true,
                        MemberStatus::Disconnected((retry_time, _)) => {
                            retry_time <= Self::get_current_time_secs()
                        }
                        _ => false,
                    })
                    .collect::<Vec<(frost_secp256k1_tr::Identifier, String, MemberStatus)>>()
            };

            // check alive for each one of them
            let mut futures = Vec::with_capacity(members_to_check.len());
            for member_data in members_to_check.iter() {
                futures.push(Self::check_alive(member_data.1.clone()));
            }

            // resolve futures and update state
            let keepalive_resp = join_all(futures).await;
            for (idx, resp) in keepalive_resp.iter().enumerate() {
                let (key, address, old_status) = &members_to_check[idx];
                if *resp {
                    if *old_status != MemberStatus::Online {
                        let mut state_w = state.write().unwrap();
                        let member_status = state_w.status.get_mut(key).unwrap();
                        *member_status = MemberStatus::Online;
                        info!("{address} is back online");
                    } else {
                        debug!("{address} is online");
                    }
                } else {
                    let mut state_w = state.write().unwrap();
                    let member_status = state_w.status.get_mut(key).unwrap();
                    let last_retries = match old_status {
                        MemberStatus::Disconnected((_, last_retry_number)) => *last_retry_number,
                        _ => 0,
                    };

                    if last_retries > KEEPALIVE_MAX_RETRIES {
                        error!("{address} is offline. Will not retry connection");
                        *member_status = MemberStatus::Offline;
                    } else {
                        let new_retries = last_retries + 1;
                        let delay = Self::get_next_fibonacci_backoff_delay(new_retries);
                        warn!("{address} is offline. Re-trying in {delay} seconds... ({new_retries}/{KEEPALIVE_MAX_RETRIES})");
                        *member_status = MemberStatus::Disconnected((
                            Self::get_current_time_secs() + delay,
                            new_retries,
                        ));
                    }
                }
            }
        }
    }
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
    pub async fn handle_request(
        &self,
        bob_request: &BobRequest,
        member_status: Arc<RwLock<MemberStatusState>>,
    ) -> Result<BobResponse> {
        // Validate transaction before forwarding it, and get smart contract
        let smart_contract = bob_request.validate_request().await?;

        // TODO: we might want to check that the zkapp/UTXO is unspent here, but this requires us to have access to a bitcoin node, so for now we don't do it :o)

        'retry: loop {
            //
            // Round 1
            //

            let mut commitments_map = BTreeMap::new();

            let mut available_members = {
                let ms_r = member_status.read().unwrap();
                self.committee_cfg
                    .members
                    .iter()
                    .filter(|(key, _)| ms_r.get_member_status(key) == MemberStatus::Online)
                    .collect_vec()
            };
            if available_members.len() < self.committee_cfg.threshold {
                return Err(anyhow::Error::msg("not enough available signers"));
            }

            available_members.shuffle(&mut rand::thread_rng());
            available_members.truncate(self.committee_cfg.threshold);

            let futures = available_members
                .iter()
                .map(|(_, member)| async {
                    let rpc_ctx =
                        RpcCtx::new(Some("2.0"), None, Some(member.address.clone()), None, None);
                    json_rpc_request(
                        &rpc_ctx,
                        "round_1_signing",
                        &[serde_json::value::to_raw_value(&bob_request).unwrap()],
                    )
                    .await
                })
                .collect_vec();

            let round_1_responses = join_all(futures).await;

            for (idx, resp) in round_1_responses.into_iter().enumerate() {
                let (member_id, member) = available_members[idx];
                debug!("resp to 1st request from {:?}: {:?}", member_id, resp);
                let resp = match resp {
                    Ok(x) => x,
                    Err(rpc_error) => {
                        warn!("Round 1 error with {}, marking as disconnected and retrying round 1: {rpc_error}", member.address);
                        let mut ms_w = member_status.write().unwrap();
                        ms_w.mark_as_disconnected(member_id);
                        continue 'retry;
                    }
                };

                let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&resp)?;
                let resp: Round1Response = response.result()?;

                // store the commitment
                commitments_map.insert(*member_id, resp.commitments);
            }

            //
            // Produce transaction and digest
            //
            let message =
                get_digest_to_hash(&bob_request.prev_outs, &bob_request.tx, &smart_contract)?;

            //
            // Round 2
            //

            let mut signature_shares = BTreeMap::new();

            let round2_request = Round2Request {
                txid: bob_request.txid()?,
                proof_hash: bob_request.proof.hash(),
                commitments_map: commitments_map.clone(),
                message,
            };

            let futures = available_members
                .iter()
                .map(|(_, member)| async {
                    let rpc_ctx =
                        RpcCtx::new(Some("2.0"), None, Some(member.address.clone()), None, None);
                    json_rpc_request(
                        &rpc_ctx,
                        "round_2_signing",
                        &[serde_json::value::to_raw_value(&round2_request)?],
                    )
                    .await
                })
                .collect_vec();

            let round_2_responses = join_all(futures).await;

            for (idx, resp) in round_2_responses.into_iter().enumerate() {
                let (member_id, member) = available_members[idx];
                debug!("resp to 2nd request from {:?}: {:?}", member_id, resp);
                let resp = match resp {
                    Ok(x) => x,
                    Err(rpc_error) => {
                        warn!("Round 2 error with {}, marking as offline and retrying from round 1: {rpc_error}", member.address);
                        let mut ms_w = member_status.write().unwrap();
                        ms_w.mark_as_offline(member_id);
                        continue 'retry;
                    }
                };

                let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&resp)?;
                let round2_response: Round2Response = response.result()?;

                // store the commitment
                signature_shares.insert(*member_id, round2_response.signature_share);
            }

            //
            // Aggregate signatures
            //

            debug!("- aggregate signature shares");
            let signing_package =
                frost_secp256k1_tr::SigningPackage::new(commitments_map, &message);
            let group_signature = {
                let res = frost_secp256k1_tr::aggregate(
                    &signing_package,
                    &signature_shares,
                    &self.pubkey_package,
                );
                if let Some(err) = res.err() {
                    error!("error: {}", err);
                }
                res.context("failed to aggregate signatures")?
            };

            #[cfg(debug_assertions)]
            {
                // verify using FROST
                let group_pubkey = self.pubkey_package.verifying_key();
                assert!(group_pubkey.verify(&message, &group_signature).is_ok());
                debug!("- the signature verified locally with FROST lib");

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
                    debug!("tweaked: {}", tweaked);

                    // from FROST
                    let xone = XOnlyPublicKey::from_slice(&group_pubkey.serialize()[1..]).unwrap();
                    let (tweaked2, _) = xone.tap_tweak(&secp, None);
                    let tweaked2 = tweaked2.to_string();
                    debug!("tweaked2: {}", tweaked2);
                    assert_eq!(tweaked, tweaked2);

                    // twaked
                    let tweaked3 = frost_secp256k1_tr::Secp256K1Sha256::tweaked_public_key(
                        group_pubkey.element(),
                    );
                    let s = <frost_secp256k1_tr::Secp256K1Sha256 as Ciphersuite>::Group::serialize(
                        &tweaked3,
                    );
                    let tweaked3 = s.to_lower_hex_string();
                    debug!("tweaked3: {}", tweaked3);
                    //assert_eq!(tweaked2, tweaked3);
                }

                // verify using bitcoin lib
                let sig =
                    secp256k1::schnorr::Signature::from_slice(&group_signature.serialize()[1..])
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
            return Ok(BobResponse {
                unlocked_tx: transaction,
            });
        }
    }
}

//
// Server logic
//

/// Bob's request to unlock funds from a smart contract.
async fn unlock_funds(
    params: Params<'static>,
    context: RpcOrchestratorContext,
) -> RpcResult<BobResponse> {
    // get bob request
    let bob_request: [BobRequest; 1] = params.parse()?;
    let bob_request = &bob_request[0];
    info!("received request: {:?}", bob_request);

    let bob_response = context
        .0
        .handle_request(bob_request, context.1.clone())
        .await
        .map_err(|e| {
            ErrorObjectOwned::owned(
                jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
                "error while unlocking funds",
                Some(format!("the request didn't validate: {e}")),
            )
        })?;

    RpcResult::Ok(bob_response)
}

async fn get_nodes_status(
    _params: Params<'static>,
    context: RpcOrchestratorContext,
) -> RpcResult<StatusResponse> {
    let (online, offline) = {
        let mss_r = context.1.read().unwrap();
        mss_r.get_status()
    };

    RpcResult::Ok(StatusResponse {
        online_members: online,
        offline_members: offline,
    })
}

pub async fn run_server(
    address: Option<&str>,
    pubkey_package: frost::PublicKeyPackage,
    committee_cfg: CommitteeConfig,
) -> Result<SocketAddr> {
    let address = address.unwrap_or("127.0.0.1:6666");
    info!("- starting orchestrator at address http://{address}");

    let member_status_state = Arc::new(RwLock::new(MemberStatusState::new(&committee_cfg).await));
    let mss_thread_copy = member_status_state.clone();
    tokio::spawn(async move { MemberStatusState::keepalive_thread(mss_thread_copy).await });

    let ctx = (
        Orchestrator {
            pubkey_package,
            committee_cfg,
        },
        member_status_state.clone(),
    );

    let server = Server::builder()
        .build(address.parse::<SocketAddr>()?)
        .await?;
    let mut module = RpcModule::new(ctx);
    module.register_async_method("unlock_funds", unlock_funds)?;
    module.register_async_method("status", get_nodes_status)?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    handle.stopped().await;

    Ok(addr)
}
