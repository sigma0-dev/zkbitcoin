use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use bitcoin::{Transaction, TxOut, Txid};
use frost_secp256k1_tr::round1;
use jsonrpsee::{
    server::{RpcModule, Server},
    types::Params,
};
use jsonrpsee_core::RpcResult;
use jsonrpsee_types::ErrorObjectOwned;
use log::info;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::{
    bob_request::{BobRequest, SmartContract}, capped_hashmap::CappedHashMap, frost, mpc_sign_tx::get_digest_to_hash
};

//
// Data structures
//

/// State of a node.
pub struct NodeState {
    /// The secret key stuff they need.
    pub key_package: frost::KeyPackage,

    /// The public key stuff they need.
    pub pubkey_package: frost::PublicKeyPackage,

    // TODO: ensure that this cannot grow like crazy? prune old tasks?
    pub signing_tasks: RwLock<CappedHashMap<Txid, LocalSigningTask>>,
}

#[derive(Clone)]
pub struct LocalSigningTask {
    /// So we know if we're processing the same request twice.
    pub proof_hash: [u8; 32],
    /// The smart contract that locked the value.
    pub smart_contract: SmartContract,
    /// transaction to sign.
    pub tx: Transaction,
    /// The previous outputs that are being spent by the transaction (needed to sign).
    pub prev_outs: Vec<TxOut>,
    /// The nonces behind these commitments
    pub nonces: round1::SigningNonces,
    // TODO: should we keep track of commitments here also to double check?
}

//
// Methods
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1Response {
    pub commitments: frost_secp256k1_tr::round1::SigningCommitments,
}

/// Bob's request to unlock funds from a smart contract.
async fn round_1_signing(
    params: Params<'static>,
    context: Arc<NodeState>,
) -> RpcResult<Round1Response> {
    // get bob request
    let bob_request: [BobRequest; 1] = params.parse()?;
    let bob_request = &bob_request[0];
    info!("received request: {:?}", bob_request);

    // check if we already have a local signing task under that txid
    let txid = bob_request.txid().map_err(|e| {
        ErrorObjectOwned::owned(
            jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
            "couldn't get txid for zkapp in request",
            Some(format!("{e}")),
        )
    })?;

    // validate request
    let smart_contract = bob_request.validate_request().await.map_err(|err| {
        ErrorObjectOwned::owned(
            jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
            "the request didn't validate",
            Some(format!("{err}")),
        )
    })?;

    // round 1 of FROST
    let rng = &mut thread_rng();
    let (nonces, commitments) =
        frost_secp256k1_tr::round1::commit(context.key_package.signing_share(), rng);

    // store it locally
    {
        let mut signing_tasks = context.signing_tasks.write().unwrap();
        signing_tasks.insert(
            txid,
            LocalSigningTask {
                proof_hash: bob_request.proof.hash(),
                smart_contract,
                tx: bob_request.tx.clone(),
                nonces,
                prev_outs: bob_request.prev_outs.clone(),
            },
        );
    }

    // response
    let resp = Round1Response { commitments };
    RpcResult::Ok(resp)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round2Request {
    /// The txid that we're referring to.
    pub txid: Txid,

    /// Hash of the proof. Useful to make sure that we're signing the request/proof.
    pub proof_hash: [u8; 32],

    /// The FROST data needed by the MPC participants in the second round.
    pub commitments_map:
        BTreeMap<frost_secp256k1_tr::Identifier, frost_secp256k1_tr::round1::SigningCommitments>,

    /// Digest to hash.
    /// While not necessary as nodes will recompute it themselves, it is good to double check that everyone is on the same page.
    pub message: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round2Response {
    pub signature_share: frost_secp256k1_tr::round2::SignatureShare,
}

async fn round_2_signing(
    params: Params<'static>,
    context: Arc<NodeState>,
) -> RpcResult<Round2Response> {
    // get commitments from params
    let round2request: [Round2Request; 1] = params.parse()?;
    let round2request = &round2request[0];
    info!("received request: {:?}", round2request);

    // retrieve metadata for this task (and prune it)
    let LocalSigningTask {
        proof_hash: _,
        smart_contract,
        tx,
        nonces,
        prev_outs,
    } = {
        let mut signing_tasks = context.signing_tasks.write().unwrap();
        if let Some(local_signing_task) = signing_tasks.remove(&round2request.txid) {
            if local_signing_task.proof_hash != round2request.proof_hash {
                return RpcResult::Err(ErrorObjectOwned::owned(
                    jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
                    "proof hash doesn't match",
                    Some("proof hash doesn't match".to_string()),
                ));
            }

            local_signing_task.clone()
        } else {
            return RpcResult::Err(ErrorObjectOwned::owned(
                jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
                "no signing task found for this txid",
                Some("no signing task found for this txid".to_string()),
            ));
        }
    };

    // deterministically create transaction
    let message = get_digest_to_hash(&prev_outs, &tx, &smart_contract).map_err(|err| {
        ErrorObjectOwned::owned(
            jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
            "error while hashing",
            Some(format!("the request didn't validate: {err}")),
        )
    })?;

    // sanity check
    if round2request.message != message {
        return RpcResult::Err(ErrorObjectOwned::owned(
            jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
            "message doesn't match",
            Some("message doesn't match".to_string()),
        ));
    }

    // signing package should be recreated no? as we want to ensure that we agree on what is being signed (should be a deterministic process).
    let signing_package =
        frost_secp256k1_tr::SigningPackage::new(round2request.commitments_map.clone(), &message);
    let signature_share =
        frost_secp256k1_tr::round2::sign(&signing_package, &nonces, &context.key_package).map_err(
            |err| {
                ErrorObjectOwned::owned(
                    jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
                    "error while signing",
                    Some(format!("the request didn't validate: {err}")),
                )
            },
        )?;

    // return signature shares
    let round2_response = Round2Response { signature_share };
    RpcResult::Ok(round2_response)
}

async fn is_alive(params: Params<'static>, _context: Arc<NodeState>) -> RpcResult<u64> {
    Ok(params.parse::<[u64; 1]>()?[0].clone())
}

//
// Main server code
//

pub async fn run_server(
    address: Option<&str>,
    key_package: frost::KeyPackage,
    pubkey_package: frost::PublicKeyPackage,
) -> anyhow::Result<SocketAddr> {
    let address = address.unwrap_or("127.0.0.1:6666");
    info!(
        "- starting node for identifier {id:?} at address http://{address}",
        id = key_package.identifier()
    );

    let ctx = NodeState {
        key_package,
        pubkey_package,
        signing_tasks: RwLock::new(CappedHashMap::new()),
    };

    let server = Server::builder()
        .build(address.parse::<SocketAddr>()?)
        .await?;
    let mut module = RpcModule::new(ctx);

    module.register_async_method("round_1_signing", round_1_signing)?;
    module.register_async_method("round_2_signing", round_2_signing)?;
    module.register_async_method("ping", is_alive)?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    handle.stopped().await;

    Ok(addr)
}
