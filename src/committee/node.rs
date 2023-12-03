use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, RwLock},
};

use bitcoin::{
    sighash::{Prevouts, SighashCache},
    TapSighashType, Txid,
};
use jsonrpsee::{
    server::{RpcModule, Server},
    types::Params,
};
use jsonrpsee_core::RpcResult;
use jsonrpsee_types::ErrorObjectOwned;
use rand::thread_rng;
use secp256k1::hashes::Hash;
use serde::{Deserialize, Serialize};

use crate::{
    bob_request::{validate_request, BobRequest, BobResponse, SmartContract},
    constants::{FEE_BITCOIN_SAT, FEE_ZKBITCOIN_SAT},
    frost,
    json_rpc_stuff::RpcCtx,
    mpc_sign_tx::create_transaction,
};

//
// Data structures
//

/// State of a node.
pub struct Ctx {
    /// Data needed to communicate to their bitcoin node.
    pub bitcoin_rpc_ctx: RpcCtx,

    /// The secret key stuff they need.
    pub key_package: frost::KeyPackage,

    /// The public key stuff they need.
    pub pubkey_package: frost::PublicKeyPackage,

    // TODO: ensure that this cannot grow like crazy? prune old tasks?
    pub signing_tasks: RwLock<HashMap<Txid, LocalSigningTask>>,
}

#[derive(Clone)]
pub struct LocalSigningTask {
    /// So we know if we're processing the same request twice.
    pub proof_hash: [u8; 32],
    /// The smart contract that locked the value.
    pub smart_contract: SmartContract,
    /// Bob's address (taken from the first public input).
    pub bob_address: bitcoin::Address,
    /// The commitments we produced to start the signature (round 1).
    pub commitments: frost_secp256k1::round1::SigningCommitments,
    /// The nonces behind these commitments
    pub nonces: frost_secp256k1::round1::SigningNonces,
}

//
// Methods
//

/// Bob's request to unlock funds from a smart contract.
async fn round_1_signing(params: Params<'static>, context: Arc<Ctx>) -> RpcResult<BobResponse> {
    // get bob request
    let bob_request: [BobRequest; 1] = params.parse()?;
    let bob_request = &bob_request[0];
    println!("received request: {:?}", bob_request);

    // check if we already have a local signing task under that txid
    let smart_contract = {
        let mut signing_tasks = context.signing_tasks.write().unwrap();
        if let Some(local_signing_task) = signing_tasks.get(&bob_request.txid) {
            if local_signing_task.proof_hash == bob_request.proof.hash() {
                // we've already validated this proof and started round 1,
                // just return the cached commitments
                return RpcResult::Ok(BobResponse {
                    commitments: local_signing_task.commitments.clone(),
                });
            } else {
                // this is a new proof, so delete it and allow bob to replace his previous proof
                // TODO: is this sane?
                let smart_contract = signing_tasks
                    .remove(&bob_request.txid)
                    .unwrap()
                    .smart_contract;
                Some(smart_contract)
            }
        } else {
            None
        }
    };

    // get bob address from first public input (TODO: move this to validate_request?)
    let bob_address = bob_request.get_bob_address().map_err(|err| {
        ErrorObjectOwned::owned(
            jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
            "couldn't get bob address:",
            Some(format!("{err}")),
        )
    })?;

    // validate request
    let smart_contract =
        match validate_request(&context.bitcoin_rpc_ctx, &bob_request, smart_contract).await {
            Ok(x) => x,
            Err(err) => {
                return RpcResult::Err(ErrorObjectOwned::owned(
                    jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
                    err,
                    Some(format!("the request didn't validate: {err}")),
                ))
            }
        };

    // round 1 of FROST
    let rng = &mut thread_rng();
    let (nonces, commitments) =
        frost_secp256k1::round1::commit(context.key_package.signing_share(), rng);

    // store it locally
    {
        let mut signing_tasks = context.signing_tasks.write().unwrap();
        signing_tasks.insert(
            bob_request.txid,
            LocalSigningTask {
                proof_hash: bob_request.proof.hash(),
                smart_contract,
                bob_address,
                commitments: commitments.clone(),
                nonces,
            },
        );
    }

    // response
    let bob_response = BobResponse { commitments };
    RpcResult::Ok(bob_response)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round2Request {
    pub txid: Txid,
    pub proof_hash: [u8; 32],
    pub commitments_map:
        BTreeMap<frost_secp256k1::Identifier, frost_secp256k1::round1::SigningCommitments>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round2Response {
    pub signature_share: frost_secp256k1::round2::SignatureShare,
}

async fn round_2_signing(params: Params<'static>, context: Arc<Ctx>) -> RpcResult<Round2Response> {
    // get commitments from params
    let round2request: [Round2Request; 1] = params.parse()?;
    let round2request = &round2request[0];
    println!("received request: {:?}", round2request);

    // retrieve metadata for this task
    let (bob_address, smart_contract, nonces) = {
        let signing_tasks = context.signing_tasks.read().unwrap();
        if let Some(local_signing_task) = signing_tasks.get(&round2request.txid) {
            if local_signing_task.proof_hash != round2request.proof_hash {
                return RpcResult::Err(ErrorObjectOwned::owned(
                    jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
                    "proof hash doesn't match",
                    Some(format!("proof hash doesn't match")),
                ));
            }

            (
                local_signing_task.bob_address.clone(),
                local_signing_task.smart_contract.clone(),
                local_signing_task.nonces.clone(),
            )
        } else {
            return RpcResult::Err(ErrorObjectOwned::owned(
                jsonrpsee_types::error::UNKNOWN_ERROR_CODE,
                "no signing task found for this txid",
                Some(format!("no signing task found for this txid")),
            ));
        }
    };

    // deterministically create transaction
    let utxo = (round2request.txid, smart_contract.vout_of_zkbitcoin_utxo);
    let transaction = create_transaction(
        utxo,
        smart_contract.locked_value,
        bob_address,
        FEE_BITCOIN_SAT,
        FEE_ZKBITCOIN_SAT,
    );
    let message = get_digest_to_hash(&transaction, &smart_contract);

    // signing package should be recreated no? as we want to ensure that we agree on what is being signed (should be a deterministic process).
    let signing_package =
        frost_secp256k1::SigningPackage::new(round2request.commitments_map.clone(), &message);
    let signature_share =
        frost_secp256k1::round2::sign(&signing_package, &nonces, &context.key_package).map_err(
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

//
// Main server code
//

pub async fn run_server(
    address: Option<&str>,
    ctx: RpcCtx,
    key_package: frost::KeyPackage,
    pubkey_package: frost::PublicKeyPackage,
) -> anyhow::Result<SocketAddr> {
    let address = address.unwrap_or("127.0.0.1:6666");

    let ctx = Ctx {
        bitcoin_rpc_ctx: ctx,
        key_package,
        pubkey_package,
        signing_tasks: RwLock::new(HashMap::new()),
    };

    let server = Server::builder()
        .build(address.parse::<SocketAddr>()?)
        .await?;
    let mut module = RpcModule::new(ctx);
    module.register_async_method("round_1_signing", round_1_signing)?;
    module.register_async_method("round_2_signing", round_2_signing)?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    handle.stopped().await;

    Ok(addr)
}

// TODO: move this to mpc_sign_tx?
pub fn get_digest_to_hash(
    transaction: &bitcoin::Transaction,
    smart_contract: &SmartContract,
) -> [u8; 32] {
    // the first input is the taproot UTXO we want to spend
    let tx_ind = 0;

    // the sighash flag is always ALL
    let hash_ty = TapSighashType::All;

    // sighash
    let mut cache = SighashCache::new(transaction);
    let mut sig_msg = Vec::new();
    cache
        .taproot_encode_signing_data_to(
            &mut sig_msg,
            tx_ind,
            &Prevouts::All(&smart_contract.prev_outs),
            None,
            None,
            hash_ty,
        )
        .unwrap();
    let sighash = cache
        .taproot_signature_hash(
            tx_ind,
            &Prevouts::All(&smart_contract.prev_outs),
            None,
            None,
            hash_ty,
        )
        .unwrap();
    sighash.to_byte_array()
}
