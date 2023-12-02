use std::{net::SocketAddr, sync::Arc};

use bitcoin::Txid;
use jsonrpsee::{
    server::{RpcModule, Server},
    types::Params,
};
use jsonrpsee_core::RpcResult;
use rand::thread_rng;
use secp256k1::hashes::Hash;

use crate::{
    bob_request::{validate_request, BobRequest, BobResponse},
    frost,
    json_rpc_stuff::RpcCtx,
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
}

//
// Methods
//

/// Bob's request to unlock funds from a smart contract.
async fn unlock_funds(params: Params<'static>, context: Arc<Ctx>) -> RpcResult<BobResponse> {
    // get bob request
    let bob_request: [BobRequest; 1] = params.parse()?;
    println!("received request: {:?}", bob_request);

    // validate request
    validate_request(&context.bitcoin_rpc_ctx, &bob_request[0], None)
        .await
        .unwrap(); // TODO: remove unwrap

    // TODO: what do we do if the request is valid at this point? Do we just mark it as "yes I will produce a signature to unlock this funds if needed?"

    // response
    let bob_response = BobResponse {
        txid: Txid::all_zeros(),
    };

    RpcResult::Ok(bob_response)
}

async fn round_1_signing(params: Params<'static>, context: Arc<Ctx>) -> RpcResult<()> {
    let rng = &mut thread_rng();
    let (nonces, commitments) =
        frost_secp256k1::round1::commit(context.key_package.signing_share(), rng);

    // TODO: store these locally

    // TODO: return the commitments
    Ok(())
}

async fn round_2_signing(params: Params<'static>, context: Arc<Ctx>) -> RpcResult<()> {
    let rng = &mut thread_rng();

    // TODO: get commitments from params
    let bob_request: [BobRequest; 1] = params.parse()?;
    println!("received request: {:?}", bob_request);

    // TODO: signing package should be recreated no? as we want to ensure that we agree on what is being signed (should be a deterministic process).
    let signing_package = frost_secp256k1::SigningPackage::new(commitments_map, message);
    let signature_share = frost_secp256k1::round2::sign(&signing_package, nonces, key_package)?;

    // TODO: return signature shares
    Ok(())
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
