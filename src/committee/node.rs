use std::{net::SocketAddr, sync::Arc};

use bitcoin::Txid;

pub struct Ctx {
    pub bitcoin_rpc_ctx: RpcCtx,
    pub key_package: frost::KeyPackage,
    pub pubkey_package: frost::PublicKeyPackage,
}

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

use jsonrpsee::{
    server::{RpcModule, Server},
    types::Params,
};
use jsonrpsee_core::RpcResult;
use secp256k1::hashes::Hash;

use crate::{
    bob_request::{validate_request, BobRequest, BobResponse},
    frost,
    json_rpc_stuff::RpcCtx,
};

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
