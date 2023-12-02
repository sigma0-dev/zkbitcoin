use std::{net::SocketAddr, sync::Arc};

use bitcoin::Txid;

pub struct Ctx {
    pub bitcoin_rpc_ctx: RpcCtx,
    pub key_package: frost::KeyPackage,
    pub pubkey_package: frost::PublicKeyPackage,
}

async fn unlock_funds(params: Params<'static>, context: Arc<Ctx>) -> RpcResult<u64> {
    // get bob request
    println!("debug: {:?}", params);

    // validate request
    // validate_request(&context.bitcoin_rpc_ctx, bob_request, None)
    //     .await
    //     .unwrap();

    // TODO: do more stuff

    // response
    let bob_response = BobResponse {
        txid: Txid::all_zeros(),
    };
    let res = serde_json::to_value(&bob_response).unwrap();

    RpcResult::Ok(5)
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
    module.register_async_method("say_hello", unlock_funds)?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    // In this example we don't care about doing shutdown so let's it run forever.
    // You may use the `ServerHandle` to shut it down or manage it yourself.
    tokio::spawn(handle.stopped());

    Ok(addr)
}
