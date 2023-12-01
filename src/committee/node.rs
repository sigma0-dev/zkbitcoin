use bitcoin::Txid;
use jsonrpc_core::{futures, futures_util::future, BoxFuture, Result};
use jsonrpc_derive::rpc;

#[rpc]
pub trait Rpc {
    /// Unlock funds for a smart contract
    #[rpc(name = "unlock_funds")]
    fn unlock_funds(&self, request: BobRequest) -> Result<BobResponse>;
}

pub struct RpcImpl {
    pub ctx: RpcCtx,
    pub key_package: frost::KeyPackage,
    pub pubkey_package: frost::PublicKeyPackage,
}

impl Rpc for RpcImpl {
    fn unlock_funds(&self, request: BobRequest) -> Result<BobResponse> {
        println!("receied a request to unlock funds: {:?}", request);

        // validate the request
        println!("validating the request...");
        if let Some(err) =
            futures::executor::block_on(validate_request(&self.ctx, request, None)).err()
        {
            println!("couldn't validate");
            return Err(jsonrpc_core::Error::invalid_params(
                "couldn't validate the request !!",
            ));
        }
        println!("validated!");

        Ok(BobResponse {
            txid: Txid::all_zeros(),
        })
    }
}

//
//
//

use jsonrpc_http_server::ServerBuilder;
use secp256k1::hashes::Hash;

use crate::{
    bob_request::{validate_request, BobRequest, BobResponse},
    frost,
    json_rpc_stuff::RpcCtx,
};

pub fn run_server(
    address: Option<&str>,
    ctx: RpcCtx,
    key_package: frost::KeyPackage,
    pubkey_package: frost::PublicKeyPackage,
) {
    let address = address.unwrap_or("127.0.0.1:6666");

    let rpc_impl = RpcImpl {
        ctx,
        key_package,
        pubkey_package,
    };

    let mut io = jsonrpc_core::IoHandler::new();
    io.extend_with(rpc_impl.to_delegate());

    let server = ServerBuilder::new(io)
        .threads(3)
        .start_http(&address.parse().unwrap())
        .unwrap();

    server.wait();
}
