use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

#[rpc]
pub trait Rpc {
    /// Unlock funds for a smart contract
    #[rpc(name = "unlock_funds")]
    fn unlock_funds(&self, request: BobRequest) -> Result<u64>;
}

pub struct RpcImpl {
    pub ctx: RpcCtx,
    pub key_package: frost::KeyPackage,
    pub pubkey_package: frost::PublicKeyPackage,
}

impl Rpc for RpcImpl {
    fn unlock_funds(&self, request: BobRequest) -> Result<u64> {
        // validate the request
        // validate_request(&self.ctx, request, None)
        //     .await
        //     .map_err(|_| "Invalid request")?;

        Ok(5)
    }
}

//
//
//

use jsonrpc_http_server::ServerBuilder;

use crate::{
    bob_request::{validate_request, BobRequest},
    frost,
    json_rpc_stuff::RpcCtx,
};

pub fn run_server(
    address: &str,
    ctx: RpcCtx,
    key_package: frost::KeyPackage,
    pubkey_package: frost::PublicKeyPackage,
) {
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
