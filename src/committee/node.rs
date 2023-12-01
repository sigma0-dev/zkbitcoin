use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

#[rpc]
pub trait Rpc {
    /// Unlock funds for a smart contract
    #[rpc(name = "unlock_funds")]
    fn unlock_funds(&self, a: BobRequest) -> Result<u64>;
}

pub struct RpcImpl {
    pub key_package: frost::KeyPackage,
    pub pubkey_package: frost::PublicKeyPackage,
}

impl Rpc for RpcImpl {
    fn unlock_funds(&self, a: BobRequest) -> Result<u64> {
        Ok(5)
    }
}

//
//
//

use jsonrpc_http_server::ServerBuilder;

use crate::{
    bob_request::{self, BobRequest},
    frost,
};

pub fn run_server(
    address: &str,
    key_package: frost::KeyPackage,
    pubkey_package: frost::PublicKeyPackage,
) {
    let rpc_impl = RpcImpl {
        key_package: key_package,
        pubkey_package: pubkey_package,
    };

    let mut io = jsonrpc_core::IoHandler::new();
    io.extend_with(rpc_impl.to_delegate());

    let server = ServerBuilder::new(io)
        .threads(3)
        .start_http(&address.parse().unwrap())
        .unwrap();

    server.wait();
}
