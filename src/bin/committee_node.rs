use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

use zkbitcoin::committee::node::{Rpc, RpcImpl};

fn main() {
    let mut io = jsonrpc_core::IoHandler::new();
    io.extend_with(RpcImpl.to_delegate())
}
