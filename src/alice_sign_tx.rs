use bitcoin::Transaction;

// https://github.com/rust-bitcoin/rust-bitcoin/issues/294

fn generate_transaction(vk: &[u8], amount: u64) {
    // 1. create transaction based on VK + amount
    // https://developer.bitcoin.org/reference/rpc/createrawtransaction.html
    let tx = Transaction {
        version: 1,
        lock_time: 0,
        // we don't need to specify inputs at this point, the wallet will fill that for us
        input: vec![],
        output: outputs,
    };

    // 2. fund transaction
    // https://developer.bitcoin.org/reference/rpc/fundrawtransaction.html

    // 3. broadcast transaction
    // sendrawtransaction
}
