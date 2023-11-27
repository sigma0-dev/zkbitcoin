use bitcoin::{
    absolute::LockTime,
    hashes::{hash160, Hash},
    opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_RETURN},
    transaction::Version,
    Amount, PubkeyHash, ScriptBuf, Transaction, TxOut,
};

// TODO: perhaps this will help https://github.com/rust-bitcoin/rust-bitcoin/issues/294

pub fn generate_transaction(vk: &[u8], satoshi_amount: u64) {
    // TODO: replace with our actual public key hash
    let zkbitcoin_pubkey_hash: PubkeyHash = PubkeyHash::from_raw_hash(hash160::Hash::all_zeros());

    // 1. create transaction based on VK + amount
    // https://developer.bitcoin.org/reference/rpc/createrawtransaction.html
    let script_pubkey = ScriptBuf::builder().
    // P2PKH
    push_opcode(OP_DUP)
    .push_opcode(OP_HASH160)
    .push_slice(zkbitcoin_pubkey_hash)
    .push_opcode(OP_EQUALVERIFY)
    .push_opcode(OP_CHECKSIG)
    // METADATA
    .push_opcode(OP_RETURN)
    // VK
    .push_slice(&[0, 0, 0, 0])
    // TODO: public input
    .push_slice(&[0, 0, 0, 0])
    // to script
    .into_script();

    let output = TxOut {
        value: Amount::from_sat(satoshi_amount),
        script_pubkey,
    };

    let tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        // we don't need to specify inputs at this point, the wallet will fill that for us
        input: vec![],
        output: vec![output],
    };

    // 2. fund transaction
    // https://developer.bitcoin.org/reference/rpc/fundrawtransaction.html

    // 3. sign transaction

    // 4. broadcast transaction
    // sendrawtransaction
}
