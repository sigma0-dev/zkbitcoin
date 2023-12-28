//! Constants used in the zkBitcoin library.

/// The public key of the zkBitcoin fund (to pay fees).
// TODO: change this!!!
pub const ZKBITCOIN_FEE_PUBKEY: &str =
    "025f822acf42cdb49de4c322f3131aa396dda0183a37889ecdfba99615ac9f6ff7"; // TODO: change this to a real pubkey in prod

/// The public key of zkBitcoin.
pub const ZKBITCOIN_PUBKEY: &str =
    "025f822acf42cdb49de4c322f3131aa396dda0183a37889ecdfba99615ac9f6ff7"; // TODO: change this to a real pubkey in prod

/// The address associated to [ZKBITCOIN_PUBKEY].
/// This is not a taproot address, we probably should not use that in production
#[cfg(test)]
pub const ZKBITCOIN_ADDRESS: &str = "tb1q5pxn428emp73saglk7ula0yx5j7ehegu6ud6ad";

/// Number of confirmation required for a transaction to be considered final.
pub const MINIMUM_CONFIRMATIONS: i32 = 0; // TODO: bad in prod?

/// The JSON-RPC version to use with bitcoind.
pub const BITCOIN_JSON_RPC_VERSION: &str = "1.0";

/// The fee payable to the zkBitcoin fund.
pub const FEE_ZKBITCOIN_SAT: u64 = 100;

pub const ORCHESTRATOR_ADDRESS: &str = "127.0.0.1:6666";
