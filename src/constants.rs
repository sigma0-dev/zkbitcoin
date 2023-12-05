//! Constants used in the zkBitcoin library.

/// The public key of zkBitcoin.
pub const ZKBITCOIN_PUBKEY: &str =
    "02c784b140ff1124304235c8381783a98e65133445eb7bd364de12c0ebec259c06"; // TODO: change this to a real pubkey in prod

/// The address associated to [ZKBITCOIN_PUBKEY].
pub const ZKBITCOIN_ADDRESS: &str = "tb1q5pxn428emp73saglk7ula0yx5j7ehegu6ud6ad";

/// Number of confirmation required for a transaction to be considered final.
pub const MINIMUM_CONFIRMATIONS: i32 = 0; // TODO: bad in prod?

/// The JSON-RPC version to use with bitcoind.
pub const BITCOIN_JSON_RPC_VERSION: &str = "1.0";

pub const FEE_ZKBITCOIN_SAT: u64 = 100;

pub const FEE_BITCOIN_SAT: u64 = 143;

pub const ORCHESTRATOR_ADDRESS: &str = "127.0.0.1:6666";
