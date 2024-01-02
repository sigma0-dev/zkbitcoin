//! Constants used in the zkBitcoin library.

/// The public key of zkBitcoin.
// TODO: do we ever need this pubkey or can we just use the address?
pub const ZKBITCOIN_PUBKEY: &str =
    "025f822acf42cdb49de4c322f3131aa396dda0183a37889ecdfba99615ac9f6ff7"; // TODO: change this to a real pubkey in prod

/// The address is associated to [ZKBITCOIN_FEE_PUBKEY]
// TODO: obviously change this in prod
pub const ZKBITCOIN_FEE_ADDRESS: &str = "tb1q6nkpv2j9lxrm6h3w4skrny3thswgdcca8cx9k6";

pub const ZKBITCOIN_FEE_PUBKEY: &str =
    "0322073bd964e8c70e4e8ebbc4108910332053cfab60558b75d5b752c41b9285a4"; // TODO: change this to a real pubkey in prod

/// The address associated to [ZKBITCOIN_PUBKEY].
// TODO: This is not a taproot address, we probably should not use that in production
// TODO: obviously change this in prod
pub const ZKBITCOIN_ADDRESS: &str = "tb1q5pxn428emp73saglk7ula0yx5j7ehegu6ud6ad";

/// Number of confirmation required for a transaction to be considered final.
pub const MINIMUM_CONFIRMATIONS: i32 = 0; // TODO: bad in prod?

/// The JSON-RPC version to use with bitcoind.
pub const BITCOIN_JSON_RPC_VERSION: &str = "1.0";

/// The fee payable to the zkBitcoin fund.
pub const FEE_ZKBITCOIN_SAT: u64 = 546; // see https://whattodevnow.medium.com/how-to-calculate-the-real-minimum-satoshis-amount-for-a-utxo-5941628ad3e8

pub const ORCHESTRATOR_ADDRESS: &str = "127.0.0.1:6666";
