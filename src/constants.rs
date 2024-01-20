//! Constants used in the zkBitcoin library.

/// The public key of zkBitcoin.
// TODO: do we ever need this pubkey or can we just use the address?
pub const ZKBITCOIN_PUBKEY: &str =
    "02bd84fcbb2ad2f274079c68580a5a1e234bd88ed6ee38f2b33a303fd38a104942"; // TODO: change this to a real pubkey in prod

// The address is associated to [ZKBITCOIN_FEE_PUBKEY]
// TODO: obviously change this in prod
//pub const ZKBITCOIN_FEE_ADDRESS: &str = "tb1q6nkpv2j9lxrm6h3w4skrny3thswgdcca8cx9k6";

pub const ZKBITCOIN_FEE_PUBKEY: &str =
    "037299ffd702cdc0537d8bb92f216ccc6058ad804741c4293cc82288f453dadadc"; // TODO: change this to a real pubkey in prod

/// Number of confirmation required for a transaction to be considered final.
pub const MINIMUM_CONFIRMATIONS: usize = 0; // TODO: bad in prod?

/// The JSON-RPC version to use with bitcoind.
pub const BITCOIN_JSON_RPC_VERSION: &str = "1.0";

/// The fee payable to the zkBitcoin fund.
pub const FEE_ZKBITCOIN_SAT: u64 = 546; // see https://whattodevnow.medium.com/how-to-calculate-the-real-minimum-satoshis-amount-for-a-utxo-5941628ad3e8

pub const ORCHESTRATOR_ADDRESS: &str = "http://64.23.171.48:8888";

pub const CIRCOM_ETH_PRIME: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// The bit-length of the Circom prime.
pub const CIRCOM_ETH_PRIME_BITLEN: usize = 254;

/// The byte-length of the Circom prime.
pub const CIRCOM_ETH_PRIME_BYTELEN: usize = 32;

/// The expected number of public inputs for a stateless zkapp.
pub const STATELESS_ZKAPP_PUBLIC_INPUT_LEN: usize = 1 /* truncated txid */;

/// The expected number of public inputs for a stateful zkapp.
pub const STATEFUL_ZKAPP_PUBLIC_INPUT_LEN: usize = 1 * 2 /* new state + prev state */ + 1 /* truncated txid */ + 1 /* amount_out */ + 1 /* amount_in */;
