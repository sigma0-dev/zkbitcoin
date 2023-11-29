//! Constants used in the zkBitcoin library.

/// The public key of zkBitcoin.
pub const ZKBITCOIN_PUBKEY: &str =
    "02c784b140ff1124304235c8381783a98e65133445eb7bd364de12c0ebec259c06";

/// The address associated to [ZKBITCOIN_PUBKEY].
pub const ZKBITCOIN_ADDRESS: &str = "tb1q5pxn428emp73saglk7ula0yx5j7ehegu6ud6ad";

/// Number of confirmation required for a transaction to be considered final.
pub const MINIMUM_CONFIRMATIONS: i32 = 6;
