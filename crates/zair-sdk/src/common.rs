//! CLI-independent configuration types.

use std::ops::RangeInclusive;

use zcash_protocol::consensus::Network;

/// Common configuration for chain access and snapshot selection.
#[derive(Debug, Clone)]
pub struct CommonConfig {
    /// Network to use (mainnet or testnet).
    pub network: Network,
    /// Block range for the snapshot (inclusive).
    pub snapshot: RangeInclusive<u64>,
    /// Lightwalletd gRPC endpoint URL.
    pub lightwalletd_url: String,
}
