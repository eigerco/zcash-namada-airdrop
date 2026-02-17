//! Network/pool activation parameters shared across workflows.

use zcash_protocol::consensus::Network;

use crate::common::PoolSelection;

/// Sapling activation height on mainnet, see [ZIP 205](https://zips.z.cash/zip-0205).
pub const SAPLING_MAINNET_START: u64 = 419_200;
/// Sapling activation height on testnet, see [ZIP 205](https://zips.z.cash/zip-0205).
pub const SAPLING_TESTNET_START: u64 = 280_000;
/// Orchard activation height on mainnet, see [ZIP 252](https://zips.z.cash/zip-0252).
pub const ORCHARD_MAINNET_START: u64 = 1_687_104;
/// Orchard activation height on testnet, see [ZIP 252](https://zips.z.cash/zip-0252).
pub const ORCHARD_TESTNET_START: u64 = 1_842_420;

/// Sapling activation height for the given network.
#[must_use]
pub const fn sapling_activation_height(network: Network) -> u64 {
    match network {
        Network::MainNetwork => SAPLING_MAINNET_START,
        Network::TestNetwork => SAPLING_TESTNET_START,
    }
}

/// Orchard activation height for the given network.
#[must_use]
pub const fn orchard_activation_height(network: Network) -> u64 {
    match network {
        Network::MainNetwork => ORCHARD_MAINNET_START,
        Network::TestNetwork => ORCHARD_TESTNET_START,
    }
}

/// Activation-aware scan start height for a selected pool.
#[must_use]
pub const fn scan_start_height(network: Network, pool: PoolSelection) -> u64 {
    match pool {
        // Sapling always activates before Orchard on all networks.
        PoolSelection::Sapling | PoolSelection::Both => sapling_activation_height(network),
        PoolSelection::Orchard => orchard_activation_height(network),
    }
}
