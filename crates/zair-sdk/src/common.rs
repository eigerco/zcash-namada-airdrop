//! CLI-independent configuration types.
use zair_core::schema::config::AirdropNetwork;
use zcash_protocol::consensus::Network;

/// Common configuration for chain access and snapshot selection.
#[derive(Debug, Clone)]
pub struct CommonConfig {
    /// Network to use (mainnet or testnet).
    pub network: Network,
    /// Snapshot height (inclusive).
    pub snapshot_height: u64,
    /// Optional lightwalletd gRPC endpoint URL override.
    pub lightwalletd_url: Option<String>,
}

/// Pool selector used by commands that can operate on one or both pools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolSelection {
    /// Sapling-only.
    Sapling,
    /// Orchard-only.
    Orchard,
    /// Both Sapling and Orchard.
    Both,
}

impl PoolSelection {
    /// Whether Sapling is selected.
    #[must_use]
    pub const fn includes_sapling(self) -> bool {
        matches!(self, Self::Sapling | Self::Both)
    }

    /// Whether Orchard is selected.
    #[must_use]
    pub const fn includes_orchard(self) -> bool {
        matches!(self, Self::Orchard | Self::Both)
    }
}

/// Convert `zcash_protocol` network to config network.
#[must_use]
pub const fn to_airdrop_network(network: Network) -> AirdropNetwork {
    match network {
        Network::MainNetwork => AirdropNetwork::Mainnet,
        Network::TestNetwork => AirdropNetwork::Testnet,
    }
}

/// Convert config network to `zcash_protocol` network.
#[must_use]
pub const fn to_zcash_network(network: AirdropNetwork) -> Network {
    match network {
        AirdropNetwork::Mainnet => Network::MainNetwork,
        AirdropNetwork::Testnet => Network::TestNetwork,
    }
}

/// Default lightwalletd endpoint for mainnet.
pub const MAINNET_LIGHTWALLETD_URL: &str = "https://zec.rocks:443";
/// Default lightwalletd endpoint for testnet.
pub const TESTNET_LIGHTWALLETD_URL: &str = "https://testnet.zec.rocks:443";

/// Resolve lightwalletd URL from optional CLI override + network defaults.
#[must_use]
pub fn resolve_lightwalletd_url(
    network: Network,
    lightwalletd_url_override: Option<&str>,
) -> String {
    if let Some(url) = lightwalletd_url_override {
        return url.to_string();
    }

    match network {
        Network::MainNetwork => MAINNET_LIGHTWALLETD_URL.to_string(),
        Network::TestNetwork => TESTNET_LIGHTWALLETD_URL.to_string(),
    }
}
