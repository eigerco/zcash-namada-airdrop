//! Airdrop configuration module.
//! This module defines the AirdropConfiguration struct, which holds
//! the configuration details for an airdrop, including snapshot range
//! and Merkle roots for Sapling and Orchard.

use std::ops::RangeInclusive;
use std::path::Path;

use schemars::{JsonSchema, Schema};
use serde::{Deserialize, Serialize};

/// Configuration for an airdrop, including snapshot range and Merkle roots.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AirdropConfiguration {
    /// The inclusive range of block heights for the snapshot.
    pub snapshot_range: RangeInclusive<u64>,
    /// The Merkle root for the Sapling shielded addresses.
    pub sapling_merkle_root: Option<String>,
    /// The Merkle root for the Orchard shielded addresses.
    pub orchard_merkle_root: Option<String>,
}

impl AirdropConfiguration {
    /// Creates a new AirdropConfiguration instance.
    ///
    /// # Arguments
    /// * `snapshot_range` - The inclusive range of block heights for the snapshot.
    /// * `sapling_merkle_root` - An optional Merkle root for Sapling addresses.
    /// * `orchard_merkle_root` - An optional Merkle root for Orchard addresses
    pub fn new(
        snapshot_range: RangeInclusive<u64>,
        sapling_merkle_root: Option<&str>,
        orchard_merkle_root: Option<&str>,
    ) -> Self {
        Self {
            snapshot_range,
            sapling_merkle_root: sapling_merkle_root.map(ToOwned::to_owned),
            orchard_merkle_root: orchard_merkle_root.map(ToOwned::to_owned),
        }
    }

    /// Exports the configuration to a JSON file at the specified destination.
    pub async fn export_config(&self, destination: impl AsRef<Path>) -> eyre::Result<()> {
        let config_json = serde_json::to_string_pretty(self)?;
        tokio::fs::write(destination, config_json).await?;
        Ok(())
    }

    /// Generates the JSON schema for the AirdropConfiguration struct.
    pub fn schema() -> Schema {
        schemars::schema_for!(AirdropConfiguration)
    }
}
