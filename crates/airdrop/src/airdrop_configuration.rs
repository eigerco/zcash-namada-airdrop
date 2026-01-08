//! Airdrop configuration module.
//! This module defines the `AirdropConfiguration` struct, which holds
//! the configuration details for an airdrop, including snapshot range
//! and Merkle roots for Sapling and Orchard.

use std::ops::RangeInclusive;
use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Configuration for an airdrop, including snapshot range and Merkle roots.
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AirdropConfiguration {
    /// The inclusive range of block heights for the snapshot.
    pub snapshot_range: RangeInclusive<u64>,
    /// The Merkle root for the Sapling shielded addresses.
    pub sapling_merkle_root: Option<String>,
    /// The Merkle root for the Orchard shielded addresses.
    pub orchard_merkle_root: Option<String>,
}

impl AirdropConfiguration {
    /// Creates a new `AirdropConfiguration` instance.
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
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    use super::*;

    #[test]
    fn deserialize_json_format() -> eyre::Result<()> {
        // Documents the expected JSON format for consumers
        let json = r#"{
          "snapshot_range": { "start": 100, "end": 200 },
          "sapling_merkle_root": "abc",
          "orchard_merkle_root": null
        }"#;

        let json_config: AirdropConfiguration = serde_json::from_str(json)?;

        let expected_config = AirdropConfiguration::new(100..=200, Some("abc"), None);
        assert_eq!(json_config.snapshot_range, expected_config.snapshot_range);

        Ok(())
    }

    #[tokio::test]
    async fn export_config() -> eyre::Result<()> {
        let config = AirdropConfiguration::new(100..=200, Some("sapling"), Some("orchard"));
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();

        config.export_config(path).await?;

        let mut file = File::open(path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;

        let loaded: AirdropConfiguration = serde_json::from_str(&contents)?;
        assert_eq!(config, loaded);

        Ok(())
    }
}
