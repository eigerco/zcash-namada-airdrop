use std::ops::RangeInclusive;
use std::path::Path;

use schemars::{JsonSchema, Schema};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AirdropConfiguration {
    pub snapshot_range: RangeInclusive<u64>,
    pub sapling_merkle_root: Option<String>,
    pub orchard_merkle_root: Option<String>,
}

impl AirdropConfiguration {
    pub fn new(
        sapling_merkle_root: Option<&str>,
        orchard_merkle_root: Option<&str>,
        snapshot_range: RangeInclusive<u64>,
    ) -> Self {
        Self {
            sapling_merkle_root: sapling_merkle_root.map(ToOwned::to_owned),
            orchard_merkle_root: orchard_merkle_root.map(ToOwned::to_owned),
            snapshot_range,
        }
    }

    pub async fn export_config(&self, destination: impl AsRef<Path>) -> eyre::Result<()> {
        let config_json = serde_json::to_string_pretty(self)?;
        tokio::fs::write(destination, config_json).await?;
        Ok(())
    }

    pub fn schema() -> Schema {
        schemars::schema_for!(AirdropConfiguration)
    }
}
