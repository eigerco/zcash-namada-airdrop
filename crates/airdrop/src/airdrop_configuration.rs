use std::ops::RangeInclusive;
use std::path::Path;

use schemars::{JsonSchema, Schema};
use serde::Serialize;

#[derive(Debug, Serialize, JsonSchema)]
pub struct AirdropConfiguration<'a> {
    snapshot_range: RangeInclusive<u64>,
    sapling_merkle_root: Option<&'a str>,
    orchard_merkle_root: Option<&'a str>,
}

impl<'a> AirdropConfiguration<'a> {
    pub const fn new(
        sapling_merkle_root: Option<&'a str>,
        orchard_merkle_root: Option<&'a str>,
        snapshot_range: RangeInclusive<u64>,
    ) -> Self {
        Self {
            sapling_merkle_root,
            orchard_merkle_root,
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
