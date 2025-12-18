use std::path::Path;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AirdropConfiguration<'a> {
    sapling_merkle_root: Option<&'a str>,
    orchard_merkle_root: Option<&'a str>,
}

impl<'a> AirdropConfiguration<'a> {
    pub const fn new(
        sapling_merkle_root: Option<&'a str>,
        orchard_merkle_root: Option<&'a str>,
    ) -> Self {
        Self {
            sapling_merkle_root,
            orchard_merkle_root,
        }
    }

    pub async fn export_config(&self, destination: impl AsRef<Path>) -> eyre::Result<()> {
        let config_json = serde_json::to_string_pretty(self)?;
        tokio::fs::write(destination, config_json).await?;
        Ok(())
    }
}
