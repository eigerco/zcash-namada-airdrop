use std::path::PathBuf;
use std::str::FromStr as _;

use eyre::{Context as _, ContextCompat as _};
use http::Uri;
use tokio::fs::File;
use tokio::io::BufWriter;
use tracing::{info, instrument, warn};
use zair_core::base::SanitiseNullifiers;
use zair_core::schema::config::{
    AirdropConfiguration, CommitmentTreeAnchors, HidingFactor, NonMembershipTreeAnchors,
};
use zair_nonmembership::NonMembershipTree;
use zair_scan::light_walletd::LightWalletd;
use zair_scan::scanner::ChainNullifiersVisitor;
use zair_scan::write_nullifiers;
use zcash_protocol::consensus::BlockHeight;

use crate::common::CommonConfig;

/// 1 MiB buffer for file I/O.
const FILE_BUF_SIZE: usize = 1024 * 1024;

/// Build the airdrop configuration by fetching nullifiers from lightwalletd
/// and computing the non-membership merkle-tree
///
/// # Errors
/// Returns an error if fetching nullifiers or writing files fails
#[instrument(skip_all, fields(
    snapshot = %format!("{}..={}", config.snapshot.start(), config.snapshot.end())
))]
pub async fn build_airdrop_configuration(
    config: CommonConfig,
    configuration_output_file: PathBuf,
    sapling_snapshot_nullifiers: PathBuf,
    orchard_snapshot_nullifiers: PathBuf,
    hiding_factor: HidingFactor,
) -> eyre::Result<()> {
    info!("Fetching nullifiers");
    let lightwalletd_url =
        Uri::from_str(&config.lightwalletd_url).context("lightwalletd URL is required")?;
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    let mut visitor = ChainNullifiersVisitor::default();
    lightwalletd
        .scan_nullifiers(&mut visitor, &config.snapshot)
        .await?;
    let (sapling_nullifiers, orchard_nullifiers) = visitor.sanitise_nullifiers();

    let sapling_handle = tokio::spawn(process_pool(
        "sapling",
        sapling_nullifiers,
        sapling_snapshot_nullifiers,
    ));
    let orchard_handle = tokio::spawn(process_pool(
        "orchard",
        orchard_nullifiers,
        orchard_snapshot_nullifiers,
    ));

    let (sapling_nf_root, orchard_nf_root) = tokio::try_join!(sapling_handle, orchard_handle)?;
    let non_membership_tree_anchors = NonMembershipTreeAnchors {
        sapling: sapling_nf_root?.unwrap_or_default(),
        orchard: orchard_nf_root?.unwrap_or_default(),
    };
    info!("Computed non-membership tree anchors");

    // These are the note commitment tree roots needed for proving note existence
    let upper_limit: u32 = (*config.snapshot.end())
        .try_into()
        .context("Snapshot end height too large")?;
    let upper_limit = upper_limit
        .checked_add(1)
        .context("Snapshot end height overflowed when adding 1")?;

    let note_commitment_tree_anchors = lightwalletd
        .commitment_tree_anchors(BlockHeight::from_u32(upper_limit))
        .await
        .context("Failed to fetch commitment tree anchors from lightwalletd")?;

    let config_out = AirdropConfiguration::new(
        config.snapshot,
        non_membership_tree_anchors,
        CommitmentTreeAnchors {
            sapling: note_commitment_tree_anchors.sapling,
            orchard: note_commitment_tree_anchors.orchard,
        },
        hiding_factor,
    );

    let json = serde_json::to_string_pretty(&config_out)?;
    tokio::fs::write(&configuration_output_file, json).await?;

    info!(file = ?configuration_output_file, "Exported configuration");
    Ok(())
}

#[instrument(skip_all, fields(pool = %pool, store = %store.display()))]
async fn process_pool(
    pool: &str,
    nullifiers: SanitiseNullifiers,
    store: PathBuf,
) -> eyre::Result<Option<[u8; 32]>> {
    if nullifiers.is_empty() {
        warn!(pool, "No nullifiers collected");
        return Ok(None);
    }

    info!(count = nullifiers.len(), "Collected nullifiers");

    let file = File::create(&store).await?;
    let mut writer = BufWriter::with_capacity(FILE_BUF_SIZE, file);
    write_nullifiers(&nullifiers, &mut writer).await?;
    info!(file = ?store, pool, "Saved nullifiers");

    let merkle_tree =
        tokio::task::spawn_blocking(move || NonMembershipTree::from_nullifiers(&nullifiers))
            .await??;

    let merkle_root = merkle_tree.root().to_bytes();

    Ok(Some(merkle_root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_json_format() {
        // Documents the expected JSON format for consumers
        let json = r#"{
          "snapshot_range": { "start": 100, "end": 200 },
          "non_membership_tree_anchors": {
            "sapling": "0505050505050505050505050505050505050505050505050505050505050505",
            "orchard": "0606060606060606060606060606060606060606060606060606060606060606"
          },
          "note_commitment_tree_anchors": {
            "sapling": "0101010101010101010101010101010101010101010101010101010101010101",
            "orchard": "0202020202020202020202020202020202020202020202020202020202020202"
          }
        }"#;

        let json_config: AirdropConfiguration =
            serde_json::from_str(json).expect("Failed to deserialize JSON");

        let expected_config = AirdropConfiguration::new(
            100..=200,
            NonMembershipTreeAnchors {
                sapling: [5_u8; 32_usize],
                orchard: [6_u8; 32_usize],
            },
            CommitmentTreeAnchors {
                sapling: [1_u8; 32_usize],
                orchard: [2_u8; 32_usize],
            },
            HidingFactor::default(),
        );
        assert_eq!(json_config.snapshot_range, expected_config.snapshot_range);
    }
}
