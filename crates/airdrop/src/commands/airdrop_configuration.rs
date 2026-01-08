use std::path::PathBuf;

use non_membership_proofs::utils::SanitiseNullifiers;
use non_membership_proofs::{NonMembershipTree, partition_by_pool, write_nullifiers};
use tokio::fs::File;
use tokio::io::BufWriter;
use tracing::{info, instrument, warn};

use crate::BUF_SIZE;
use crate::airdrop_configuration::AirdropConfiguration;
use crate::chain_nullifiers::{self};
use crate::cli::CommonArgs;

#[instrument(skip_all, fields(
    snapshot = %format!("{}..={}", config.snapshot.start(), config.snapshot.end())
))]
pub async fn build_airdrop_configuration(
    config: CommonArgs,
    configuration_output_file: PathBuf,
    sapling_snapshot_nullifiers: PathBuf,
    orchard_snapshot_nullifiers: PathBuf,
) -> eyre::Result<()> {
    info!("Fetching nullifiers");
    let stream = chain_nullifiers::get_nullifiers(&config).await?;
    let (sapling_nullifiers, orchard_nullifiers) = partition_by_pool(stream).await?;

    let sapling_handle = tokio::spawn(process_pool(
        "sapling",
        SanitiseNullifiers::new(sapling_nullifiers),
        sapling_snapshot_nullifiers,
    ));
    let orchard_handle = tokio::spawn(process_pool(
        "orchard",
        SanitiseNullifiers::new(orchard_nullifiers),
        orchard_snapshot_nullifiers,
    ));

    let (sapling_root, orchard_root) = tokio::try_join!(sapling_handle, orchard_handle)?;
    let sapling_root = sapling_root?;
    let orchard_root = orchard_root?;

    AirdropConfiguration::new(
        config.snapshot,
        sapling_root.as_deref(),
        orchard_root.as_deref(),
    )
    .export_config(&configuration_output_file)
    .await?;

    info!(file = ?configuration_output_file, "Exported configuration");
    Ok(())
}

#[instrument(skip_all, fields(pool = %pool, store = %store.display()))]
async fn process_pool(
    pool: &str,
    nullifiers: SanitiseNullifiers,
    store: PathBuf,
) -> eyre::Result<Option<String>> {
    if nullifiers.is_empty() {
        warn!(pool, "No nullifiers collected");
        return Ok(None);
    }

    info!(count = nullifiers.len(), "Collected nullifiers");

    let file = File::create(&store).await?;
    let mut writer = BufWriter::with_capacity(BUF_SIZE, file);
    write_nullifiers(&nullifiers, &mut writer).await?;
    info!(file = ?store, pool, "Saved nullifiers");

    let merkle_tree =
        tokio::task::spawn_blocking(move || NonMembershipTree::from_nullifiers(&nullifiers))
            .await??;

    let root = merkle_tree.root();
    let root_hex = hex::encode(root.to_bytes());
    info!(pool, root = %root_hex, "Built merkle tree");

    Ok(Some(root_hex))
}
