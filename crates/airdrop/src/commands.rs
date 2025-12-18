use std::path::{Path, PathBuf};

use eyre::{ContextCompat as _, ensure};
use futures::StreamExt as _;
use non_membership_proofs::source::light_walletd::LightWalletd;
use non_membership_proofs::user_nullifiers::{
    OrchardViewingKeys, SaplingViewingKeys, UserNullifiers as _, ViewingKeys,
};
use non_membership_proofs::utils::ReverseBytes as _;
use non_membership_proofs::{
    Nullifier, Pool, build_merkle_tree, partition_by_pool, write_raw_nullifiers,
};
use rs_merkle::Hasher;
use rs_merkle::algorithms::Sha256;
use tracing::{debug, info, instrument, warn};
use zcash_protocol::consensus::{MainNetwork, Network, TestNetwork};

use crate::chain_nullifiers::{self, load_nullifiers_from_file};
use crate::cli::CommonArgs;
use crate::proof::generate_non_membership_proof;
use crate::{airdrop_configuration, is_sanitize};

#[instrument(skip_all, fields(
    snapshot = %format!("{}..={}", config.snapshot.start(), config.snapshot.end())
))]
pub(crate) async fn build_airdrop_configuration(
    config: &CommonArgs,
    configuration_output_file: impl AsRef<Path>,
    sapling_snapshot_nullifiers: impl AsRef<Path>,
    orchard_snapshot_nullifiers: impl AsRef<Path>,
) -> eyre::Result<()> {
    info!("Fetching nullifiers from chain");
    let stream = chain_nullifiers::get_nullifiers(config).await?;
    let (sapling_nullifiers, orchard_nullifiers) = partition_by_pool(stream).await?;

    let sapling_handle = tokio::spawn(process_pool::<Sha256>(
        "sapling",
        sapling_nullifiers,
        sapling_snapshot_nullifiers.as_ref().to_path_buf(),
    ));
    let orchard_handle = tokio::spawn(process_pool::<Sha256>(
        "orchard",
        orchard_nullifiers,
        orchard_snapshot_nullifiers.as_ref().to_path_buf(),
    ));

    let (sapling_root, orchard_root) = tokio::try_join!(sapling_handle, orchard_handle)?;
    let sapling_root = sapling_root?;
    let orchard_root = orchard_root?;

    airdrop_configuration::AirdropConfiguration::new(
        sapling_root.as_deref(),
        orchard_root.as_deref(),
    )
    .export_config(&configuration_output_file)
    .await?;

    info!(file = %configuration_output_file.as_ref().display(), "Exported configuration");
    Ok(())
}

async fn process_pool<H>(
    pool: &str,
    mut nullifiers: Vec<Nullifier>,
    store: PathBuf,
) -> eyre::Result<Option<String>>
where
    H: Hasher + 'static,
    H::Hash: std::marker::Send,
{
    if nullifiers.is_empty() {
        warn!(pool, "No nullifiers collected");
        return Ok(None);
    }

    info!(pool, count = nullifiers.len(), "Collected nullifiers");

    nullifiers.sort_unstable();

    ensure!(
        is_sanitize(&nullifiers),
        "Nullifier lists contain duplicates"
    );

    write_raw_nullifiers(&nullifiers, &store).await?;
    info!(file = ?store, pool, "Saved nullifiers");

    let merkle_tree = tokio::task::spawn_blocking(move || {
        non_membership_proofs::build_merkle_tree::<H>(&nullifiers)
    })
    .await??;
    info!(pool, root = ?merkle_tree.root_hex(), "Built merkle tree");

    Ok(Some(
        merkle_tree
            .root_hex()
            .context("Failed to get merkle root")?,
    ))
}

#[instrument(skip_all, fields(
    snapshot = %format!("{}..={}", config.snapshot.start(), config.snapshot.end()),
))]
#[allow(
    clippy::too_many_lines,
    reason = "Complex but coherent airdrop claim logic"
)]
pub(crate) async fn airdrop_claim(
    config: &CommonArgs,
    sapling_snapshot_nullifiers: impl AsRef<Path>,
    orchard_snapshot_nullifiers: impl AsRef<Path>,
    orchard_fvk: &orchard::keys::FullViewingKey,
    sapling_fvk: &sapling::zip32::DiversifiableFullViewingKey,
    birthday_height: u64,
    airdrop_claims_output_file: impl AsRef<Path>,
) -> eyre::Result<()> {
    ensure!(
        birthday_height <= *config.snapshot.end(),
        "Birthday height cannot be greater than the snapshot end height"
    );

    let lightwalletd_url = config
        .source
        .lightwalletd_url
        .as_ref()
        .context("lightwalletd URL is required")?;

    // Load snapshot
    info!("Loading snapshot nullifiers");
    let sapling_nullifiers = load_nullifiers_from_file(&sapling_snapshot_nullifiers).await?;
    let orchard_nullifiers = load_nullifiers_from_file(&orchard_snapshot_nullifiers).await?;

    ensure!(
        is_sanitize(&sapling_nullifiers) && is_sanitize(&orchard_nullifiers),
        "Nullifier lists contain duplicates"
    );

    info!(
        sapling = sapling_nullifiers.len(),
        orchard = orchard_nullifiers.len(),
        "Loaded nullifiers"
    );

    let sapling_tree = build_merkle_tree::<Sha256>(&sapling_nullifiers)?;
    info!(pool = "sapling", root = ?sapling_tree.root_hex(), "Built merkle tree");

    let orchard_tree = build_merkle_tree::<Sha256>(&orchard_nullifiers)?;
    info!(pool = "orchard", root = ?orchard_tree.root_hex(), "Built merkle tree");

    // Connect to lightwalletd
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    let viewing_keys = ViewingKeys {
        sapling: Some(SaplingViewingKeys::from_dfvk(sapling_fvk)),
        orchard: Some(OrchardViewingKeys::from_fvk(orchard_fvk)),
    };

    // Scan for notes
    info!("Scanning for user notes");
    let mut stream = match config.network {
        Network::TestNetwork => Box::pin(lightwalletd.user_nullifiers::<TestNetwork>(
            &TestNetwork,
            (*config.snapshot.start()).max(birthday_height),
            *config.snapshot.end(),
            orchard_fvk,
            sapling_fvk,
        )),
        Network::MainNetwork => Box::pin(lightwalletd.user_nullifiers::<MainNetwork>(
            &MainNetwork,
            (*config.snapshot.start()).max(birthday_height),
            *config.snapshot.end(),
            orchard_fvk,
            sapling_fvk,
        )),
    };

    let mut found_notes = vec![];

    while let Some(found_note) = stream.next().await {
        let found_note = found_note?;

        let Some(nullifier) = found_note.nullifier(&viewing_keys) else {
            debug!(
                height = found_note.height(),
                "Skipping note: no viewing key"
            );
            continue;
        };

        info!(
            pool = ?found_note.pool(),
            height = found_note.height(),
            nullifier = %hex::encode::<Nullifier>(nullifier.reverse_into_array().unwrap_or_default()),
            scope = ?found_note.scope(),
            "Found note"
        );

        found_notes.push(found_note);
    }

    let (sapling_count, orchard_count) = found_notes
        .iter()
        .try_fold::<_, _, eyre::Result<_, eyre::Report>>(
            (0_usize, 0_usize),
            |(s_count, o_count), n| match n.pool() {
                Pool::Sapling => Ok((
                    s_count
                        .checked_add(1_usize)
                        .context("Sapling note count overflow")?,
                    o_count,
                )),
                Pool::Orchard => Ok((
                    s_count,
                    o_count
                        .checked_add(1_usize)
                        .context("Orchard note count overflow")?,
                )),
            },
        )?;

    info!(
        total = found_notes.len(),
        sapling = sapling_count,
        orchard = orchard_count,
        "Scan complete"
    );

    // Generate proofs
    info!(
        count = found_notes.len(),
        "Generating non-membership proofs"
    );

    let mut proofs = Vec::new();

    for note in &found_notes {
        if note.nullifier(&viewing_keys).is_none() {
            continue;
        }

        let proof = match note.pool() {
            Pool::Sapling => generate_non_membership_proof(
                note,
                &sapling_nullifiers,
                &sapling_tree,
                &viewing_keys,
            )?,
            Pool::Orchard => generate_non_membership_proof(
                note,
                &orchard_nullifiers,
                &orchard_tree,
                &viewing_keys,
            )?,
        };

        if let Some(proof) = proof {
            proofs.push(proof);
        }
    }

    let json = serde_json::to_string_pretty(&proofs)?;
    tokio::fs::write(&airdrop_claims_output_file, json).await?;

    info!(
        file = %airdrop_claims_output_file.as_ref().display(),
        count = proofs.len(),
        "Proofs written"
    );

    Ok(())
}
