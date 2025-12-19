use std::path::PathBuf;
use std::str::FromStr as _;

use eyre::{ContextCompat as _, ensure};
use futures::StreamExt as _;
use http::Uri;
use non_membership_proofs::source::light_walletd::LightWalletd;
use non_membership_proofs::user_nullifiers::{
    OrchardViewingKeys, SaplingViewingKeys, UserNullifiers as _, ViewingKeys,
};
use non_membership_proofs::utils::ReverseBytes as _;
use non_membership_proofs::{
    Nullifier, Pool, build_merkle_tree, partition_by_pool, write_raw_nullifiers,
};
use rs_merkle::algorithms::Sha256;
use rs_merkle::{Hasher, MerkleTree};
use tracing::{debug, info, instrument, warn};
use zcash_protocol::consensus::{MainNetwork, Network, TestNetwork};

use crate::airdrop_configuration::AirdropConfiguration;
use crate::chain_nullifiers::{self, load_nullifiers_from_file};
use crate::cli::CommonArgs;
use crate::is_sanitize;
use crate::proof::generate_non_membership_proof;

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

    let sapling_handle = tokio::spawn(process_pool::<Sha256>(
        "sapling",
        sapling_nullifiers,
        sapling_snapshot_nullifiers,
    ));
    let orchard_handle = tokio::spawn(process_pool::<Sha256>(
        "orchard",
        orchard_nullifiers,
        orchard_snapshot_nullifiers,
    ));

    let (sapling_root, orchard_root) = tokio::try_join!(sapling_handle, orchard_handle)?;
    let sapling_root = sapling_root?;
    let orchard_root = orchard_root?;

    AirdropConfiguration::new(
        sapling_root.as_deref(),
        orchard_root.as_deref(),
        config.snapshot,
    )
    .export_config(&configuration_output_file)
    .await?;

    info!(file = ?configuration_output_file, "Exported configuration");
    Ok(())
}

#[instrument(skip_all, fields(pool = %pool, store = %store.display()))]
async fn process_pool<H>(
    pool: &str,
    mut nullifiers: Vec<Nullifier>,
    store: PathBuf,
) -> eyre::Result<Option<String>>
where
    H: Hasher + 'static,
    H::Hash: Send,
{
    if nullifiers.is_empty() {
        warn!(pool, "No nullifiers collected");
        return Ok(None);
    }

    info!(count = nullifiers.len(), "Collected nullifiers");

    nullifiers.sort_unstable();

    ensure!(
        is_sanitize(&nullifiers),
        "Nullifier lists contain duplicates"
    );

    write_raw_nullifiers(&nullifiers, &store).await?;
    info!(file = ?store, pool, "Saved nullifiers");

    let merkle_tree =
        tokio::task::spawn_blocking(move || build_merkle_tree::<H>(&nullifiers)).await??;
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
    clippy::too_many_arguments,
    reason = "Complex but coherent airdrop claim logic"
)]
pub async fn airdrop_claim(
    config: CommonArgs,
    sapling_snapshot_nullifiers: Option<PathBuf>,
    orchard_snapshot_nullifiers: Option<PathBuf>,
    orchard_fvk: &orchard::keys::FullViewingKey,
    sapling_fvk: &sapling::zip32::DiversifiableFullViewingKey,
    birthday_height: u64,
    airdrop_claims_output_file: PathBuf,
    airdrop_configuration_file: Option<PathBuf>,
) -> eyre::Result<()> {
    ensure!(
        birthday_height <= *config.snapshot.end(),
        "Birthday height cannot be greater than the snapshot end height"
    );

    #[cfg(feature = "file-source")]
    ensure!(
        config.source.input_files.is_none(),
        "Airdrop claims can only be generated using lightwalletd as the source"
    );

    if airdrop_configuration_file.is_none() {
        warn!("Airdrop configuration file is not provided. Merkle roots cannot be verified");
    }

    let lightwalletd_url = config
        .source
        .lightwalletd_url
        .as_deref()
        .map(Uri::from_str)
        .context("lightwalletd URL is required")??;

    let sapling = airdrop_claim_merkle_tree("sapling", sapling_snapshot_nullifiers);
    let orchard = airdrop_claim_merkle_tree("orchard", orchard_snapshot_nullifiers);
    let (sapling_result, orchard_result) = tokio::try_join!(sapling, orchard)?;

    if let Some(ref file) = airdrop_configuration_file {
        let airdrop_config: AirdropConfiguration =
            serde_json::from_str(&tokio::fs::read_to_string(file).await?)?;

        verify_merkle_roots(
            &airdrop_config,
            sapling_result.as_ref().map(|(_, tree)| tree),
            orchard_result.as_ref().map(|(_, tree)| tree),
        )
        .await?;
    }

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
            vec![],
        )),
        Network::MainNetwork => Box::pin(lightwalletd.user_nullifiers::<MainNetwork>(
            &MainNetwork,
            (*config.snapshot.start()).max(birthday_height),
            *config.snapshot.end(),
            orchard_fvk,
            sapling_fvk,
            vec![],
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

    let proofs = found_notes
        .iter()
        .filter_map(|note| {
            let (nullifiers, tree) = match note.pool() {
                Pool::Sapling => {
                    let (nullifiers, tree) = sapling_result.as_ref().or_else(|| {
                        warn!("Skipping Sapling note: no snapshot nullifiers available");
                        None
                    })?;
                    (nullifiers, tree)
                }
                Pool::Orchard => {
                    let (nullifiers, tree) = orchard_result.as_ref().or_else(|| {
                        warn!("Skipping Orchard note: no snapshot nullifiers available");
                        None
                    })?;
                    (nullifiers, tree)
                }
            };

            generate_non_membership_proof::<Sha256>(note, nullifiers, tree, &viewing_keys)
                .transpose()
        })
        .collect::<Vec<_>>();

    // Report errors
    let proofs = proofs
        .iter()
        .filter_map(|res| match res {
            Ok(proof) => Some(proof),
            Err(e) => {
                warn!("Failed to generate merkle-proof for note: {e:?}");
                None
            }
        })
        .collect::<Vec<_>>();

    let json = serde_json::to_string_pretty(&proofs)?;
    tokio::fs::write(&airdrop_claims_output_file, json).await?;

    info!(
        file = ?airdrop_claims_output_file,
        count = proofs.len(),
        "Proofs written"
    );

    Ok(())
}

#[instrument]
async fn airdrop_claim_merkle_tree<H>(
    pool: &str,
    snapshot_nullifiers: Option<PathBuf>,
) -> eyre::Result<Option<(Vec<Nullifier>, MerkleTree<H>)>>
where
    H: Hasher + 'static,
    H::Hash: Send,
{
    let Some(snapshot_nullifiers) = snapshot_nullifiers else {
        warn!(pool, "No snapshot nullifiers provided");
        return Ok(None);
    };

    let nullifiers = load_nullifiers_from_file(&snapshot_nullifiers).await?;

    ensure!(
        is_sanitize(&nullifiers),
        "Nullifier lists contain duplicates"
    );

    info!(pool, count = nullifiers.len(), "Loaded nullifiers");

    let (nullifiers, merkle_tree) = tokio::task::spawn_blocking(move || {
        let tree = build_merkle_tree::<H>(&nullifiers)?;
        Ok::<_, non_membership_proofs::MerkleTreeError>((nullifiers, tree))
    })
    .await??;

    Ok(Some((nullifiers, merkle_tree)))
}

/// Verifies that the merkle roots from the snapshot nullifiers match the airdrop configuration.
#[instrument(skip_all)]
async fn verify_merkle_roots<H>(
    airdrop_config: &AirdropConfiguration,
    sapling_tree: Option<&MerkleTree<H>>,
    orchard_tree: Option<&MerkleTree<H>>,
) -> eyre::Result<()>
where
    H: Hasher,
{
    let sapling_root = sapling_tree.and_then(MerkleTree::root_hex);
    ensure!(
        airdrop_config.sapling_merkle_root == sapling_root,
        "Sapling merkle root mismatch with airdrop configuration"
    );

    let orchard_root = orchard_tree.and_then(MerkleTree::root_hex);
    ensure!(
        airdrop_config.orchard_merkle_root == orchard_root,
        "Orchard merkle root mismatch with airdrop configuration"
    );

    info!(
        sapling_root,
        orchard_root, "Airdrop configuration merkle roots verified"
    );
    Ok(())
}

#[instrument]
pub async fn airdrop_configuration_schema() -> eyre::Result<()> {
    let schema = AirdropConfiguration::schema();
    let schema_str = serde_json::to_string_pretty(&schema)?;
    println!("Airdrop Configuration JSON Schema:\n{schema_str}");

    Ok(())
}
