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
use rs_merkle::algorithms::Sha256;
use tracing::{debug, info, instrument};
use zcash_primitives::consensus::{MainNetwork, Network, TestNetwork};

use crate::airdrop_configuration;
use crate::chain_nullifiers::{self, load_nullifiers_from_file};
use crate::cli::CommonArgs;
use crate::proof::generate_non_membership_proof;

#[instrument(skip_all, fields(
    snapshot = %format!("{}..={}", config.snapshot.start(), config.snapshot.end())
))]
pub(crate) async fn build_airdrop_configuration(
    config: &CommonArgs,
    configuration_output_file: &str,
    sapling_snapshot_nullifiers: &str,
    orchard_snapshot_nullifiers: &str,
) -> eyre::Result<()> {
    info!("Fetching nullifiers from chain");
    let stream = chain_nullifiers::get_nullifiers(config).await?;
    let (mut sapling_nullifiers, mut orchard_nullifiers) = partition_by_pool(stream).await?;

    info!(
        sapling = sapling_nullifiers.len(),
        orchard = orchard_nullifiers.len(),
        "Collected nullifiers"
    );

    sapling_nullifiers.sort_unstable();
    orchard_nullifiers.sort_unstable();

    write_raw_nullifiers(&sapling_nullifiers, sapling_snapshot_nullifiers).await?;
    info!(file = %sapling_snapshot_nullifiers, pool = "sapling", "Saved nullifiers");

    write_raw_nullifiers(&orchard_nullifiers, orchard_snapshot_nullifiers).await?;
    info!(file = %orchard_snapshot_nullifiers, pool = "orchard", "Saved nullifiers");

    let sapling_tree = build_merkle_tree::<Sha256>(&sapling_nullifiers)?;
    info!(pool = "sapling", root = %sapling_tree.root_hex().unwrap_or_default(), "Built merkle tree");

    let orchard_tree = build_merkle_tree::<Sha256>(&orchard_nullifiers)?;
    info!(pool = "orchard", root = %orchard_tree.root_hex().unwrap_or_default(), "Built merkle tree");

    airdrop_configuration::AirdropConfiguration::new(
        sapling_tree.root_hex().as_deref(),
        orchard_tree.root_hex().as_deref(),
    )
    .export_config(configuration_output_file)
    .await?;

    info!(file = %configuration_output_file, "Exported configuration");
    Ok(())
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
    sapling_snapshot_nullifiers: &str,
    orchard_snapshot_nullifiers: &str,
    orchard_fvk: &orchard::keys::FullViewingKey,
    sapling_fvk: &sapling::zip32::DiversifiableFullViewingKey,
    birthday_height: u64,
    airdrop_claims_output_file: &str,
) -> eyre::Result<()> {
    ensure!(
        birthday_height <= *config.snapshot.end(),
        "Birthday height cannot be greater than the snapshot end height"
    );

    ensure!(
        config.source.lightwalletd_url.is_some(),
        "lightwalletd URL must be provided"
    );

    // Load snapshot
    info!("Loading snapshot nullifiers");
    let sapling_nullifiers = load_nullifiers_from_file(sapling_snapshot_nullifiers).await?;
    let orchard_nullifiers = load_nullifiers_from_file(orchard_snapshot_nullifiers).await?;

    info!(
        sapling = sapling_nullifiers.len(),
        orchard = orchard_nullifiers.len(),
        "Loaded nullifiers"
    );

    let sapling_tree = build_merkle_tree::<Sha256>(&sapling_nullifiers)?;
    info!(pool = "sapling", root = %sapling_tree.root_hex().unwrap_or_default(), "Built merkle tree");

    let orchard_tree = build_merkle_tree::<Sha256>(&orchard_nullifiers)?;
    info!(pool = "orchard", root = %orchard_tree.root_hex().unwrap_or_default(), "Built merkle tree");

    // Connect to lightwalletd
    let lightwalletd_url = config
        .source
        .lightwalletd_url
        .as_ref()
        .context("lightwalletd URL is required")?;
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
            *config.snapshot.start(),
            *config.snapshot.end(),
            orchard_fvk,
            sapling_fvk,
        )),
        Network::MainNetwork => Box::pin(lightwalletd.user_nullifiers::<MainNetwork>(
            &MainNetwork,
            *config.snapshot.start(),
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

    let sapling_count = found_notes
        .iter()
        .filter(|n| n.pool() == Pool::Sapling)
        .count();
    let orchard_count = found_notes
        .iter()
        .filter(|n| n.pool() == Pool::Orchard)
        .count();

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
    tokio::fs::write(airdrop_claims_output_file, json).await?;

    info!(
        file = %airdrop_claims_output_file,
        count = proofs.len(),
        "Proofs written"
    );

    Ok(())
}
