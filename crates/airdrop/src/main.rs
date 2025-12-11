//! Airdrop CLI Application

use clap::Parser as _;
use eyre::{ContextCompat as _, ensure};
use futures::StreamExt as _;
use non_membership_proofs::source::light_walletd::LightWalletd;
use non_membership_proofs::user_nullifiers::{
    AnyFoundNote, OrchardViewingKeys, SaplingViewingKeys, UserNullifiers as _, ViewingKeys,
};
use non_membership_proofs::utils::ReverseBytes as _;
use non_membership_proofs::{
    Nullifier, Pool, build_leaf, build_merkle_tree, partition_by_pool, write_raw_nullifiers,
};
use rs_merkle::algorithms::Sha256;
use rs_merkle::{Hasher, MerkleTree};
use serde::Serialize;
use serde_with::hex::Hex;
use serde_with::serde_as;
use tracing::{debug, info, instrument, warn};
use zcash_primitives::consensus::{MainNetwork, Network, TestNetwork};

use crate::chain_nullifiers::load_nullifiers_from_file;
use crate::cli::{Cli, Commands, CommonArgs};

mod airdrop_configuration;
mod chain_nullifiers;
mod cli;

#[serde_as]
#[derive(Serialize)]
struct NullifierProof {
    #[serde_as(as = "Hex")]
    left_nullifier: Nullifier,
    #[serde_as(as = "Hex")]
    right_nullifier: Nullifier,
    #[serde_as(as = "Hex")]
    merkle_proof: Vec<u8>,
}

impl std::fmt::Debug for NullifierProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let left = self
            .left_nullifier
            .reverse_into_array()
            .map_or_else(|| "<invalid>".to_owned(), hex::encode::<Nullifier>);
        let right = self
            .right_nullifier
            .reverse_into_array()
            .map_or_else(|| "<invalid>".to_owned(), hex::encode::<Nullifier>);
        f.debug_struct("NullifierProof")
            .field("left_nullifier", &left)
            .field("right_nullifier", &right)
            .field("merkle_proof", &hex::encode(&self.merkle_proof))
            .finish()
    }
}

/// Search for a nullifier in the snapshot and generate a non-membership proof if not found.
/// Returns `Some(proof)` if the note is unspent, `None` if the note was already spent.
#[instrument(
    skip(snapshot_nullifiers, merkle_tree, keys, note),
    fields(pool = ?note.pool(), height = note.height())
)]
#[allow(
    clippy::indexing_slicing,
    reason = "Indices are bounded by binary_search result which is always in range [0, len]"
)]
fn generate_non_membership_proof<H: Hasher>(
    note: &AnyFoundNote,
    snapshot_nullifiers: &[Nullifier],
    merkle_tree: &MerkleTree<H>,
    keys: &ViewingKeys,
) -> eyre::Result<Option<NullifierProof>> {
    let nullifier = note
        .nullifier(keys)
        .context("Failed to get nullifier from note")?;
    let nullifier_hex = hex::encode::<Nullifier>(
        nullifier
            .reverse_into_array()
            .context("Failed to reverse nullifier bytes order")?,
    );

    match snapshot_nullifiers.binary_search(&nullifier) {
        Ok(_) => {
            warn!(nullifier = %nullifier_hex, "Nullifier found in snapshot - note was spent");
            Ok(None)
        }
        Err(idx) => {
            let left = idx.saturating_sub(1);
            let right = idx;

            debug!(
                nullifier = %nullifier_hex,
                left_idx = left,
                left_nullifier = %hex::encode::<Nullifier>(
                    snapshot_nullifiers[left]
                        .reverse_into_array()
                        .context("Failed to reverse left nullifier bytes order")?
                ),
                right_idx = right,
                right_nullifier = %hex::encode::<Nullifier>(
                    snapshot_nullifiers[right]
                        .reverse_into_array()
                        .context("Failed to reverse right nullifier bytes order")?
                ),
                "Found bounding nullifiers"
            );

            let leaf = build_leaf(&snapshot_nullifiers[left], &snapshot_nullifiers[right]);
            let leaf_hash = H::hash(&leaf);

            let merkle_proof = merkle_tree.proof(&[right]);

            ensure!(
                snapshot_nullifiers[left] < nullifier && nullifier < snapshot_nullifiers[right],
                "Snapshot nullifiers at indices {left} and {right} do not bound nullifier {nullifier_hex}",
            );

            ensure!(
                merkle_proof.verify(
                    merkle_tree.root().context("Merkle tree has no root")?,
                    &[right],
                    &[leaf_hash],
                    merkle_tree.leaves_len()
                ),
                "Merkle proof verification failed"
            );

            info!(nullifier = %nullifier_hex, "Generated non-membership proof");

            Ok(Some(NullifierProof {
                left_nullifier: snapshot_nullifiers[left],
                right_nullifier: snapshot_nullifiers[right],
                merkle_proof: merkle_proof.to_bytes(),
            }))
        }
    }
}

#[instrument(skip_all, fields(
    snapshot = %format!("{}..={}", config.snapshot.start(), config.snapshot.end())
))]
async fn build_airdrop_configuration(
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
async fn airdrop_claim(
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

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize rustls crypto provider (required for TLS connections)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load .env file (fails silently if not found)
    #[allow(
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        reason = "Ignoring dotenv result intentionally"
    )]
    let _ = dotenvy::dotenv();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::BuildAirdropConfiguration {
            config,
            configuration_output_file,
            sapling_snapshot_nullifiers,
            orchard_snapshot_nullifiers,
        } => {
            build_airdrop_configuration(
                config,
                configuration_output_file,
                sapling_snapshot_nullifiers,
                orchard_snapshot_nullifiers,
            )
            .await
        }
        Commands::AirdropClaim {
            config,
            sapling_snapshot_nullifiers,
            orchard_snapshot_nullifiers,
            orchard_fvk,
            sapling_fvk,
            birthday_height,
            airdrop_claims_output_file,
        } => {
            airdrop_claim(
                config,
                sapling_snapshot_nullifiers,
                orchard_snapshot_nullifiers,
                orchard_fvk,
                sapling_fvk,
                *birthday_height,
                airdrop_claims_output_file,
            )
            .await
        }
    }
}
