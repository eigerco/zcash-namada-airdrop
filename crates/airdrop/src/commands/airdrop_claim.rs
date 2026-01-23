//! Airdrop claim generation entry point.
//!
//! This module provides the main `airdrop_claim` function that orchestrates
//! the claim generation process for both Sapling and Orchard pools.

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use eyre::{Context as _, ensure};
use http::Uri;
use non_membership_proofs::light_walletd::LightWalletd;
use non_membership_proofs::scanner::{AccountNotesVisitor, BlockScanner};
use non_membership_proofs::{
    NonMembershipTree, Nullifier, SanitiseNullifiers, TreePosition, ViewingKeys,
};
use tokio::fs::File;
use tokio::io::BufReader;
use tracing::{debug, info, instrument, warn};
use zcash_keys::keys::UnifiedFullViewingKey;

use super::airdrop_configuration::AirdropConfiguration;
use super::note_metadata::NoteMetadata;
use super::pool_processor::{OrchardPool, SaplingPool};
use crate::BUF_SIZE;
use crate::cli::CommonArgs;
use crate::commands::pool_processor::{PoolClaimResult, PoolProcessor};
use crate::unspent_notes_proofs::{ClaimInput, PublicInputs, UnspentNotesProofs};

/// Generate airdrop claim
///
/// Generate airdrop claim proof for the given unified full viewing key (UFVK)
/// and output them to the specified file. The function scans the blockchain
/// for notes associated with the UFVK, constructs non-membership Merkle trees
/// for the provided snapshot nullifiers, and generates non-membership proofs
/// for the user's notes.
///
/// # Errors
/// Returns error if any step in the process fails,
/// including scanning for notes, loading nullifiers, building Merkle trees,
/// or generating proofs.
#[instrument(skip_all, fields(
    network = ?config.network,
    snapshot = %format!("{}..={}", config.snapshot.start(), config.snapshot.end()),
))]
pub async fn airdrop_claim(
    config: CommonArgs,
    sapling_snapshot_nullifiers: Option<PathBuf>,
    orchard_snapshot_nullifiers: Option<PathBuf>,
    ufvk: UnifiedFullViewingKey,
    birthday_height: u64,
    airdrop_claims_output_file: PathBuf,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    let account_notes = find_user_notes(&config, ufvk.clone(), birthday_height).await?;

    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(airdrop_configuration_file).await?)?;

    let viewing_keys = ViewingKeys::new(&ufvk);

    // Process pools in parallel
    let (sapling_result, orchard_result) = tokio::try_join!(
        process_pool_claims::<SaplingPool>(
            &account_notes,
            &viewing_keys,
            &airdrop_config,
            sapling_snapshot_nullifiers,
        ),
        process_pool_claims::<OrchardPool>(
            &account_notes,
            &viewing_keys,
            &airdrop_config,
            orchard_snapshot_nullifiers,
        ),
    )?;

    let total_claims = sapling_result
        .claims
        .len()
        .checked_add(orchard_result.claims.len());

    let user_proofs = UnspentNotesProofs::new(
        sapling_result.anchor,
        orchard_result.anchor,
        airdrop_config.note_commitment_tree_anchors,
        sapling_result.claims,
        orchard_result.claims,
    );

    let json = serde_json::to_string_pretty(&user_proofs)?;
    tokio::fs::write(&airdrop_claims_output_file, json).await?;

    info!(
        file = ?airdrop_claims_output_file,
        count = total_claims,
        "airdrop claims written"
    );

    Ok(())
}

/// Scan the blockchain for user notes within the snapshot range.
#[instrument(skip_all)]
async fn find_user_notes(
    config: &CommonArgs,
    ufvk: UnifiedFullViewingKey,
    birthday_height: u64,
) -> eyre::Result<AccountNotesVisitor> {
    ensure!(
        birthday_height <= *config.snapshot.end(),
        "Birthday height cannot be past the end of the snapshot range"
    );

    let lightwalletd_url =
        Uri::from_str(&config.lightwalletd_url).context("lightwalletd URL is required")?;
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    // NOTE: We are interested at tree state from the point that the account could have notes
    let start_block = birthday_height;
    let tree_state_height = start_block.saturating_sub(1);
    let tree_state = lightwalletd.get_tree_state(tree_state_height).await?;

    // Initialize visitor from tree state
    let visitor = AccountNotesVisitor::from_tree_state(&tree_state)?;

    let scan_range = RangeInclusive::new(birthday_height, *config.snapshot.end());

    info!("Scanning for user notes");
    let initial_metadata = BlockScanner::parse_tree_state(&tree_state)?;

    // Use channel-based scanning to keep non-Send BlockScanner off async tasks
    let (visitor, _final_metadata) = lightwalletd
        .scan_blocks_spawned(
            ufvk,
            config.network,
            visitor,
            &scan_range,
            Some(initial_metadata),
        )
        .await?;

    info!(
        total = visitor
            .sapling_notes()
            .len()
            .checked_add(visitor.orchard_notes().len()),
        "Scan complete"
    );

    Ok(visitor)
}

/// Loaded pool data including the non-membership merkle-tree and user's nullifier positions.
pub struct LoadedPoolData {
    /// The non-membership merkle tree for the pool.
    pub tree: NonMembershipTree,
    /// The user's nullifiers with tree positions needed to generate proofs.
    pub user_nullifiers: Vec<TreePosition>,
}

/// Build the non-membership merkle tree for a pool.
async fn build_pool_merkle_tree(
    snapshot_nullifiers_path: &Path,
    user_nullifiers: SanitiseNullifiers,
) -> eyre::Result<LoadedPoolData> {
    let chain_nullifiers = load_nullifiers_from_file(snapshot_nullifiers_path).await?;

    info!(count = chain_nullifiers.len(), "Loaded chain nullifiers");

    let loaded_data = tokio::task::spawn_blocking(move || {
        let (tree, user_nullifiers) =
            NonMembershipTree::from_chain_and_user_nullifiers(&chain_nullifiers, &user_nullifiers)?;
        Ok::<_, non_membership_proofs::MerklePathError>(LoadedPoolData {
            tree,
            user_nullifiers,
        })
    })
    .await??;

    Ok(loaded_data)
}

/// Generate non-membership proofs for notes of any pool type.
///
/// This generic function works with any metadata type implementing `NoteMetadata`,
/// producing claim inputs with the appropriate pool-specific private inputs.
fn generate_proofs<M: NoteMetadata>(
    tree: &NonMembershipTree,
    user_nullifiers: Vec<TreePosition>,
    note_metadata_map: &HashMap<Nullifier, M>,
) -> Vec<ClaimInput<M::PoolPrivateInputs>> {
    user_nullifiers
        .into_iter()
        .filter_map(|tree_position| {
            // Find metadata by matching hiding_nullifier
            let metadata = note_metadata_map
                .values()
                .find(|meta| meta.hiding_nullifier() == tree_position.nullifier)?;

            let witness = tree.witness(tree_position.leaf_position).ok()?;

            let nf_merkle_proof: Vec<[u8; 32]> = witness
                .iter()
                .map(non_membership_proofs::NonMembershipNode::to_bytes)
                .collect();

            Some(ClaimInput {
                block_height: metadata.block_height(),
                public_inputs: PublicInputs {
                    hiding_nullifier: metadata.hiding_nullifier(),
                },
                private_inputs: metadata.to_private_inputs(&tree_position, nf_merkle_proof),
            })
        })
        .collect()
}

/// Generic pool claim processor.
///
/// Processes claims for any pool type implementing `PoolProcessor`.
#[instrument(skip_all, fields(pool_name = P::POOL_NAME))]
async fn process_pool_claims<P: PoolProcessor>(
    visitor: &AccountNotesVisitor,
    viewing_keys: &ViewingKeys,
    airdrop_config: &AirdropConfiguration,
    snapshot_nullifiers: Option<PathBuf>,
) -> eyre::Result<PoolClaimResult<P::PrivateInputs>> {
    let Some(snapshot_nullifiers) = snapshot_nullifiers else {
        warn!("No snapshot nullifiers provided");
        return Ok(PoolClaimResult::empty());
    };

    let Some(notes) = P::collect_notes(visitor, viewing_keys, airdrop_config)? else {
        warn!("No viewing key available");
        return Ok(PoolClaimResult::empty());
    };

    // Build merkle tree
    let user_nullifiers =
        SanitiseNullifiers::new(notes.values().map(NoteMetadata::hiding_nullifier).collect());
    let pool_data = build_pool_merkle_tree(&snapshot_nullifiers, user_nullifiers).await?;

    // Verify merkle root
    let anchor = pool_data.tree.root().to_bytes();
    ensure!(
        P::expected_root(airdrop_config) == anchor,
        "{} merkle root mismatch with airdrop configuration",
        P::POOL_NAME
    );

    info!("Generating non-membership proofs");
    let claims = generate_proofs(&pool_data.tree, pool_data.user_nullifiers, &notes);

    Ok(PoolClaimResult { anchor, claims })
}

/// Load nullifiers from a file.
#[instrument(fields(path))]
pub async fn load_nullifiers_from_file(path: &Path) -> eyre::Result<SanitiseNullifiers> {
    debug!("Loading nullifiers from file");

    let file = File::open(path).await?;
    let reader = BufReader::with_capacity(BUF_SIZE, file);

    let nullifiers = non_membership_proofs::read_nullifiers(reader)
        .await
        .context(format!("Failed to read {}", path.display()))?;
    let sanitised_nullifiers = SanitiseNullifiers::new(nullifiers);

    info!("Read {} nullifiers from disk", sanitised_nullifiers.len());

    Ok(sanitised_nullifiers)
}
