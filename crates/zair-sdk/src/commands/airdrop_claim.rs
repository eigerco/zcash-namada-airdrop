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
use tokio::fs::File;
use tokio::io::BufReader;
use tracing::{debug, info, instrument, warn};
use zair_core::base::{Nullifier, SanitiseNullifiers};
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::proof_inputs::{AirdropClaimInputs, ClaimInput, PublicInputs};
use zair_nonmembership::{MerklePathError, NonMembershipNode, NonMembershipTree, TreePosition};
use zair_scan::ViewingKeys;
use zair_scan::light_walletd::LightWalletd;
use zair_scan::scanner::{AccountNotesVisitor, BlockScanner};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Network;

use super::note_metadata::NoteMetadata;
use super::pool_processor::{OrchardPool, PoolClaimResult, PoolProcessor, SaplingPool};
use crate::common::{resolve_lightwalletd_url, to_zcash_network};
/// 1 MiB buffer for file I/O.
const FILE_BUF_SIZE: usize = 1024 * 1024;

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
    lightwalletd_url = ?lightwalletd_url,
))]
pub async fn airdrop_claim(
    lightwalletd_url: Option<String>,
    sapling_snapshot_nullifiers: Option<PathBuf>,
    orchard_snapshot_nullifiers: Option<PathBuf>,
    unified_full_viewing_key: String,
    birthday_height: u64,
    airdrop_claims_output_file: PathBuf,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(airdrop_configuration_file).await?)?;
    validate_pool_inputs(
        &airdrop_config,
        sapling_snapshot_nullifiers.as_ref(),
        orchard_snapshot_nullifiers.as_ref(),
    )?;

    let network = to_zcash_network(airdrop_config.network);
    let lightwalletd_url = resolve_lightwalletd_url(network, lightwalletd_url.as_deref());
    let ufvk = UnifiedFullViewingKey::decode(&network, &unified_full_viewing_key)
        .map_err(|e| eyre::eyre!("Failed to decode Unified Full Viewing Key: {e:?}"))?;

    let account_notes = find_user_notes(
        &lightwalletd_url,
        network,
        airdrop_config.snapshot_height,
        ufvk.clone(),
        birthday_height,
    )
    .await?;

    let viewing_keys = ViewingKeys::new(&ufvk);

    // Process pools in parallel
    let (sapling_result, orchard_result) = tokio::try_join!(
        process_pool_claims::<SaplingPool>(
            airdrop_config.sapling.is_some(),
            &account_notes,
            &viewing_keys,
            &airdrop_config,
            sapling_snapshot_nullifiers,
        ),
        process_pool_claims::<OrchardPool>(
            airdrop_config.orchard.is_some(),
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

    let user_proofs = AirdropClaimInputs::new(
        sapling_result.anchor,
        orchard_result.anchor,
        airdrop_config.note_commitment_tree_anchors(),
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

fn validate_pool_inputs(
    airdrop_config: &AirdropConfiguration,
    sapling_snapshot_nullifiers: Option<&PathBuf>,
    orchard_snapshot_nullifiers: Option<&PathBuf>,
) -> eyre::Result<()> {
    let config_has_sapling = airdrop_config.sapling.is_some();
    let config_has_orchard = airdrop_config.orchard.is_some();

    ensure!(
        config_has_sapling || config_has_orchard,
        "Airdrop configuration must enable at least one pool (sapling/orchard)"
    );

    ensure!(
        !(config_has_sapling && sapling_snapshot_nullifiers.is_none()),
        "Airdrop configuration enables Sapling, but --sapling-snapshot-nullifiers is missing"
    );
    ensure!(
        config_has_sapling || sapling_snapshot_nullifiers.is_none(),
        "Sapling snapshot file was provided, but configuration has no sapling pool"
    );

    ensure!(
        !(config_has_orchard && orchard_snapshot_nullifiers.is_none()),
        "Airdrop configuration enables Orchard, but --orchard-snapshot-nullifiers is missing"
    );
    ensure!(
        config_has_orchard || orchard_snapshot_nullifiers.is_none(),
        "Orchard snapshot file was provided, but configuration has no orchard pool"
    );

    Ok(())
}

/// Scan the blockchain for user notes within the snapshot range.
#[instrument(skip_all)]
async fn find_user_notes(
    lightwalletd_url: &str,
    network: Network,
    snapshot_height: u64,
    ufvk: UnifiedFullViewingKey,
    birthday_height: u64,
) -> eyre::Result<AccountNotesVisitor> {
    ensure!(
        birthday_height <= snapshot_height,
        "Birthday height cannot be past snapshot height"
    );

    let lightwalletd_url =
        Uri::from_str(lightwalletd_url).context("lightwalletd URL is required")?;
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    // NOTE: We are interested at tree state from the point that the account could have notes
    let start_block = birthday_height;
    let tree_state_height = start_block.saturating_sub(1);
    let tree_state = lightwalletd.get_tree_state(tree_state_height).await?;

    // Initialize visitor from tree state
    let visitor = AccountNotesVisitor::from_tree_state(&tree_state)?;

    let scan_range = RangeInclusive::new(birthday_height, snapshot_height);

    info!("Scanning for user notes");
    let initial_metadata = BlockScanner::parse_tree_state(&tree_state)?;

    // Use channel-based scanning to keep non-Send BlockScanner off async tasks
    let (visitor, _final_metadata) = lightwalletd
        .scan_blocks_spawned(ufvk, network, visitor, &scan_range, Some(initial_metadata))
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
        Ok::<_, MerklePathError>(LoadedPoolData {
            tree,
            user_nullifiers,
        })
    })
    .await??;

    Ok(loaded_data)
}

/// Generate airdrop claims for the user's notes.
///
/// This generic function works with any metadata type implementing `NoteMetadata`,
/// producing claim inputs with the appropriate pool-specific private inputs.
fn generate_claims<M: NoteMetadata>(
    tree: &NonMembershipTree,
    user_nullifiers: &[TreePosition],
    note_metadata_map: &HashMap<Nullifier, M>,
    viewing_keys: &ViewingKeys,
) -> Vec<ClaimInput<M::PoolPrivateInputs>> {
    user_nullifiers
        .iter()
        .filter_map(|tree_position| {
            let metadata = note_metadata_map.get(&tree_position.nullifier)?;

            let nf_merkle_proof: Vec<[u8; 32]> = tree
                .witness(tree_position.leaf_position)
                .ok()?
                .iter()
                .map(NonMembershipNode::to_bytes)
                .collect();

            debug!(
                "Generated proof for nullifier {:x?} at block height {}",
                tree_position.nullifier,
                metadata.block_height()
            );

            Some(ClaimInput {
                block_height: metadata.block_height(),
                public_inputs: PublicInputs {
                    hiding_nullifier: metadata.hiding_nullifier(),
                },
                private_inputs: metadata
                    .to_private_inputs(tree_position, nf_merkle_proof, viewing_keys)
                    .ok()?,
            })
        })
        .collect()
}

/// Generic pool claim processor.
///
/// Processes claims for any pool type implementing `PoolProcessor`.
#[instrument(skip_all, fields(pool_name = P::POOL_NAME))]
async fn process_pool_claims<P: PoolProcessor>(
    pool_enabled_in_config: bool,
    visitor: &AccountNotesVisitor,
    viewing_keys: &ViewingKeys,
    airdrop_config: &AirdropConfiguration,
    snapshot_nullifiers: Option<PathBuf>,
) -> eyre::Result<PoolClaimResult<P::PrivateInputs>> {
    if !pool_enabled_in_config {
        return Ok(PoolClaimResult::empty());
    }

    let Some(snapshot_nullifiers) = snapshot_nullifiers else {
        return Err(eyre::eyre!(
            "{} snapshot nullifiers path is required by the airdrop configuration",
            P::POOL_NAME
        ));
    };

    let Some(notes) = P::collect_notes(visitor, viewing_keys, airdrop_config)? else {
        warn!("UFVK has no {} viewing key; skipping", P::POOL_NAME);
        return Ok(PoolClaimResult::empty());
    };

    // Build merkle tree
    let user_nullifiers = SanitiseNullifiers::new(notes.keys().copied().collect());
    let pool_data = build_pool_merkle_tree(&snapshot_nullifiers, user_nullifiers).await?;

    // Verify merkle root
    let anchor = pool_data.tree.root().to_bytes();
    let Some(expected_root) = P::expected_root(airdrop_config) else {
        return Err(eyre::eyre!(
            "{} pool is unexpectedly missing in the airdrop configuration",
            P::POOL_NAME
        ));
    };
    ensure!(
        expected_root == anchor,
        "{} merkle root mismatch with airdrop configuration",
        P::POOL_NAME
    );

    info!("Generating non-membership proofs");
    let claims = generate_claims(
        &pool_data.tree,
        &pool_data.user_nullifiers,
        &notes,
        viewing_keys,
    );

    Ok(PoolClaimResult { anchor, claims })
}

/// Load nullifiers from a file.
#[instrument(fields(path))]
pub async fn load_nullifiers_from_file(path: &Path) -> eyre::Result<SanitiseNullifiers> {
    debug!("Loading nullifiers from file");

    let file = File::open(path).await?;
    let reader = BufReader::with_capacity(FILE_BUF_SIZE, file);

    let nullifiers = zair_scan::read_nullifiers(reader)
        .await
        .context(format!("Failed to read {}", path.display()))?;
    let sanitised_nullifiers = SanitiseNullifiers::new(nullifiers);

    info!("Read {} nullifiers from disk", sanitised_nullifiers.len());

    Ok(sanitised_nullifiers)
}
