use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use eyre::{Context as _, ensure};
use http::Uri;
use non_membership_proofs::light_walletd::LightWalletd;
use non_membership_proofs::scanner::{AccountNotesVisitor, BlockScanner};
use non_membership_proofs::user_nullifiers::NoteNullifier as _;
use non_membership_proofs::{
    NonMembershipTree, Nullifier, Pool, SanitiseNullifiers, TreePosition, ViewingKeys,
};
use tokio::fs::File;
use tokio::io::BufReader;
use tracing::{debug, info, instrument, warn};
use zcash_keys::keys::UnifiedFullViewingKey;
use zip32::Scope;

use crate::BUF_SIZE;
use crate::cli::CommonArgs;
use crate::commands::airdrop_configuration::AirdropConfiguration;
use crate::unspent_notes_proofs::{
    NullifierProof, OrchardPrivateInputs, PrivateInputs, PublicInputs, SaplingPrivateInputs,
    UnspentNotesProofs,
};

/// Metadata collected from a found note needed for proof generation.
#[derive(Debug, Clone)]
enum NoteMetadata {
    /// Sapling note metadata
    Sapling(Box<SaplingNoteMetadata>),
    /// Orchard note metadata
    Orchard(Box<OrchardNoteMetadata>),
}

/// Metadata for a Sapling note.
#[derive(Debug, Clone)]
struct SaplingNoteMetadata {
    /// The hiding nullifier (public input)
    hiding_nullifier: Nullifier,
    /// Diversified generator
    g_d: [u8; 32],
    /// Diversified transmission key
    pk_d: [u8; 32],
    /// Note value in zatoshis
    value: u64,
    /// Commitment randomness
    rcm: [u8; 32],
    /// The note position in the commitment tree.
    note_position: u64,
    /// The scope of the note (External for received payments, Internal for change).
    scope: Scope,
    /// The block height where the note was created
    block_height: u64,
    /// Merkle proof for the note commitment
    cm_merkle_proof: sapling::MerklePath,
}

/// Metadata for an Orchard note.
#[derive(Debug, Clone)]
struct OrchardNoteMetadata {
    /// The hiding nullifier (public input)
    hiding_nullifier: Nullifier,
    /// The note commitment
    note_commitment: [u8; 32],
    /// The block height where the note was created
    block_height: u64,
    /// Merkle proof for the note commitment
    cm_merkle_proof: orchard::tree::MerklePath,
}

/// Parameters for processing a single pool's nullifiers.
struct PoolParams {
    pool: Pool,
    snapshot_nullifiers: Option<PathBuf>,
    user_nullifiers: SanitiseNullifiers,
}

/// Generate airdrop claim
///
/// Generate airdrop claim proof for the given unified full viewing key (UFVK)
/// and output them to the specified file. The function scans the blockchain
/// for notes associated with the UFVK, constructs non-membership Merkle trees
/// for the provided snapshot nullifiers, and generates non-membership proofs
/// for the user's notes.
///
/// # Errors
/// This function will return an error if any step in the process fails,
/// including scanning for notes, loading nullifiers, building Merkle trees,
/// or generating proofs.
#[allow(
    clippy::too_many_lines,
    reason = "Too many steps involved in airdrop claim generation"
)]
#[instrument(skip_all, fields(
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
    let visitor = find_user_notes(&config, ufvk.clone(), birthday_height).await?;

    // Partition found notes by pool and collect note metadata
    let mut user_nullifiers_by_pool: HashMap<Pool, Vec<Nullifier>> = HashMap::new();
    let mut note_metadata_map: HashMap<Nullifier, NoteMetadata> = HashMap::new();

    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(airdrop_configuration_file).await?)?;

    let orchard_hiding_factor: non_membership_proofs::user_nullifiers::OrchardHidingFactor =
        (&airdrop_config.hiding_factor.orchard).into();
    let sapling_hiding_factor: non_membership_proofs::user_nullifiers::SaplingHidingFactor =
        (&airdrop_config.hiding_factor.sapling).into();

    let viewing_keys = ViewingKeys::new(&ufvk);

    // Process Sapling notes
    if let Some(sapling_key) = viewing_keys.sapling() {
        for found_note in visitor.sapling_notes() {
            let nullifier = found_note.nullifier(sapling_key);
            let hiding_nullifier =
                found_note.hiding_nullifier(sapling_key, &sapling_hiding_factor)?;

            let cm_merkle_proof = visitor
                .sapling_witness(found_note.note.position)?
                .ok_or_else(|| {
                    eyre::eyre!(
                        "Missing Sapling witness for position {}",
                        found_note.note.position
                    )
                })?;

            note_metadata_map.insert(
                nullifier,
                NoteMetadata::Sapling(Box::new(SaplingNoteMetadata {
                    hiding_nullifier,
                    g_d: found_note.note.g_d(),
                    pk_d: found_note.note.pk_d(),
                    value: found_note.note.note.value().inner(),
                    rcm: found_note.note.rcm(),
                    note_position: found_note.note.position,
                    scope: found_note.note.scope,
                    block_height: found_note.metadata.height,
                    cm_merkle_proof,
                })),
            );
            user_nullifiers_by_pool
                .entry(Pool::Sapling)
                .or_default()
                .push(nullifier);
        }
    }

    // Process Orchard notes
    if let Some(orchard_key) = viewing_keys.orchard() {
        for found_note in visitor.orchard_notes() {
            let nullifier = found_note.nullifier(orchard_key);
            let hiding_nullifier =
                found_note.hiding_nullifier(orchard_key, &orchard_hiding_factor)?;

            let cm_merkle_proof = visitor
                .orchard_witness(found_note.metadata.position)?
                .ok_or_else(|| {
                    eyre::eyre!(
                        "Missing Orchard witness for position {}",
                        found_note.metadata.position
                    )
                })?;

            note_metadata_map.insert(
                nullifier,
                NoteMetadata::Orchard(Box::new(OrchardNoteMetadata {
                    hiding_nullifier,
                    note_commitment: found_note.note_commitment(),
                    block_height: found_note.metadata.height,
                    cm_merkle_proof,
                })),
            );
            user_nullifiers_by_pool
                .entry(Pool::Orchard)
                .or_default()
                .push(nullifier);
        }
    }

    // Build pool parameters
    let pools = [
        PoolParams {
            pool: Pool::Sapling,
            snapshot_nullifiers: sapling_snapshot_nullifiers,
            user_nullifiers: SanitiseNullifiers::new(
                user_nullifiers_by_pool
                    .remove(&Pool::Sapling)
                    .unwrap_or_default(),
            ),
        },
        PoolParams {
            pool: Pool::Orchard,
            snapshot_nullifiers: orchard_snapshot_nullifiers,
            user_nullifiers: SanitiseNullifiers::new(
                user_nullifiers_by_pool
                    .remove(&Pool::Orchard)
                    .unwrap_or_default(),
            ),
        },
    ];

    // Process pools in parallel
    let [sapling_result, orchard_result] = pools.map(build_pool_merkle_tree);
    let (sapling_result, orchard_result) = tokio::try_join!(sapling_result, orchard_result)?;

    // Collect results into a HashMap keyed by Pool
    let mut pool_data: HashMap<Pool, LoadedPoolData> = HashMap::new();
    if let Some(data) = sapling_result {
        pool_data.insert(Pool::Sapling, data);
    }
    if let Some(data) = orchard_result {
        pool_data.insert(Pool::Orchard, data);
    }

    // Verify merkle roots if configuration file is provided
    verify_merkle_roots(&airdrop_config, &pool_data)?;

    // Generate proofs
    info!("Generating non-membership proofs");

    // Extract merkle roots before consuming pool_data
    let sapling_merkle_root = pool_data
        .get(&Pool::Sapling)
        .map_or([0u8; 32], |data| data.tree.root().to_bytes());
    let orchard_merkle_root = pool_data
        .get(&Pool::Orchard)
        .map_or([0u8; 32], |data| data.tree.root().to_bytes());

    let mut proofs_by_pool: HashMap<Pool, Vec<NullifierProof>> = HashMap::new();
    for (pool, data) in pool_data {
        let proofs = generate_user_proofs(&data.tree, data.user_nullifiers, &note_metadata_map);
        proofs_by_pool.insert(pool, proofs);
    }

    let total_user_proofs: usize = proofs_by_pool.values().map(Vec::len).sum();

    let user_proofs = UnspentNotesProofs::new(
        sapling_merkle_root,
        orchard_merkle_root,
        airdrop_config.note_commitment_tree_anchors,
        proofs_by_pool,
    );

    let json = serde_json::to_string_pretty(&user_proofs)?;
    tokio::fs::write(&airdrop_claims_output_file, json).await?;

    info!(
        file = ?airdrop_claims_output_file,
        count = total_user_proofs,
        "Proofs written"
    );

    Ok(())
}

async fn find_user_notes(
    config: &CommonArgs, // Note: take reference now
    ufvk: UnifiedFullViewingKey,
    birthday_height: u64,
) -> eyre::Result<AccountNotesVisitor> {
    ensure!(
        birthday_height <= *config.snapshot.end(),
        "Birthday height cannot be greater than the snapshot end height"
    );

    let lightwalletd_url =
        Uri::from_str(&config.lightwalletd_url).context("lightwalletd URL is required")?;
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    // Get tree state before scan range for initialization
    let tree_state_height = (*config.snapshot.start())
        .max(birthday_height)
        .saturating_sub(1);
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

/// Loaded pool data including the non-membership merkle-tree, user's nullifiers, and all the
/// on-chain nullifiers.
struct LoadedPoolData {
    /// The non-membership merkle tree for the pool.
    tree: NonMembershipTree,
    /// The user's nullifiers with the metadata needed to generate proofs.
    user_nullifiers: Vec<TreePosition>,
}

#[instrument(skip(params), fields(pool = ?params.pool))]
async fn build_pool_merkle_tree(params: PoolParams) -> eyre::Result<Option<LoadedPoolData>> {
    let PoolParams {
        pool,
        snapshot_nullifiers,
        user_nullifiers,
    } = params;

    let Some(snapshot_nullifiers) = snapshot_nullifiers else {
        warn!(?pool, "No snapshot nullifiers provided");
        return Ok(None);
    };

    let nullifiers = load_nullifiers_from_file(&snapshot_nullifiers).await?;
    let nullifiers = SanitiseNullifiers::new(nullifiers);

    info!(?pool, count = nullifiers.len(), "Loaded nullifiers");

    let loaded_data = tokio::task::spawn_blocking(move || {
        let (tree, user_nullifiers) =
            NonMembershipTree::from_chain_and_user_nullifiers(&nullifiers, &user_nullifiers)?;
        let loaded_data = LoadedPoolData {
            tree,
            user_nullifiers,
        };
        Ok::<_, non_membership_proofs::MerklePathError>(loaded_data)
    })
    .await??;

    Ok(Some(loaded_data))
}

fn verify_merkle_roots(
    airdrop_config: &AirdropConfiguration,
    pool_data: &HashMap<Pool, LoadedPoolData>,
) -> eyre::Result<()> {
    let get_root = |pool: Pool| pool_data.get(&pool).map(|data| data.tree.root().to_bytes());

    let sapling_root = get_root(Pool::Sapling);
    ensure!(
        airdrop_config.non_membership_tree_anchors.sapling == sapling_root.unwrap_or_default(),
        "Sapling merkle root mismatch with airdrop configuration"
    );

    let orchard_root = get_root(Pool::Orchard);
    ensure!(
        airdrop_config.non_membership_tree_anchors.orchard == orchard_root.unwrap_or_default(),
        "Orchard merkle root mismatch with airdrop configuration"
    );

    info!(
        ?airdrop_config.non_membership_tree_anchors,
        "Airdrop configuration merkle roots verified"
    );
    Ok(())
}

fn generate_user_proofs(
    tree: &NonMembershipTree,
    user_nullifiers: Vec<TreePosition>,
    note_metadata_map: &HashMap<Nullifier, NoteMetadata>,
) -> Vec<NullifierProof> {
    user_nullifiers
        .into_iter()
        .filter_map(|tree_position| {
            let metadata = note_metadata_map.get(&tree_position.nullifier);

            let Some(metadata) = metadata else {
                warn!(
                    nullifier = %tree_position.nullifier,
                    "Missing note metadata for user nullifier"
                );
                return None;
            };

            tree.witness(tree_position.leaf_position).ok().map_or_else(
                || {
                    warn!(
                        left_nullifier = %tree_position.left_bound,
                        right_nullifier = %tree_position.right_bound,
                        "Failed to generate proof"
                    );

                    None
                },
                |witness| {
                    let nf_merkle_proof: Vec<[u8; 32]> = witness
                        .iter()
                        .map(non_membership_proofs::NonMembershipNode::to_bytes)
                        .collect();

                    let (hiding_nullifier, block_height, private_inputs) = match metadata {
                        NoteMetadata::Sapling(meta) => {
                            let cm_merkle_proof: Vec<[u8; 32]> = meta
                                .cm_merkle_proof
                                .path_elems()
                                .iter()
                                .map(sapling::Node::to_bytes)
                                .collect();

                            (
                                meta.hiding_nullifier,
                                meta.block_height,
                                PrivateInputs::Sapling(SaplingPrivateInputs {
                                    g_d: meta.g_d,
                                    pk_d: meta.pk_d,
                                    value: meta.value,
                                    rcm: meta.rcm,
                                    cm_note_position: meta.note_position,
                                    scope: meta.scope.into(),
                                    cm_merkle_proof,
                                    left_nullifier: tree_position.left_bound,
                                    right_nullifier: tree_position.right_bound,
                                    nf_leaf_position: tree_position.leaf_position.into(),
                                    nf_merkle_proof,
                                }),
                            )
                        }
                        NoteMetadata::Orchard(meta) => {
                            let cm_merkle_proof: Vec<[u8; 32]> = meta
                                .cm_merkle_proof
                                .auth_path()
                                .iter()
                                .map(orchard::tree::MerkleHashOrchard::to_bytes)
                                .collect();

                            (
                                meta.hiding_nullifier,
                                meta.block_height,
                                PrivateInputs::Orchard(OrchardPrivateInputs {
                                    nullifier: tree_position.nullifier,
                                    note_commitment: meta.note_commitment,
                                    cm_merkle_proof,
                                    left_nullifier: tree_position.left_bound,
                                    right_nullifier: tree_position.right_bound,
                                    nf_leaf_position: tree_position.leaf_position.into(),
                                    nf_merkle_proof,
                                }),
                            )
                        }
                    };

                    Some(NullifierProof {
                        block_height,
                        public_inputs: PublicInputs { hiding_nullifier },
                        private_inputs,
                    })
                },
            )
        })
        .collect()
}

/// Load nullifiers from a file
#[instrument(fields(path))]
pub async fn load_nullifiers_from_file(path: &Path) -> eyre::Result<Vec<Nullifier>> {
    debug!("Loading nullifiers from file");

    let file = File::open(path).await?;
    let reader = BufReader::with_capacity(BUF_SIZE, file);

    let mut nullifiers = non_membership_proofs::read_nullifiers(reader)
        .await
        .context(format!("Failed to read {}", path.display()))?;
    if !nullifiers.is_sorted() {
        nullifiers.sort_unstable();
    }

    debug!("Read {} nullifiers from disk", nullifiers.len());

    Ok(nullifiers)
}
