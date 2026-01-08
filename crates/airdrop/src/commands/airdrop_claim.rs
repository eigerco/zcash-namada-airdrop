use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::str::FromStr as _;

use eyre::{ContextCompat as _, ensure};
use futures::StreamExt as _;
use http::Uri;
use non_membership_proofs::source::light_walletd::LightWalletd;
use non_membership_proofs::user_nullifiers::{AnyFoundNote, UserNullifiers as _, ViewingKeys};
use non_membership_proofs::utils::{ReverseBytes as _, SanitiseNullifiers};
use non_membership_proofs::{NonMembershipNode, NonMembershipTree, Nullifier, Pool, TreePosition};
use tracing::{debug, info, instrument, warn};
use zcash_protocol::consensus::{MainNetwork, Network, TestNetwork};

use crate::airdrop_configuration::AirdropConfiguration;
use crate::chain_nullifiers::load_nullifiers_from_file;
use crate::cli::CommonArgs;
use crate::unspent_notes_proofs::{NullifierProof, UnspentNotesProofs};

/// Parameters for processing a single pool's nullifiers.
struct PoolParams {
    pool: Pool,
    snapshot_nullifiers: Option<PathBuf>,
    user_nullifiers: SanitiseNullifiers,
}

#[instrument(skip_all, fields(
    snapshot = %format!("{}..={}", config.snapshot.start(), config.snapshot.end()),
))]
pub async fn airdrop_claim(
    config: CommonArgs,
    sapling_snapshot_nullifiers: Option<PathBuf>,
    orchard_snapshot_nullifiers: Option<PathBuf>,
    viewing_keys: ViewingKeys,
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
        warn!("Airdrop configuration file is not provided. Merkle roots will not be verified");
    }

    let found_notes = find_user_notes(config, &viewing_keys, birthday_height).await?;

    // Partition found notes by pool
    let mut user_nullifiers_by_pool: HashMap<Pool, Vec<Nullifier>> = HashMap::new();
    for note in &found_notes {
        if let Some(nullifier) = note.nullifier(&viewing_keys) {
            user_nullifiers_by_pool
                .entry(note.pool())
                .or_default()
                .push(nullifier);
        } else {
            debug!(height = note.height(), "Skipping note: no viewing key");
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
    if let Some(ref file) = airdrop_configuration_file {
        let airdrop_config: AirdropConfiguration =
            serde_json::from_str(&tokio::fs::read_to_string(file).await?)?;

        verify_merkle_roots(&airdrop_config, &pool_data)?;
    }

    // Generate proofs
    info!("Generating non-membership proofs");

    let mut proofs_by_pool: HashMap<Pool, Vec<NullifierProof>> = HashMap::new();
    for (pool, data) in pool_data {
        let proofs = generate_user_proofs(&data.tree, data.user_nullifiers);
        proofs_by_pool.insert(pool, proofs);
    }

    let total_user_proofs: usize = proofs_by_pool.values().map(Vec::len).sum();

    let user_proofs = UnspentNotesProofs::new(proofs_by_pool);

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
    config: CommonArgs,
    viewing_keys: &ViewingKeys,
    birthday_height: u64,
) -> eyre::Result<Vec<AnyFoundNote>> {
    ensure!(
        birthday_height <= *config.snapshot.end(),
        "Birthday height cannot be greater than the snapshot end height"
    );
    let lightwalletd_url = config
        .source
        .lightwalletd_url
        .as_deref()
        .map(Uri::from_str)
        .context("lightwalletd URL is required")??;

    // Connect to lightwalletd
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    let scan_range = RangeInclusive::new(
        (*config.snapshot.start()).max(birthday_height),
        *config.snapshot.end(),
    );

    // Scan for notes
    info!("Scanning for user notes");
    let mut stream = match config.network {
        Network::TestNetwork => Box::pin(lightwalletd.user_nullifiers::<TestNetwork>(
            &TestNetwork,
            scan_range,
            viewing_keys.clone(),
        )),
        Network::MainNetwork => Box::pin(lightwalletd.user_nullifiers::<MainNetwork>(
            &MainNetwork,
            scan_range,
            viewing_keys.clone(),
        )),
    };

    let mut found_notes = vec![];

    while let Some(found_note) = stream.next().await {
        let found_note = found_note?;

        let Some(nullifier) = found_note.nullifier(viewing_keys) else {
            debug!(
                height = found_note.height(),
                "Skipping note: no viewing key"
            );
            continue;
        };

        info!(
            pool = ?found_note.pool(),
            height = found_note.height(),
            nullifier = %hex::encode::<Nullifier>(nullifier.reverse_bytes().unwrap_or_default()),
            scope = ?found_note.scope(),
            "Found note"
        );

        found_notes.push(found_note);
    }

    info!(total = found_notes.len(), "Scan complete");

    Ok(found_notes)
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

/// Verifies that the merkle roots from the snapshot nullifiers match the airdrop configuration.
///
/// This re-builds the tree from nullifiers to verify the root matches.
fn verify_merkle_roots(
    airdrop_config: &AirdropConfiguration,
    pool_data: &HashMap<Pool, LoadedPoolData>,
) -> eyre::Result<()> {
    let get_root = |pool: Pool| {
        pool_data
            .get(&pool)
            .map(|data| hex::encode(data.tree.root().to_bytes()))
    };

    let sapling_root = get_root(Pool::Sapling);
    ensure!(
        airdrop_config.sapling_merkle_root == sapling_root,
        "Sapling merkle root mismatch with airdrop configuration"
    );

    let orchard_root = get_root(Pool::Orchard);
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

fn generate_user_proofs(
    tree: &NonMembershipTree,
    user_nullifiers: Vec<TreePosition>,
) -> Vec<NullifierProof> {
    user_nullifiers
        .into_iter()
        .filter_map(|tree_position| {
            tree.witness(tree_position.leaf_position)
                .ok()
                .map_or_else(|| {
                    warn!(
                        left_nullifier = %hex::encode::<Nullifier>(tree_position.left_bound.reverse_bytes().unwrap_or_default()),
                        right_nullifier = %hex::encode::<Nullifier>(tree_position.right_bound.reverse_bytes().unwrap_or_default()),
                        "Failed to generate proof"
                    );

                    None
                }, |witness| Some(NullifierProof {
                        left_nullifier: tree_position.left_bound,
                        right_nullifier: tree_position.right_bound,
                        position: tree_position.leaf_position.into(),
                        merkle_proof: witness
                            .iter()
                            .flat_map(NonMembershipNode::to_bytes)
                            .collect(),
                    })
                )
        })
        .collect()
}
