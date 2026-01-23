//! Commitment tree management using `ShardTree`

use incrementalmerkletree::frontier::Frontier;
use incrementalmerkletree::{Hashable, Marking, MerklePath, Position, Retention};
use orchard::tree::MerkleHashOrchard;
use shardtree::ShardTree;
use shardtree::store::ShardStore;
use shardtree::store::memory::MemoryShardStore;
use zcash_protocol::consensus::BlockHeight;

use super::ScannerError;

const SAPLING_SHARD_HEIGHT: u8 = sapling::NOTE_COMMITMENT_TREE_DEPTH / 2;
// Hardcoded to avoid usize->u8 cast; assertion ensures it matches the library
const ORCHARD_TREE_DEPTH: u8 = 32;
const _: () = assert!(orchard::NOTE_COMMITMENT_TREE_DEPTH == 32);
const ORCHARD_SHARD_HEIGHT: u8 = ORCHARD_TREE_DEPTH / 2;
const MAX_CHECKPOINTS: usize = 100;

type SaplingTree = ShardTree<
    MemoryShardStore<sapling::Node, BlockHeight>,
    { sapling::NOTE_COMMITMENT_TREE_DEPTH },
    SAPLING_SHARD_HEIGHT,
>;

type OrchardTree = ShardTree<
    MemoryShardStore<MerkleHashOrchard, BlockHeight>,
    ORCHARD_TREE_DEPTH,
    ORCHARD_SHARD_HEIGHT,
>;

/// Manages Sapling and Orchard commitment trees
#[derive(Debug)]
pub struct CommitmentTrees {
    sapling: SaplingTree,
    orchard: OrchardTree,
}

impl CommitmentTrees {
    /// Creates new empty commitment trees
    ///
    /// # Errors
    /// Returns `ScannerError` if initialization fails
    pub fn new(
        sapling_frontier: &Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>,
        orchard_frontier: &Frontier<MerkleHashOrchard, ORCHARD_TREE_DEPTH>,
        checkpoint_height: BlockHeight,
    ) -> Result<Self, ScannerError> {
        let mut sapling_tree = ShardTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
        init_frontier(
            &mut sapling_tree,
            sapling_frontier,
            checkpoint_height,
            "Sapling",
        )?;

        let mut orchard_tree = ShardTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
        init_frontier(
            &mut orchard_tree,
            orchard_frontier,
            checkpoint_height,
            "Orchard",
        )?;

        Ok(Self {
            sapling: sapling_tree,
            orchard: orchard_tree,
        })
    }

    /// Appends Sapling commitments to the Sapling note commitment merkle-tree
    ///
    /// # Errors
    /// Returns `ScannerError` if appending fails
    pub fn append_sapling(
        &mut self,
        commitments: &[(sapling::Node, Retention<BlockHeight>)],
    ) -> Result<(), ScannerError> {
        append_commitments(&mut self.sapling, commitments, "Sapling")
    }

    /// Appends Orchard commitments to the Orchard note commitment merkle-tree
    ///
    /// # Errors
    /// Returns `ScannerError` if appending fails
    pub fn append_orchard(
        &mut self,
        commitments: &[(MerkleHashOrchard, Retention<BlockHeight>)],
    ) -> Result<(), ScannerError> {
        append_commitments(&mut self.orchard, commitments, "Orchard")
    }

    /// Retrieves a Sapling note commitment witness at the given position
    ///
    /// # Errors
    /// Returns `ScannerError` if the witness cannot be retrieved
    pub fn sapling_witness(
        &self,
        position: Position,
    ) -> Result<Option<sapling::MerklePath>, ScannerError> {
        witness(&self.sapling, position, "Sapling")
    }

    /// Retrieves an Orchard note commitment witness at the given position
    ///
    /// # Errors
    /// Returns `ScannerError` if the witness cannot be retrieved
    pub fn orchard_witness(
        &self,
        position: Position,
    ) -> Result<Option<orchard::tree::MerklePath>, ScannerError> {
        witness(&self.orchard, position, "Orchard")
    }

    /// Retrieves the current Sapling note commitment tree root
    ///
    /// # Errors
    /// Returns `ScannerError` if the root cannot be retrieved
    pub fn sapling_root(&self) -> Result<sapling::Anchor, ScannerError> {
        root(&self.sapling, "Sapling")
    }

    /// Retrieves the current Orchard note commitment tree root
    ///
    /// # Errors
    /// Returns `ScannerError` if the root cannot be retrieved
    pub fn orchard_root(&self) -> Result<orchard::Anchor, ScannerError> {
        root(&self.orchard, "Orchard")
    }
}

// Generic helper functions

fn init_frontier<H, S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<S, DEPTH, SHARD_HEIGHT>,
    frontier: &Frontier<H, DEPTH>,
    checkpoint_height: BlockHeight,
    name: &str,
) -> Result<(), ScannerError>
where
    H: Hashable + Clone + PartialEq,
    S: ShardStore<H = H, CheckpointId = BlockHeight>,
{
    if let Some(nonempty_frontier) = frontier.value() {
        tree.insert_frontier_nodes(
            nonempty_frontier.clone(),
            Retention::Checkpoint {
                id: checkpoint_height,
                marking: Marking::Reference,
            },
        )
        .map_err(|e| ScannerError::TreeError(format!("{name} frontier insert: {e:?}")))?;
    }
    Ok(())
}

fn append_commitments<H, S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<S, DEPTH, SHARD_HEIGHT>,
    commitments: &[(H, Retention<BlockHeight>)],
    name: &str,
) -> Result<(), ScannerError>
where
    H: Hashable + Clone + PartialEq,
    S: ShardStore<H = H, CheckpointId = BlockHeight>,
{
    for (node, retention) in commitments {
        tree.append(node.clone(), *retention)
            .map_err(|e| ScannerError::TreeError(format!("{name} append: {e:?}")))?;
    }
    Ok(())
}

fn witness<H, S, P, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<S, DEPTH, SHARD_HEIGHT>,
    position: Position,
    name: &str,
) -> Result<Option<P>, ScannerError>
where
    H: Hashable + Clone + PartialEq,
    S: ShardStore<H = H, CheckpointId = BlockHeight>,
    P: From<MerklePath<H, DEPTH>>,
{
    tree.witness_at_checkpoint_depth(position, 0)
        .map(|opt| opt.map(Into::into))
        .map_err(|e| ScannerError::TreeError(format!("{name} witness: {e:?}")))
}

fn root<H, S, A, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<S, DEPTH, SHARD_HEIGHT>,
    name: &str,
) -> Result<A, ScannerError>
where
    H: Hashable + Clone + PartialEq,
    S: ShardStore<H = H, CheckpointId = BlockHeight>,
    A: From<H>,
{
    tree.root_at_checkpoint_depth(Some(0))
        .map_err(|e| ScannerError::TreeError(format!("{name} root: {e:?}")))?
        .map(Into::into)
        .ok_or_else(|| ScannerError::TreeError(format!("No {name} root available")))
}
