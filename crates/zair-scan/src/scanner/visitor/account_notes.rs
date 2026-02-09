use incrementalmerkletree::{Position, Retention};
use orchard::tree::MerkleHashOrchard;
use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::proto::service::TreeState;
use zcash_protocol::consensus::BlockHeight;

use super::ScanVisitor;
use crate::scanner::{CommitmentTrees, ScannerError};
use crate::user_nullifiers::{FoundNote, SaplingNote};

/// Account visitor tracking notes and commitment trees
pub struct AccountNotesVisitor {
    trees: CommitmentTrees,
    sapling_notes: Vec<FoundNote<SaplingNote>>,
    orchard_notes: Vec<FoundNote<orchard::Note>>,
    latest_height: Option<BlockHeight>,
}

impl AccountNotesVisitor {
    /// Create from a `TreeState` (required for initialization)
    ///
    /// # Errors
    /// Returns `ScannerError` if sapling or orchard frontiers can not be retrieved
    pub fn from_tree_state(tree_state: &TreeState) -> Result<Self, ScannerError> {
        let height = BlockHeight::from_u32(u32::try_from(tree_state.height)?);

        let sapling_frontier = tree_state
            .sapling_tree()
            .map_err(|e| ScannerError::TreeError(format!("Sapling: {e:?}")))?
            .to_frontier();

        let orchard_frontier = tree_state
            .orchard_tree()
            .map_err(|e| ScannerError::TreeError(format!("Orchard: {e:?}")))?
            .to_frontier();

        let trees = CommitmentTrees::new(&sapling_frontier, &orchard_frontier, height)?;

        Ok(Self {
            trees,
            sapling_notes: Vec::new(),
            orchard_notes: Vec::new(),
            latest_height: None,
        })
    }

    /// Get account's Sapling notes
    #[must_use]
    pub fn sapling_notes(&self) -> &[FoundNote<SaplingNote>] {
        &self.sapling_notes
    }

    /// Get account's Orchard notes
    #[must_use]
    pub fn orchard_notes(&self) -> &[FoundNote<orchard::Note>] {
        &self.orchard_notes
    }

    /// Get latest visitted block height
    #[must_use]
    pub const fn latest_height(&self) -> Option<BlockHeight> {
        self.latest_height
    }

    /// Get Sapling witness for a note position
    ///
    /// # Errors
    /// Returns `ScannerError` if the witness cannot be retrieved
    pub fn sapling_witness(
        &self,
        position: u64,
    ) -> Result<Option<sapling::MerklePath>, ScannerError> {
        self.trees.sapling_witness(Position::from(position))
    }

    /// Get Orchard witness for a note position
    ///
    /// # Errors
    /// Returns `ScannerError` if the witness cannot be retrieved
    pub fn orchard_witness(
        &self,
        position: u64,
    ) -> Result<Option<orchard::tree::MerklePath>, ScannerError> {
        self.trees.orchard_witness(Position::from(position))
    }

    /// Get current Sapling anchor
    ///
    /// # Errors
    /// Returns `ScannerError` if the root cannot be retrieved
    pub fn sapling_anchor(&self) -> Result<sapling::Anchor, ScannerError> {
        self.trees.sapling_root()
    }

    /// Get current Orchard anchor
    ///
    /// # Errors
    /// Returns `ScannerError` if the root cannot be retrieved
    pub fn orchard_anchor(&self) -> Result<orchard::Anchor, ScannerError> {
        self.trees.orchard_root()
    }
}

impl ScanVisitor for AccountNotesVisitor {
    fn on_sapling_note(&mut self, note: &FoundNote<SaplingNote>, _height: BlockHeight) {
        self.sapling_notes.push(note.clone());
    }

    fn on_orchard_note(&mut self, note: &FoundNote<orchard::Note>, _height: BlockHeight) {
        self.orchard_notes.push(note.clone());
    }

    fn on_sapling_commitment(&mut self, node: sapling::Node, retention: Retention<BlockHeight>) {
        let _ = self.trees.append_sapling(&[(node, retention)]);
    }

    fn on_orchard_commitment(
        &mut self,
        node: MerkleHashOrchard,
        retention: Retention<BlockHeight>,
    ) {
        let _ = self.trees.append_orchard(&[(node, retention)]);
    }

    fn on_block_scanned(&mut self, height: BlockHeight, _metadata: &BlockMetadata) {
        self.latest_height = Some(height);
    }
}
