//! Stateless block scanner

use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::TreeState;
use zcash_client_backend::scanning::{Nullifiers, ScanningKeys, scan_block};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Network};
use zip32::{AccountId, Scope};

use super::{ScanVisitor, ScannerError};
use crate::user_nullifiers::{FoundNote, NoteMetadata, SaplingNote};

/// Stateless block scanner using visitor pattern
pub struct BlockScanner {
    network: Network,
    scanning_keys: ScanningKeys<AccountId, (AccountId, Scope)>,
    nullifiers: Nullifiers<AccountId>,
}

impl BlockScanner {
    /// Create from a UFVK string
    #[must_use]
    pub fn from_ufvk(ufvk: UnifiedFullViewingKey, network: Network) -> Self {
        let account_id = AccountId::ZERO;
        let scanning_keys = ScanningKeys::from_account_ufvks([(account_id, ufvk)]);

        Self {
            network,
            scanning_keys,
            nullifiers: Nullifiers::empty(),
        }
    }

    /// Scan a block, calling visitor for each event
    ///
    /// # Errors
    /// Returns errors if scanning fails
    pub fn scan_block<V: ScanVisitor>(
        &self,
        block: CompactBlock,
        visitor: &mut V,
        prior_metadata: Option<&BlockMetadata>,
    ) -> Result<BlockMetadata, ScannerError> {
        let height = BlockHeight::from_u32(u32::try_from(block.height)?);

        for tx in &block.vtx {
            for spend in &tx.spends {
                let nf = spend
                    .nf()
                    .map_err(|()| ScannerError::Other("Failed to get Sapling nullifier"))?;
                visitor.on_sapling_nullifier(&nf.0);
            }

            for action in &tx.actions {
                let nf = action
                    .nf()
                    .map_err(|()| ScannerError::Other("Failed to get Orchard nullifier"))?;
                visitor.on_orchard_nullifier(&nf.to_bytes());
            }
        }

        let scanned = scan_block(
            &self.network,
            block,
            &self.scanning_keys,
            &self.nullifiers,
            prior_metadata,
        )
        .map_err(ScannerError::ScanError)?;

        // Notify visitor of commitments first (tree must be updated before notes)
        for (node, retention) in scanned.sapling().commitments() {
            visitor.on_sapling_commitment(*node, *retention);
        }
        for (node, retention) in scanned.orchard().commitments() {
            visitor.on_orchard_commitment(*node, *retention);
        }

        // Then notify of found notes
        for tx in scanned.transactions() {
            let txid = tx.txid();

            for output in tx.sapling_outputs() {
                let note = FoundNote {
                    note: SaplingNote {
                        note: output.note().clone(),
                        position: output.note_commitment_tree_position().into(),
                        scope: output.recipient_key_scope().ok_or({
                            ScannerError::Other("Sapling output missing recipient key scope")
                        })?,
                    },
                    metadata: NoteMetadata {
                        height: height.into(),
                        txid,
                        scope: output.recipient_key_scope().ok_or({
                            ScannerError::Other("Sapling output missing recipient key scope")
                        })?,
                        position: output.note_commitment_tree_position().into(),
                    },
                };
                visitor.on_sapling_note(&note, height);
            }

            for output in tx.orchard_outputs() {
                let note = FoundNote {
                    note: *output.note(),
                    metadata: NoteMetadata {
                        height: height.into(),
                        txid,
                        scope: output.recipient_key_scope().ok_or({
                            ScannerError::Other("Orchard output missing recipient key scope")
                        })?,
                        position: output.note_commitment_tree_position().into(),
                    },
                };
                visitor.on_orchard_note(&note, height);
            }
        }

        let metadata = scanned.to_block_metadata();
        visitor.on_block_scanned(height, &metadata);

        Ok(metadata)
    }

    /// Parse `TreeState` into `BlockMetadata` for initialization
    ///
    /// # Errors
    /// Returns errors if hash decoding fails or if number conversions fail
    pub fn parse_tree_state(tree_state: &TreeState) -> Result<BlockMetadata, ScannerError> {
        let height = BlockHeight::from_u32(u32::try_from(tree_state.height)?);

        let mut hash_bytes = hex::decode(&tree_state.hash)
            .map_err(|e| ScannerError::TreeError(format!("Parse hash: {e:?}")))?;
        hash_bytes.reverse();
        let block_hash = BlockHash::try_from_slice(&hash_bytes)
            .ok_or_else(|| ScannerError::TreeError("Invalid hash length".to_string()))?;

        let sapling_tree = tree_state
            .sapling_tree()
            .map_err(|e| ScannerError::TreeError(format!("Sapling tree: {e:?}")))?;
        let sapling_size = u32::try_from(
            sapling_tree
                .to_frontier()
                .value()
                .map_or(0, |f| u64::from(f.position()).saturating_add(1)),
        )?;

        let orchard_tree = tree_state
            .orchard_tree()
            .map_err(|e| ScannerError::TreeError(format!("Orchard tree: {e:?}")))?;
        let orchard_size = u32::try_from(
            orchard_tree
                .to_frontier()
                .value()
                .map_or(0, |f| u64::from(f.position()).saturating_add(1)),
        )?;

        Ok(BlockMetadata::from_parts(
            height,
            block_hash,
            Some(sapling_size),
            Some(orchard_size),
        ))
    }
}
