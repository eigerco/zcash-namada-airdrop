//! Visitor trait for block scanning

use incrementalmerkletree::Retention;
use orchard::tree::MerkleHashOrchard;
use zcash_client_backend::data_api::BlockMetadata;
use zcash_protocol::consensus::BlockHeight;

use crate::user_nullifiers::{FoundNote, SaplingNote};

pub mod account_notes;
pub mod chain_nullifiers;

/// Visitor trait for processing scan events.
pub trait ScanVisitor {
    /// Called when a Sapling note is found.
    fn on_sapling_note(&mut self, _note: &FoundNote<SaplingNote>, _height: BlockHeight) {}

    /// Called when an Orchard note is found.
    fn on_orchard_note(&mut self, _note: &FoundNote<orchard::Note>, _height: BlockHeight) {}

    /// Called for every Sapling commitment in the block.
    fn on_sapling_commitment(&mut self, _node: sapling::Node, _retention: Retention<BlockHeight>) {}

    /// Called for every Orchard commitment in the block.
    fn on_orchard_commitment(
        &mut self,
        _node: MerkleHashOrchard,
        _retention: Retention<BlockHeight>,
    ) {
    }

    /// Called when a Sapling nullifier is found.
    fn on_sapling_nullifier(&mut self, _nullifier: &[u8; 32]) {}

    /// Called when an Orchard nullifier is found.
    fn on_orchard_nullifier(&mut self, _nullifier: &[u8; 32]) {}

    /// Called after a block is fully processed.
    fn on_block_scanned(&mut self, _height: BlockHeight, _metadata: &BlockMetadata) {}
}
