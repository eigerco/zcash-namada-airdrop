//! Block scanning with visitor pattern for commitment tree tracking

mod block_scanner;
mod error;
mod trees;
mod visitor;

pub use block_scanner::BlockScanner;
pub use error::ScannerError;
pub use trees::CommitmentTrees;
pub use visitor::ScanVisitor;
pub use visitor::account_notes::AccountNotesVisitor;
pub use visitor::chain_nullifiers::ChainNullifiersVisitor;
use zcash_client_backend::proto::compact_formats::CompactBlock;

/// Scan a block for nullifiers only (no decryption)
pub fn extract_nullifiers<V: ScanVisitor>(block: &CompactBlock, visitor: &mut V) {
    for tx in &block.vtx {
        for spend in &tx.spends {
            if let Ok(nf) = spend.nf() {
                visitor.on_sapling_nullifier(&nf.0);
            }
        }

        for action in &tx.actions {
            if let Ok(nf) = action.nf() {
                visitor.on_orchard_nullifier(&nf.to_bytes());
            }
        }
    }
}
