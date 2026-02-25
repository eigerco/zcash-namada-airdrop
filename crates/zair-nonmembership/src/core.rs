//! Shared non-membership types and helpers.

use incrementalmerkletree::Position;
use thiserror::Error;
use zair_core::base::Nullifier;

/// Mapping a nullifier to its gap index (leaf position).
#[derive(Debug, PartialEq, Eq)]
pub struct TreePosition {
    /// The nullifier.
    pub nullifier: Nullifier,
    /// The leaf position (gap index) in the tree.
    pub leaf_position: Position,
    /// The left bound of the gap.
    pub left_bound: Nullifier,
    /// The right bound of the gap.
    pub right_bound: Nullifier,
}

impl TreePosition {
    /// Create a new `TreePosition`.
    ///
    /// # Errors
    /// Returns error if the leaf position (`usize`) cannot be converted to `Position`.
    pub fn new(
        nullifier: Nullifier,
        leaf_position: usize,
        left_bound: Nullifier,
        right_bound: Nullifier,
    ) -> Result<Self, MerklePathError> {
        Ok(Self {
            nullifier,
            leaf_position: leaf_position.try_into()?,
            left_bound,
            right_bound,
        })
    }
}

/// Errors that can occur when working with the Merkle tree.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum MerklePathError {
    /// The position is not marked for witnessing.
    #[error("Position {0} is not marked for witnessing")]
    NotMarked(u64),

    /// Failed to generate witness.
    #[error("Failed to generate witness: {0}")]
    WitnessError(String),

    /// Position conversion error.
    #[error("Position conversion error: {0}")]
    PositionConversionError(#[from] std::num::TryFromIntError),

    /// The tree can support up to 2^32 leaves.
    #[error("Leaves {0} exceeds maximum supported leaves (2^32)")]
    LeavesOverflow(usize),

    /// Orchard nullifier bytes are not a canonical `pallas::Base` encoding.
    #[error("Non-canonical Orchard nullifier at index {index} in {set} set")]
    NonCanonicalOrchardNullifier {
        /// The set being parsed (`chain` or `user`).
        set: &'static str,
        /// Index in the original set.
        index: usize,
    },

    /// Unexpected error.
    #[error("Unexpected error: {0}")]
    Unexpected(&'static str),
}

/// Validate that a leaf count is valid for a non-membership tree.
///
/// # Errors
/// Returns an error if the count is zero or exceeds the tree capacity.
pub fn validate_leaf_count(leaf_count: usize) -> Result<(), MerklePathError> {
    if leaf_count == 0 {
        return Err(MerklePathError::Unexpected(
            "gap-tree leaf count must be greater than zero",
        ));
    }
    if leaf_count >= (1_usize << u32::from(crate::node::NON_MEMBERSHIP_TREE_DEPTH)) {
        return Err(MerklePathError::LeavesOverflow(leaf_count));
    }
    Ok(())
}

pub const fn should_report_progress(current: usize, total: usize, last_pct: &mut usize) -> bool {
    if total == 0 {
        return false;
    }
    #[allow(clippy::arithmetic_side_effects)]
    let pct = current.saturating_mul(100).saturating_div(total);
    if pct >= last_pct.saturating_add(10) {
        *last_pct = pct;
        true
    } else {
        false
    }
}
