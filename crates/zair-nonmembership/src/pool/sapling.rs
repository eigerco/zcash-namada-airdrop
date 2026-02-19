//! Sapling pool helpers shared by sparse and dense non-membership trees.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Gap-bound indexing is validated by caller-controlled bounds"
)]

use zair_core::base::{Nullifier, SanitiseNullifiers};

use crate::core::{MerklePathError, TreePosition};

pub fn map_sapling_user_positions(
    chain_nullifiers: &SanitiseNullifiers,
    user_nullifiers: &SanitiseNullifiers,
) -> Result<Vec<TreePosition>, MerklePathError> {
    let mut mapping = Vec::new();
    for user_nf in user_nullifiers.iter().copied() {
        if let Err(gap_idx) = chain_nullifiers.binary_search(&user_nf) {
            let (left, right) = sapling_gap_bounds(chain_nullifiers, gap_idx);
            mapping.push(TreePosition::new(user_nf, gap_idx, left, right)?);
        }
    }
    Ok(mapping)
}

#[must_use]
pub fn sapling_gap_bounds(nullifiers: &[Nullifier], gap_idx: usize) -> (Nullifier, Nullifier) {
    if nullifiers.is_empty() {
        return (Nullifier::MIN, Nullifier::MAX);
    }

    match gap_idx {
        0 => (Nullifier::MIN, nullifiers[0]),
        i if i == nullifiers.len() => (nullifiers[i - 1], Nullifier::MAX),
        i if i < nullifiers.len() => (nullifiers[i - 1], nullifiers[i]),
        _ => panic!(
            "gap_idx {gap_idx} out of bounds for {} nullifiers",
            nullifiers.len()
        ),
    }
}
