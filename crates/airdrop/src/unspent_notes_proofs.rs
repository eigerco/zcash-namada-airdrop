//! Helpers for serializing nullifiers non-membership proofs.

use std::collections::HashMap;

use non_membership_proofs::{Nullifier, Pool};
use serde::Serialize;
use serde_with::hex::Hex;
use serde_with::serde_as;

#[derive(Serialize)]
pub struct UnspentNotesProofs {
    pools: HashMap<Pool, Vec<NullifierProof>>,
}

impl UnspentNotesProofs {
    /// Create a new `UnspentNotesProofs` from a map of pool proofs.
    #[must_use]
    pub const fn new(pools: HashMap<Pool, Vec<NullifierProof>>) -> Self {
        Self { pools }
    }
}

/// A non-membership proof demonstrating that a nullifier is not in the snapshot.
///
/// This proof contains the two adjacent nullifiers that bound the target nullifier
/// (proving it falls in a "gap") along with a Merkle proof that this gap exists
/// in the committed snapshot.
#[serde_as]
#[derive(Serialize)]
pub struct NullifierProof {
    /// The lower bound nullifier (the largest nullifier smaller than the target).
    #[serde_as(as = "Hex")]
    pub left_nullifier: Nullifier,
    /// The upper bound nullifier (the smallest nullifier larger than the target).
    #[serde_as(as = "Hex")]
    pub right_nullifier: Nullifier,
    /// The position of the leaf note in the Merkle tree.
    pub position: u64,
    /// The Merkle proof bytes proving the `(left, right)` range leaf exists in the tree.
    #[serde_as(as = "Hex")]
    pub merkle_proof: Vec<u8>,
}
