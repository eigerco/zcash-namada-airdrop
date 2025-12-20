//! Witness data for the airdrop circuit.
//!
//! The witness contains all private inputs needed to generate a proof.

use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};
use pasta_curves::pallas;
use rs_merkle::algorithms::Sha256;
use rs_merkle::{Hasher, MerkleProof};

/// A 32-byte nullifier (same as used in non-membership-proofs crate)
pub type Nullifier = [u8; 32];

/// A 32-byte beneficiary address (Namada account)
pub type Beneficiary = [u8; 32];

/// Witness data for generating an airdrop proof.
///
/// Contains all private inputs the prover uses to generate the ZK proof.
#[derive(Clone, Debug)]
pub struct AirdropWitness {
    /// The note value in zatoshis (smallest ZEC unit)
    pub note_value: u64,

    /// The hiding nullifier derived from the note
    /// This is NOT the standard nullifier - it uses custom domain separation
    /// to break linkability with on-chain nullifiers
    pub hiding_nullifier: Nullifier,

    /// Left bound from snapshot: largest nullifier smaller than hiding_nullifier
    pub left_nullifier: Nullifier,

    /// Right bound from snapshot: smallest nullifier larger than hiding_nullifier
    pub right_nullifier: Nullifier,

    /// Merkle proof that the range leaf (left || right) exists in snapshot tree (SHA256)
    pub merkle_proof: Vec<u8>,

    /// Index of the range leaf in the Merkle tree
    pub leaf_index: usize,

    /// Total number of leaves in the Merkle tree
    pub tree_size: usize,

    /// Merkle root of the snapshot tree (public input)
    pub snapshot_root: [u8; 32],

    /// The beneficiary Namada address receiving the airdrop
    pub beneficiary: Beneficiary,

    /// Merkle path siblings as field elements (for in-circuit Poseidon verification)
    /// This is populated when using Poseidon trees for testing
    pub merkle_path_poseidon: Option<Vec<pallas::Base>>,

    /// Merkle root computed with Poseidon (for in-circuit verification)
    pub snapshot_root_poseidon: Option<pallas::Base>,
}

/// Errors that can occur when constructing or validating a witness.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessError {
    /// The hiding nullifier is not strictly between left and right bounds
    #[error("Nullifier not in range: left >= hiding or hiding >= right")]
    NullifierNotInRange,

    /// The Merkle proof is invalid or doesn't verify against the expected root
    #[error("Invalid Merkle proof")]
    InvalidMerkleProof,

    /// The note value is zero
    #[error("Note value cannot be zero")]
    ZeroValue,
}

impl AirdropWitness {
    /// Creates a new witness, validating all inputs.
    ///
    /// # Arguments
    ///
    /// * `note_value` - The ZEC value of the note in zatoshis
    /// * `hiding_nullifier` - The hiding nullifier (derived with custom domain)
    /// * `left_nullifier` - Lower bound from snapshot
    /// * `right_nullifier` - Upper bound from snapshot
    /// * `merkle_proof` - Proof bytes for the range leaf
    /// * `leaf_index` - Index of the leaf in the tree
    /// * `tree_size` - Total leaves in the tree
    /// * `snapshot_root` - Expected Merkle root to validate against
    /// * `beneficiary` - Namada address receiving the airdrop
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `hiding_nullifier` is not strictly between left and right bounds
    /// - The Merkle proof doesn't verify against `snapshot_root`
    /// - `note_value` is zero
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        note_value: u64,
        hiding_nullifier: Nullifier,
        left_nullifier: Nullifier,
        right_nullifier: Nullifier,
        merkle_proof: Vec<u8>,
        leaf_index: usize,
        tree_size: usize,
        snapshot_root: &[u8; 32],
        beneficiary: Beneficiary,
    ) -> Result<Self, WitnessError> {
        // Validate note value
        if note_value == 0 {
            return Err(WitnessError::ZeroValue);
        }

        // Validate nullifier is in range
        if left_nullifier >= hiding_nullifier || hiding_nullifier >= right_nullifier {
            return Err(WitnessError::NullifierNotInRange);
        }

        // Validate Merkle proof
        let leaf = build_range_leaf(&left_nullifier, &right_nullifier);
        let leaf_hash = Sha256::hash(&leaf);

        let proof = MerkleProof::<Sha256>::from_bytes(&merkle_proof)
            .map_err(|_| WitnessError::InvalidMerkleProof)?;

        if !proof.verify(*snapshot_root, &[leaf_index], &[leaf_hash], tree_size) {
            return Err(WitnessError::InvalidMerkleProof);
        }

        Ok(Self {
            note_value,
            hiding_nullifier,
            left_nullifier,
            right_nullifier,
            merkle_proof,
            leaf_index,
            tree_size,
            snapshot_root: *snapshot_root,
            beneficiary,
            merkle_path_poseidon: None,
            snapshot_root_poseidon: None,
        })
    }

    /// Sets the Poseidon Merkle path data for in-circuit verification.
    #[must_use]
    pub fn with_poseidon_merkle(
        mut self,
        path: Vec<pallas::Base>,
        root: pallas::Base,
    ) -> Self {
        self.merkle_path_poseidon = Some(path);
        self.snapshot_root_poseidon = Some(root);
        self
    }

    /// Validates that the hiding nullifier is strictly between the bounds.
    #[must_use]
    pub fn is_nullifier_in_range(&self) -> bool {
        self.left_nullifier < self.hiding_nullifier
            && self.hiding_nullifier < self.right_nullifier
    }
}

/// Builds a range leaf by concatenating two nullifiers.
/// This matches the implementation in non-membership-proofs crate.
#[must_use]
pub fn build_range_leaf(left: &Nullifier, right: &Nullifier) -> [u8; 64] {
    let mut leaf = [0u8; 64];
    leaf[..32].copy_from_slice(left);
    leaf[32..].copy_from_slice(right);
    leaf
}

// ============================================================
// Poseidon Merkle Tree Helpers (for in-circuit verification)
// ============================================================

/// Computes Poseidon hash of two field elements (for Merkle tree nodes).
#[must_use]
pub fn poseidon_hash_merkle(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([left, right])
}

/// Converts 32 bytes to a Pallas base field element.
/// Masks top 2 bits to ensure value fits in field.
#[must_use]
pub fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
    use ff::PrimeField;
    let mut repr = [0u8; 32];
    repr.copy_from_slice(bytes);
    repr[31] &= 0x3F;
    pallas::Base::from_repr(repr).expect("masked bytes always fit in field")
}

/// Builds a Poseidon Merkle tree from leaf field elements.
///
/// Returns (root, tree_levels) where tree_levels[0] = leaves, tree_levels[n] = root level.
#[must_use]
pub fn build_poseidon_merkle_tree(leaves: &[pallas::Base]) -> (pallas::Base, Vec<Vec<pallas::Base>>) {
    if leaves.is_empty() {
        return (pallas::Base::zero(), vec![]);
    }
    if let [single_leaf] = leaves {
        return (*single_leaf, vec![leaves.to_vec()]);
    }

    let mut levels: Vec<Vec<pallas::Base>> = vec![leaves.to_vec()];
    let mut current_level = leaves.to_vec();

    while current_level.len() > 1 {
        // Pad to even length if necessary
        if !current_level.len().is_multiple_of(2) {
            current_level.push(pallas::Base::zero());
        }

        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for chunk in current_level.chunks_exact(2) {
            if let [left, right] = chunk {
                let parent = poseidon_hash_merkle(*left, *right);
                next_level.push(parent);
            }
        }

        levels.push(next_level.clone());
        current_level = next_level;
    }

    // Safe: we only exit the loop when current_level.len() == 1
    let root = current_level.first().copied().unwrap_or(pallas::Base::zero());
    (root, levels)
}

/// Extracts the Merkle path (sibling hashes) for a given leaf index.
///
/// Returns a vector of siblings from leaf level to just below the root.
#[must_use]
pub fn extract_merkle_path(
    tree_levels: &[Vec<pallas::Base>],
    leaf_index: usize,
) -> Vec<pallas::Base> {
    let mut path = Vec::new();
    let mut idx = leaf_index;

    // Iterate through all levels except the root
    for level in tree_levels.iter().take(tree_levels.len().saturating_sub(1)) {
        // Find sibling index: if even, sibling is idx+1; if odd, sibling is idx-1
        let sibling_idx = if idx.is_multiple_of(2) {
            idx.saturating_add(1)
        } else {
            idx.saturating_sub(1)
        };

        // Get sibling value (or zero if out of bounds due to padding)
        let sibling = level.get(sibling_idx).copied().unwrap_or(pallas::Base::zero());
        path.push(sibling);

        // Move to parent index
        idx /= 2;
    }

    path
}

/// Computes the Merkle root from a leaf and its path.
/// Used to verify that extract_merkle_path is correct.
#[must_use]
pub fn compute_root_from_path(
    leaf: pallas::Base,
    leaf_index: usize,
    path: &[pallas::Base],
) -> pallas::Base {
    let mut current = leaf;
    let mut idx = leaf_index;

    for sibling in path {
        let (left, right) = if idx.is_multiple_of(2) {
            (current, *sibling)
        } else {
            (*sibling, current)
        };
        current = poseidon_hash_merkle(left, right);
        idx /= 2;
    }

    current
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;
    use rs_merkle::MerkleTree;

    /// Helper to create a nullifier with specific last byte
    fn nf(val: u8) -> Nullifier {
        let mut arr = [0u8; 32];
        arr[31] = val;
        arr
    }

    /// Helper to build a valid Merkle tree and proof for testing
    fn build_test_tree_and_proof(
        nullifiers: &[Nullifier],
        target_index: usize,
    ) -> (MerkleTree<Sha256>, Vec<u8>, [u8; 32]) {
        // Build leaves as ranges
        let min_nf = [0u8; 32];
        let max_nf = [0xFFu8; 32];

        let mut leaves = Vec::new();

        // Front leaf: [MIN, first_nf]
        if !nullifiers.is_empty() {
            let leaf = build_range_leaf(&min_nf, &nullifiers[0]);
            leaves.push(Sha256::hash(&leaf));
        }

        // Middle leaves: [nf[i], nf[i+1]]
        for window in nullifiers.windows(2) {
            let leaf = build_range_leaf(&window[0], &window[1]);
            leaves.push(Sha256::hash(&leaf));
        }

        // Back leaf: [last_nf, MAX]
        if !nullifiers.is_empty() {
            let leaf = build_range_leaf(&nullifiers[nullifiers.len() - 1], &max_nf);
            leaves.push(Sha256::hash(&leaf));
        }

        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let proof = tree.proof(&[target_index]);
        let root = tree.root().expect("Tree should have root");

        (tree, proof.to_bytes(), root)
    }

    #[test]
    fn witness_validates_nullifier_in_range() {
        let nullifiers = vec![nf(20), nf(40), nf(60)];
        let (tree, proof_bytes, root) = build_test_tree_and_proof(&nullifiers, 1);

        // Valid: hiding nullifier between 20 and 40
        let result = AirdropWitness::new(
            1000,
            nf(30), // hiding nullifier
            nf(20), // left bound
            nf(40), // right bound
            proof_bytes.clone(),
            1,
            tree.leaves_len(),
            &root,
            [0xAB; 32], // beneficiary
        );
        assert!(result.is_ok());

        // Invalid: hiding nullifier equals left bound
        let result = AirdropWitness::new(
            1000,
            nf(20), // equals left
            nf(20),
            nf(40),
            proof_bytes.clone(),
            1,
            tree.leaves_len(),
            &root,
            [0xAB; 32],
        );
        assert_eq!(result.unwrap_err(), WitnessError::NullifierNotInRange);

        // Invalid: hiding nullifier outside range
        let result = AirdropWitness::new(
            1000,
            nf(50), // outside [20, 40]
            nf(20),
            nf(40),
            proof_bytes,
            1,
            tree.leaves_len(),
            &root,
            [0xAB; 32],
        );
        assert_eq!(result.unwrap_err(), WitnessError::NullifierNotInRange);
    }

    #[test]
    fn witness_rejects_invalid_merkle_proof() {
        let nullifiers = vec![nf(20), nf(40), nf(60)];
        let (tree, _, root) = build_test_tree_and_proof(&nullifiers, 1);

        // Invalid proof bytes
        let result = AirdropWitness::new(
            1000,
            nf(30),
            nf(20),
            nf(40),
            vec![0u8; 32], // garbage proof
            1,
            tree.leaves_len(),
            &root,
            [0xAB; 32],
        );
        assert_eq!(result.unwrap_err(), WitnessError::InvalidMerkleProof);
    }

    #[test]
    fn witness_rejects_zero_value() {
        let nullifiers = vec![nf(20), nf(40)];
        let (tree, proof_bytes, root) = build_test_tree_and_proof(&nullifiers, 1);

        let result = AirdropWitness::new(
            0, // zero value
            nf(30),
            nf(20),
            nf(40),
            proof_bytes,
            1,
            tree.leaves_len(),
            &root,
            [0xAB; 32],
        );
        assert_eq!(result.unwrap_err(), WitnessError::ZeroValue);
    }

    #[test]
    fn witness_can_be_constructed_with_valid_inputs() {
        let nullifiers = vec![nf(20), nf(40), nf(60)];
        let (tree, proof_bytes, root) = build_test_tree_and_proof(&nullifiers, 1);

        let witness = AirdropWitness::new(
            1_000_000, // 0.01 ZEC
            nf(30),
            nf(20),
            nf(40),
            proof_bytes,
            1,
            tree.leaves_len(),
            &root,
            [0xAB; 32],
        )
        .expect("Should create valid witness");

        assert_eq!(witness.note_value, 1_000_000);
        assert!(witness.is_nullifier_in_range());
    }
}
