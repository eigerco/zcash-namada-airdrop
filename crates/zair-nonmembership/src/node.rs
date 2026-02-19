//! Non-membership Merkle tree node type.
//!
//! This module defines the node type used in non-membership Merkle trees,
//! implementing the `Hashable` trait from `incrementalmerkletree` using
//! Pedersen hash to be ZK friendly.

#![allow(clippy::indexing_slicing, reason = "Allow indexing for clarity")]

use std::sync::LazyLock;

use incrementalmerkletree::{Hashable, Level};
use sapling::merkle_hash;
use sapling::pedersen_hash::{Personalization, pedersen_hash};
use zair_core::base::{NULLIFIER_SIZE, Nullifier};

/// Level used for hashing nullifier pairs into leaves.
///
/// This provides domain separation from internal Pedersen hashes which use
/// levels 0-31. Using level 62 (max valid for Sapling Pedersen hash, which
/// requires level < 63) ensures no collision with any internal node hash.
const LEAF_HASH_LEVEL: u8 = 62;

/// The depth of the non-membership tree.
///
/// With 32 levels, the tree can hold up to 2^32 leaves.
/// This matches the Sapling note commitment tree depth.
pub const NON_MEMBERSHIP_TREE_DEPTH: u8 = 32;

/// A node in the non-membership Merkle tree.
///
/// This is a 32-byte value that represents either:
/// - A leaf: hash of `(left_nullifier || right_nullifier)` representing a gap
/// - An internal node: Pedersen hash of two child nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct NonMembershipNode([u8; 32]);

impl NonMembershipNode {
    /// The zero node (all zeros).
    pub const ZERO: Self = Self([0u8; NULLIFIER_SIZE]);

    /// Create a new node from a 32-byte array.
    #[cfg(test)]
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Create a leaf node from two nullifiers representing a gap.
    ///
    /// This hashes `left_nullifier || right_nullifier` using Pedersen hash
    /// with level-based domain separation (level 62) to produce a 32-byte leaf.
    ///
    /// Using a level outside the tree depth (0-31) ensures domain separation
    /// from internal node hashes while keeping the hash ZK-circuit compatible.
    #[must_use]
    pub fn leaf_from_nullifiers(left_nf: &Nullifier, right_nf: &Nullifier) -> Self {
        Self(gap_leaf_hash_full(left_nf, right_nf))
    }
}

/// Compute the non-membership leaf hash over the full 256 bits of each nullifier.
///
/// This matches the ZK circuit's `witness_bytes_as_bits` which produces 256 bits per
/// 32-byte input. Using `sapling::merkle_hash` would truncate to 255 bits via
/// `.take(Scalar::NUM_BITS)`, which is safe for field elements but not for raw nullifiers.
#[must_use]
fn gap_leaf_hash_full(left_nf: &Nullifier, right_nf: &Nullifier) -> [u8; 32] {
    let bits = bytes_to_bits_le(left_nf.as_ref())
        .into_iter()
        .chain(bytes_to_bits_le(right_nf.as_ref()));

    let subgroup_point = pedersen_hash(
        Personalization::MerkleTree(usize::from(LEAF_HASH_LEVEL)),
        bits,
    );
    jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(subgroup_point))
        .get_u()
        .to_bytes()
}

/// Convert a 32-byte array to 256 boolean bits in little-endian order.
#[must_use]
fn bytes_to_bits_le(bytes: &[u8; 32]) -> [bool; 256] {
    let mut bits = [false; 256];
    for (byte_index, byte) in bytes.iter().enumerate() {
        for bit_in_byte in 0..8 {
            let idx = byte_index.saturating_mul(8).saturating_add(bit_in_byte);
            bits[idx] = ((byte >> bit_in_byte) & 1) == 1;
        }
    }
    bits
}

impl From<Nullifier> for NonMembershipNode {
    fn from(bytes: Nullifier) -> Self {
        Self(bytes.into())
    }
}

impl From<NonMembershipNode> for Nullifier {
    fn from(node: NonMembershipNode) -> Self {
        node.0.into()
    }
}

impl From<[u8; 32]> for NonMembershipNode {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<NonMembershipNode> for [u8; 32] {
    fn from(node: NonMembershipNode) -> Self {
        node.0
    }
}

impl Hashable for NonMembershipNode {
    /// Returns the empty leaf node.
    ///
    /// For the non-membership tree, an empty leaf is all zeros.
    fn empty_leaf() -> Self {
        Self::ZERO
    }

    /// Combines two nodes at the given level using Pedersen hash.
    ///
    /// This uses the Sapling `merkle_hash` function which applies
    /// level-based domain separation (personalization) to prevent
    /// second preimage attacks.
    fn combine(level: Level, lhs: &Self, rhs: &Self) -> Self {
        Self(merkle_hash(level.into(), &lhs.0, &rhs.0))
    }

    /// Returns the empty root at the given level.
    ///
    /// This is computed by repeatedly combining empty nodes.
    fn empty_root(level: Level) -> Self {
        #[allow(
            clippy::indexing_slicing,
            reason = "Level is bounded by tree depth (0-32)"
        )]
        EMPTY_ROOTS[usize::from(u8::from(level))]
    }
}

/// Pre-computed empty roots for each level of the tree.
static EMPTY_ROOTS: LazyLock<Vec<NonMembershipNode>> = LazyLock::new(|| {
    let mut roots = vec![NonMembershipNode::empty_leaf()];
    for depth in 0..NON_MEMBERSHIP_TREE_DEPTH {
        let prev = roots[usize::from(depth)];
        let next = NonMembershipNode::combine(Level::from(depth), &prev, &prev);
        roots.push(next);
    }
    roots
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_leaf_is_zeros() {
        assert_eq!(NonMembershipNode::empty_leaf(), NonMembershipNode::ZERO);

        assert_eq!(NonMembershipNode::empty_leaf().to_bytes(), [0u8; 32]);

        assert_eq!(
            NonMembershipNode::from([0u8; 32]),
            NonMembershipNode::empty_leaf()
        );

        assert_eq!(<[u8; 32]>::from(NonMembershipNode::empty_leaf()), [0u8; 32]);
    }

    #[test]
    fn empty_roots_are_computed() {
        let leaf = NonMembershipNode::empty_leaf();
        let level0_root = NonMembershipNode::combine(Level::from(0), &leaf, &leaf);

        assert_eq!(NonMembershipNode::empty_root(Level::from(0)), leaf);
        assert_eq!(NonMembershipNode::empty_root(Level::from(1)), level0_root);
    }

    #[test]
    fn combine_uses_level_for_domain_separation() {
        let a = NonMembershipNode([1u8; 32]);
        let b = NonMembershipNode([2u8; 32]);

        let level0 = NonMembershipNode::combine(Level::from(0), &a, &b);
        let level1 = NonMembershipNode::combine(Level::from(1), &a, &b);

        assert_ne!(level0, level1);
    }

    #[test]
    fn order_matters() {
        let a = NonMembershipNode([1u8; 32]);
        let b = NonMembershipNode([2u8; 32]);

        let a_b = NonMembershipNode::combine(Level::from(0), &a, &b);
        let b_a = NonMembershipNode::combine(Level::from(0), &b, &a);

        assert_ne!(a_b, b_a);

        let nf1 = Nullifier::from([1u8; 32]);
        let nf2 = Nullifier::from([2u8; 32]);

        let leaf_12 = NonMembershipNode::leaf_from_nullifiers(&nf1, &nf2);
        let leaf_21 = NonMembershipNode::leaf_from_nullifiers(&nf2, &nf1);

        assert_ne!(leaf_12, leaf_21);
    }
}
