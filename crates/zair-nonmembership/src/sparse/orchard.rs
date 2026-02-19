//! Orchard non-membership Merkle tree (Sinsemilla) utilities.
//!
//! This module provides an Orchard-specific non-membership tree for nullifier gaps:
//! - nullifiers are parsed as canonical `pallas::Base` encodings,
//! - gap leaves are `MerkleCRH^Orchard(level=62, left, right)`,
//! - internal nodes use standard Orchard `MerkleCRH` levels `0..31`.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Merkle tree index and field arithmetic is bounded by construction"
)]

use std::cmp::Ordering;
use std::collections::BTreeSet;

use bridgetree::BridgeTree;
use ff::PrimeField as _;
use incrementalmerkletree::{Hashable, Position};
use orchard::tree::MerkleHashOrchard;
use pasta_curves::pallas;
use zair_core::base::Nullifier;

use crate::core::{MerklePathError, TreePosition};
use crate::node::NON_MEMBERSHIP_TREE_DEPTH;

const ORCHARD_LEAF_HASH_LEVEL: u8 = 62;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CanonicalOrchardNullifier {
    bytes: Nullifier,
    node: MerkleHashOrchard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gap {
    left_nf: Nullifier,
    left_node: MerkleHashOrchard,
    right_nf: Nullifier,
    right_node: MerkleHashOrchard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// A non-membership tree node for the Orchard gap tree.
pub struct OrchardNonMembershipNode(MerkleHashOrchard);

impl OrchardNonMembershipNode {
    /// Convert this node into canonical bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    fn leaf_from_nodes(left: MerkleHashOrchard, right: MerkleHashOrchard) -> Self {
        Self(MerkleHashOrchard::combine(
            ORCHARD_LEAF_HASH_LEVEL.into(),
            &left,
            &right,
        ))
    }
}

impl Hashable for OrchardNonMembershipNode {
    fn empty_leaf() -> Self {
        Self(MerkleHashOrchard::empty_leaf())
    }

    fn combine(level: incrementalmerkletree::Level, lhs: &Self, rhs: &Self) -> Self {
        Self(MerkleHashOrchard::combine(level, &lhs.0, &rhs.0))
    }

    fn empty_root(level: incrementalmerkletree::Level) -> Self {
        Self(MerkleHashOrchard::empty_root(level))
    }
}

/// A space-efficient Orchard non-membership tree for nullifier gaps.
#[derive(Debug, Clone)]
pub struct OrchardNonMembershipTree {
    inner: BridgeTree<OrchardNonMembershipNode, (), { NON_MEMBERSHIP_TREE_DEPTH }>,
    cached_root: OrchardNonMembershipNode,
    leaf_count: usize,
}

impl OrchardNonMembershipTree {
    #[allow(
        dead_code,
        reason = "Kept for focused tree-construction tests; production path uses marked-construction APIs"
    )]
    fn from_leaves<I>(leaves: I) -> Result<Self, MerklePathError>
    where
        I: IntoIterator<Item = Result<OrchardNonMembershipNode, MerklePathError>>,
        I::IntoIter: ExactSizeIterator,
    {
        let leaves_iter = leaves.into_iter();
        let len = leaves_iter.len();

        if len >= 2_usize.pow(u32::from(NON_MEMBERSHIP_TREE_DEPTH)) {
            return Err(MerklePathError::LeavesOverflow(len));
        }
        if len == 0_usize {
            return Err(MerklePathError::Unexpected(
                "0 leaves provided for a non-membership tree. This is not a valid case.",
            ));
        }

        let mut tree: BridgeTree<OrchardNonMembershipNode, (), { NON_MEMBERSHIP_TREE_DEPTH }> =
            BridgeTree::new(1);
        let mut leaf_count = 0_usize;
        for leaf in leaves_iter {
            if !tree.append(leaf?) {
                return Err(MerklePathError::Unexpected(
                    "Failed to append leaf to the Merkle tree",
                ));
            }
            leaf_count = leaf_count.saturating_add(1);
        }

        tree.checkpoint(());
        let cached_root = tree.root(0).ok_or(MerklePathError::Unexpected(
            "Merkle root should exist at this point",
        ))?;

        Ok(Self {
            inner: tree,
            cached_root,
            leaf_count,
        })
    }

    /// Build an Orchard non-membership tree from nullifiers (no positions marked).
    ///
    /// # Errors
    /// Returns an error if any nullifier is not canonical Orchard encoding.
    pub fn from_nullifiers(
        nullifiers: &zair_core::base::SanitiseNullifiers,
    ) -> Result<Self, MerklePathError> {
        Self::from_nullifiers_with_progress(nullifiers, |_, _| {})
    }

    /// Build an Orchard non-membership tree from nullifiers (no positions marked),
    /// with progress callback.
    ///
    /// Calls `on_progress(current, total)` after each leaf is appended.
    ///
    /// # Errors
    /// Returns an error if any nullifier is not canonical Orchard encoding.
    pub fn from_nullifiers_with_progress(
        nullifiers: &zair_core::base::SanitiseNullifiers,
        on_progress: impl FnMut(usize, usize),
    ) -> Result<Self, MerklePathError> {
        let empty_user = zair_core::base::SanitiseNullifiers::new(vec![]);
        let (tree, _mapping) = Self::from_chain_and_user_nullifiers_with_progress(
            nullifiers,
            &empty_user,
            on_progress,
        )?;
        Ok(tree)
    }

    /// Build an Orchard non-membership tree and mark user gap positions.
    ///
    /// # Errors
    /// Returns an error if any chain/user nullifier is not canonical Orchard encoding.
    pub fn from_chain_and_user_nullifiers(
        chain_nullifiers: &zair_core::base::SanitiseNullifiers,
        user_nullifiers: &zair_core::base::SanitiseNullifiers,
    ) -> Result<(Self, Vec<TreePosition>), MerklePathError> {
        Self::from_chain_and_user_nullifiers_with_progress(
            chain_nullifiers,
            user_nullifiers,
            |_, _| {},
        )
    }

    /// Build an Orchard non-membership tree and mark user gap positions,
    /// calling `on_progress(current, total)` after each leaf is appended.
    ///
    /// # Errors
    /// Returns an error if any chain/user nullifier is not canonical Orchard encoding.
    pub fn from_chain_and_user_nullifiers_with_progress(
        chain_nullifiers: &zair_core::base::SanitiseNullifiers,
        user_nullifiers: &zair_core::base::SanitiseNullifiers,
        mut on_progress: impl FnMut(usize, usize),
    ) -> Result<(Self, Vec<TreePosition>), MerklePathError> {
        let chain = canonicalize_orchard_chain_nullifiers("chain", chain_nullifiers)?;
        let user = canonicalize_orchard_user_nullifiers("user", user_nullifiers)?;
        let min_node = orchard_node_from_bytes(*Nullifier::MIN.as_ref()).ok_or(
            MerklePathError::Unexpected("invalid Orchard min nullifier encoding"),
        )?;
        let max_nf = orchard_max_nullifier();
        let max_node = orchard_node_from_bytes(*max_nf.as_ref()).ok_or(
            MerklePathError::Unexpected("invalid Orchard max nullifier encoding"),
        )?;

        let mut tree: BridgeTree<OrchardNonMembershipNode, (), { NON_MEMBERSHIP_TREE_DEPTH }> =
            BridgeTree::new(1);
        let mut leaf_count = 0usize;
        let mut user_gap_mapping = Vec::new();
        let mut user_idx = 0usize;

        let num_gaps = chain.len().saturating_add(1);
        for gap_idx in 0..num_gaps {
            let gap = orchard_gap_bounds(&chain, gap_idx, min_node, max_nf, max_node);
            let leaf = OrchardNonMembershipNode::leaf_from_nodes(gap.left_node, gap.right_node);
            tree.append(leaf);

            let mut should_mark = false;
            while user_idx < user.len() {
                let user_nf = user[user_idx];
                if orchard_cmp(&user_nf, &gap.left_nf) != Ordering::Greater {
                    user_idx = user_idx.saturating_add(1);
                    continue;
                }

                if orchard_cmp(&user_nf, &gap.right_nf) != Ordering::Less {
                    break;
                }

                should_mark = true;
                user_gap_mapping.push(TreePosition::new(
                    user_nf,
                    gap_idx,
                    gap.left_nf,
                    gap.right_nf,
                )?);
                user_idx = user_idx.saturating_add(1);
            }

            if should_mark {
                tree.mark();
            }

            leaf_count = leaf_count.saturating_add(1);
            on_progress(leaf_count, num_gaps);
        }

        tree.checkpoint(());
        let cached_root = tree.root(0).ok_or(MerklePathError::Unexpected(
            "Merkle root should exist at this point",
        ))?;

        Ok((
            Self {
                inner: tree,
                cached_root,
                leaf_count,
            },
            user_gap_mapping,
        ))
    }

    /// Return root bytes as canonical `pallas::Base`.
    #[must_use]
    pub fn root_bytes(&self) -> [u8; 32] {
        self.cached_root.to_bytes()
    }

    /// Return number of leaves in this tree.
    #[must_use]
    pub const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns the set of positions marked for witnessing.
    #[must_use]
    pub fn marked_positions(&self) -> BTreeSet<Position> {
        self.inner.marked_positions()
    }

    /// Produce a witness as canonical node bytes.
    ///
    /// # Errors
    /// Returns an error if witness generation fails.
    pub fn witness_bytes(&self, position: Position) -> Result<Vec<[u8; 32]>, MerklePathError> {
        self.inner
            .witness(position, 0)
            .map(|path| {
                path.iter()
                    .copied()
                    .map(OrchardNonMembershipNode::to_bytes)
                    .collect()
            })
            .map_err(|e| MerklePathError::WitnessError(format!("{e:?}")))
    }
}

fn orchard_node_from_bytes(bytes: [u8; 32]) -> Option<MerkleHashOrchard> {
    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes))
}

fn canonicalize_orchard_chain_nullifiers(
    set: &'static str,
    nullifiers: &[Nullifier],
) -> Result<Vec<CanonicalOrchardNullifier>, MerklePathError> {
    let mut canonical = Vec::with_capacity(nullifiers.len());
    for (index, nullifier) in nullifiers.iter().enumerate() {
        let bytes = *nullifier.as_ref();
        let node = orchard_node_from_bytes(bytes)
            .ok_or(MerklePathError::NonCanonicalOrchardNullifier { set, index })?;
        canonical.push(CanonicalOrchardNullifier {
            bytes: *nullifier,
            node,
        });
    }

    canonical.sort_unstable_by(|lhs, rhs| orchard_cmp(&lhs.bytes, &rhs.bytes));
    canonical.dedup_by(|lhs, rhs| lhs.bytes == rhs.bytes);
    Ok(canonical)
}

fn canonicalize_orchard_user_nullifiers(
    set: &'static str,
    nullifiers: &[Nullifier],
) -> Result<Vec<Nullifier>, MerklePathError> {
    let mut canonical = Vec::with_capacity(nullifiers.len());
    for (index, nullifier) in nullifiers.iter().enumerate() {
        let bytes = *nullifier.as_ref();
        orchard_node_from_bytes(bytes)
            .ok_or(MerklePathError::NonCanonicalOrchardNullifier { set, index })?;
        canonical.push(*nullifier);
    }

    canonical.sort_unstable_by(orchard_cmp);
    canonical.dedup();
    Ok(canonical)
}

fn orchard_cmp(lhs: &Nullifier, rhs: &Nullifier) -> Ordering {
    cmp_pallas_repr_le(lhs.as_ref(), rhs.as_ref())
}

fn cmp_pallas_repr_le(lhs: &[u8; 32], rhs: &[u8; 32]) -> Ordering {
    for index in (0..32).rev() {
        let ordering = lhs[index].cmp(&rhs[index]);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

fn orchard_max_nullifier() -> Nullifier {
    let max = pallas::Base::from(0u64) - pallas::Base::from(1u64);
    Nullifier::from(max.to_repr())
}

fn orchard_gap_bounds(
    nullifiers: &[CanonicalOrchardNullifier],
    gap_idx: usize,
    min_node: MerkleHashOrchard,
    max_nf: Nullifier,
    max_node: MerkleHashOrchard,
) -> Gap {
    let len = nullifiers.len();

    if len == 0 {
        return Gap {
            left_nf: Nullifier::MIN,
            left_node: min_node,
            right_nf: max_nf,
            right_node: max_node,
        };
    }

    match gap_idx {
        0 => Gap {
            left_nf: Nullifier::MIN,
            left_node: min_node,
            right_nf: nullifiers[0].bytes,
            right_node: nullifiers[0].node,
        },
        i if i == len => Gap {
            left_nf: nullifiers[i - 1].bytes,
            left_node: nullifiers[i - 1].node,
            right_nf: max_nf,
            right_node: max_node,
        },
        i if i > len => {
            panic!("gap_idx {gap_idx} out of bounds for {len} nullifiers")
        }
        i => Gap {
            left_nf: nullifiers[i - 1].bytes,
            left_node: nullifiers[i - 1].node,
            right_nf: nullifiers[i].bytes,
            right_node: nullifiers[i].node,
        },
    }
}

#[allow(
    dead_code,
    reason = "Used by test-only leaf-construction path retained for unit tests"
)]
struct OrchardNullifierLeafIterator<'a> {
    nullifiers: &'a [CanonicalOrchardNullifier],
    min_node: MerkleHashOrchard,
    max_nf: Nullifier,
    max_node: MerkleHashOrchard,
    index: usize,
    total: usize,
}

impl<'a> OrchardNullifierLeafIterator<'a> {
    #[allow(
        dead_code,
        reason = "Used by test-only leaf-construction path retained for unit tests"
    )]
    fn new(nullifiers: &'a [CanonicalOrchardNullifier]) -> Result<Self, MerklePathError> {
        let min_node = orchard_node_from_bytes(*Nullifier::MIN.as_ref()).ok_or(
            MerklePathError::Unexpected("invalid Orchard min nullifier encoding"),
        )?;
        let max_nf = orchard_max_nullifier();
        let max_node = orchard_node_from_bytes(*max_nf.as_ref()).ok_or(
            MerklePathError::Unexpected("invalid Orchard max nullifier encoding"),
        )?;
        Ok(Self {
            nullifiers,
            min_node,
            max_nf,
            max_node,
            index: 0,
            total: nullifiers.len().saturating_add(1),
        })
    }
}

impl Iterator for OrchardNullifierLeafIterator<'_> {
    type Item = Result<OrchardNonMembershipNode, MerklePathError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total {
            return None;
        }

        let gap = orchard_gap_bounds(
            self.nullifiers,
            self.index,
            self.min_node,
            self.max_nf,
            self.max_node,
        );

        self.index = self.index.saturating_add(1);
        Some(Ok(OrchardNonMembershipNode::leaf_from_nodes(
            gap.left_node,
            gap.right_node,
        )))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for OrchardNullifierLeafIterator<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn orchard_nf(v: u64) -> Nullifier {
        Nullifier::from(pallas::Base::from(v).to_repr())
    }

    #[test]
    fn rejects_non_canonical_orchard_nullifier() {
        let mut bytes = [0xff_u8; 32];
        bytes[31] = 0x7f;
        let invalid = Nullifier::from(bytes);

        let chain = zair_core::base::SanitiseNullifiers::new(vec![invalid]);
        let result = OrchardNonMembershipTree::from_nullifiers(&chain);
        assert!(matches!(
            result,
            Err(MerklePathError::NonCanonicalOrchardNullifier {
                set: "chain",
                index: 0
            })
        ));
    }

    #[test]
    fn orchard_ordering_is_field_ordering() {
        let chain = zair_core::base::SanitiseNullifiers::new(vec![orchard_nf(256)]);
        let user = zair_core::base::SanitiseNullifiers::new(vec![orchard_nf(1)]);

        let (_tree, mapping) =
            OrchardNonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("tree creation should succeed");

        assert_eq!(mapping.len(), 1);
        assert_eq!(mapping[0].leaf_position, Position::from(0_u64));
        assert_eq!(mapping[0].left_bound, Nullifier::MIN);
        assert_eq!(mapping[0].right_bound, orchard_nf(256));
    }
}
