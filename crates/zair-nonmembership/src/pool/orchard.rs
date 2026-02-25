//! Orchard pool helpers shared by sparse and dense non-membership trees.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Canonicalized Orchard gap indexing is bounded by sorted nullifier lengths"
)]

use std::cmp::Ordering;

use ff::PrimeField as _;
use orchard::tree::MerkleHashOrchard;
use pasta_curves::pallas;
use zair_core::base::{Nullifier, SanitiseNullifiers};

use crate::core::{MerklePathError, TreePosition};

/// Orchard leaf hash level for gap tree leaves (`MerkleCRH^Orchard(level=62, left, right)`).
pub const ORCHARD_LEAF_HASH_LEVEL: u8 = 62;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalOrchardNullifier {
    pub bytes: Nullifier,
    pub node: MerkleHashOrchard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrchardGap {
    pub left_nf: Nullifier,
    pub left_node: MerkleHashOrchard,
    pub right_nf: Nullifier,
    pub right_node: MerkleHashOrchard,
}

pub fn map_orchard_user_positions(
    chain_nullifiers: &SanitiseNullifiers,
    user_nullifiers: &SanitiseNullifiers,
) -> Result<Vec<TreePosition>, MerklePathError> {
    let chain = canonicalize_orchard_chain_nullifiers("chain", chain_nullifiers)?;
    let user = canonicalize_orchard_user_nullifiers("user", user_nullifiers)?;
    let max = orchard_max_nullifier();

    let chain_bytes: Vec<Nullifier> = chain.into_iter().map(|item| item.bytes).collect();
    let mut mapping = Vec::with_capacity(user.len());
    for user_nf in user {
        if let Err(gap_idx) =
            chain_bytes.binary_search_by(|candidate| orchard_cmp(candidate, &user_nf))
        {
            let left = if gap_idx == 0 {
                Nullifier::MIN
            } else {
                chain_bytes[gap_idx - 1]
            };
            let right = if gap_idx == chain_bytes.len() {
                max
            } else {
                chain_bytes[gap_idx]
            };
            mapping.push(TreePosition::new(user_nf, gap_idx, left, right)?);
        }
    }
    Ok(mapping)
}

pub fn orchard_node_from_bytes(bytes: [u8; 32]) -> Option<MerkleHashOrchard> {
    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes))
}

pub fn canonicalize_orchard_chain_nullifiers(
    set: &'static str,
    nullifiers: &[Nullifier],
) -> Result<Vec<CanonicalOrchardNullifier>, MerklePathError> {
    let mut canonical = Vec::with_capacity(nullifiers.len());
    for (index, nullifier) in nullifiers.iter().enumerate() {
        let bytes = *nullifier.as_ref();
        let node = orchard_node_from_bytes(bytes)
            .ok_or(MerklePathError::NonCanonicalOrchardNullifier { set, index })?;
        canonical.push(CanonicalOrchardNullifier {
            bytes: Nullifier::from(node.to_bytes()),
            node,
        });
    }
    canonical.sort_unstable_by(|lhs, rhs| orchard_cmp(&lhs.bytes, &rhs.bytes));
    canonical.dedup_by(|lhs, rhs| lhs.bytes == rhs.bytes);
    Ok(canonical)
}

pub fn canonicalize_orchard_user_nullifiers(
    set: &'static str,
    nullifiers: &[Nullifier],
) -> Result<Vec<Nullifier>, MerklePathError> {
    let mut canonical = Vec::with_capacity(nullifiers.len());
    for (index, nullifier) in nullifiers.iter().enumerate() {
        let bytes = *nullifier.as_ref();
        let node = orchard_node_from_bytes(bytes)
            .ok_or(MerklePathError::NonCanonicalOrchardNullifier { set, index })?;
        canonical.push(Nullifier::from(node.to_bytes()));
    }
    canonical.sort_unstable_by(orchard_cmp);
    canonical.dedup();
    Ok(canonical)
}

pub fn orchard_cmp(lhs: &Nullifier, rhs: &Nullifier) -> Ordering {
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

pub fn orchard_max_nullifier() -> Nullifier {
    let max = pallas::Base::from(0_u64) - pallas::Base::from(1_u64);
    Nullifier::from(max.to_repr())
}

/// # Errors
/// Returns an error if `gap_idx` is out of bounds for the given chain.
pub fn orchard_gap_bounds(
    chain: &[CanonicalOrchardNullifier],
    gap_idx: usize,
    min_node: MerkleHashOrchard,
    max_node: MerkleHashOrchard,
) -> Result<OrchardGap, MerklePathError> {
    if gap_idx > chain.len() {
        return Err(MerklePathError::Unexpected("gap_idx out of bounds"));
    }

    let (left_nf, left_node) = gap_idx
        .checked_sub(1)
        .map_or((Nullifier::MIN, min_node), |i| {
            (chain[i].bytes, chain[i].node)
        });

    let (right_nf, right_node) = chain.get(gap_idx).map_or_else(
        || (orchard_max_nullifier(), max_node),
        |c| (c.bytes, c.node),
    );

    Ok(OrchardGap {
        left_nf,
        left_node,
        right_nf,
        right_node,
    })
}
