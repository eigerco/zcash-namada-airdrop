//! Note metadata types and traits for non-membership proof generation.
//!
//! This module defines the `NoteMetadata` trait and pool-specific metadata types
//! that enable generic proof generation for both Sapling and Orchard pools.

use non_membership_proofs::{Nullifier, TreePosition};
use zip32::Scope;

use crate::unspent_notes_proofs::{OrchardPrivateInputs, SaplingPrivateInputs};

/// Trait for note metadata that can generate claim inputs.
///
/// This trait abstracts over the pool-specific metadata types, enabling
/// generic proof generation for both Sapling and Orchard pools.
pub trait NoteMetadata {
    /// The pool-specific private inputs type.
    type PoolPrivateInputs;

    /// Returns the hiding nullifier for this note.
    fn hiding_nullifier(&self) -> Nullifier;

    /// Returns the block height where this note was created.
    fn block_height(&self) -> u64;

    /// Builds the private inputs for this note type.
    fn to_private_inputs(
        &self,
        tree_position: &TreePosition,
        nf_merkle_proof: Vec<[u8; 32]>,
    ) -> Self::PoolPrivateInputs;
}

/// Metadata for a Sapling note.
#[derive(Debug, Clone)]
pub struct SaplingNoteMetadata {
    /// The hiding nullifier (public input)
    pub hiding_nullifier: Nullifier,
    /// Diversified generator
    pub g_d: [u8; 32],
    /// Diversified transmission key
    pub pk_d: [u8; 32],
    /// Note value in zatoshis
    pub value: u64,
    /// Commitment randomness
    pub rcm: [u8; 32],
    /// The note position in the commitment tree.
    pub note_position: u64,
    /// The scope of the note (External for received payments, Internal for change).
    pub scope: Scope,
    /// The block height where the note was created
    pub block_height: u64,
    /// Merkle proof for the note commitment
    pub cm_merkle_proof: sapling::MerklePath,
}

impl NoteMetadata for SaplingNoteMetadata {
    type PoolPrivateInputs = SaplingPrivateInputs;

    fn hiding_nullifier(&self) -> Nullifier {
        self.hiding_nullifier
    }

    fn block_height(&self) -> u64 {
        self.block_height
    }

    fn to_private_inputs(
        &self,
        tree_position: &TreePosition,
        nf_merkle_proof: Vec<[u8; 32]>,
    ) -> Self::PoolPrivateInputs {
        let cm_merkle_proof: Vec<[u8; 32]> = self
            .cm_merkle_proof
            .path_elems()
            .iter()
            .map(sapling::Node::to_bytes)
            .collect();

        SaplingPrivateInputs {
            g_d: self.g_d,
            pk_d: self.pk_d,
            value: self.value,
            rcm: self.rcm,
            cm_note_position: self.note_position,
            scope: self.scope.into(),
            cm_merkle_proof,
            left_nullifier: tree_position.left_bound,
            right_nullifier: tree_position.right_bound,
            nf_leaf_position: tree_position.leaf_position.into(),
            nf_merkle_proof,
        }
    }
}

/// Metadata for an Orchard note.
#[derive(Debug, Clone)]
pub struct OrchardNoteMetadata {
    /// The hiding nullifier (public input)
    pub hiding_nullifier: Nullifier,
    /// The note commitment
    pub note_commitment: [u8; 32],
    /// The block height where the note was created
    pub block_height: u64,
    /// Merkle proof for the note commitment
    pub cm_merkle_proof: orchard::tree::MerklePath,
}

impl NoteMetadata for OrchardNoteMetadata {
    type PoolPrivateInputs = OrchardPrivateInputs;

    fn hiding_nullifier(&self) -> Nullifier {
        self.hiding_nullifier
    }

    fn block_height(&self) -> u64 {
        self.block_height
    }

    fn to_private_inputs(
        &self,
        tree_position: &TreePosition,
        nf_merkle_proof: Vec<[u8; 32]>,
    ) -> Self::PoolPrivateInputs {
        let cm_merkle_proof: Vec<[u8; 32]> = self
            .cm_merkle_proof
            .auth_path()
            .iter()
            .map(orchard::tree::MerkleHashOrchard::to_bytes)
            .collect();

        OrchardPrivateInputs {
            note_commitment: self.note_commitment,
            cm_merkle_proof,
            left_nullifier: tree_position.left_bound,
            right_nullifier: tree_position.right_bound,
            nf_leaf_position: tree_position.leaf_position.into(),
            nf_merkle_proof,
        }
    }
}
