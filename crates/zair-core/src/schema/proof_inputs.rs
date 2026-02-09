//! Serializable claim input formats.

use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;
use zip32::Scope;

use crate::base::Nullifier;
use crate::schema::config::{CommitmentTreeAnchors, NonMembershipTreeAnchors};

/// Serializable version of `zip32::Scope`.
///
/// Indicates whether a note was received externally or is change from a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerializableScope {
    /// External scope - received payments from others.
    External,
    /// Internal scope - change outputs from own transactions.
    Internal,
}

impl From<Scope> for SerializableScope {
    fn from(scope: Scope) -> Self {
        match scope {
            Scope::External => Self::External,
            Scope::Internal => Self::Internal,
        }
    }
}

impl From<SerializableScope> for Scope {
    fn from(scope: SerializableScope) -> Self {
        match scope {
            SerializableScope::External => Self::External,
            SerializableScope::Internal => Self::Internal,
        }
    }
}

/// Unspent notes proofs
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AirdropClaimInputs {
    /// The non-membership tree anchors for Orchard and Sapling.
    pub non_membership_tree_anchors: NonMembershipTreeAnchors,
    /// The note commitment tree anchors for Orchard and Sapling.
    pub note_commitment_tree_anchors: CommitmentTreeAnchors,
    /// Sapling claim inputs
    pub sapling_claim_input: Vec<ClaimInput<SaplingPrivateInputs>>,
    /// Orchard claim inputs
    pub orchard_claim_input: Vec<ClaimInput<OrchardPrivateInputs>>,
}

impl AirdropClaimInputs {
    /// Create a new `AirdropClaimInputs` from pool claim results.
    #[must_use]
    pub const fn new(
        sapling_merkle_root: [u8; 32],
        orchard_merkle_root: [u8; 32],
        note_commitment_tree_anchors: CommitmentTreeAnchors,
        sapling_claim_input: Vec<ClaimInput<SaplingPrivateInputs>>,
        orchard_claim_input: Vec<ClaimInput<OrchardPrivateInputs>>,
    ) -> Self {
        Self {
            non_membership_tree_anchors: NonMembershipTreeAnchors {
                sapling: sapling_merkle_root,
                orchard: orchard_merkle_root,
            },
            note_commitment_tree_anchors,
            sapling_claim_input,
            orchard_claim_input,
        }
    }
}

/// A non-membership proof demonstrating that a nullifier is not in the snapshot.
///
/// This proof contains the two adjacent nullifiers that bound the target nullifier
/// (proving it falls in a "gap") along with a Merkle proof that this gap exists
/// in the committed snapshot.
///
/// Generic over the private inputs type `P`, which is pool-specific
/// (`SaplingPrivateInputs` or `OrchardPrivateInputs`).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimInput<P> {
    /// The block height where the note was created.
    pub block_height: u64,
    /// The public inputs for the non-membership proof.
    pub public_inputs: PublicInputs,
    /// The private inputs for the non-membership proof.
    pub private_inputs: P,
}

/// Private inputs for a Sapling airdrop claim proof.
///
/// Contains:
/// - Note preimage components for commitment recomputation in circuit
/// - Key material for nullifier derivation and ivk verification
/// - Merkle proofs for note commitment inclusion and nullifier non-membership
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaplingPrivateInputs {
    // === Note preimage (for commitment recomputation in circuit) ===
    /// Diversifier (11 bytes) - used to derive `g_d` and create payment address.
    #[serde_as(as = "Hex")]
    pub diversifier: [u8; 11],
    /// Diversified transmission key (from recipient address).
    #[serde_as(as = "Hex")]
    pub pk_d: [u8; 32],
    /// Note value in zatoshis.
    pub value: u64,
    /// Note commitment randomness (rcm).
    #[serde_as(as = "Hex")]
    pub rcm: [u8; 32],

    // === Key material (for nullifier derivation + ivk verification) ===
    /// The authorization key (ak) - Jubjub point, 32 bytes.
    /// Used for ivk derivation: ivk = BLAKE2s("Zcashivk", ak || nk)
    #[serde_as(as = "Hex")]
    pub ak: [u8; 32],
    /// The nullifier deriving key (nk) - Jubjub point, 32 bytes.
    /// Used for: 1) nullifier derivation `nf = BLAKE2s("Zcash_nf", nk || ρ)`, 2) ivk derivation.
    #[serde_as(as = "Hex")]
    pub nk: [u8; 32],

    // === For nullifier derivation ===
    /// The position of the note in Sapling commitment tree (used for nullifier derivation).
    pub cm_note_position: u64,
    /// The scope of the note (External for received payments, Internal for change).
    /// Informational - the actual keys (ak, nk) are already included above.
    pub scope: SerializableScope,

    // === For note commitment inclusion proof (proves note exists in Zcash) ===
    /// The Merkle proof siblings for the note commitment tree.
    /// Proves the note commitment exists in Zcash at the snapshot height.
    #[serde_as(as = "Vec<Hex>")]
    pub cm_merkle_proof: Vec<[u8; 32]>,

    // === For non-membership proof (proves nullifier not spent) ===
    /// The lower bound nullifier (the largest nullifier smaller than the target).
    pub left_nullifier: Nullifier,
    /// The upper bound nullifier (the smallest nullifier larger than the target).
    pub right_nullifier: Nullifier,
    /// The position of the leaf in the non-membership Merkle tree.
    pub nf_leaf_position: u64,
    /// The Merkle proof siblings proving the `(left, right)` range leaf exists in the tree.
    #[serde_as(as = "Vec<Hex>")]
    pub nf_merkle_proof: Vec<[u8; 32]>,
}

/// Private inputs for an Orchard non-membership proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardPrivateInputs {
    /// The commitment of the note that is unspent.
    #[serde_as(as = "Hex")]
    pub note_commitment: [u8; 32],
    /// Proves the note commitment exists in Zcash at the snapshot height.
    #[serde_as(as = "Vec<Hex>")]
    pub cm_merkle_proof: Vec<[u8; 32]>,
    /// The lower bound nullifier (the largest nullifier smaller than the target).
    pub left_nullifier: Nullifier,
    /// The upper bound nullifier (the smallest nullifier larger than the target).
    pub right_nullifier: Nullifier,
    /// The position of the leaf in the non-membership Merkle tree.
    pub nf_leaf_position: u64,
    /// The Merkle proof bytes proving the `(left, right)` range leaf exists in the non-membership
    /// tree.
    #[serde_as(as = "Vec<Hex>")]
    pub nf_merkle_proof: Vec<[u8; 32]>,
}

/// Public inputs for the non-membership proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// The hiding nullifier
    #[serde_as(as = "Hex")]
    pub hiding_nullifier: Nullifier,
}
