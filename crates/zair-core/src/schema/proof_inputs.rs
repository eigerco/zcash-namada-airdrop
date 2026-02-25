//! Serializable claim input formats.

use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;
use zip32::Scope;

use crate::base::Nullifier;

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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AirdropClaimInputs {
    /// Sapling claim inputs
    pub sapling_claim_input: Vec<ClaimInput<SaplingPrivateInputs>>,
    /// Orchard claim inputs
    pub orchard_claim_input: Vec<ClaimInput<OrchardPrivateInputs>>,
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
    pub note_commitment_position: u64,
    /// The scope of the note (External for received payments, Internal for change).
    /// Informational - the actual keys (ak, nk) are already included above.
    pub scope: SerializableScope,

    // === For note commitment inclusion proof (proves note exists in Zcash) ===
    /// The Merkle proof siblings for the note commitment tree.
    /// Proves the note commitment exists in Zcash at the snapshot height.
    #[serde_as(as = "Vec<Hex>")]
    pub note_commitment_merkle_path: Vec<[u8; 32]>,

    // === For non-membership proof (proves nullifier not spent) ===
    /// The lower bound nullifier (the largest nullifier smaller than the target).
    pub nullifier_gap_left_bound: Nullifier,
    /// The upper bound nullifier (the smallest nullifier larger than the target).
    pub nullifier_gap_right_bound: Nullifier,
    /// The position of the leaf in the non-membership Merkle tree.
    pub nullifier_gap_position: u64,
    /// The Merkle proof siblings proving the `(left, right)` range leaf exists in the tree.
    #[serde_as(as = "Vec<Hex>")]
    pub nullifier_gap_merkle_path: Vec<[u8; 32]>,
}

/// Private inputs for an Orchard non-membership proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardPrivateInputs {
    // === Note preimage / identity ===
    /// The note rho value (used to derive psi/rcm inside the Orchard circuit).
    #[serde_as(as = "Hex")]
    pub rho: [u8; 32],
    /// The note rseed (ZIP-212 seed randomness).
    #[serde_as(as = "Hex")]
    pub rseed: [u8; 32],
    /// The diversified base point `g_d` (recipient).
    #[serde_as(as = "Hex")]
    pub g_d: [u8; 32],
    /// The diversified transmission key `pk_d` (recipient).
    #[serde_as(as = "Hex")]
    pub pk_d: [u8; 32],
    /// Note value in zatoshis.
    pub value: u64,

    // === For note commitment inclusion proof (proves note exists in Zcash) ===
    /// The position of the note in the Orchard commitment tree.
    pub note_commitment_position: u64,
    /// The scope of the note (External for received payments, Internal for change).
    pub scope: SerializableScope,
    /// Proves the note commitment exists in Zcash at the snapshot height.
    #[serde_as(as = "Vec<Hex>")]
    pub note_commitment_merkle_path: Vec<[u8; 32]>,

    // === For non-membership proof (proves nullifier not spent) ===
    /// The lower bound nullifier (the largest nullifier smaller than the target).
    pub nullifier_gap_left_bound: Nullifier,
    /// The upper bound nullifier (the smallest nullifier larger than the target).
    pub nullifier_gap_right_bound: Nullifier,
    /// The position of the leaf in the non-membership Merkle tree.
    pub nullifier_gap_position: u64,
    /// The Merkle proof bytes proving the `(left, right)` range leaf exists in the non-membership
    /// tree.
    #[serde_as(as = "Vec<Hex>")]
    pub nullifier_gap_merkle_path: Vec<[u8; 32]>,
}

/// Public inputs for the non-membership proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// The airdrop nullifier
    pub airdrop_nullifier: Nullifier,
}

#[cfg(test)]
mod tests {
    use super::PublicInputs;
    use crate::base::Nullifier;

    #[test]
    fn public_inputs_serializes_nullifier_in_reversed_hex() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;
        let inputs = PublicInputs {
            airdrop_nullifier: Nullifier::new(bytes),
        };

        let json = serde_json::to_string(&inputs).expect("serialize public inputs");
        assert_eq!(
            json,
            format!(r#"{{"airdrop_nullifier":"cd{}ab"}}"#, "00".repeat(30))
        );
    }
}
