//! Proof generation and verification for the Claim circuit.
//!
//! This module provides functions for creating and verifying Groth16 proofs
//! for the Claim circuit, following the same structure as the Sapling prover.

// ZK proof code requires patterns that trigger these lints.
//
use bellman::groth16::{
    Parameters, PreparedVerifyingKey, Proof, VerifyingKey, create_random_proof,
    prepare_verifying_key,
};
use bls12_381::Bls12;
use rand::RngCore;
// Re-export sapling's MerklePath (same as Sapling prover uses)
pub use sapling::MerklePath;
use sapling::value::{NoteValue, ValueCommitTrapdoor};
use sapling::{Diversifier, Note, ProofGenerationKey, Rseed};
use zair_sapling_circuit::circuit::{Claim, ValueCommitmentOpening};

use crate::error::ClaimProofError;
use crate::types::{GROTH_PROOF_SIZE, GrothProofBytes, ValueCommitmentScheme};

/// Parameters for the Claim circuit.
pub struct ClaimParameters(pub Parameters<Bls12>);

impl ClaimParameters {
    /// Returns the verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey<Bls12> {
        &self.0.vk
    }

    /// Returns a prepared verifying key for efficient verification.
    #[must_use]
    pub fn prepared_verifying_key(&self) -> PreparedVerifyingKey<Bls12> {
        prepare_verifying_key(&self.0.vk)
    }
}

// ============================================================================
// Circuit Preparation (same as Sapling's SpendProver::prepare_circuit)
// ============================================================================

/// Prepares an instance of the Claim circuit for the given inputs.
///
/// This function is identical to Sapling's `SpendProver::prepare_circuit`
/// but as a standalone function (no trait).
///
/// # Arguments
/// * `proof_generation_key` - The proof generation key (ak, nsk)
/// * `diversifier` - The diversifier for the payment address
/// * `rseed` - The note randomness seed
/// * `value` - The note value
/// * `alpha` - Re-randomization scalar for the spend auth key
/// * `rcv` - Value commitment trapdoor (randomness)
/// * `anchor` - The merkle tree root
/// * `merkle_path` - The merkle path proving note inclusion (use `sapling::MerklePath`)
///
/// # Errors
/// Returns an error if the payment address is invalid or the non-membership merkle path
/// contains invalid scalars.
#[allow(clippy::too_many_arguments)]
pub fn prepare_circuit(
    proof_generation_key: ProofGenerationKey,
    diversifier: Diversifier,
    rseed: Rseed,
    value: NoteValue,
    alpha: jubjub::Fr,
    rcv: &ValueCommitTrapdoor,
    anchor: bls12_381::Scalar,
    merkle_path: &MerklePath,
    nm_left_nf: [u8; 32],
    nm_right_nf: [u8; 32],
    nm_merkle_path: Vec<([u8; 32], bool)>,
    nm_anchor: bls12_381::Scalar,
    value_commitment_scheme: ValueCommitmentScheme,
    rcv_sha256: Option<[u8; 32]>,
) -> Result<Claim, ClaimProofError> {
    // Construct the value commitment opening
    let value_commitment_opening = ValueCommitmentOpening {
        value,
        randomness: rcv.inner(),
    };

    // Construct the viewing key
    let viewing_key = proof_generation_key.to_viewing_key();

    // Construct the payment address with the viewing key / diversifier
    let payment_address = viewing_key
        .to_payment_address(diversifier)
        .ok_or(ClaimProofError::InvalidPaymentAddress)?;

    // Construct the note
    let note = Note::from_parts(payment_address, value, rseed);

    // Build the auth path for the circuit (same as Sapling)
    let pos: u64 = merkle_path.position().into();

    // Convert non-membership merkle path, validating each sibling
    let nm_merkle_path: Vec<Option<(bls12_381::Scalar, bool)>> = nm_merkle_path
        .into_iter()
        .enumerate()
        .map(|(i, (sibling, is_right))| {
            bls12_381::Scalar::from_bytes(&sibling)
                .into_option()
                .ok_or_else(|| {
                    ClaimProofError::InvalidNmMerklePath(format!("Invalid scalar at index {i}"))
                })
                .map(|scalar| Some((scalar, is_right)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Claim {
        value_commitment_opening: Some(value_commitment_opening),
        proof_generation_key: Some(proof_generation_key),
        payment_address: Some(payment_address),
        commitment_randomness: Some(note.rcm()),
        ar: Some(alpha),
        auth_path: merkle_path
            .path_elems()
            .iter()
            .enumerate()
            .map(|(i, node)| Some(((*node).into(), (pos >> i) & 0x1 == 1)))
            .collect(),
        anchor: Some(anchor),
        nm_left_nf: Some(nm_left_nf),
        nm_right_nf: Some(nm_right_nf),
        nm_merkle_path,
        nm_anchor: Some(nm_anchor),
        value_commitment_scheme: value_commitment_scheme.into(),
        rcv_sha256,
    })
}

// ============================================================================
// Proof Creation (similar to Sapling's SpendProver::create_proof)
// ============================================================================

/// Create the Groth16 proof for a Claim circuit.
///
/// # Arguments
/// * `params` - The proving parameters
/// * `circuit` - The prepared circuit instance
/// * `rng` - Random number generator
///
/// # Panics
/// Panics if proof creation fails (should not happen with valid inputs).
///
/// Note: This function is identical to Sapling's `SpendProver::create_proof`.
pub fn create_proof<R: RngCore>(
    params: &ClaimParameters,
    circuit: Claim,
    rng: &mut R,
) -> Proof<Bls12> {
    create_random_proof(circuit, &params.0, rng).expect("proving should not fail")
}

// ============================================================================
// Proof Encoding/Decoding (similar to Sapling's SpendProver::encode_proof)
// ============================================================================

/// Encodes a Groth16 proof to bytes.
///
/// # Panics
/// Panics if the proof cannot be serialized (should never happen with valid proofs).
///
/// Note: This function is identical to Sapling's `SpendProver::encode_proof`.
#[must_use]
pub fn encode_proof(proof: &Proof<Bls12>) -> GrothProofBytes {
    let mut zkproof = [0u8; GROTH_PROOF_SIZE];
    proof
        .write(&mut zkproof[..])
        .expect("should be able to serialize a proof");
    zkproof
}
