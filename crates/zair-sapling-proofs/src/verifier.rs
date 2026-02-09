//! Verification for the Claim circuit.
//!
//! This module provides functions for verifying Groth16 proofs for the Claim circuit.

use bellman::gadgets::multipack;
use bellman::groth16::{PreparedVerifyingKey, Proof, verify_proof};
use bls12_381::Bls12;

use crate::ClaimProofError;
use crate::types::{ClaimProofOutput, GrothProofBytes};

/// Errors that can occur during claim proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// Invalid anchor value
    #[error("Invalid anchor: not a valid scalar")]
    InvalidAnchor,
    /// Invalid non-membership anchor value
    #[error("Invalid nm_anchor: not a valid scalar")]
    InvalidNmAnchor,
    /// Invalid hiding nullifier value
    #[error("Invalid hiding nullifier: not a valid scalar")]
    InvalidHidingNullifier,
    /// Point parsing failed
    #[error("Point parsing failed")]
    InvalidPoint,
    /// Proof decoding failed
    #[error("Proof decoding failed: {0}")]
    ProofDecoding(String),
    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    /// Multipack produced unexpected number of elements
    #[error("Multipack produced {0} elements, expected 2")]
    UnexpectedMultipackLength(usize),
}

/// Public inputs for claim proof verification.
///
/// Note: The Zcash nullifier is NOT included as a public input to preserve privacy.
/// The circuit computes it internally but does not expose it.
/// The hiding nullifier IS included for airdrop double-claim prevention.
/// The `nm_anchor` IS included for non-membership verification.
#[derive(Debug, Clone)]
pub struct ClaimPublicInputs {
    /// The re-randomized spend verification key (rk)
    pub rk: jubjub::AffinePoint,
    /// The value commitment (cv)
    pub cv: jubjub::AffinePoint,
    /// The anchor (merkle tree root)
    pub anchor: bls12_381::Scalar,
    /// The hiding nullifier (airdrop-specific, 32 bytes)
    pub hiding_nf: [u8; 32],
    /// The non-membership tree root
    pub nm_anchor: bls12_381::Scalar,
}

impl ClaimPublicInputs {
    /// Creates public inputs from raw bytes.
    ///
    /// # Errors
    /// Returns an error if any field is invalid.
    pub fn from_bytes(
        rk: &[u8; 32],
        cv: &[u8; 32],
        anchor: &[u8; 32],
        hiding_nf: &[u8; 32],
        nm_anchor: &[u8; 32],
    ) -> Result<Self, VerificationError> {
        let rk = parse_point(rk)?;
        let cv = parse_point(cv)?;
        let anchor = bls12_381::Scalar::from_bytes(anchor)
            .into_option()
            .ok_or(VerificationError::InvalidAnchor)?;
        let nm_anchor = bls12_381::Scalar::from_bytes(nm_anchor)
            .into_option()
            .ok_or(VerificationError::InvalidNmAnchor)?;
        Ok(Self {
            rk,
            cv,
            anchor,
            hiding_nf: *hiding_nf,
            nm_anchor,
        })
    }

    /// Converts public inputs to the vector format expected by the verifier.
    ///
    /// The format is: `[rk.u, rk.v, cv.u, cv.v, anchor, hiding_nf_0, hiding_nf_1, nm_anchor]`
    ///
    /// # Errors
    /// Returns an error if the hiding nullifier cannot be packed into exactly 2 scalars.
    pub fn to_vec(&self) -> Result<Vec<bls12_381::Scalar>, VerificationError> {
        // Pack hiding nullifier into scalars using bellman's multipack (same as circuit does)
        let hiding_nf_bits = multipack::bytes_to_bits_le(&self.hiding_nf);
        let hiding_nf_packed = multipack::compute_multipacking(&hiding_nf_bits);

        let hiding_nf_0 = hiding_nf_packed.first().copied().ok_or(
            VerificationError::UnexpectedMultipackLength(hiding_nf_packed.len()),
        )?;
        let hiding_nf_1 = hiding_nf_packed.get(1).copied().ok_or(
            VerificationError::UnexpectedMultipackLength(hiding_nf_packed.len()),
        )?;

        // Build public inputs vector: [rk.u, rk.v, cv.u, cv.v, anchor, hiding_nf_0, hiding_nf_1,
        // nm_anchor]
        Ok(vec![
            self.rk.get_u(),
            self.rk.get_v(),
            self.cv.get_u(),
            self.cv.get_v(),
            self.anchor,
            hiding_nf_0,
            hiding_nf_1,
            self.nm_anchor,
        ])
    }
}

/// Verify a claim proof with typed inputs.
///
/// # Arguments
/// * `pvk` - The prepared verifying key
/// * `proof` - The Groth16 proof
/// * `public_inputs` - The public inputs
///
/// # Errors
/// Returns an error if verification fails.
pub fn verify_claim_proof(
    pvk: &PreparedVerifyingKey<Bls12>,
    proof: &Proof<Bls12>,
    public_inputs: &ClaimPublicInputs,
) -> Result<(), VerificationError> {
    let inputs = public_inputs.to_vec()?;
    verify_proof(pvk, proof, &inputs)
        .map_err(|e| VerificationError::VerificationFailed(e.to_string()))
}

/// Decodes a Groth16 proof from bytes.
///
/// # Errors
/// Returns an error if the bytes are not a valid proof.
pub fn decode_proof(bytes: &GrothProofBytes) -> Result<Proof<Bls12>, ClaimProofError> {
    Proof::read(&bytes[..]).map_err(|e| ClaimProofError::ProofDecoding(e.to_string()))
}

/// Verify a claim proof from raw bytes.
///
/// This is a convenience function that combines decoding and verification.
///
/// # Arguments
/// * `pvk` - The prepared verifying key
/// * `zkproof` - The proof bytes (192 bytes)
/// * `rk` - The re-randomized verification key bytes (32 bytes)
/// * `cv` - The value commitment bytes (32 bytes)
/// * `anchor` - The anchor bytes (32 bytes)
/// * `hiding_nf` - The hiding nullifier bytes (32 bytes)
/// * `nm_anchor` - The non-membership tree root bytes (32 bytes)
///
/// # Errors
/// Returns an error if decoding or verification fails.
pub fn verify_claim_proof_bytes(
    pvk: &PreparedVerifyingKey<Bls12>,
    zkproof: &GrothProofBytes,
    rk: &[u8; 32],
    cv: &[u8; 32],
    anchor: &[u8; 32],
    hiding_nf: &[u8; 32],
    nm_anchor: &[u8; 32],
) -> Result<(), VerificationError> {
    let proof =
        decode_proof(zkproof).map_err(|e| VerificationError::ProofDecoding(e.to_string()))?;
    let public_inputs = ClaimPublicInputs::from_bytes(rk, cv, anchor, hiding_nf, nm_anchor)?;
    verify_claim_proof(pvk, &proof, &public_inputs)
}

/// Verify a claim proof from a [`ClaimProofOutput`].
///
/// This is a convenience function for verifying proofs produced by
/// [`generate_claim_proof`](crate::generate_claim_proof).
///
/// # Errors
/// Returns an error if verification fails.
pub fn verify_claim_proof_output(
    proof_output: &ClaimProofOutput,
    pvk: &PreparedVerifyingKey<Bls12>,
) -> Result<(), VerificationError> {
    verify_claim_proof_bytes(
        pvk,
        &proof_output.zkproof,
        &proof_output.rk,
        &proof_output.cv,
        &proof_output.anchor,
        &proof_output.hiding_nf,
        &proof_output.nm_anchor,
    )
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse a 32-byte array as a Jubjub affine point.
fn parse_point(bytes: &[u8; 32]) -> Result<jubjub::AffinePoint, VerificationError> {
    jubjub::AffinePoint::from_bytes(*bytes)
        .into_option()
        .ok_or(VerificationError::InvalidPoint)
}
