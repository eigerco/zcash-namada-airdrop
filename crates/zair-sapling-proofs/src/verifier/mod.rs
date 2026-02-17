//! Verification for the Claim circuit.
//!
//! This module provides functions for verifying Groth16 proofs for the Claim circuit.

use bellman::gadgets::multipack;
use bellman::groth16::{PreparedVerifyingKey, Proof, verify_proof};
use bls12_381::Bls12;

pub use crate::error::ClaimProofError;
pub use crate::types::{
    ClaimProofOutput, GROTH_PROOF_SIZE, GrothProofBytes, ValueCommitmentScheme,
};

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
    /// Missing native value commitment for native scheme.
    #[error("Missing cv for native value commitment scheme")]
    MissingCv,
    /// Missing SHA-256 value commitment for sha256 scheme.
    #[error("Missing cv_sha256 for sha256 value commitment scheme")]
    MissingCvSha256,
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
    /// Which value commitment scheme this proof uses.
    pub value_commitment_scheme: ValueCommitmentScheme,
    /// The native value commitment (cv), when using the native scheme.
    pub cv: Option<jubjub::AffinePoint>,
    /// SHA-256 value commitment (`cv_sha256`), when using the `sha256` scheme.
    pub cv_sha256: Option<[u8; 32]>,
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
        value_commitment_scheme: ValueCommitmentScheme,
        rk: &[u8; 32],
        cv: Option<&[u8; 32]>,
        cv_sha256: Option<&[u8; 32]>,
        anchor: &[u8; 32],
        hiding_nf: &[u8; 32],
        nm_anchor: &[u8; 32],
    ) -> Result<Self, VerificationError> {
        let rk = parse_point(rk)?;
        let cv = match value_commitment_scheme {
            ValueCommitmentScheme::Native => {
                Some(parse_point(cv.ok_or(VerificationError::MissingCv)?)?)
            }
            ValueCommitmentScheme::Sha256 => None,
        };
        let cv_sha256 = match value_commitment_scheme {
            ValueCommitmentScheme::Native => None,
            ValueCommitmentScheme::Sha256 => {
                Some(*cv_sha256.ok_or(VerificationError::MissingCvSha256)?)
            }
        };
        let anchor = bls12_381::Scalar::from_bytes(anchor)
            .into_option()
            .ok_or(VerificationError::InvalidAnchor)?;
        let nm_anchor = bls12_381::Scalar::from_bytes(nm_anchor)
            .into_option()
            .ok_or(VerificationError::InvalidNmAnchor)?;
        Ok(Self {
            rk,
            value_commitment_scheme,
            cv,
            cv_sha256,
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

        let mut out = vec![self.rk.get_u(), self.rk.get_v()];

        match self.value_commitment_scheme {
            ValueCommitmentScheme::Native => {
                let cv = self.cv.ok_or(VerificationError::MissingCv)?;
                out.push(cv.get_u());
                out.push(cv.get_v());
            }
            ValueCommitmentScheme::Sha256 => {
                let cv_sha256 = self.cv_sha256.ok_or(VerificationError::MissingCvSha256)?;
                let value_bits = multipack::bytes_to_bits_le(&cv_sha256);
                let packed = multipack::compute_multipacking(&value_bits);
                let vc_0 = packed
                    .first()
                    .copied()
                    .ok_or(VerificationError::UnexpectedMultipackLength(packed.len()))?;
                let vc_1 = packed
                    .get(1)
                    .copied()
                    .ok_or(VerificationError::UnexpectedMultipackLength(packed.len()))?;
                out.push(vc_0);
                out.push(vc_1);
            }
        }

        out.extend([self.anchor, hiding_nf_0, hiding_nf_1, self.nm_anchor]);
        Ok(out)
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
/// * `note_commitment_root` - The note commitment root bytes (32 bytes)
/// * `hiding_nf` - The hiding nullifier bytes (32 bytes)
/// * `nullifier_gap_root` - The non-membership tree root bytes (32 bytes)
///
/// # Errors
/// Returns an error if decoding or verification fails.
#[allow(
    clippy::too_many_arguments,
    reason = "Public verifier API takes explicit proof fields"
)]
pub fn verify_claim_proof_bytes(
    pvk: &PreparedVerifyingKey<Bls12>,
    zkproof: &GrothProofBytes,
    value_commitment_scheme: ValueCommitmentScheme,
    rk: &[u8; 32],
    cv: Option<&[u8; 32]>,
    cv_sha256: Option<&[u8; 32]>,
    note_commitment_root: &[u8; 32],
    hiding_nf: &[u8; 32],
    nullifier_gap_root: &[u8; 32],
) -> Result<(), VerificationError> {
    let proof =
        decode_proof(zkproof).map_err(|e| VerificationError::ProofDecoding(e.to_string()))?;
    let public_inputs = ClaimPublicInputs::from_bytes(
        value_commitment_scheme,
        rk,
        cv,
        cv_sha256,
        note_commitment_root,
        hiding_nf,
        nullifier_gap_root,
    )?;
    verify_claim_proof(pvk, &proof, &public_inputs)
}

/// Verify a claim proof from a [`ClaimProofOutput`].
///
/// This is a convenience function for verifying proofs produced by
/// [`generate_claim_proof`](crate::prover::generate_claim_proof).
///
/// # Errors
/// Returns an error if verification fails.
pub fn verify_claim_proof_output(
    proof_output: &ClaimProofOutput,
    pvk: &PreparedVerifyingKey<Bls12>,
    value_commitment_scheme: ValueCommitmentScheme,
    note_commitment_root: &[u8; 32],
    nullifier_gap_root: &[u8; 32],
) -> Result<(), VerificationError> {
    verify_claim_proof_bytes(
        pvk,
        &proof_output.zkproof,
        value_commitment_scheme,
        &proof_output.rk,
        proof_output.cv.as_ref(),
        proof_output.cv_sha256.as_ref(),
        note_commitment_root,
        &proof_output.hiding_nf,
        nullifier_gap_root,
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
