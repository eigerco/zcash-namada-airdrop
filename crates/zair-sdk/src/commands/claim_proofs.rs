//! Claim proof DTOs and verification command implementation.

use std::path::PathBuf;

use eyre::{Context as _, ensure};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use zair_core::base::Nullifier;
use zair_sapling_proofs::verifier::{ClaimProofOutput, verify_claim_proof_output};

/// Output format for claim proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimProofsOutput {
    /// Sapling claim proofs.
    pub sapling_proofs: Vec<SaplingClaimProofResult>,
    /// Orchard claim proofs (not yet implemented).
    pub orchard_proofs: Vec<()>,
}

/// Result of generating a single Sapling claim proof.
///
/// This struct extends [`zair_sapling_proofs::verifier::ClaimProofOutput`] with metadata (`value`,
/// `block_height`) needed for airdrop claim submission. The proof fields (`zkproof`, `rk`, `cv`,
/// `anchor`, `nm_anchor`) mirror `ClaimProofOutput`, while `hiding_nullifier` corresponds to
/// `ClaimProofOutput::hiding_nf` but uses [`Nullifier`] type with reversed-hex serialization for
/// display consistency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaplingClaimProofResult {
    /// The Groth16 proof (192 bytes)
    #[serde(with = "hex::serde")]
    pub zkproof: [u8; 192],
    /// The re-randomized spend verification key (rk)
    #[serde(with = "hex::serde")]
    pub rk: [u8; 32],
    /// The value commitment (cv)
    #[serde(with = "hex::serde")]
    pub cv: [u8; 32],
    /// The anchor (merkle tree root)
    #[serde(with = "hex::serde")]
    pub anchor: [u8; 32],
    /// The non-membership tree root
    #[serde(with = "hex::serde")]
    pub nm_anchor: [u8; 32],
    /// The note value
    pub value: u64,
    /// The hiding nullifier (airdrop-specific nullifier for double-claim prevention)
    pub hiding_nullifier: Nullifier,
    /// Block height where the note was created
    pub block_height: u64,
}

/// Verify all Sapling claim proofs from a proofs file (output of prove).
///
/// # Arguments
///
/// * `proofs_file` - Path to JSON file containing the proofs (`ClaimProofsOutput` format)
/// * `verifying_key_file` - Path to the verifying key file
///
/// # Errors
/// Returns an error if file I/O, parsing, or proof verification fails.
pub async fn verify_claim_sapling_proof(
    proofs_file: PathBuf,
    verifying_key_file: PathBuf,
) -> eyre::Result<()> {
    info!(file = ?proofs_file, "Loading claim proofs for verification...");

    // Load proofs from JSON (ClaimProofsOutput format from prove)
    let proofs: ClaimProofsOutput =
        serde_json::from_str(&tokio::fs::read_to_string(&proofs_file).await?)
            .context("Failed to parse proofs JSON")?;

    info!(
        sapling_count = proofs.sapling_proofs.len(),
        "Proofs loaded, starting verification..."
    );

    // Load verifying key
    eyre::ensure!(
        tokio::fs::try_exists(&verifying_key_file).await?,
        "Verifying key not found at {}",
        verifying_key_file.display()
    );

    let bytes = tokio::fs::read(&verifying_key_file).await?;
    let vk =
        bellman::groth16::VerifyingKey::read(&bytes[..]).context("Failed to read verifying key")?;
    let pvk = bellman::groth16::prepare_verifying_key(&vk);

    // Verification is CPU-intensive, run in blocking task
    let (valid_count, invalid_count, total) = tokio::task::spawn_blocking(move || {
        let mut valid_count = 0_usize;
        let mut invalid_count = 0_usize;

        for (i, proof_result) in proofs.sapling_proofs.iter().enumerate() {
            // Convert to ClaimProofOutput
            let proof_output = ClaimProofOutput {
                zkproof: proof_result.zkproof,
                rk: proof_result.rk,
                cv: proof_result.cv,
                anchor: proof_result.anchor,
                hiding_nf: proof_result.hiding_nullifier.into(),
                nm_anchor: proof_result.nm_anchor,
            };

            // Verify the proof
            match verify_claim_proof_output(&proof_output, &pvk) {
                Ok(()) => {
                    info!(
                        index = i,
                        value = proof_result.value,
                        hiding_nullifier = %proof_result.hiding_nullifier,
                        block_height = proof_result.block_height,
                        "Proof VALID"
                    );
                    valid_count = valid_count.saturating_add(1);
                }
                Err(e) => {
                    warn!(
                        index = i,
                        value = proof_result.value,
                        hiding_nullifier = %proof_result.hiding_nullifier,
                        block_height = proof_result.block_height,
                        error = %e,
                        "Proof INVALID"
                    );
                    invalid_count = invalid_count.saturating_add(1);
                }
            }
        }

        (valid_count, invalid_count, proofs.sapling_proofs.len())
    })
    .await?;

    info!(
        valid = valid_count,
        invalid = invalid_count,
        total = total,
        "Verification complete"
    );

    ensure!(
        invalid_count == 0,
        "{invalid_count} proofs failed verification"
    );

    info!("All {total} Sapling claim proofs are VALID");

    Ok(())
}
