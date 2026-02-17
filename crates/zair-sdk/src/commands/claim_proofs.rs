//! Claim proof DTOs and verification command implementation.

use std::path::PathBuf;

use eyre::{Context as _, ContextCompat as _, ensure};
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;
use tracing::{info, warn};
use zair_core::base::Nullifier;
use zair_core::schema::config::AirdropConfiguration;
use zair_sapling_proofs::verifier::{
    ValueCommitmentScheme as SaplingValueCommitmentScheme, verify_claim_proof_bytes,
};

/// Output format for claim proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimProofsOutput {
    /// Sapling claim proofs.
    pub sapling_proofs: Vec<SaplingClaimProofResult>,
    /// Orchard claim proofs (not yet implemented).
    pub orchard_proofs: Vec<()>,
}

/// Serializable output of a single Sapling claim proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaplingClaimProofResult {
    /// The Groth16 proof (192 bytes)
    #[serde_as(as = "Hex")]
    pub zkproof: [u8; 192],
    /// The re-randomized spend verification key (rk)
    #[serde_as(as = "Hex")]
    pub rk: [u8; 32],
    /// The native value commitment (cv), if the scheme is `native`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv: Option<[u8; 32]>,
    /// The SHA-256 value commitment (`cv_sha256`), if the scheme is `sha256`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv_sha256: Option<[u8; 32]>,
    /// The airdrop nullifier (airdrop-specific nullifier for double-claim prevention).
    pub airdrop_nullifier: Nullifier,
}

/// Local-only secrets output format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSecretsOutput {
    /// Sapling local-only secret material.
    pub sapling: Vec<SaplingClaimSecretResult>,
    /// Orchard local-only secret material (not yet implemented).
    pub orchard: Vec<()>,
}

/// Local-only secret material for a single Sapling claim proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaplingClaimSecretResult {
    /// The airdrop nullifier this secret material corresponds to.
    pub airdrop_nullifier: Nullifier,
    /// Spend authorization randomizer used for rk/signature binding.
    #[serde_as(as = "Hex")]
    pub alpha: [u8; 32],
    /// Native commitment randomness `rcv`, if the scheme is `native`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcv: Option<[u8; 32]>,
    /// SHA-256 commitment randomness `rcv_sha256`, if the scheme is `sha256`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcv_sha256: Option<[u8; 32]>,
}

/// Verify all Sapling claim proofs from a proofs file (output of prove).
///
/// # Arguments
///
/// * `proofs_file` - Path to JSON file containing the proofs (`ClaimProofsOutput` format)
/// * `verifying_key_file` - Path to the verifying key file
/// * `airdrop_configuration_file` - Airdrop configuration used to bind expected anchors/scheme
///
/// # Errors
/// Returns an error if file I/O, parsing, or proof verification fails.
#[allow(
    clippy::too_many_lines,
    reason = "End-to-end verification flow performs config binding, key loading, and batch checks"
)]
pub async fn verify_claim_sapling_proof(
    proofs_file: PathBuf,
    verifying_key_file: PathBuf,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    info!(file = ?proofs_file, "Loading claim proofs for verification...");

    // Load proofs from JSON (ClaimProofsOutput format from prove)
    let proofs: ClaimProofsOutput =
        serde_json::from_str(&tokio::fs::read_to_string(&proofs_file).await?)
            .context("Failed to parse proofs JSON")?;
    verify_claim_sapling_proofs(proofs, verifying_key_file, airdrop_configuration_file).await
}

/// Verify all Sapling claim proofs from an in-memory `ClaimProofsOutput`.
///
/// # Errors
/// Returns an error if parsing, key loading, or proof verification fails.
#[allow(
    clippy::too_many_lines,
    reason = "End-to-end verification flow performs config binding, key loading, and batch checks"
)]
pub(super) async fn verify_claim_sapling_proofs(
    proofs: ClaimProofsOutput,
    verifying_key_file: PathBuf,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(&airdrop_configuration_file).await?)
            .context("Failed to parse airdrop configuration JSON")?;

    ensure!(
        proofs.orchard_proofs.is_empty(),
        "Orchard proof verification is not implemented yet"
    );

    let (sapling_scheme, note_commitment_root, nullifier_gap_root) =
        if proofs.sapling_proofs.is_empty() {
            (SaplingValueCommitmentScheme::Native, [0_u8; 32], [0_u8; 32])
        } else {
            let sapling = airdrop_config.sapling.as_ref().context(
                "Sapling proofs provided, but airdrop configuration has no sapling pool",
            )?;
            (
                sapling.value_commitment_scheme.into(),
                sapling.note_commitment_root,
                sapling.nullifier_gap_root,
            )
        };

    info!(
        sapling_count = proofs.sapling_proofs.len(),
        "Proofs loaded, starting verification..."
    );

    // Load verifying key
    eyre::ensure!(
        tokio::fs::try_exists(&verifying_key_file).await?,
        "Verifying key not found at {}. Run `zair setup local --scheme native` or `zair setup local --scheme sha256` (matching the airdrop configuration scheme) and use the generated verifying key path.",
        verifying_key_file.display(),
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
            let hiding_nf: [u8; 32] = proof_result.airdrop_nullifier.into();

            match verify_claim_proof_bytes(
                &pvk,
                &proof_result.zkproof,
                sapling_scheme,
                &proof_result.rk,
                proof_result.cv.as_ref(),
                proof_result.cv_sha256.as_ref(),
                &note_commitment_root,
                &hiding_nf,
                &nullifier_gap_root,
            ) {
                Ok(()) => {
                    info!(
                        index = i,
                        airdrop_nullifier = %proof_result.airdrop_nullifier,
                        "Proof VALID"
                    );
                    valid_count = valid_count.saturating_add(1);
                }
                Err(e) => {
                    warn!(
                        index = i,
                        airdrop_nullifier = %proof_result.airdrop_nullifier,
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
