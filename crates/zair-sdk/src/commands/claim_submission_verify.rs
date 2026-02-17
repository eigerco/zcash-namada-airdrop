//! Claim submission signature verification command implementation.

use std::path::PathBuf;

use eyre::{Context as _, ContextCompat as _, ensure};
use tracing::{info, warn};
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::submission::{ClaimSubmission, SubmissionPool};

use super::claim_proofs::{ClaimProofsOutput, SaplingClaimProofResult};
use super::signature_digest::{hash_message, hash_proof_bundle, signature_digest};

/// Verify spend-auth signatures in a submission package.
///
/// # Errors
/// Returns an error if parsing fails, digest mismatches are found, config-binding checks fail,
/// or any signature is invalid.
pub async fn verify_claim_submission_signature(
    submission_file: PathBuf,
    message_file: PathBuf,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    info!(file = ?submission_file, "Loading signed submission...");
    let submission: ClaimSubmission =
        serde_json::from_str(&tokio::fs::read_to_string(&submission_file).await?)
            .context("Failed to parse submission JSON")?;

    ensure!(
        submission.pool == SubmissionPool::Sapling,
        "Orchard signature verification is not implemented yet"
    );
    ensure!(
        submission.orchard.is_empty(),
        "Orchard signature verification is not implemented yet"
    );
    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(&airdrop_configuration_file).await?)
            .context("Failed to parse airdrop configuration JSON")?;
    let sapling = airdrop_config.sapling.as_ref().context(
        "Sapling signature verification requested, but airdrop configuration has no sapling pool",
    )?;
    ensure!(
        submission.target_id == sapling.target_id,
        "Submission target_id does not match airdrop configuration"
    );

    let message_bytes = tokio::fs::read(&message_file)
        .await
        .context("Failed to read message file")?;
    let expected_message_hash = hash_message(&message_bytes);
    ensure!(
        expected_message_hash == submission.message_hash,
        "Message hash mismatch for signed submission"
    );

    let proofs = ClaimProofsOutput {
        sapling_proofs: submission
            .sapling
            .iter()
            .map(|entry| SaplingClaimProofResult {
                zkproof: entry.zkproof,
                rk: entry.rk,
                cv: entry.cv,
                cv_sha256: entry.cv_sha256,
                airdrop_nullifier: entry.airdrop_nullifier,
            })
            .collect(),
        orchard_proofs: Vec::new(),
    };
    let expected_proof_hash = hash_proof_bundle(&proofs)?;
    ensure!(
        expected_proof_hash == submission.proof_hash,
        "Proof hash mismatch for signed submission"
    );

    let digest = signature_digest(
        submission.pool,
        &submission.target_id,
        &submission.proof_hash,
        &submission.message_hash,
    )?;

    let mut invalid_count = 0_usize;
    for (idx, entry) in submission.sapling.iter().enumerate() {
        let rk = redjubjub::VerificationKey::<redjubjub::SpendAuth>::try_from(entry.rk)
            .map_err(|_| eyre::eyre!("Invalid rk encoding at index {idx}"))?;
        let signature = redjubjub::Signature::from(entry.spend_auth_sig);

        if rk.verify(&digest, &signature).is_ok() {
            info!(
                index = idx,
                airdrop_nullifier = %entry.airdrop_nullifier,
                "Signature VALID"
            );
        } else {
            invalid_count = invalid_count.saturating_add(1);
            warn!(
                index = idx,
                airdrop_nullifier = %entry.airdrop_nullifier,
                "Signature INVALID"
            );
        }
    }

    ensure!(
        invalid_count == 0,
        "{invalid_count} submission signatures failed verification"
    );

    info!(
        count = submission.sapling.len(),
        "All submission signatures are VALID"
    );
    Ok(())
}
