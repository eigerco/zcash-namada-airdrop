//! Claim submission signing command implementation.

use std::collections::BTreeMap;
use std::path::PathBuf;

use eyre::{Context as _, ContextCompat as _, ensure};
use jubjub::Fr;
use secrecy::{ExposeSecret, SecretBox};
use tokio::io::AsyncReadExt;
use tracing::info;
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::submission::{ClaimSubmission, SaplingSignedClaim, SubmissionPool};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Network;
use zip32::AccountId;

use super::claim_proofs::{
    ClaimProofsOutput, ClaimSecretsOutput, SaplingClaimProofResult, SaplingClaimSecretResult,
};
use super::signature_digest::{hash_message, hash_proof_bundle, signature_digest};
use crate::common::to_zcash_network;

struct SaplingSpendAuthKeys {
    external: sapling::keys::SpendAuthorizingKey,
    internal: sapling::keys::SpendAuthorizingKey,
}

fn parse_seed(seed_hex: &str) -> eyre::Result<SecretBox<[u8; 64]>> {
    let seed_bytes = zeroize::Zeroizing::new(hex::decode(seed_hex).context("Invalid hex seed")?);

    let array: [u8; 64] = seed_bytes[..].try_into().map_err(|_| {
        eyre::eyre!(
            "Seed must be exactly 64 bytes (128 hex characters), got {} bytes",
            seed_bytes.len()
        )
    })?;

    Ok(SecretBox::new(Box::new(array)))
}

fn derive_sapling_spend_auth_keys(
    network: Network,
    seed: &[u8; 64],
    account_id: u32,
) -> eyre::Result<SaplingSpendAuthKeys> {
    let account_id =
        AccountId::try_from(account_id).map_err(|_| eyre::eyre!("Invalid account-id"))?;

    let usk = UnifiedSpendingKey::from_seed(&network, seed, account_id)
        .map_err(|e| eyre::eyre!("Failed to derive spending key: {e:?}"))?;

    let extsk = usk.sapling();
    Ok(SaplingSpendAuthKeys {
        external: extsk.expsk.ask.clone(),
        internal: extsk.derive_internal().expsk.ask,
    })
}

fn sign_sapling_claim(
    proof: &SaplingClaimProofResult,
    secret: &SaplingClaimSecretResult,
    keys: &SaplingSpendAuthKeys,
    digest: &[u8; 32],
) -> eyre::Result<[u8; 64]> {
    ensure!(
        proof.airdrop_nullifier == secret.airdrop_nullifier,
        "Proof/secret mismatch: airdrop nullifier differs"
    );

    let alpha = Fr::from_bytes(&secret.alpha)
        .into_option()
        .context("Invalid alpha in secrets file")?;

    let mut matched_signing_key: Option<redjubjub::SigningKey<redjubjub::SpendAuth>> = None;

    let external_signing_key = keys.external.randomize(&alpha);
    let external_rk_bytes: [u8; 32] =
        redjubjub::VerificationKey::from(&external_signing_key).into();
    if external_rk_bytes == proof.rk {
        matched_signing_key = Some(external_signing_key);
    }

    let internal_signing_key = keys.internal.randomize(&alpha);
    let internal_rk_bytes: [u8; 32] =
        redjubjub::VerificationKey::from(&internal_signing_key).into();
    if internal_rk_bytes == proof.rk && matched_signing_key.is_none() {
        matched_signing_key = Some(internal_signing_key);
    }

    ensure!(
        matched_signing_key.is_some(),
        "Cannot match proof rk to a seed-derived Sapling spend key"
    );

    let signing_key = matched_signing_key.context("Missing matched Sapling signing key")?;
    let signature = signing_key.sign(rand_core::OsRng, digest);
    Ok(signature.into())
}

/// Sign a Sapling proof bundle into a submission package.
///
/// # Errors
/// Returns an error if inputs are invalid, key derivation fails, or signing fails.
#[allow(clippy::too_many_arguments, reason = "CLI entrypoint parameters")]
pub async fn sign_claim_submission(
    proofs_file: PathBuf,
    secrets_file: PathBuf,
    seed_file: PathBuf,
    account_id: u32,
    airdrop_configuration_file: PathBuf,
    message_file: PathBuf,
    submission_output_file: PathBuf,
) -> eyre::Result<()> {
    info!(file = ?proofs_file, "Loading proofs for signing...");
    let proofs: ClaimProofsOutput =
        serde_json::from_str(&tokio::fs::read_to_string(&proofs_file).await?)
            .context("Failed to parse proofs JSON")?;

    info!(file = ?secrets_file, "Loading local secrets...");
    let secrets: ClaimSecretsOutput =
        serde_json::from_str(&tokio::fs::read_to_string(&secrets_file).await?)
            .context("Failed to parse secrets JSON")?;

    ensure!(
        proofs.orchard_proofs.is_empty(),
        "Orchard proof signing is not implemented yet"
    );
    ensure!(
        secrets.orchard.is_empty(),
        "Orchard secret signing material is not implemented yet"
    );
    ensure!(
        proofs.sapling_proofs.len() == secrets.sapling.len(),
        "Proof/secret count mismatch for Sapling entries"
    );

    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(&airdrop_configuration_file).await?)
            .context("Failed to parse airdrop configuration JSON")?;
    let sapling_config = airdrop_config
        .sapling
        .as_ref()
        .context("Sapling signing requested, but airdrop configuration has no sapling pool")?;

    info!(file = ?seed_file, "Reading seed from file...");
    let mut file = tokio::fs::File::open(&seed_file)
        .await
        .context("Failed to open seed file")?;
    let mut buffer = zeroize::Zeroizing::new(Vec::new());
    file.read_to_end(&mut buffer)
        .await
        .context("Failed to read seed file")?;
    let seed_hex = std::str::from_utf8(&buffer)
        .context("Seed file is not valid UTF-8")?
        .trim();
    let seed = parse_seed(seed_hex)?;

    let network = to_zcash_network(airdrop_config.network);
    let keys = derive_sapling_spend_auth_keys(network, seed.expose_secret(), account_id)?;

    let message_bytes = tokio::fs::read(&message_file)
        .await
        .context("Failed to read message file")?;
    let message_hash = hash_message(&message_bytes);
    let proof_hash = hash_proof_bundle(&proofs)?;
    let digest = signature_digest(
        SubmissionPool::Sapling,
        &sapling_config.target_id,
        &proof_hash,
        &message_hash,
    )?;

    let mut secret_by_nf = BTreeMap::new();
    for secret in secrets.sapling {
        let existing = secret_by_nf.insert(secret.airdrop_nullifier, secret);
        ensure!(
            existing.is_none(),
            "Duplicate Sapling secret entry for airdrop nullifier"
        );
    }

    let mut sapling = Vec::with_capacity(proofs.sapling_proofs.len());
    for proof in &proofs.sapling_proofs {
        let secret = secret_by_nf
            .get(&proof.airdrop_nullifier)
            .context("Missing secret material for Sapling proof entry")?;
        let spend_auth_sig = sign_sapling_claim(proof, secret, &keys, &digest)?;
        sapling.push(SaplingSignedClaim {
            zkproof: proof.zkproof,
            rk: proof.rk,
            cv: proof.cv,
            cv_sha256: proof.cv_sha256,
            airdrop_nullifier: proof.airdrop_nullifier,
            spend_auth_sig,
        });
    }

    let submission = ClaimSubmission {
        pool: SubmissionPool::Sapling,
        target_id: sapling_config.target_id.clone(),
        proof_hash,
        message_hash,
        sapling,
        orchard: Vec::new(),
    };

    let json = serde_json::to_string_pretty(&submission)?;
    tokio::fs::write(&submission_output_file, json).await?;
    info!(
        file = ?submission_output_file,
        count = submission.sapling.len(),
        "Signed claim submission written"
    );

    Ok(())
}
