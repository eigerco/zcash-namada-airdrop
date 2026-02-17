//! Generate claim proofs using the custom claim circuit.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bellman::groth16::PreparedVerifyingKey;
use bls12_381::Bls12;
use eyre::{Context as _, ContextCompat as _, ensure};
use group::GroupEncoding as _;
use secrecy::{ExposeSecret, SecretBox};
use tokio::io::AsyncReadExt;
use tracing::info;
use zair_core::base::Nullifier;
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::proof_inputs::{
    AirdropClaimInputs, ClaimInput, SaplingPrivateInputs, SerializableScope,
};
use zair_sapling_proofs::prover::{
    ClaimParameters, ClaimProofInputs, ClaimProofSecretMaterial,
    ValueCommitmentScheme as SaplingValueCommitmentScheme, generate_claim_proof_with_secrets,
    generate_parameters, load_parameters, save_parameters,
};
use zair_sapling_proofs::verifier::{ClaimProofOutput, verify_claim_proof_output};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Network;
use zip32::AccountId;

use super::claim_proofs::{
    ClaimProofsOutput, ClaimSecretsOutput, SaplingClaimProofResult, SaplingClaimSecretResult,
};
use crate::common::to_zcash_network;

/// Sapling setup output scheme(s) for `setup local`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaplingSetupScheme {
    /// Generate parameters for native `cv` proofs.
    Native,
    /// Generate parameters for `cv_sha256` proofs.
    Sha256,
}

fn setup_targets(
    proving_key_file: &Path,
    verifying_key_file: &Path,
    scheme: SaplingSetupScheme,
) -> Vec<(SaplingValueCommitmentScheme, PathBuf, PathBuf)> {
    match scheme {
        SaplingSetupScheme::Native => vec![(
            SaplingValueCommitmentScheme::Native,
            proving_key_file.to_path_buf(),
            verifying_key_file.to_path_buf(),
        )],
        SaplingSetupScheme::Sha256 => vec![(
            SaplingValueCommitmentScheme::Sha256,
            proving_key_file.to_path_buf(),
            verifying_key_file.to_path_buf(),
        )],
    }
}

/// Generate or load the claim circuit parameters with custom paths.
async fn load_params(proving_key_path: PathBuf) -> eyre::Result<ClaimParameters> {
    ensure!(
        tokio::fs::try_exists(&proving_key_path).await?,
        "Proving key not found at {}. Run `zair setup local --scheme native` or `zair setup local --scheme sha256` with matching output paths first.",
        proving_key_path.display(),
    );

    info!("Loading existing claim circuit parameters (this may take a moment)...");
    let params = tokio::task::spawn_blocking(move || load_parameters(&proving_key_path, false))
        .await?
        .context("Failed to load parameters")?;
    info!("Parameters loaded successfully");

    Ok(params)
}

/// Generate claim circuit parameters (proving and verifying keys).
///
/// # Arguments
///
/// * `proving_key_file` - Path to write the proving key
/// * `verifying_key_file` - Path to write the verifying key
///
/// # Errors
/// Returns an error if parameter generation or file I/O fails.
pub async fn generate_claim_params(
    proving_key_file: PathBuf,
    verifying_key_file: PathBuf,
    scheme: SaplingSetupScheme,
) -> eyre::Result<()> {
    info!("Generating claim circuit parameters...");
    info!("This creates Groth16 proving and verifying keys for the Sapling claim circuit.");

    let targets = setup_targets(&proving_key_file, &verifying_key_file, scheme);
    for (scheme, proving_key_path, verifying_key_path) in targets {
        info!(
            scheme = ?scheme,
            proving_key = %proving_key_path.display(),
            verifying_key = %verifying_key_path.display(),
            "Generating parameter set"
        );

        let params = tokio::task::spawn_blocking(move || generate_parameters(scheme))
            .await?
            .map_err(|e| eyre::eyre!("Parameter generation failed for {:?}: {e}", scheme))?;

        tokio::task::spawn_blocking({
            let proving_key_path = proving_key_path.clone();
            let verifying_key_path = verifying_key_path.clone();
            move || save_parameters(&params, &proving_key_path, &verifying_key_path)
        })
        .await?
        .context("Failed to save parameters")?;

        let proving_size = tokio::fs::metadata(&proving_key_path).await?.len();
        let verifying_size = tokio::fs::metadata(&verifying_key_path).await?.len();

        info!(
            scheme = ?scheme,
            proving_key = %proving_key_path.display(),
            proving_size_kb = proving_size / 1024,
            verifying_key = %verifying_key_path.display(),
            verifying_size_kb = verifying_size / 1024,
            "Parameter set generated successfully"
        );
    }

    Ok(())
}

/// Parse a hex-encoded seed into a 64-byte array.
fn parse_seed(seed_hex: &str) -> eyre::Result<SecretBox<[u8; 64]>> {
    // Wrap in Zeroizing immediately so it's zeroized on drop even if we return early.
    let seed_bytes = zeroize::Zeroizing::new(hex::decode(seed_hex).context("Invalid hex seed")?);

    let array: [u8; 64] = seed_bytes[..].try_into().map_err(|_| {
        eyre::eyre!(
            "Seed must be exactly 64 bytes (128 hex characters), got {} bytes",
            seed_bytes.len()
        )
    })?;

    Ok(SecretBox::new(Box::new(array)))
}

/// Sapling proof generation keys for both external and internal scopes.
struct SaplingProofGenerationKeys {
    external: sapling::ProofGenerationKey,
    internal: sapling::ProofGenerationKey,
}

/// Derive Sapling proof generation keys from a seed.
fn derive_sapling_proof_generation_keys(
    network: Network,
    seed: &[u8; 64],
    account_id: u32,
) -> eyre::Result<SaplingProofGenerationKeys> {
    let account_id =
        AccountId::try_from(account_id).map_err(|_| eyre::eyre!("Invalid account-id"))?;

    let usk = UnifiedSpendingKey::from_seed(&network, seed, account_id)
        .map_err(|e| eyre::eyre!("Failed to derive spending key: {e:?}"))?;

    let extsk = usk.sapling();
    Ok(SaplingProofGenerationKeys {
        external: extsk.expsk.proof_generation_key(),
        internal: extsk.derive_internal().expsk.proof_generation_key(),
    })
}

/// Returns true when claim key material matches seed-derived key material for its scope.
#[allow(clippy::similar_names)]
fn claim_matches_seed_keys(
    claim_input: &ClaimInput<SaplingPrivateInputs>,
    keys: &SaplingProofGenerationKeys,
) -> bool {
    let proof_generation_key = match claim_input.private_inputs.scope {
        SerializableScope::External => &keys.external,
        SerializableScope::Internal => &keys.internal,
    };

    let seed_ak = proof_generation_key.ak.to_bytes();
    let seed_nk = proof_generation_key.to_viewing_key().nk.0.to_bytes();

    claim_input.private_inputs.ak == seed_ak && claim_input.private_inputs.nk == seed_nk
}

/// Generate and verify a single Sapling claim proof.
fn generate_single_sapling_proof(
    claim_input: &ClaimInput<SaplingPrivateInputs>,
    params: &ClaimParameters,
    pvk: &PreparedVerifyingKey<Bls12>,
    keys: &SaplingProofGenerationKeys,
    note_commitment_root: [u8; 32],
    nullifier_gap_root: [u8; 32],
    value_commitment_scheme: SaplingValueCommitmentScheme,
) -> eyre::Result<(SaplingClaimProofResult, SaplingClaimSecretResult)> {
    info!(
        value = claim_input.private_inputs.value,
        "Generating claim proof..."
    );

    let proof_generation_key = match claim_input.private_inputs.scope {
        SerializableScope::External => keys.external.clone(),
        SerializableScope::Internal => keys.internal.clone(),
    };

    let hiding_nf: [u8; 32] = claim_input.public_inputs.airdrop_nullifier.into();
    let claim_inputs = to_claim_proof_inputs(
        &claim_input.private_inputs,
        hiding_nf,
        note_commitment_root,
        nullifier_gap_root,
        value_commitment_scheme,
    );

    let (proof_output, secret_material) =
        generate_claim_proof_with_secrets(params, &claim_inputs, &proof_generation_key)
            .map_err(|e| eyre::eyre!("Failed to generate Sapling proof: {e}"))?;

    verify_claim_proof_output(
        &proof_output,
        pvk,
        value_commitment_scheme,
        &note_commitment_root,
        &nullifier_gap_root,
    )
    .map_err(|e| eyre::eyre!("Generated Sapling proof failed self-verification: {e}"))?;

    info!("Proof generated and verified successfully");
    Ok((
        to_proof_result(&proof_output, claim_input.public_inputs.airdrop_nullifier),
        to_secret_result(
            &secret_material,
            claim_input.public_inputs.airdrop_nullifier,
        ),
    ))
}

/// Generate Sapling proofs in parallel using tokio's blocking thread pool.
async fn generate_sapling_proofs_parallel(
    sapling_inputs: Vec<ClaimInput<SaplingPrivateInputs>>,
    params: Arc<ClaimParameters>,
    pvk: Arc<PreparedVerifyingKey<Bls12>>,
    keys: Arc<SaplingProofGenerationKeys>,
    note_commitment_root: [u8; 32],
    nullifier_gap_root: [u8; 32],
    value_commitment_scheme: SaplingValueCommitmentScheme,
) -> eyre::Result<(Vec<SaplingClaimProofResult>, Vec<SaplingClaimSecretResult>)> {
    let mut join_set = tokio::task::JoinSet::new();

    for claim_input in sapling_inputs {
        let params = Arc::clone(&params);
        let pvk = Arc::clone(&pvk);
        let keys = Arc::clone(&keys);

        join_set.spawn_blocking(move || {
            generate_single_sapling_proof(
                &claim_input,
                &params,
                &pvk,
                &keys,
                note_commitment_root,
                nullifier_gap_root,
                value_commitment_scheme,
            )
        });
    }

    let mut proofs = Vec::new();
    let mut secrets = Vec::new();
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok((proof, secret))) => {
                proofs.push(proof);
                secrets.push(secret);
            }
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(eyre::eyre!("Sapling proving task failed: {e}")),
        }
    }
    Ok((proofs, secrets))
}

/// Generate claim proofs using the custom claim circuit.
///
/// # Arguments
///
/// * `claim_inputs_file` - Path to JSON file containing claim inputs (from `AirdropClaim`)
/// * `proofs_output_file` - Path to write generated proofs
/// * `seed_file` - Path to file containing 64-byte seed as hex string for deriving spending keys
/// * `account_id` - ZIP-32 account index used to derive Sapling keys from the seed
/// * `proving_key_file` - Path to proving key
/// * `secrets_output_file` - Path to local-only secrets output file
/// * `airdrop_configuration_file` - Path to airdrop configuration JSON
///
/// # Errors
/// Returns an error if file I/O, parsing, key derivation, or proof generation fails.
pub async fn generate_claim_proofs(
    claim_inputs_file: PathBuf,
    proofs_output_file: PathBuf,
    seed_file: PathBuf,
    account_id: u32,
    proving_key_file: PathBuf,
    secrets_output_file: PathBuf,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    info!(file = ?claim_inputs_file, "Reading claim inputs...");
    let inputs: AirdropClaimInputs =
        serde_json::from_str(&tokio::fs::read_to_string(&claim_inputs_file).await?)?;

    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(&airdrop_configuration_file).await?)
            .context("Failed to parse airdrop configuration JSON")?;

    let network = to_zcash_network(airdrop_config.network);
    let sapling_config = if inputs.sapling_claim_input.is_empty() {
        None
    } else {
        Some(
            airdrop_config
                .sapling
                .as_ref()
                .context("Sapling claims present but airdrop configuration has no sapling pool")?,
        )
    };
    let sapling_scheme = sapling_config.map_or(SaplingValueCommitmentScheme::Native, |s| {
        s.value_commitment_scheme.into()
    });

    info!(file = ?seed_file, "Reading seed from file...");

    let mut file = tokio::fs::File::open(&seed_file)
        .await
        .context("Failed to open seed file")?;

    // Read directly into a Zeroizing buffer to avoid intermediate String allocations
    let mut buffer = zeroize::Zeroizing::new(Vec::new());
    file.read_to_end(&mut buffer)
        .await
        .context("Failed to read seed file")?;

    // Borrow as &str - no intermediate String allocation
    let seed_hex_str = std::str::from_utf8(&buffer)
        .context("Seed file is not valid UTF-8")?
        .trim();

    let seed = parse_seed(seed_hex_str)?;

    info!("Deriving spending keys...");
    let keys = derive_sapling_proof_generation_keys(network, seed.expose_secret(), account_id)?;
    info!("Derived Sapling proof generation keys (external + internal)");

    ensure!(
        inputs
            .sapling_claim_input
            .iter()
            .all(|claim| claim_matches_seed_keys(claim, &keys)),
        "Seed mismatch: seed-derived Sapling keys do not match claim file"
    );

    let params = load_params(proving_key_file).await?;
    let pvk = params.prepared_verifying_key();
    info!("Parameters ready");

    info!(
        sapling_count = inputs.sapling_claim_input.len(),
        orchard_count = inputs.orchard_claim_input.len(),
        "Loaded claim inputs"
    );

    if !inputs.orchard_claim_input.is_empty() {
        return Err(eyre::eyre!(
            "Orchard claim proof generation is not implemented yet ({} Orchard claims in prepared file)",
            inputs.orchard_claim_input.len()
        ));
    }

    let expected_sapling_count = inputs.sapling_claim_input.len();
    let (sapling_proofs, sapling_secrets) = generate_sapling_proofs_parallel(
        inputs.sapling_claim_input,
        Arc::new(params),
        Arc::new(pvk),
        Arc::new(keys),
        sapling_config.map_or([0_u8; 32], |s| s.note_commitment_root),
        sapling_config.map_or([0_u8; 32], |s| s.nullifier_gap_root),
        sapling_scheme,
    )
    .await?;

    ensure!(
        sapling_proofs.len() == expected_sapling_count,
        "Expected {expected_sapling_count} Sapling proofs, generated {}",
        sapling_proofs.len()
    );
    ensure!(
        sapling_secrets.len() == expected_sapling_count,
        "Expected {expected_sapling_count} Sapling secrets, generated {}",
        sapling_secrets.len()
    );

    let output = ClaimProofsOutput {
        sapling_proofs,
        orchard_proofs: Vec::new(),
    };

    let json = serde_json::to_string_pretty(&output)?;
    tokio::fs::write(&proofs_output_file, json).await?;

    info!(
        file = ?proofs_output_file,
        sapling_count = output.sapling_proofs.len(),
        "Claim proofs written"
    );

    let secrets = ClaimSecretsOutput {
        sapling: sapling_secrets,
        orchard: Vec::new(),
    };
    let secrets_json = serde_json::to_string_pretty(&secrets)?;
    tokio::fs::write(&secrets_output_file, secrets_json).await?;
    info!(file = ?secrets_output_file, "Claim secrets written");

    Ok(())
}

/// Convert `SaplingPrivateInputs` to `ClaimProofInputs`.
fn to_claim_proof_inputs(
    private: &SaplingPrivateInputs,
    hiding_nf: [u8; 32],
    anchor: [u8; 32],
    nm_anchor: [u8; 32],
    value_commitment_scheme: SaplingValueCommitmentScheme,
) -> ClaimProofInputs {
    // Convert the non-membership merkle path from Vec<[u8; 32]> to Vec<([u8; 32], bool)>
    // The bool indicates if the current node is on the right side
    let nm_merkle_path: Vec<([u8; 32], bool)> = private
        .nf_merkle_proof
        .iter()
        .enumerate()
        .map(|(i, sibling)| {
            let is_right = (private.nf_leaf_position >> i) & 1 == 1;
            (*sibling, is_right)
        })
        .collect();

    ClaimProofInputs {
        diversifier: private.diversifier,
        pk_d: private.pk_d,
        value: private.value,
        rcm: private.rcm,
        ak: private.ak,
        position: private.cm_note_position,
        merkle_path: private.cm_merkle_proof.clone(),
        anchor,
        hiding_nf,
        nm_left_nf: private.left_nullifier.into(),
        nm_right_nf: private.right_nullifier.into(),
        nm_merkle_path,
        nm_anchor,
        value_commitment_scheme,
    }
}

/// Convert `ClaimProofOutput` to `SaplingClaimProofResult`.
const fn to_proof_result(
    output: &ClaimProofOutput,
    airdrop_nullifier: Nullifier,
) -> SaplingClaimProofResult {
    SaplingClaimProofResult {
        zkproof: output.zkproof,
        rk: output.rk,
        cv: output.cv,
        cv_sha256: output.cv_sha256,
        airdrop_nullifier,
    }
}

/// Convert `ClaimProofSecretMaterial` to `SaplingClaimSecretResult`.
const fn to_secret_result(
    secret_material: &ClaimProofSecretMaterial,
    airdrop_nullifier: Nullifier,
) -> SaplingClaimSecretResult {
    SaplingClaimSecretResult {
        airdrop_nullifier,
        alpha: secret_material.alpha,
        rcv: secret_material.rcv,
        rcv_sha256: secret_material.rcv_sha256,
    }
}
