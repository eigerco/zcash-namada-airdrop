//! Generate claim proofs using the custom claim circuit.

use std::path::PathBuf;
use std::sync::Arc;

use bellman::groth16::PreparedVerifyingKey;
use bls12_381::Bls12;
use eyre::{Context as _, ensure};
use secrecy::{ExposeSecret, SecretBox};
use tokio::io::AsyncReadExt;
use tracing::{info, warn};
use zair_core::base::Nullifier;
use zair_core::schema::proof_inputs::{
    AirdropClaimInputs, ClaimInput, SaplingPrivateInputs, SerializableScope,
};
use zair_sapling_proofs::prover::{
    ClaimParameters, ClaimProofInputs, generate_claim_proof, generate_parameters, load_parameters,
    save_parameters,
};
use zair_sapling_proofs::verifier::{ClaimProofOutput, verify_claim_proof_output};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Network;
use zip32::AccountId;

use super::claim_proofs::{ClaimProofsOutput, SaplingClaimProofResult};

/// Generate or load the claim circuit parameters with custom paths.
async fn load_params(proving_key_path: PathBuf) -> eyre::Result<ClaimParameters> {
    ensure!(
        tokio::fs::try_exists(&proving_key_path).await?,
        "Proving key not found at {}, please use the generated parameters for the airdrop",
        proving_key_path.display()
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
) -> eyre::Result<()> {
    info!("Generating claim circuit parameters...");
    info!("This creates Groth16 proving and verifying keys for the claim circuit.");

    let params = tokio::task::spawn_blocking(generate_parameters)
        .await?
        .map_err(|e| eyre::eyre!("Parameter generation failed: {e}"))?;

    info!("Saving proving key to {}...", proving_key_file.display());
    info!(
        "Saving verifying key to {}...",
        verifying_key_file.display()
    );

    tokio::task::spawn_blocking({
        let proving_key_file = proving_key_file.clone();
        let verifying_key_file = verifying_key_file.clone();
        move || save_parameters(&params, &proving_key_file, &verifying_key_file)
    })
    .await?
    .context("Failed to save parameters")?;

    // Log file sizes
    let proving_size = tokio::fs::metadata(&proving_key_file).await?.len();
    let verifying_size = tokio::fs::metadata(&verifying_key_file).await?.len();

    info!(
        proving_key = %proving_key_file.display(),
        proving_size_kb = proving_size / 1024,
        verifying_key = %verifying_key_file.display(),
        verifying_size_kb = verifying_size / 1024,
        "Parameters generated successfully"
    );

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
) -> eyre::Result<SaplingProofGenerationKeys> {
    let usk = UnifiedSpendingKey::from_seed(&network, seed, AccountId::ZERO)
        .map_err(|e| eyre::eyre!("Failed to derive spending key: {e:?}"))?;

    let extsk = usk.sapling();
    Ok(SaplingProofGenerationKeys {
        external: extsk.expsk.proof_generation_key(),
        internal: extsk.derive_internal().expsk.proof_generation_key(),
    })
}

/// Generate and verify a single Sapling claim proof.
///
/// Returns `Some(proof_result)` on success, `None` if generation or verification fails.
fn generate_single_sapling_proof(
    claim_input: &ClaimInput<SaplingPrivateInputs>,
    params: &ClaimParameters,
    pvk: &PreparedVerifyingKey<Bls12>,
    keys: &SaplingProofGenerationKeys,
    nm_anchor: [u8; 32],
) -> Option<SaplingClaimProofResult> {
    info!(
        value = claim_input.private_inputs.value,
        block_height = claim_input.block_height,
        "Generating claim proof..."
    );

    let proof_generation_key = match claim_input.private_inputs.scope {
        SerializableScope::External => keys.external.clone(),
        SerializableScope::Internal => keys.internal.clone(),
    };

    let hiding_nf: [u8; 32] = claim_input.public_inputs.hiding_nullifier.into();
    let claim_inputs = to_claim_proof_inputs(&claim_input.private_inputs, hiding_nf, nm_anchor);

    match generate_claim_proof(params, &claim_inputs, &proof_generation_key) {
        Ok(proof_output) => match verify_claim_proof_output(&proof_output, pvk) {
            Ok(()) => {
                info!("Proof generated and verified successfully");
                Some(to_proof_result(
                    &proof_output,
                    claim_input.private_inputs.value,
                    claim_input.public_inputs.hiding_nullifier,
                    claim_input.block_height,
                ))
            }
            Err(e) => {
                warn!(error = %e, "Proof verification failed, skipping");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "Failed to generate proof, skipping");
            None
        }
    }
}

/// Generate Sapling proofs in parallel using tokio's blocking thread pool.
async fn generate_sapling_proofs_parallel(
    sapling_inputs: Vec<ClaimInput<SaplingPrivateInputs>>,
    params: Arc<ClaimParameters>,
    pvk: Arc<PreparedVerifyingKey<Bls12>>,
    keys: Arc<SaplingProofGenerationKeys>,
    nm_anchor: [u8; 32],
) -> Vec<SaplingClaimProofResult> {
    let mut join_set = tokio::task::JoinSet::new();

    for claim_input in sapling_inputs {
        let params = Arc::clone(&params);
        let pvk = Arc::clone(&pvk);
        let keys = Arc::clone(&keys);

        join_set.spawn_blocking(move || {
            generate_single_sapling_proof(&claim_input, &params, &pvk, &keys, nm_anchor)
        });
    }

    let mut proofs = Vec::new();
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Some(proof)) => proofs.push(proof),
            Ok(None) => {} // Proof generation/verification failed, already logged
            Err(e) => warn!(error = %e, "Task panicked"),
        }
    }
    proofs
}

/// Generate claim proofs using the custom claim circuit.
///
/// # Arguments
///
/// * `claim_inputs_file` - Path to JSON file containing claim inputs (from `AirdropClaim`)
/// * `proofs_output_file` - Path to write generated proofs
/// * `seed_file` - Path to file containing 64-byte seed as hex string for deriving spending keys
/// * `network` - Network (mainnet or testnet)
/// * `proving_key_file` - Path to proving key (will be generated if not exists)
///
/// # Errors
/// Returns an error if file I/O, parsing, key derivation, or proof generation fails.
pub async fn generate_claim_proofs(
    claim_inputs_file: PathBuf,
    proofs_output_file: PathBuf,
    seed_file: PathBuf,
    network: Network,
    proving_key_file: PathBuf,
) -> eyre::Result<()> {
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
    let keys = derive_sapling_proof_generation_keys(network, seed.expose_secret())?;
    info!("Derived Sapling proof generation keys (external + internal)");

    let params = load_params(proving_key_file).await?;
    let pvk = params.prepared_verifying_key();
    info!("Parameters ready");

    info!(file = ?claim_inputs_file, "Reading claim inputs...");
    let inputs: AirdropClaimInputs =
        serde_json::from_str(&tokio::fs::read_to_string(&claim_inputs_file).await?)?;

    info!(
        sapling_count = inputs.sapling_claim_input.len(),
        orchard_count = inputs.orchard_claim_input.len(),
        "Loaded claim inputs"
    );

    if !inputs.orchard_claim_input.is_empty() {
        warn!(
            count = inputs.orchard_claim_input.len(),
            "Orchard claim proof generation not yet implemented, skipping"
        );
    }

    let sapling_proofs = generate_sapling_proofs_parallel(
        inputs.sapling_claim_input,
        Arc::new(params),
        Arc::new(pvk),
        Arc::new(keys),
        inputs.non_membership_tree_anchors.sapling,
    )
    .await;

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

    Ok(())
}

/// Convert `SaplingPrivateInputs` to `ClaimProofInputs`.
fn to_claim_proof_inputs(
    private: &SaplingPrivateInputs,
    hiding_nf: [u8; 32],
    nm_anchor: [u8; 32],
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
        hiding_nf,
        nm_left_nf: private.left_nullifier.into(),
        nm_right_nf: private.right_nullifier.into(),
        nm_merkle_path,
        nm_anchor,
    }
}

/// Convert `ClaimProofOutput` to `SaplingClaimProofResult`.
const fn to_proof_result(
    output: &ClaimProofOutput,
    value: u64,
    hiding_nullifier: Nullifier,
    block_height: u64,
) -> SaplingClaimProofResult {
    SaplingClaimProofResult {
        zkproof: output.zkproof,
        rk: output.rk,
        cv: output.cv,
        anchor: output.anchor,
        nm_anchor: output.nm_anchor,
        value,
        hiding_nullifier,
        block_height,
    }
}
