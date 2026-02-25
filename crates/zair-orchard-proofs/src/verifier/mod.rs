use halo2_proofs::plonk::{SingleVerifier, verify_proof};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::Blake2bRead;
use pasta_curves::vesta;

use crate::error::ClaimProofError;
use crate::instance::to_instance;
use crate::keys::keys_for;
use crate::types::{ClaimProofOutput, ValueCommitmentScheme};

/// Verify an Orchard claim proof with the given public inputs.
///
/// # Errors
/// Returns an error if the public inputs fail decoding or if Halo2 verification fails.
pub fn verify_claim_proof_output(
    params: &Params<vesta::Affine>,
    output: &ClaimProofOutput,
    note_commitment_root: [u8; 32],
    nullifier_gap_root: [u8; 32],
    value_commitment_scheme: ValueCommitmentScheme,
    target_id: &[u8],
) -> Result<(), ClaimProofError> {
    if target_id.len() > 32 {
        return Err(ClaimProofError::InvalidTargetIdLength);
    }
    std::str::from_utf8(target_id).map_err(|_| ClaimProofError::InvalidTargetIdUtf8)?;
    let mut target_id_arr = [0_u8; 32];
    target_id_arr[..target_id.len()].copy_from_slice(target_id);
    let target_id_len = target_id.len() as u8;

    let [col0] = to_instance(
        note_commitment_root,
        output.cv,
        output.cv_sha256,
        output.airdrop_nullifier,
        output.rk,
        nullifier_gap_root,
        value_commitment_scheme,
    )?;
    let instance_cols: [&[vesta::Scalar]; 1] = [&col0[..]];
    let instances: [&[&[vesta::Scalar]]; 1] = [&instance_cols];

    let keys = keys_for(
        params,
        value_commitment_scheme,
        target_id_arr,
        target_id_len,
    )?;
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::init(&output.zkproof[..]);
    verify_proof(params, &keys.vk, strategy, &instances, &mut transcript)?;
    Ok(())
}
