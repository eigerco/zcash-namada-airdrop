//! Proof generation and verification for the airdrop circuit.
//!
//! This module provides the API for generating and verifying ZK proofs
//! that demonstrate eligibility for the Zcash-Namada airdrop.

use ff::PrimeField;
use halo2_proofs::{
    plonk::{self, create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};
use rand::rngs::OsRng;

use crate::circuit::{compute_beneficiary_commitment_poseidon, AirdropCircuit, K};
use crate::public_inputs::PublicInputs;
use crate::witness::AirdropWitness;

/// Parameters for the proving system.
pub type AirdropParams = Params<vesta::Affine>;

/// Errors that can occur during proof operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// Failed to generate proving key
    #[error("Failed to generate proving key: {0}")]
    KeyGeneration(String),

    /// Failed to create proof
    #[error("Failed to create proof: {0}")]
    ProofCreation(String),

    /// Failed to verify proof
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid proof bytes
    #[error("Invalid proof bytes")]
    InvalidProofBytes,
}

/// A serializable proof for the airdrop circuit.
#[derive(Clone, Debug)]
pub struct AirdropProof {
    /// The raw proof bytes
    bytes: Vec<u8>,
}

impl AirdropProof {
    /// Creates a new proof from bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the proof bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Returns the length of the proof in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if the proof is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Generates the proving and verifying keys for the airdrop circuit.
///
/// This is an expensive operation that should be done once and cached.
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_keys(
    params: &AirdropParams,
) -> Result<(ProvingKey<vesta::Affine>, VerifyingKey<vesta::Affine>), ProofError> {
    let empty_circuit = AirdropCircuit::empty();

    let vk = keygen_vk(params, &empty_circuit)
        .map_err(|e| ProofError::KeyGeneration(format!("{e:?}")))?;

    let pk = keygen_pk(params, vk.clone(), &empty_circuit)
        .map_err(|e| ProofError::KeyGeneration(format!("{e:?}")))?;

    Ok((pk, vk))
}

/// Generates a proof for the given witness and public inputs.
///
/// # Arguments
///
/// * `params` - The proving system parameters
/// * `pk` - The proving key
/// * `witness` - The private witness data
/// * `blinding` - The blinding factor for beneficiary commitment
///
/// # Errors
///
/// Returns an error if proof generation fails.
pub fn create_airdrop_proof(
    params: &AirdropParams,
    pk: &ProvingKey<vesta::Affine>,
    witness: AirdropWitness,
    blinding: [u8; 32],
) -> Result<AirdropProof, ProofError> {
    // Public inputs: [note_value, snapshot_root, beneficiary_commitment]
    let note_value = pallas::Base::from(witness.note_value);
    let snapshot_root = bytes_to_field(&witness.snapshot_root);
    // Use Poseidon directly - it returns a field element
    let beneficiary_commitment =
        compute_beneficiary_commitment_poseidon(&witness.beneficiary, &blinding);
    let public_inputs: Vec<pallas::Base> = vec![note_value, snapshot_root, beneficiary_commitment];

    let circuit = AirdropCircuit::new(witness, blinding);
    let instances: &[&[pallas::Base]] = &[&public_inputs];

    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);

    create_proof(
        params,
        pk,
        &[circuit],
        &[instances],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| ProofError::ProofCreation(format!("{e:?}")))?;

    let proof_bytes = transcript.finalize();
    Ok(AirdropProof::from_bytes(proof_bytes))
}

/// Converts 32 bytes to a Pallas base field element.
///
/// Since the Pallas field modulus is ~2^254, we mask the top 2 bits
/// to ensure the value always fits within the field.
fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
    use ff::PrimeField;
    let mut repr = [0u8; 32];
    repr.copy_from_slice(bytes);
    // Mask the highest 2 bits to ensure the value fits in the Pallas field
    repr[31] &= 0x3F;
    pallas::Base::from_repr(repr).expect("masked bytes always fit in field")
}

/// Verifies an airdrop proof.
///
/// # Arguments
///
/// * `params` - The proving system parameters
/// * `vk` - The verifying key
/// * `proof` - The proof to verify
/// * `public_inputs` - The public inputs to verify against
///
/// # Errors
///
/// Returns an error if verification fails.
pub fn verify_airdrop_proof(
    params: &AirdropParams,
    vk: &VerifyingKey<vesta::Affine>,
    proof: &AirdropProof,
    public_inputs: &PublicInputs,
) -> Result<(), ProofError> {
    // Public inputs: [note_value, snapshot_root, beneficiary_commitment]
    let note_value = pallas::Base::from(public_inputs.note_value);
    let snapshot_root = bytes_to_field(&public_inputs.snapshot_root);
    // Beneficiary commitment is already a valid field element (from Poseidon)
    let beneficiary_commitment = pallas::Base::from_repr(public_inputs.beneficiary_commitment)
        .expect("commitment is valid field element from Poseidon");
    let pi: Vec<pallas::Base> = vec![note_value, snapshot_root, beneficiary_commitment];
    let instances: &[&[pallas::Base]] = &[&pi];

    let mut transcript =
        Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof.bytes.as_slice());

    let strategy = plonk::SingleVerifier::new(params);

    verify_proof(params, vk, strategy, &[instances], &mut transcript)
        .map_err(|e| ProofError::VerificationFailed(format!("{e:?}")))
}

/// Creates new parameters for the proving system.
///
/// This is an expensive operation that should be done once and cached.
#[must_use]
pub fn setup_params() -> AirdropParams {
    Params::new(K)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;
    use crate::witness::AirdropWitness;
    use rs_merkle::algorithms::Sha256;
    use rs_merkle::{Hasher, MerkleTree};

    /// Helper to create a nullifier with specific last byte
    fn nf(val: u8) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr[31] = val;
        arr
    }

    /// Build range leaf
    fn build_range_leaf(left: &[u8; 32], right: &[u8; 32]) -> [u8; 64] {
        let mut leaf = [0u8; 64];
        leaf[..32].copy_from_slice(left);
        leaf[32..].copy_from_slice(right);
        leaf
    }

    /// Build a test Merkle tree and get proof
    fn build_test_tree(nullifiers: &[[u8; 32]]) -> (MerkleTree<Sha256>, [u8; 32]) {
        let min_nf = [0u8; 32];
        let max_nf = [0xFFu8; 32];

        let mut leaves = Vec::new();

        if !nullifiers.is_empty() {
            let leaf = build_range_leaf(&min_nf, &nullifiers[0]);
            leaves.push(Sha256::hash(&leaf));
        }

        for window in nullifiers.windows(2) {
            let leaf = build_range_leaf(&window[0], &window[1]);
            leaves.push(Sha256::hash(&leaf));
        }

        if !nullifiers.is_empty() {
            let leaf = build_range_leaf(&nullifiers[nullifiers.len() - 1], &max_nf);
            leaves.push(Sha256::hash(&leaf));
        }

        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = tree.root().unwrap_or([0u8; 32]);

        (tree, root)
    }

    fn create_test_witness() -> (AirdropWitness, [u8; 32]) {
        let nullifiers = vec![nf(20), nf(40), nf(60)];
        let (tree, root) = build_test_tree(&nullifiers);
        let proof = tree.proof(&[1]);

        let witness = AirdropWitness::new(
            1_000_000,
            nf(30),
            nf(20),
            nf(40),
            proof.to_bytes(),
            1,
            tree.leaves_len(),
            &root,
            [0xAB; 32],
        )
        .expect("Valid witness");

        (witness, root)
    }

    #[test]
    fn test_setup_params() {
        let params = setup_params();
        assert!(params.k() >= K);
    }

    #[test]
    fn test_generate_keys() {
        let params = setup_params();
        let result = generate_keys(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_and_verify_proof() {
        let params = setup_params();
        let (pk, vk) = generate_keys(&params).expect("Key generation");

        let (witness, root) = create_test_witness();
        let blinding = [0x12; 32];

        let proof =
            create_airdrop_proof(&params, &pk, witness.clone(), blinding).expect("Proof creation");

        assert!(!proof.is_empty());

        let public_inputs =
            PublicInputs::new(root, &witness.beneficiary, &blinding, witness.note_value);

        let result = verify_airdrop_proof(&params, &vk, &proof, &public_inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_serialization() {
        let params = setup_params();
        let (pk, _vk) = generate_keys(&params).expect("Key generation");

        let (witness, _root) = create_test_witness();
        let blinding = [0x12; 32];

        let proof = create_airdrop_proof(&params, &pk, witness, blinding).expect("Proof creation");

        // Test serialization round-trip
        let bytes = proof.to_bytes();
        let restored = AirdropProof::from_bytes(bytes.clone());

        assert_eq!(proof.len(), restored.len());
        assert_eq!(proof.to_bytes(), restored.to_bytes());
    }
}
