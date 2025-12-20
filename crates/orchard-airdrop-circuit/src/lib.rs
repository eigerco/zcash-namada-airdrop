//! Orchard Airdrop Circuit - ZK proof of funds for Namada airdrop
//!
//! This crate implements a ZK circuit proving:
//! 1. Note ownership (prover knows the FVK)
//! 2. Note unspentness (hiding nullifier not in snapshot)
//! 3. Beneficiary binding (proof bound to Namada address)

mod circuit;
mod proof;
mod public_inputs;
mod witness;

pub use circuit::{compute_beneficiary_commitment_poseidon, AirdropCircuit, AirdropConfig, K};
pub use proof::{
    create_airdrop_proof, generate_keys, setup_params, verify_airdrop_proof, AirdropParams,
    AirdropProof, ProofError,
};
pub use public_inputs::PublicInputs;
pub use witness::{
    build_poseidon_merkle_tree, bytes_to_field, compute_root_from_path, extract_merkle_path,
    poseidon_hash_merkle, AirdropWitness, Nullifier,
};

#[cfg(test)]
mod tests {
    //! Tests defining the expected behavior of the airdrop circuit.
    //!
    //! These tests are written first (TDD) to define what the circuit should do.
    //! Implementation will be added step by step to make each test pass.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    // ============================================================
    // PART 1: Witness Structure Tests
    // ============================================================
    // These tests are implemented in witness.rs module.
    // See crate::witness::tests for the actual test implementations.

    // ============================================================
    // PART 2: Public Input Tests
    // ============================================================
    // These tests are implemented in public_inputs.rs module.
    // See crate::public_inputs::tests for the actual test implementations.

    // ============================================================
    // PART 3: Circuit Constraint Tests
    // ============================================================
    // These tests verify the circuit enforces correct constraints.
    //
    // Note: Full Merkle path verification in-circuit requires a ZK-friendly
    // hash function (like Poseidon). The current implementation validates
    // Merkle proofs in the witness construction phase using SHA256, which
    // is sufficient for the claim workflow where the prover is honest.
    // For trustless verification, the Merkle tree should be rebuilt with
    // Poseidon and verified in-circuit.

    mod circuit_constraint_tests {
        use crate::circuit::AirdropCircuit;
        use crate::witness::AirdropWitness;
        use halo2_proofs::dev::MockProver;
        use pasta_curves::pallas;
        use rs_merkle::algorithms::Sha256;
        use rs_merkle::{Hasher, MerkleTree};

        /// Circuit parameter K
        const K: u32 = 11;

        /// Helper to create a nullifier with specific last byte
        fn nf(val: u8) -> [u8; 32] {
            let mut arr = [0u8; 32];
            arr[31] = val;
            arr
        }

        /// Build range leaf (same as in witness.rs)
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

            // Front leaf
            if !nullifiers.is_empty() {
                let leaf = build_range_leaf(&min_nf, &nullifiers[0]);
                leaves.push(Sha256::hash(&leaf));
            }

            // Middle leaves
            for window in nullifiers.windows(2) {
                let leaf = build_range_leaf(&window[0], &window[1]);
                leaves.push(Sha256::hash(&leaf));
            }

            // Back leaf
            if !nullifiers.is_empty() {
                let leaf = build_range_leaf(&nullifiers[nullifiers.len() - 1], &max_nf);
                leaves.push(Sha256::hash(&leaf));
            }

            let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
            let root = tree.root().unwrap_or([0u8; 32]);

            (tree, root)
        }

        #[test]
        fn circuit_enforces_nullifier_in_range() {
            // The circuit must prove: left_nf < hiding_nf < right_nf
            // This ensures the hiding nullifier falls in a valid gap
            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (tree, root) = build_test_tree(&nullifiers);
            let proof = tree.proof(&[1]);

            let note_value = 1_000_000u64;
            let blinding = [0x12; 32];
            let witness = AirdropWitness::new(
                note_value,
                nf(30), // hiding nullifier between 20 and 40
                nf(20),
                nf(40),
                proof.to_bytes(),
                1,
                tree.leaves_len(),
                &root,
                [0xAB; 32],
            )
            .expect("Valid witness");

            // Helper to convert bytes to field
            fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
                use ff::PrimeField;
                let mut repr = [0u8; 32];
                repr.copy_from_slice(bytes);
                repr[31] &= 0x3F;
                pallas::Base::from_repr(repr).expect("masked bytes fit")
            }

            let circuit = AirdropCircuit::new(witness.clone(), blinding);
            // Public inputs: [note_value, snapshot_root, beneficiary_commitment]
            let snapshot_root_field = bytes_to_field(&witness.snapshot_root);
            let beneficiary_commitment =
                crate::compute_beneficiary_commitment_poseidon(&witness.beneficiary, &blinding);
            let public_inputs: Vec<pallas::Base> =
                vec![pallas::Base::from(note_value), snapshot_root_field, beneficiary_commitment];

            let prover = MockProver::run(K, &circuit, vec![public_inputs]).expect("MockProver::run");
            prover.assert_satisfied();
        }

        #[test]
        fn circuit_verifies_merkle_path() {
            // The Merkle path verification currently happens during witness
            // construction (in AirdropWitness::new). For in-circuit verification,
            // we would need to implement a Poseidon-based Merkle gadget.
            //
            // This test verifies that the witness correctly validates the Merkle proof.
            let nullifiers = vec![nf(10), nf(30), nf(50)];
            let (tree, root) = build_test_tree(&nullifiers);
            let proof = tree.proof(&[1]); // Proof for leaf [10, 30]

            let witness = AirdropWitness::new(
                500_000,
                nf(20), // hiding nullifier between 10 and 30
                nf(10),
                nf(30),
                proof.to_bytes(),
                1,
                tree.leaves_len(),
                &root,
                [0xCD; 32],
            );

            assert!(witness.is_ok(), "Valid Merkle proof should be accepted");
        }

        #[test]
        fn circuit_binds_to_beneficiary() {
            // The beneficiary commitment is computed in PublicInputs and
            // would be constrained as a public input in the full circuit.
            // This test verifies the commitment computation.
            use crate::public_inputs::PublicInputs;

            let beneficiary = [0xAB; 32];
            let blinding = [0xCD; 32];
            let root = [0x01; 32];

            let inputs = PublicInputs::new(root, &beneficiary, &blinding, 1_000_000);

            // Verify commitment is deterministic
            let commitment1 = PublicInputs::compute_beneficiary_commitment(&beneficiary, &blinding);
            let commitment2 = PublicInputs::compute_beneficiary_commitment(&beneficiary, &blinding);
            assert_eq!(commitment1, commitment2);
            assert_eq!(inputs.beneficiary_commitment, commitment1);

            // Verify different beneficiary produces different commitment
            let other_beneficiary = [0x12; 32];
            let other_commitment =
                PublicInputs::compute_beneficiary_commitment(&other_beneficiary, &blinding);
            assert_ne!(commitment1, other_commitment);
        }

        #[test]
        fn circuit_rejects_invalid_range() {
            // If left_nf >= hiding_nf or hiding_nf >= right_nf,
            // witness construction should fail (validated in AirdropWitness::new)
            use crate::witness::WitnessError;

            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (tree, root) = build_test_tree(&nullifiers);
            let proof = tree.proof(&[1]);

            // Try to create witness where hiding == left (invalid)
            let result = AirdropWitness::new(
                1_000_000,
                nf(20), // hiding equals left bound
                nf(20),
                nf(40),
                proof.to_bytes(),
                1,
                tree.leaves_len(),
                &root,
                [0xAB; 32],
            );

            assert!(matches!(result, Err(WitnessError::NullifierNotInRange)));
        }

        #[test]
        fn circuit_rejects_invalid_merkle_path() {
            // If the Merkle path doesn't lead to the claimed root,
            // witness construction should fail
            use crate::witness::WitnessError;

            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (tree, _root) = build_test_tree(&nullifiers);
            let proof = tree.proof(&[1]);

            // Use a wrong root
            let wrong_root = [0xFF; 32];

            let result = AirdropWitness::new(
                1_000_000,
                nf(30),
                nf(20),
                nf(40),
                proof.to_bytes(),
                1,
                tree.leaves_len(),
                &wrong_root, // Wrong root!
                [0xAB; 32],
            );

            assert!(matches!(result, Err(WitnessError::InvalidMerkleProof)));
        }

        // --------------------------------------------------------
        // In-Circuit Constraint Tests (using Poseidon hash)
        // --------------------------------------------------------
        // These tests verify that constraints are enforced IN the circuit,
        // not just during witness construction.

        #[test]
        fn circuit_verifies_merkle_path_in_circuit() {
            // The circuit verifies the Merkle path using Poseidon hash.
            // 1. Build a Merkle tree with Poseidon hash
            // 2. Compute leaf hash in-circuit: Poseidon(left_nf, right_nf)
            // 3. Verify path from leaf to root in-circuit
            use crate::witness::{
                build_poseidon_merkle_tree, bytes_to_field, extract_merkle_path,
                poseidon_hash_merkle,
            };

            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (sha_tree, sha_root) = build_test_tree(&nullifiers);
            let sha_proof = sha_tree.proof(&[1]);

            // Build Poseidon Merkle tree
            // Leaves: hash(left_nf, right_nf) for each range
            let min_nf = [0u8; 32];
            let max_nf = [0xFFu8; 32];

            let mut poseidon_leaves = Vec::new();
            // Front leaf: [MIN, first_nf]
            poseidon_leaves.push(poseidon_hash_merkle(
                bytes_to_field(&min_nf),
                bytes_to_field(&nullifiers[0]),
            ));
            // Middle leaves
            for window in nullifiers.windows(2) {
                poseidon_leaves.push(poseidon_hash_merkle(
                    bytes_to_field(&window[0]),
                    bytes_to_field(&window[1]),
                ));
            }
            // Back leaf
            poseidon_leaves.push(poseidon_hash_merkle(
                bytes_to_field(&nullifiers[nullifiers.len() - 1]),
                bytes_to_field(&max_nf),
            ));

            let (poseidon_root, tree_levels) = build_poseidon_merkle_tree(&poseidon_leaves);
            let poseidon_path = extract_merkle_path(&tree_levels, 1);

            let note_value = 1_000_000u64;
            let blinding = [0x12; 32];
            let beneficiary = [0xAB; 32];

            // Create witness with both SHA256 and Poseidon data
            let witness = AirdropWitness::new(
                note_value,
                nf(30),
                nf(20),
                nf(40),
                sha_proof.to_bytes(),
                1,
                sha_tree.leaves_len(),
                &sha_root,
                beneficiary,
            )
            .expect("Valid witness")
            .with_poseidon_merkle(poseidon_path, poseidon_root);

            let circuit = AirdropCircuit::new(witness, blinding);

            // Public inputs with Poseidon root
            let beneficiary_commitment =
                crate::compute_beneficiary_commitment_poseidon(&beneficiary, &blinding);
            let public_inputs: Vec<pallas::Base> = vec![
                pallas::Base::from(note_value),
                poseidon_root, // Use Poseidon root as public input
                beneficiary_commitment,
            ];

            let prover = MockProver::run(K, &circuit, vec![public_inputs]).expect("MockProver::run");
            prover.assert_satisfied();
        }

        #[test]
        fn circuit_rejects_tampered_merkle_path_in_circuit() {
            // Even if we provide a bad Merkle path, the circuit constraints catch it.
            use crate::witness::{
                build_poseidon_merkle_tree, bytes_to_field, extract_merkle_path,
                poseidon_hash_merkle,
            };

            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (sha_tree, sha_root) = build_test_tree(&nullifiers);
            let sha_proof = sha_tree.proof(&[1]);

            // Build Poseidon Merkle tree
            let min_nf = [0u8; 32];
            let max_nf = [0xFFu8; 32];

            let mut poseidon_leaves = Vec::new();
            poseidon_leaves.push(poseidon_hash_merkle(
                bytes_to_field(&min_nf),
                bytes_to_field(&nullifiers[0]),
            ));
            for window in nullifiers.windows(2) {
                poseidon_leaves.push(poseidon_hash_merkle(
                    bytes_to_field(&window[0]),
                    bytes_to_field(&window[1]),
                ));
            }
            poseidon_leaves.push(poseidon_hash_merkle(
                bytes_to_field(&nullifiers[nullifiers.len() - 1]),
                bytes_to_field(&max_nf),
            ));

            let (poseidon_root, tree_levels) = build_poseidon_merkle_tree(&poseidon_leaves);
            let mut poseidon_path = extract_merkle_path(&tree_levels, 1);

            // TAMPER with the path - change the first sibling
            if !poseidon_path.is_empty() {
                poseidon_path[0] = pallas::Base::from(0x12345678u64);
            }

            let note_value = 1_000_000u64;
            let blinding = [0x12; 32];
            let beneficiary = [0xAB; 32];

            let witness = AirdropWitness::new(
                note_value,
                nf(30),
                nf(20),
                nf(40),
                sha_proof.to_bytes(),
                1,
                sha_tree.leaves_len(),
                &sha_root,
                beneficiary,
            )
            .expect("Valid witness")
            .with_poseidon_merkle(poseidon_path, poseidon_root);

            let circuit = AirdropCircuit::new(witness, blinding);

            // Public inputs with correct Poseidon root
            let beneficiary_commitment =
                crate::compute_beneficiary_commitment_poseidon(&beneficiary, &blinding);
            let public_inputs: Vec<pallas::Base> = vec![
                pallas::Base::from(note_value),
                poseidon_root,
                beneficiary_commitment,
            ];

            let prover = MockProver::run(K, &circuit, vec![public_inputs]).expect("MockProver::run");
            // The computed root won't match the expected root due to tampered path
            assert!(
                prover.verify().is_err(),
                "Should reject tampered Merkle path"
            );
        }

        #[test]
        fn circuit_constrains_beneficiary_commitment() {
            // The circuit computes beneficiary_commitment = Poseidon(beneficiary, blinding)
            // in-circuit and constrains it to match the public input.
            // This ensures the proof is bound to a specific Namada address.

            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (tree, root) = build_test_tree(&nullifiers);
            let proof = tree.proof(&[1]);

            let note_value = 1_000_000u64;
            let blinding = [0x12; 32];
            let beneficiary = [0xAB; 32];

            let witness = AirdropWitness::new(
                note_value,
                nf(30),
                nf(20),
                nf(40),
                proof.to_bytes(),
                1,
                tree.leaves_len(),
                &root,
                beneficiary,
            )
            .expect("Valid witness");

            // Helper to convert bytes to field
            fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
                use ff::PrimeField;
                let mut repr = [0u8; 32];
                repr.copy_from_slice(bytes);
                repr[31] &= 0x3F;
                pallas::Base::from_repr(repr).expect("masked bytes fit")
            }

            let circuit = AirdropCircuit::new(witness.clone(), blinding);
            let snapshot_root_field = bytes_to_field(&witness.snapshot_root);

            // Correct beneficiary commitment (computed with same beneficiary and blinding)
            let correct_commitment =
                crate::compute_beneficiary_commitment_poseidon(&beneficiary, &blinding);
            let public_inputs: Vec<pallas::Base> =
                vec![pallas::Base::from(note_value), snapshot_root_field, correct_commitment];

            let prover = MockProver::run(K, &circuit, vec![public_inputs]).expect("MockProver::run");
            prover.assert_satisfied();
        }

        #[test]
        fn circuit_rejects_wrong_beneficiary_commitment() {
            // If the witness beneficiary doesn't match the public beneficiary_commitment,
            // the circuit should fail to satisfy constraints.

            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (tree, root) = build_test_tree(&nullifiers);
            let proof = tree.proof(&[1]);

            let note_value = 1_000_000u64;
            let blinding = [0x12; 32];
            let beneficiary = [0xAB; 32];

            let witness = AirdropWitness::new(
                note_value,
                nf(30),
                nf(20),
                nf(40),
                proof.to_bytes(),
                1,
                tree.leaves_len(),
                &root,
                beneficiary,
            )
            .expect("Valid witness");

            // Helper to convert bytes to field
            fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
                use ff::PrimeField;
                let mut repr = [0u8; 32];
                repr.copy_from_slice(bytes);
                repr[31] &= 0x3F;
                pallas::Base::from_repr(repr).expect("masked bytes fit")
            }

            let circuit = AirdropCircuit::new(witness.clone(), blinding);
            let snapshot_root_field = bytes_to_field(&witness.snapshot_root);

            // Wrong beneficiary commitment (computed with different beneficiary)
            let wrong_beneficiary = [0xFF; 32];
            let wrong_commitment =
                crate::compute_beneficiary_commitment_poseidon(&wrong_beneficiary, &blinding);
            let public_inputs: Vec<pallas::Base> =
                vec![pallas::Base::from(note_value), snapshot_root_field, wrong_commitment];

            let prover = MockProver::run(K, &circuit, vec![public_inputs]).expect("MockProver::run");
            assert!(
                prover.verify().is_err(),
                "Should reject wrong beneficiary commitment"
            );
        }

        #[test]
        fn circuit_constrains_snapshot_root() {
            // The snapshot root is a public input that the circuit constrains.
            // Verification with wrong root should fail.
            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (tree, root) = build_test_tree(&nullifiers);
            let proof = tree.proof(&[1]);

            let note_value = 1_000_000u64;
            let blinding = [0x12; 32];
            let witness = AirdropWitness::new(
                note_value,
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

            let circuit = AirdropCircuit::new(witness.clone(), blinding);

            // Helper to convert bytes to field (same as in circuit.rs)
            fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
                use ff::PrimeField;
                let mut repr = [0u8; 32];
                repr.copy_from_slice(bytes);
                repr[31] &= 0x3F; // Mask top 2 bits to fit in field
                pallas::Base::from_repr(repr).expect("masked bytes fit")
            }

            let beneficiary_commitment =
                crate::compute_beneficiary_commitment_poseidon(&witness.beneficiary, &blinding);

            // Correct root - should pass
            let correct_root = bytes_to_field(&witness.snapshot_root);
            let public_inputs: Vec<pallas::Base> =
                vec![pallas::Base::from(note_value), correct_root, beneficiary_commitment];
            let prover = MockProver::run(K, &circuit, vec![public_inputs]).expect("MockProver::run");
            prover.assert_satisfied();

            // Wrong root - should fail
            let wrong_root = bytes_to_field(&[0x12; 32]);
            let wrong_inputs: Vec<pallas::Base> =
                vec![pallas::Base::from(note_value), wrong_root, beneficiary_commitment];
            let prover2 = MockProver::run(K, &circuit, vec![wrong_inputs]).expect("MockProver::run");
            assert!(prover2.verify().is_err(), "Should reject wrong snapshot_root");
        }

        #[test]
        fn circuit_constrains_note_value() {
            // The note value should be a public input.
            // This allows Namada to verify the claimed airdrop amount.
            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (tree, root) = build_test_tree(&nullifiers);
            let proof = tree.proof(&[1]);

            let note_value = 1_000_000u64;
            let blinding = [0x12; 32];
            let witness = AirdropWitness::new(
                note_value,
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

            // Helper to convert bytes to field
            fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
                use ff::PrimeField;
                let mut repr = [0u8; 32];
                repr.copy_from_slice(bytes);
                repr[31] &= 0x3F;
                pallas::Base::from_repr(repr).expect("masked bytes fit")
            }

            let circuit = AirdropCircuit::new(witness.clone(), blinding);
            let snapshot_root_field = bytes_to_field(&witness.snapshot_root);
            let beneficiary_commitment =
                crate::compute_beneficiary_commitment_poseidon(&witness.beneficiary, &blinding);

            // Correct note_value - should pass
            let public_inputs: Vec<pallas::Base> =
                vec![pallas::Base::from(note_value), snapshot_root_field, beneficiary_commitment];
            let prover = MockProver::run(K, &circuit, vec![public_inputs]).expect("MockProver::run");
            prover.assert_satisfied();

            // Wrong note_value - should fail
            let wrong_value = 999_999u64;
            let wrong_inputs: Vec<pallas::Base> =
                vec![pallas::Base::from(wrong_value), snapshot_root_field, beneficiary_commitment];
            let prover2 = MockProver::run(K, &circuit, vec![wrong_inputs]).expect("MockProver::run");
            assert!(prover2.verify().is_err(), "Should reject wrong note_value");
        }

        #[test]
        fn circuit_full_constraint_verification() {
            // Full end-to-end test with all constraints:
            // 1. Range check (left < hiding < right)
            // 2. Merkle path verification (Poseidon)
            // 3. Beneficiary commitment (Poseidon)
            // 4. All public inputs constrained
            //
            // A valid proof should:
            // - Verify with correct public inputs
            // - FAIL with wrong snapshot_root
            // - FAIL with wrong beneficiary_commitment
            // - FAIL with wrong note_value
            use crate::witness::{
                build_poseidon_merkle_tree, bytes_to_field, extract_merkle_path,
                poseidon_hash_merkle,
            };

            let nullifiers = vec![nf(20), nf(40), nf(60)];
            let (sha_tree, sha_root) = build_test_tree(&nullifiers);
            let sha_proof = sha_tree.proof(&[1]);

            // Build Poseidon Merkle tree
            let min_nf = [0u8; 32];
            let max_nf = [0xFFu8; 32];

            let mut poseidon_leaves = Vec::new();
            // Front leaf: [MIN, first_nf]
            poseidon_leaves.push(poseidon_hash_merkle(
                bytes_to_field(&min_nf),
                bytes_to_field(&nullifiers[0]),
            ));
            // Middle leaves
            for window in nullifiers.windows(2) {
                poseidon_leaves.push(poseidon_hash_merkle(
                    bytes_to_field(&window[0]),
                    bytes_to_field(&window[1]),
                ));
            }
            // Back leaf
            poseidon_leaves.push(poseidon_hash_merkle(
                bytes_to_field(&nullifiers[nullifiers.len() - 1]),
                bytes_to_field(&max_nf),
            ));

            let (poseidon_root, tree_levels) = build_poseidon_merkle_tree(&poseidon_leaves);
            let poseidon_path = extract_merkle_path(&tree_levels, 1);

            let note_value = 1_000_000u64;
            let blinding = [0x12; 32];
            let beneficiary = [0xAB; 32];

            // Create witness with both SHA256 and Poseidon data
            let witness = AirdropWitness::new(
                note_value,
                nf(30),
                nf(20),
                nf(40),
                sha_proof.to_bytes(),
                1,
                sha_tree.leaves_len(),
                &sha_root,
                beneficiary,
            )
            .expect("Valid witness")
            .with_poseidon_merkle(poseidon_path, poseidon_root);

            let circuit = AirdropCircuit::new(witness, blinding);

            // Correct public inputs
            let beneficiary_commitment =
                crate::compute_beneficiary_commitment_poseidon(&beneficiary, &blinding);
            let correct_inputs: Vec<pallas::Base> = vec![
                pallas::Base::from(note_value),
                poseidon_root,
                beneficiary_commitment,
            ];

            // 1. Test: Valid proof should pass with correct public inputs
            let prover = MockProver::run(K, &circuit, vec![correct_inputs.clone()])
                .expect("MockProver::run");
            prover.assert_satisfied();

            // 2. Test: FAIL with wrong snapshot_root
            let wrong_root = pallas::Base::from(0x12345678u64);
            let wrong_root_inputs: Vec<pallas::Base> = vec![
                pallas::Base::from(note_value),
                wrong_root,
                beneficiary_commitment,
            ];
            let prover2 = MockProver::run(K, &circuit, vec![wrong_root_inputs])
                .expect("MockProver::run");
            assert!(
                prover2.verify().is_err(),
                "Should reject wrong snapshot_root"
            );

            // 3. Test: FAIL with wrong beneficiary_commitment
            let wrong_beneficiary = [0xFF; 32];
            let wrong_commitment =
                crate::compute_beneficiary_commitment_poseidon(&wrong_beneficiary, &blinding);
            let wrong_commitment_inputs: Vec<pallas::Base> = vec![
                pallas::Base::from(note_value),
                poseidon_root,
                wrong_commitment,
            ];
            let prover3 = MockProver::run(K, &circuit, vec![wrong_commitment_inputs])
                .expect("MockProver::run");
            assert!(
                prover3.verify().is_err(),
                "Should reject wrong beneficiary_commitment"
            );

            // 4. Test: FAIL with wrong note_value
            let wrong_value = 999_999u64;
            let wrong_value_inputs: Vec<pallas::Base> = vec![
                pallas::Base::from(wrong_value),
                poseidon_root,
                beneficiary_commitment,
            ];
            let prover4 = MockProver::run(K, &circuit, vec![wrong_value_inputs])
                .expect("MockProver::run");
            assert!(
                prover4.verify().is_err(),
                "Should reject wrong note_value"
            );
        }
    }

    // ============================================================
    // PART 4: Proof Generation and Verification Tests
    // ============================================================
    // These tests verify the full proof lifecycle.

    mod proof_tests {
        use crate::proof::{create_airdrop_proof, generate_keys, setup_params, verify_airdrop_proof};
        use crate::public_inputs::PublicInputs;
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

        /// Build a test Merkle tree and get root
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
        fn can_generate_proving_and_verifying_keys() {
            let params = setup_params();
            let result = generate_keys(&params);
            assert!(result.is_ok(), "Key generation should succeed");

            // Just verify we got the keys without errors
            let (_pk, _vk) = result.expect("Keys");
        }

        #[test]
        fn can_generate_valid_proof() {
            let params = setup_params();
            let (pk, _vk) = generate_keys(&params).expect("Key generation");

            let (witness, _root) = create_test_witness();
            let blinding = [0x12; 32];

            let result = create_airdrop_proof(&params, &pk, witness, blinding);
            assert!(result.is_ok(), "Proof generation should succeed");

            let proof = result.expect("Proof");
            assert!(!proof.is_empty(), "Proof should not be empty");
        }

        #[test]
        fn proof_verifies_with_correct_public_inputs() {
            let params = setup_params();
            let (pk, vk) = generate_keys(&params).expect("Key generation");

            let (witness, root) = create_test_witness();
            let blinding = [0x12; 32];

            let proof = create_airdrop_proof(&params, &pk, witness.clone(), blinding)
                .expect("Proof creation");

            let public_inputs =
                PublicInputs::new(root, &witness.beneficiary, &blinding, witness.note_value);

            let result = verify_airdrop_proof(&params, &vk, &proof, &public_inputs);
            assert!(result.is_ok(), "Proof should verify with correct inputs");
        }

        #[test]
        fn proof_fails_with_wrong_snapshot_root() {
            // Verification with wrong snapshot_root should fail because
            // snapshot_root is constrained as a public input in the circuit.
            let params = setup_params();
            let (pk, vk) = generate_keys(&params).expect("Key generation");

            let (witness, _root) = create_test_witness();
            let blinding = [0x12; 32];

            let proof = create_airdrop_proof(&params, &pk, witness.clone(), blinding)
                .expect("Proof creation");

            // Use wrong root - verification should fail
            let wrong_root = [0xFF; 32];
            let public_inputs =
                PublicInputs::new(wrong_root, &witness.beneficiary, &blinding, witness.note_value);

            let result = verify_airdrop_proof(&params, &vk, &proof, &public_inputs);
            assert!(result.is_err(), "Verification should fail with wrong snapshot_root");
        }

        #[test]
        fn proof_fails_with_wrong_beneficiary() {
            // Verification with wrong beneficiary should fail because
            // beneficiary_commitment is constrained as a public input.
            let params = setup_params();
            let (pk, vk) = generate_keys(&params).expect("Key generation");

            let (witness, root) = create_test_witness();
            let blinding = [0x12; 32];

            let proof = create_airdrop_proof(&params, &pk, witness.clone(), blinding)
                .expect("Proof creation");

            // Use wrong beneficiary - this produces a different beneficiary_commitment
            let wrong_beneficiary = [0xFF; 32];
            let public_inputs =
                PublicInputs::new(root, &wrong_beneficiary, &blinding, witness.note_value);

            let result = verify_airdrop_proof(&params, &vk, &proof, &public_inputs);
            assert!(result.is_err(), "Verification should fail with wrong beneficiary");
        }

        #[test]
        fn proof_is_serializable() {
            let params = setup_params();
            let (pk, _vk) = generate_keys(&params).expect("Key generation");

            let (witness, _root) = create_test_witness();
            let blinding = [0x12; 32];

            let proof =
                create_airdrop_proof(&params, &pk, witness, blinding).expect("Proof creation");

            // Test serialization round-trip
            let bytes = proof.to_bytes();
            let restored = crate::AirdropProof::from_bytes(bytes.clone());

            assert_eq!(proof.len(), restored.len());
            assert_eq!(proof.to_bytes(), restored.to_bytes());
            assert!(!proof.is_empty(), "Proof should have non-zero length");
        }
    }

    // ============================================================
    // PART 5: Integration Tests
    // ============================================================
    // End-to-end tests with realistic data.

    mod integration_tests {
        use crate::proof::{create_airdrop_proof, generate_keys, setup_params, verify_airdrop_proof};
        use crate::public_inputs::PublicInputs;
        use crate::witness::{AirdropWitness, WitnessError};
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

        /// Build a nullifier snapshot Merkle tree
        fn build_snapshot_tree(nullifiers: &[[u8; 32]]) -> (MerkleTree<Sha256>, [u8; 32]) {
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

        #[test]
        fn full_airdrop_claim_flow() {
            // 1. Build a nullifier snapshot (simulating spent notes on-chain)
            //    Nullifiers 20, 40, 60 are "spent" (in the snapshot)
            let spent_nullifiers = vec![nf(20), nf(40), nf(60)];
            let (tree, snapshot_root) = build_snapshot_tree(&spent_nullifiers);

            // 2. Create a "hiding nullifier" for an unspent note
            //    This nullifier (30) is NOT in the snapshot, so the note is unspent
            //    It falls in the gap between 20 and 40
            let hiding_nullifier = nf(30);
            let note_value = 1_000_000; // 0.01 ZEC in zatoshis
            let beneficiary = [0xAB; 32]; // Namada address receiving the airdrop

            // 3. Get the Merkle proof for the range leaf [20, 40]
            //    (This is the gap where our hiding nullifier falls)
            let leaf_index = 1; // Middle leaf (between 20 and 40)
            let merkle_proof = tree.proof(&[leaf_index]);

            // 4. Create the witness
            let witness = AirdropWitness::new(
                note_value,
                hiding_nullifier,
                nf(20), // left bound
                nf(40), // right bound
                merkle_proof.to_bytes(),
                leaf_index,
                tree.leaves_len(),
                &snapshot_root,
                beneficiary,
            )
            .expect("Valid witness");

            // 5. Generate proving and verifying keys
            let params = setup_params();
            let (pk, vk) = generate_keys(&params).expect("Key generation");

            // 6. Generate the proof
            let blinding = [0x12; 32];
            let proof =
                create_airdrop_proof(&params, &pk, witness.clone(), blinding).expect("Proof");

            // 7. Verify the proof
            let public_inputs =
                PublicInputs::new(snapshot_root, &beneficiary, &blinding, note_value);
            let result = verify_airdrop_proof(&params, &vk, &proof, &public_inputs);

            assert!(result.is_ok(), "Full airdrop claim flow should succeed");
        }

        #[test]
        fn spent_note_cannot_generate_valid_proof() {
            // Build a snapshot where nullifier 30 IS spent (in the snapshot)
            let spent_nullifiers = vec![nf(20), nf(30), nf(40), nf(60)];
            let (tree, snapshot_root) = build_snapshot_tree(&spent_nullifiers);

            // Try to claim with hiding nullifier 30 (which is now spent)
            // The witness construction should fail because 30 is not in any gap
            // (it's exactly on a boundary)

            // The gaps are: [MIN, 20], [20, 30], [30, 40], [40, 60], [60, MAX]
            // If we try hiding_nf = 30, it equals the right bound of gap [20, 30]
            // or the left bound of gap [30, 40], so it won't be strictly in range

            let merkle_proof = tree.proof(&[1]); // Gap [20, 30]

            let result = AirdropWitness::new(
                1_000_000,
                nf(30), // Trying to use spent nullifier
                nf(20),
                nf(30), // Right bound equals hiding nullifier!
                merkle_proof.to_bytes(),
                1,
                tree.leaves_len(),
                &snapshot_root,
                [0xAB; 32],
            );

            // This should fail because hiding_nf (30) >= right_nf (30)
            assert!(
                matches!(result, Err(WitnessError::NullifierNotInRange)),
                "Spent note (on boundary) should be rejected"
            );

            // Also try with the adjacent gap [30, 40]
            let merkle_proof2 = tree.proof(&[2]); // Gap [30, 40]

            let result2 = AirdropWitness::new(
                1_000_000,
                nf(30), // Trying to use spent nullifier
                nf(30), // Left bound equals hiding nullifier!
                nf(40),
                merkle_proof2.to_bytes(),
                2,
                tree.leaves_len(),
                &snapshot_root,
                [0xAB; 32],
            );

            // This should fail because hiding_nf (30) <= left_nf (30)
            assert!(
                matches!(result2, Err(WitnessError::NullifierNotInRange)),
                "Spent note (on boundary) should be rejected"
            );
        }
    }
}
