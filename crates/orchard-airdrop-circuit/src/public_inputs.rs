//! Public inputs for the airdrop circuit.
//!
//! These are the values that verifiers will check against the proof.
//! They are public, meaning anyone can see them.

use ff::PrimeField;
use pasta_curves::pallas;

use crate::circuit::compute_beneficiary_commitment_poseidon;
use crate::witness::Beneficiary;

/// Public inputs for the airdrop proof.
///
/// These values are visible to verifiers and are used to:
/// - Verify the proof was generated for a specific snapshot
/// - Verify the airdrop is bound to a specific beneficiary
/// - Determine the airdrop amount based on note value
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    /// Merkle root of the snapshot nullifier tree.
    /// Verifiers check this matches the official published snapshot.
    pub snapshot_root: [u8; 32],

    /// Commitment to the beneficiary address.
    /// This is hash(beneficiary || blinding) to hide the actual address
    /// while still binding the proof to a specific recipient.
    pub beneficiary_commitment: [u8; 32],

    /// The note value in zatoshis.
    /// This is public so Namada can determine the airdrop amount.
    pub note_value: u64,
}

impl PublicInputs {
    /// Creates new public inputs.
    ///
    /// # Arguments
    ///
    /// * `snapshot_root` - Merkle root from the nullifier snapshot
    /// * `beneficiary` - Namada address receiving the airdrop
    /// * `blinding` - Random blinding factor for the commitment
    /// * `note_value` - The ZEC value of the note
    #[must_use]
    pub fn new(
        snapshot_root: [u8; 32],
        beneficiary: &Beneficiary,
        blinding: &[u8; 32],
        note_value: u64,
    ) -> Self {
        let beneficiary_commitment = Self::compute_beneficiary_commitment(beneficiary, blinding);

        Self {
            snapshot_root,
            beneficiary_commitment,
            note_value,
        }
    }

    /// Computes the beneficiary commitment using Poseidon hash.
    ///
    /// commitment = Poseidon(beneficiary_field, blinding_field)
    ///
    /// Returns the commitment as bytes for storage/serialization.
    #[must_use]
    pub fn compute_beneficiary_commitment(
        beneficiary: &Beneficiary,
        blinding: &[u8; 32],
    ) -> [u8; 32] {
        let commitment_field = compute_beneficiary_commitment_poseidon(beneficiary, blinding);
        commitment_field.to_repr()
    }

    /// Converts public inputs to field elements for the circuit.
    ///
    /// Returns a vector of Pallas base field elements in the order:
    /// [note_value, snapshot_root, beneficiary_commitment]
    #[must_use]
    pub fn to_field_elements(&self) -> Vec<pallas::Base> {
        let mut elements = Vec::with_capacity(3);

        // Instance row 0: note_value
        elements.push(pallas::Base::from(self.note_value));

        // Instance row 1: snapshot_root (with top 2 bits masked)
        let mut root_repr = self.snapshot_root;
        root_repr[31] &= 0x3F;
        elements.push(
            pallas::Base::from_repr(root_repr).expect("masked bytes fit in field"),
        );

        // Instance row 2: beneficiary_commitment
        // Already a valid field element from Poseidon
        elements.push(
            pallas::Base::from_repr(self.beneficiary_commitment)
                .expect("commitment is valid field element"),
        );

        elements
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn public_inputs_include_snapshot_root() {
        let snapshot_root = [0xAB; 32];
        let beneficiary = [0xCD; 32];
        let blinding = [0xEF; 32];

        let inputs = PublicInputs::new(snapshot_root, &beneficiary, &blinding, 1000);

        assert_eq!(inputs.snapshot_root, snapshot_root);
    }

    #[test]
    fn public_inputs_include_beneficiary_commitment() {
        let snapshot_root = [0xAB; 32];
        let beneficiary = [0xCD; 32];
        let blinding = [0xEF; 32];

        let inputs = PublicInputs::new(snapshot_root, &beneficiary, &blinding, 1000);

        // Verify commitment is computed correctly
        let expected = PublicInputs::compute_beneficiary_commitment(&beneficiary, &blinding);
        assert_eq!(inputs.beneficiary_commitment, expected);

        // Verify commitment changes with different beneficiary
        let other_beneficiary = [0x12; 32];
        let other_inputs = PublicInputs::new(snapshot_root, &other_beneficiary, &blinding, 1000);
        assert_ne!(inputs.beneficiary_commitment, other_inputs.beneficiary_commitment);
    }

    #[test]
    fn public_inputs_include_note_value() {
        let snapshot_root = [0xAB; 32];
        let beneficiary = [0xCD; 32];
        let blinding = [0xEF; 32];

        let inputs = PublicInputs::new(snapshot_root, &beneficiary, &blinding, 1_000_000);

        assert_eq!(inputs.note_value, 1_000_000);
    }

    #[test]
    fn public_inputs_convert_to_field_elements() {
        let snapshot_root = [0x01; 32];
        let beneficiary = [0x02; 32];
        let blinding = [0x03; 32];

        let inputs = PublicInputs::new(snapshot_root, &beneficiary, &blinding, 42);

        let elements = inputs.to_field_elements();
        assert_eq!(elements.len(), 3);

        // First element should be the note value (instance row 0)
        assert_eq!(elements[0], pallas::Base::from(42u64));
    }

    #[test]
    fn beneficiary_commitment_is_deterministic() {
        let beneficiary = [0xCD; 32];
        let blinding = [0xEF; 32];

        let c1 = PublicInputs::compute_beneficiary_commitment(&beneficiary, &blinding);
        let c2 = PublicInputs::compute_beneficiary_commitment(&beneficiary, &blinding);

        assert_eq!(c1, c2);
    }

    #[test]
    fn beneficiary_commitment_changes_with_blinding() {
        let beneficiary = [0xCD; 32];
        let blinding1 = [0xEF; 32];
        let blinding2 = [0x12; 32];

        let c1 = PublicInputs::compute_beneficiary_commitment(&beneficiary, &blinding1);
        let c2 = PublicInputs::compute_beneficiary_commitment(&beneficiary, &blinding2);

        assert_ne!(c1, c2);
    }
}
