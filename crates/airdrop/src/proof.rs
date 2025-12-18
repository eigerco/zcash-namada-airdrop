use eyre::{ContextCompat as _, ensure};
use non_membership_proofs::user_nullifiers::{AnyFoundNote, ViewingKeys};
use non_membership_proofs::utils::ReverseBytes as _;
use non_membership_proofs::{Nullifier, build_leaf};
use rs_merkle::{Hasher, MerkleTree};
use serde::Serialize;
use serde_with::hex::Hex;
use serde_with::serde_as;
use tracing::{debug, info, instrument, warn};

#[serde_as]
#[derive(Serialize)]
pub(crate) struct NullifierProof {
    #[serde_as(as = "Hex")]
    left_nullifier: Nullifier,
    #[serde_as(as = "Hex")]
    right_nullifier: Nullifier,
    #[serde_as(as = "Hex")]
    merkle_proof: Vec<u8>,
}

impl std::fmt::Debug for NullifierProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let left = self
            .left_nullifier
            .reverse_into_array()
            .map_or_else(|| "<invalid>".to_owned(), hex::encode::<Nullifier>);
        let right = self
            .right_nullifier
            .reverse_into_array()
            .map_or_else(|| "<invalid>".to_owned(), hex::encode::<Nullifier>);
        f.debug_struct("NullifierProof")
            .field("left_nullifier", &left)
            .field("right_nullifier", &right)
            .field("merkle_proof", &hex::encode(&self.merkle_proof))
            .finish()
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
enum MerkleProofError {
    #[error("Snapshot nullifiers must be sorted")]
    NotSorted,
    #[error(
        "Merkle tree leaves count ({0}) must equal nullifiers count + 1. Actual nullifiers count {1}"
    )]
    NullifiersNotMatchingTreeSize(usize, usize),
    #[error("Merkle proof verification failed")]
    InvalidProof,
}

/// Search for a nullifier in the snapshot and generate a non-membership proof if not found.
/// Returns:
/// - `Some(proof)` if the note is unspent
/// - `None` if the note was already spent.
#[instrument(
    skip(snapshot_nullifiers, merkle_tree, keys, note),
    fields(pool = ?note.pool(), height = note.height())
)]
pub(crate) fn generate_non_membership_proof<H: Hasher>(
    note: &AnyFoundNote,
    snapshot_nullifiers: &[Nullifier],
    merkle_tree: &MerkleTree<H>,
    keys: &ViewingKeys,
) -> eyre::Result<Option<NullifierProof>> {
    let Some(nullifier) = note.nullifier(keys) else {
        warn!(?note, "Could not derive nullifier for note");
        return Ok(None);
    };

    generate_non_membership_proof_for_nullifier(nullifier, snapshot_nullifiers, merkle_tree)
}

/// Generates a non-membership proof for a nullifier against a snapshot.
///
/// This function proves that a nullifier is NOT present in the snapshot by finding two
/// adjacent nullifiers that bound it and providing a Merkle proof for that bounding leaf.
///
/// # Arguments
///
/// * `nullifier` - The nullifier to prove non-membership for (any valid 32-byte value).
/// * `snapshot_nullifiers` - A sorted slice of nullifiers from the snapshot.
/// * `merkle_tree` - A Merkle tree built from `snapshot_nullifiers` using [`build_merkle_tree`].
///
/// # Preconditions
///
/// * `snapshot_nullifiers` must be non-empty and sorted in ascending order.
/// * `merkle_tree` must have exactly `snapshot_nullifiers.len() + 1` leaves.
///
/// # Returns
///
/// * `Ok(Some(proof))` - The nullifier is NOT in the snapshot (note is unspent)
/// * `Ok(None)` - The nullifier IS in the snapshot (note was spent)
/// * `Err(_)` - Validation failed or proof generation failed
///
/// # Errors
///
/// * `"Snapshot nullifiers cannot be empty"` - Empty snapshot slice provided
/// * [`MerkleProofError::NotSorted`] - `snapshot_nullifiers` is not sorted
/// * [`MerkleProofError::NullifiersNotMatchingTreeSize`] - Tree leaves count doesn't equal
///   `nullifiers.len() + 1`
/// * [`MerkleProofError::InvalidProof`] - Generated proof failed verification (indicates tree was
///   not built from the same nullifiers)
///
/// # Algorithm
///
/// Uses virtual boundaries `[0u8; 32]` (MIN) and `[0xFFu8; 32]` (MAX) to handle edge cases:
///
/// 1. Binary search to find where `nullifier` would be inserted in `snapshot_nullifiers`
/// 2. If found, return `None` (spent)
/// 3. Determine the bounding nullifiers:
///    - Below all nullifiers → bounds are `[MIN, first_nullifier]`
///    - Above all nullifiers → bounds are `[last_nullifier, MAX]`
///    - Between two nullifiers → bounds are `[nullifier[i-1], nullifier[i]]`
/// 4. Build the leaf from bounds and generate a Merkle proof
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "We ensure bounds before indexing"
)]
fn generate_non_membership_proof_for_nullifier<H: Hasher>(
    nullifier: Nullifier,
    snapshot_nullifiers: &[Nullifier],
    merkle_tree: &MerkleTree<H>,
) -> eyre::Result<Option<NullifierProof>> {
    const MIN_NF: Nullifier = [0_u8; 32];
    const MAX_NF: Nullifier = [0xFF_u8; 32];

    ensure!(
        !snapshot_nullifiers.is_empty(),
        "Snapshot nullifiers cannot be empty"
    );
    ensure!(snapshot_nullifiers.is_sorted(), MerkleProofError::NotSorted);
    ensure!(
        merkle_tree.leaves_len() == snapshot_nullifiers.len().saturating_add(1_usize),
        MerkleProofError::NullifiersNotMatchingTreeSize(
            merkle_tree.leaves_len(),
            snapshot_nullifiers.len()
        )
    );

    let nullifier_hex = hex::encode::<Nullifier>(
        nullifier
            .reverse_into_array()
            .context("Failed to reverse nullifier bytes order")?,
    );

    // Binary search to find where nullifier would be inserted
    // Err(idx) means nullifier is not found and would be inserted at idx
    let (left_nf, right_nf, leaf_idx) = match snapshot_nullifiers.binary_search(&nullifier) {
        Ok(_) => {
            warn!(nullifier = %nullifier_hex, "Nullifier found in snapshot - note was spent");
            return Ok(None);
        }
        Err(0) => {
            // Nullifier is smaller than all snapshot nullifiers
            // Falls in front leaf: [MIN, first_nf]
            (MIN_NF, snapshot_nullifiers[0], 0)
        }
        Err(idx) if idx == snapshot_nullifiers.len() => {
            // Nullifier is larger than all snapshot nullifiers
            // Falls in back leaf: [last_nf, MAX]
            (snapshot_nullifiers[idx - 1], MAX_NF, idx)
        }
        Err(idx) => {
            // Nullifier falls between two existing nullifiers
            // Falls in leaf: [nf[idx-1], nf[idx]]
            (snapshot_nullifiers[idx - 1], snapshot_nullifiers[idx], idx)
        }
    };

    debug!(
        nullifier = %nullifier_hex,
        leaf_idx = leaf_idx,
        left_nullifier = %hex::encode::<Nullifier>(
            left_nf
                .reverse_into_array()
                .context("Failed to reverse left nullifier bytes order")?
        ),
        right_nullifier = %hex::encode::<Nullifier>(
            right_nf
                .reverse_into_array()
                .context("Failed to reverse right nullifier bytes order")?
        ),
        "Found bounding nullifiers"
    );

    ensure!(
        left_nf <= nullifier && nullifier <= right_nf,
        "Bounding nullifiers do not properly bound nullifier {nullifier_hex}",
    );

    let leaf = build_leaf(&left_nf, &right_nf);
    let leaf_hash = H::hash(&leaf);
    let merkle_proof = merkle_tree.proof(&[leaf_idx]);

    ensure!(
        merkle_proof.verify(
            merkle_tree.root().context("Merkle tree has no root")?,
            &[leaf_idx],
            &[leaf_hash],
            merkle_tree.leaves_len()
        ),
        MerkleProofError::InvalidProof
    );

    info!(nullifier = %nullifier_hex, "Generated non-membership proof");

    Ok(Some(NullifierProof {
        left_nullifier: left_nf,
        right_nullifier: right_nf,
        merkle_proof: merkle_proof.to_bytes(),
    }))
}

#[cfg(test)]
mod tests {
    use non_membership_proofs::build_merkle_tree;
    use rs_merkle::algorithms::Sha256;

    use super::*;

    const MIN_NF: Nullifier = [0u8; 32];
    const MAX_NF: Nullifier = [0xFFu8; 32];

    /// Helper macro to create a nullifier with a specific last byte.
    macro_rules! nf {
        ($v:expr) => {{
            let mut arr = [0u8; 32];
            arr[31] = $v;
            arr
        }};
    }

    /// Helper macro to create a sorted vector of nullifiers.
    macro_rules! nfs {
        ($($v:expr),* $(,)?) => {{
            let mut v = vec![$( nf!($v) ),*];
            v.sort();
            v
        }};
    }

    #[test]
    fn min_max_boundaries() {
        let sorted = nfs![10, 50];
        let tree = build_merkle_tree::<Sha256>(&sorted).unwrap();

        let result = generate_non_membership_proof_for_nullifier(MIN_NF, &sorted, &tree).unwrap();
        assert!(
            result.is_some(),
            "Expected Some(proof) for unspent note with MIN nullifier."
        );

        let result = generate_non_membership_proof_for_nullifier(MAX_NF, &sorted, &tree).unwrap();
        assert!(
            result.is_some(),
            "Expected Some(proof) for unspent note with MAX nullifier."
        );

        let mut sorted = nfs![10, 50];
        sorted.insert(0, MIN_NF);
        sorted.push(MAX_NF);
        let tree = build_merkle_tree::<Sha256>(&sorted).unwrap();

        let result = generate_non_membership_proof_for_nullifier(MIN_NF, &sorted, &tree).unwrap();
        assert!(
            result.is_none(),
            "Expected None. Nullifier was found in snapshot."
        );
        let result = generate_non_membership_proof_for_nullifier(MAX_NF, &sorted, &tree).unwrap();
        assert!(
            result.is_none(),
            "Expected None. Nullifier was found in snapshot."
        );

        let mut sorted = nfs![10, 50];
        sorted.insert(0, MIN_NF);
        let tree = build_merkle_tree::<Sha256>(&sorted).unwrap();

        let result = generate_non_membership_proof_for_nullifier(MIN_NF, &sorted, &tree).unwrap();
        assert!(
            result.is_none(),
            "Expected None. Nullifier was found in snapshot."
        );
        let result = generate_non_membership_proof_for_nullifier(MAX_NF, &sorted, &tree).unwrap();
        assert!(
            result.is_some(),
            "Expected Some(proof) for unspent note with MAX nullifier."
        );

        let mut sorted = nfs![10, 50];
        sorted.push(MAX_NF);
        let tree = build_merkle_tree::<Sha256>(&sorted).unwrap();

        let result = generate_non_membership_proof_for_nullifier(MIN_NF, &sorted, &tree).unwrap();
        assert!(
            result.is_some(),
            "Expected Some(proof) for unspent note with MIN nullifier."
        );
        let result = generate_non_membership_proof_for_nullifier(MAX_NF, &sorted, &tree).unwrap();
        assert!(
            result.is_none(),
            "Expected None. Nullifier was found in snapshot."
        );
    }

    #[test]
    fn returns_error_for_unsorted_nullifiers() {
        let sorted = nfs![10, 50];
        let tree = build_merkle_tree::<Sha256>(&sorted).unwrap();
        let unsorted = vec![nf!(50), nf!(10)]; // intentionally unsorted

        let result = generate_non_membership_proof_for_nullifier(nf!(30), &unsorted, &tree);

        assert!(
            matches!(result, Err(e) if e.downcast_ref::<MerkleProofError>() == Some(&MerkleProofError::NotSorted))
        );
    }

    #[test]
    fn returns_error_for_wrong_tree_size() {
        let nullifiers = nfs![10, 20, 30];
        let wrong_nullifiers = nfs![10, 20];
        let tree = build_merkle_tree::<Sha256>(&wrong_nullifiers).unwrap();

        let result = generate_non_membership_proof_for_nullifier(nf!(25), &nullifiers, &tree);

        assert!(
            matches!(result, Err(e) if e.downcast_ref::<MerkleProofError>() == Some(&MerkleProofError::NullifiersNotMatchingTreeSize(3, 3)))
        );
    }

    #[test]
    fn returns_none_when_nullifier_found() {
        let nullifiers = nfs![10, 20, 30, 40];
        let tree = build_merkle_tree::<Sha256>(&nullifiers).unwrap();

        let result =
            generate_non_membership_proof_for_nullifier(nf!(30), &nullifiers, &tree).unwrap();

        assert!(
            result.is_none(),
            "Expected None. Nullifier was found in snapshot."
        );
    }

    #[test]
    fn no_nullifiers() {
        let nullifiers = vec![];
        let tree = build_merkle_tree::<Sha256>(&nullifiers).unwrap();

        let result = generate_non_membership_proof_for_nullifier(nf!(10), &nullifiers, &tree);

        assert!(
            matches!(result, Err(e) if e.to_string() == "Snapshot nullifiers cannot be empty"),
            "Expected error for empty nullifiers"
        );
    }

    #[test]
    fn merkle_proof_is_verifiable() {
        let nullifiers = nfs![10, 30, 50, 70];
        let test_nullifiers = nfs![5, 20, 40, 60, 80];
        let expected_bounds = vec![
            (MIN_NF, nf!(10)),  // for 5
            (nf!(10), nf!(30)), // for 20
            (nf!(30), nf!(50)), // for 40
            (nf!(50), nf!(70)), // for 60
            (nf!(70), MAX_NF),  // for 80
        ];

        let tree = build_merkle_tree::<Sha256>(&nullifiers).unwrap();

        for (test_nullifier, (left, right)) in test_nullifiers.iter().zip(expected_bounds.iter()) {
            let result =
                generate_non_membership_proof_for_nullifier(*test_nullifier, &nullifiers, &tree)
                    .unwrap();

            assert!(result.is_some(), "Expected Some(proof) for unspent note");
            let proof = result.unwrap();

            assert_eq!(proof.left_nullifier, *left);
            assert_eq!(proof.right_nullifier, *right);

            let leaf = build_leaf(&proof.left_nullifier, &proof.right_nullifier);
            let leaf_hash = Sha256::hash(&leaf);

            // Find the leaf index for verification
            let leaf_idx = nullifiers.binary_search(test_nullifier).unwrap_err();

            let merkle_proof =
                rs_merkle::MerkleProof::<Sha256>::from_bytes(&proof.merkle_proof).unwrap();

            assert!(
                merkle_proof.verify(
                    tree.root().unwrap(),
                    &[leaf_idx],
                    &[leaf_hash],
                    tree.leaves_len()
                ),
                "Merkle proof should be valid"
            );
        }
    }

    #[test]
    fn handles_single_nullifier_below() {
        let nullifiers = nfs![50];
        let tree = build_merkle_tree::<Sha256>(&nullifiers).unwrap();

        let result =
            generate_non_membership_proof_for_nullifier(nf!(25), &nullifiers, &tree).unwrap();
        assert!(result.is_some());
        let proof = result.unwrap();
        assert_eq!(proof.left_nullifier, MIN_NF);
        assert_eq!(proof.right_nullifier, nf!(50));
    }

    #[test]
    fn handles_single_nullifier_above() {
        let nullifiers = nfs![50];
        let tree = build_merkle_tree::<Sha256>(&nullifiers).unwrap();

        let result =
            generate_non_membership_proof_for_nullifier(nf!(75), &nullifiers, &tree).unwrap();

        assert!(result.is_some());
        let proof = result.unwrap();
        assert_eq!(proof.left_nullifier, nf!(50));
        assert_eq!(proof.right_nullifier, MAX_NF);
    }
}
