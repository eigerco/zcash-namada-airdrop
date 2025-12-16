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

/// Search for a nullifier in the snapshot and generate a non-membership proof if not found.
/// Returns `Some(proof)` if the note is unspent, `None` if the note was already spent.
#[instrument(
    skip(snapshot_nullifiers, merkle_tree, keys, note),
    fields(pool = ?note.pool(), height = note.height())
)]
#[allow(
    clippy::indexing_slicing,
    reason = "Indices are bounded by binary_search result which is always in range [0, len]"
)]
pub(crate) fn generate_non_membership_proof<H: Hasher>(
    note: &AnyFoundNote,
    snapshot_nullifiers: &[Nullifier],
    merkle_tree: &MerkleTree<H>,
    keys: &ViewingKeys,
) -> eyre::Result<Option<NullifierProof>> {
    ensure!(
        !snapshot_nullifiers.is_empty() &&
            snapshot_nullifiers.is_sorted() &&
            merkle_tree.leaves_len() == snapshot_nullifiers.len().saturating_add(1_usize),
        "Snapshot nullifiers are not sorted"
    );

    let nullifier = note
        .nullifier(keys)
        .context("Failed to get nullifier from note")?;
    let nullifier_hex = hex::encode::<Nullifier>(
        nullifier
            .reverse_into_array()
            .context("Failed to reverse nullifier bytes order")?,
    );

    match snapshot_nullifiers.binary_search(&nullifier) {
        Ok(_) => {
            warn!(nullifier = %nullifier_hex, "Nullifier found in snapshot - note was spent");
            Ok(None)
        }
        Err(idx) => {
            let left = idx.saturating_sub(1);
            let right = idx;

            debug!(
                nullifier = %nullifier_hex,
                left_idx = left,
                left_nullifier = %hex::encode::<Nullifier>(
                    snapshot_nullifiers[left]
                        .reverse_into_array()
                        .context("Failed to reverse left nullifier bytes order")?
                ),
                right_idx = right,
                right_nullifier = %hex::encode::<Nullifier>(
                    snapshot_nullifiers[right]
                        .reverse_into_array()
                        .context("Failed to reverse right nullifier bytes order")?
                ),
                "Found bounding nullifiers"
            );

            let leaf = build_leaf(&snapshot_nullifiers[left], &snapshot_nullifiers[right]);
            let leaf_hash = H::hash(&leaf);

            let merkle_proof = merkle_tree.proof(&[right]);

            ensure!(
                snapshot_nullifiers[left] < nullifier && nullifier < snapshot_nullifiers[right],
                "Snapshot nullifiers at indices {left} and {right} do not bound nullifier {nullifier_hex}",
            );

            ensure!(
                merkle_proof.verify(
                    merkle_tree.root().context("Merkle tree has no root")?,
                    &[right],
                    &[leaf_hash],
                    merkle_tree.leaves_len()
                ),
                "Merkle proof verification failed"
            );

            info!(nullifier = %nullifier_hex, "Generated non-membership proof");

            Ok(Some(NullifierProof {
                left_nullifier: snapshot_nullifiers[left],
                right_nullifier: snapshot_nullifiers[right],
                merkle_proof: merkle_proof.to_bytes(),
            }))
        }
    }
}
