//! Non-membership proofs library

pub mod chain_nullifiers;
pub mod source;
pub mod user_nullifiers;
pub mod utils;

use std::path::Path;

use chain_nullifiers::PoolNullifier;
use futures::{Stream, TryStreamExt as _};
use rs_merkle::{Hasher, MerkleTree};
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader, BufWriter};

/// Buffer size for file I/O
const BUF_SIZE: usize = 1024 * 1024;

/// Size of a nullifier in bytes
const NULLIFIER_SIZE: usize = 32;

/// A representation of Nullifiers
///
/// Nullifiers in Zcash Orchard and Sapling pools are both 32 bytes long.
pub type Nullifier = [u8; 32];

/// Zcash pools
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pool {
    /// Sapling pool
    Sapling,
    /// Orchard pool
    Orchard,
}

/// Collect stream into separate vectors, by pool.
///
/// # Errors
///
/// Returns an error if the stream returns an error.
pub async fn partition_by_pool<S, E>(stream: S) -> Result<(Vec<Nullifier>, Vec<Nullifier>), E>
where
    S: Stream<Item = Result<PoolNullifier, E>>,
{
    let mut sapling = Vec::new();
    let mut orchard = Vec::new();

    tokio::pin!(stream);
    while let Some(nullifier) = stream.try_next().await? {
        match nullifier.pool {
            Pool::Sapling => sapling.push(nullifier.nullifier),
            Pool::Orchard => orchard.push(nullifier.nullifier),
        }
    }

    Ok((sapling, orchard))
}

/// Errors that can occur when building a Merkle tree for non-membership proofs
#[derive(Error, Debug)]
pub enum MerkleTreeError {
    /// Nullifiers are not sorted.
    /// Nullifiers must be sorted to build the Merkle tree for non-membership proofs.
    #[error(
        "Nullifiers are not sorted. Nullifiers must be sorted to build the Merkle tree for non-membership proofs."
    )]
    NotSorted,
}

/// Builds a Merkle tree from a sorted slice of nullifiers for non-membership proofs.
///
/// # Arguments
///
/// * `nullifiers` - A slice of nullifiers, which must be sorted in ascending order.
///
/// # Returns
///
/// Returns a `MerkleTree` constructed from the nullifiers, or an error if the input is not sorted.
///
/// # Errors
///
/// Returns [`MerkleTreeError::NotSorted`] if the input slice is not sorted in ascending order.
///
/// # Algorithm
///
/// - Adds a "front" leaf node representing the range from 0 to the first nullifier.
/// - Adds leaf nodes for each consecutive pair of nullifiers.
/// - Adds a "back" leaf node representing the range from the last nullifier to 0xFF..FF.
/// - Hashes each leaf node and constructs the Merkle tree from these hashes.
#[allow(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "Panics are impossible: we check is_empty() before .expect(), and windows(2) guarantees 2 elements"
)]
pub fn build_merkle_tree<H: Hasher>(
    nullifiers: &[Nullifier],
) -> Result<MerkleTree<H>, MerkleTreeError> {
    if nullifiers.is_empty() {
        return Ok(MerkleTree::new());
    }

    if !nullifiers.is_sorted() {
        return Err(MerkleTreeError::NotSorted);
    }

    // Safe: we already checked nullifiers is not empty above
    let first = nullifiers
        .first()
        .expect("Nullifiers array is not empty, and this should always have a value");
    let last = nullifiers
        .last()
        .expect("Nullifiers array is not empty, and this should always have a value");

    let front = H::hash(&build_leaf(&[0_u8; NULLIFIER_SIZE], first));
    let back = H::hash(&build_leaf(last, &[0xFF; NULLIFIER_SIZE]));

    // Pre-allocate: 1 front + (n-1) windows + 1 back = n + 1
    let mut leaves = Vec::with_capacity(nullifiers.len().saturating_add(1));

    leaves.push(front);
    leaves.extend(nullifiers.windows(2).map(|w| {
        // windows(2) guarantees w.len() == 2
        assert_eq!(
            w.len(),
            2,
            "windows(2) should always yield slices of length 2"
        );
        H::hash(&build_leaf(&w[0], &w[1]))
    }));
    leaves.push(back);

    Ok(MerkleTree::from_leaves(&leaves))
}

/// Build a leaf node from two nullifiers
#[must_use]
pub fn build_leaf(nf1: &Nullifier, nf2: &Nullifier) -> [u8; 2 * NULLIFIER_SIZE] {
    let mut leaf = [0_u8; 2 * NULLIFIER_SIZE];
    leaf[..NULLIFIER_SIZE].copy_from_slice(nf1);
    leaf[NULLIFIER_SIZE..].copy_from_slice(nf2);
    leaf
}

/// Write leaf notes to binary file without intermediate allocation
///
/// # Errors
/// If writing to the file fails
pub async fn write_raw_nullifiers<P>(notes: &[Nullifier], path: P) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    let file = File::create(path).await?;
    let mut writer = BufWriter::with_capacity(BUF_SIZE, file);

    writer.write_all(bytemuck::cast_slice(notes)).await?;
    writer.flush().await?;

    Ok(())
}

/// Read leaf notes from binary file without intermediate allocation
///
/// # Errors
/// If reading from the file fails
pub async fn read_raw_nullifiers<P>(path: P) -> std::io::Result<Vec<Nullifier>>
where
    P: AsRef<Path>,
{
    let file = File::open(path).await?;
    let mut reader = BufReader::with_capacity(BUF_SIZE, file);

    let mut buf = Vec::with_capacity(BUF_SIZE);
    reader.read_to_end(&mut buf).await?;
    let nullifiers: Vec<Nullifier> = bytemuck::cast_slice(&buf).to_vec();

    Ok(nullifiers)
}
