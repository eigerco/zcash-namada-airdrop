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

/// Collect stream into separate pools
///
/// TODO: use Vec::capacity
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

/// Build a Merkle tree from the given nullifiers to produce non-membership proofs
///
/// Algorithm:
/// 1. Sort the nullifiers
/// 2. Concatenate each consecutive nullifiers to store ranges of nullifiers in leaf nodes.
/// Merge: [nf1, nf2, nf3, nf4] -> [(nf1, nf2), (nf2, nf3)]
/// 3. Hash each leaf node
pub fn build_merkle_tree<H: Hasher>(
    nullifiers: &[Nullifier],
) -> Result<MerkleTree<H>, MerkleTreeError> {
    if nullifiers.is_empty() {
        return Ok(MerkleTree::new());
    }

    if !nullifiers.is_sorted() {
        return Err(MerkleTreeError::NotSorted);
    }

    let front = H::hash(&build_leaf(&[0u8; NULLIFIER_SIZE], &nullifiers[0]));
    let back = H::hash(&build_leaf(
        &nullifiers[nullifiers.len() - 1],
        &[0xFF; NULLIFIER_SIZE],
    ));

    // Pre-allocate: 1 front + (n-1) windows + 1 back = n + 1
    let mut leaves = Vec::with_capacity(nullifiers.len() + 1);

    leaves.push(front);
    leaves.extend(
        nullifiers
            .windows(2)
            .map(|w| H::hash(&build_leaf(&w[0], &w[1]))),
    );
    leaves.push(back);

    Ok(MerkleTree::from_leaves(&leaves))
}

/// Build a leaf node from two nullifiers
pub fn build_leaf(nf1: &Nullifier, nf2: &Nullifier) -> [u8; 2 * NULLIFIER_SIZE] {
    let mut leaf = [0u8; 2 * NULLIFIER_SIZE];
    leaf[..NULLIFIER_SIZE].copy_from_slice(nf1);
    leaf[NULLIFIER_SIZE..].copy_from_slice(nf2);
    leaf
}

/// Write leaf notes to binary file without intermediate allocation
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
