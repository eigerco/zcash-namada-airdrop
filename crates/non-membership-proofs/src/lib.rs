//! Non-membership proofs library

pub mod chain_nullifiers;
pub mod print_utils;
pub mod source;
pub mod user_nullifiers;
pub mod utils;

use chain_nullifiers::PoolNullifier;
use futures::{Stream, TryStreamExt as _};
use rayon::iter::ParallelIterator as _;
use rayon::slice::ParallelSlice as _;
use rs_merkle::{Hasher, MerkleTree};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
#[derive(Error, Debug, PartialEq, Eq)]
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
/// Note: This function may be CPU-intensive for large slices. If used in an async context, consider
/// offloading to a blocking thread.
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
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_asserts_for_indexing,
    reason = "Panics are impossible: we check is_empty() before .expect(), and windows(2) guarantees 2 elements"
)]
pub fn build_merkle_tree<H>(nullifiers: &[Nullifier]) -> Result<MerkleTree<H>, MerkleTreeError>
where
    H: Hasher,
    H::Hash: Send,
{
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
    leaves.extend(
        nullifiers
            .par_windows(2)
            .map(|w| H::hash(&build_leaf(&w[0], &w[1])))
            .collect::<Vec<_>>(),
    );
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

/// Write nullifiers in binary format to an async writer
///
/// # Errors
/// If write fails
pub async fn write_nullifiers(
    nullifiers: &[Nullifier],
    mut writer: impl AsyncWriteExt + Unpin,
) -> std::io::Result<()> {
    writer.write_all(bytemuck::cast_slice(nullifiers)).await?;
    writer.flush().await?;

    Ok(())
}

/// Read nullifiers from an async reader
///
/// # Errors
///
/// Returns an error if:
/// - Reading from the file fails
/// - The input size is not a multiple of 32 bytes (nullifier size)
pub async fn read_nullifiers(
    mut reader: impl AsyncReadExt + Unpin,
) -> std::io::Result<Vec<Nullifier>> {
    let mut buf = Vec::with_capacity(BUF_SIZE);
    reader.read_to_end(&mut buf).await?;

    if buf.len() % NULLIFIER_SIZE != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "file has {} bytes which is not a multiple of nullifier size ({NULLIFIER_SIZE})",
                buf.len(),
            ),
        ));
    }

    let nullifiers: Vec<Nullifier> = bytemuck::cast_slice(&buf).to_vec();

    Ok(nullifiers)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "Test code - relax these lints for clarity"
    )]

    use futures::io::Cursor;
    use test_utils::{MAX_NF, MIN_NF, nf, nfs};
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    use super::*;

    mod read {
        use super::*;

        #[tokio::test]
        async fn read_nullifiers_valid() {
            #![allow(clippy::indexing_slicing, reason = "Test code")]

            let mut data = vec![0_u8; 64];
            data[31] = 1;
            data[63] = 2;

            let cursor = Cursor::new(&data);
            let nullifiers = read_nullifiers(cursor.compat())
                .await
                .expect("Failed to read nullifiers");

            assert_eq!(nullifiers.len(), 2, "Expected 2 nullifiers");

            assert_eq!(
                data,
                bytemuck::cast_slice(&nullifiers),
                "Buffer does not match expected nullifier bytes"
            );
        }

        #[tokio::test]
        async fn read_nullifiers_invalid_size() {
            let data = vec![0_u8; 33];
            let cursor = Cursor::new(data);

            let result = read_nullifiers(cursor.compat()).await;
            assert!(
                matches!(
                    result,
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData
                ),
                "Expected InvalidData error"
            );
        }

        #[tokio::test]
        async fn read_nullifiers_empty() {
            let cursor = Cursor::new(Vec::new());
            let nullifiers = read_nullifiers(cursor.compat())
                .await
                .expect("Failed to read nullifiers");
            assert!(nullifiers.is_empty(), "Expected empty nullifiers vector");
        }
    }

    mod write {
        use super::*;

        #[tokio::test]
        async fn write_nullifiers_valid() {
            #![allow(clippy::indexing_slicing, reason = "Test code")]

            // Order does not matter here, as we are just testing write functionality
            let nullifiers: [Nullifier; 3] = rand::random();

            let cursor = Cursor::new(Vec::new());
            let mut writer = cursor.compat();
            write_nullifiers(&nullifiers, &mut writer)
                .await
                .expect("Failed to write nullifiers");

            let buf = writer.into_inner().into_inner();

            // buf is Vec<u8>
            // nullifiers is &[Nullifier] -> &[ [u8; 32] ]
            assert_eq!(buf.len(), nullifiers.len() * NULLIFIER_SIZE,);

            assert_eq!(buf, bytemuck::cast_slice(&nullifiers),);
        }
    }

    #[tokio::test]
    async fn write_read_roundtrip() {
        // Order does not matter here, as we are just testing read/write functionality
        let original: [Nullifier; 3] = rand::random();

        // Write
        let cursor = Cursor::new(Vec::new());
        let mut writer = cursor.compat();
        write_nullifiers(&original, &mut writer)
            .await
            .expect("Failed to write nullifiers");
        let buf = writer.into_inner().into_inner();

        // Read back
        let cursor = Cursor::new(buf);
        let read_back = read_nullifiers(cursor.compat())
            .await
            .expect("Failed to read nullifiers");

        assert_eq!(
            original.to_vec(),
            read_back,
            "Roundtrip should preserve nullifiers"
        );
    }

    mod merkle_tree {
        use rs_merkle::algorithms::Sha256;

        use super::*;

        #[test]
        fn build_leaf_test() {
            let nf1: Nullifier = [1_u8; NULLIFIER_SIZE];
            let nf2: Nullifier = [2_u8; NULLIFIER_SIZE];

            let leaf = build_leaf(&nf1, &nf2);

            assert_eq!(&leaf[..NULLIFIER_SIZE], &nf1,);
            assert_eq!(&leaf[NULLIFIER_SIZE..], &nf2,);
        }

        #[test]
        fn build_merkle_tree_empty() {
            let nullifiers: Vec<Nullifier> = vec![];
            let tree =
                build_merkle_tree::<Sha256>(&nullifiers).expect("Failed to build Merkle tree");

            assert_eq!(tree.leaves_len(), 0);
            assert!(tree.root().is_none());
        }

        #[test]
        fn build_merkle_tree_unsorted_error() {
            let nullifiers = vec![nf![0x3], nf![0x1], nf![0x2]];
            let result = build_merkle_tree::<Sha256>(&nullifiers);

            assert!(matches!(result, Err(MerkleTreeError::NotSorted)));
        }

        #[test]
        fn build_merkle_tree_sorted() {
            let nullifiers = nfs![0x1, 0x2, 0x3];
            let tree =
                build_merkle_tree::<Sha256>(&nullifiers).expect("Failed to build Merkle tree");

            // n nullifiers -> n+1 leaves (front + n-1 windows + back)
            assert_eq!(tree.leaves_len(), 4);
            assert!(tree.root().is_some());

            // Verify leaf structure
            let expected_leaves: Vec<_> = [
                build_leaf(&MIN_NF, &nullifiers[0]),
                build_leaf(&nullifiers[0], &nullifiers[1]),
                build_leaf(&nullifiers[1], &nullifiers[2]),
                build_leaf(&nullifiers[2], &MAX_NF),
            ]
            .iter()
            .map(|leaf| Sha256::hash(leaf))
            .collect();

            for (i, expected) in expected_leaves.iter().enumerate() {
                assert_eq!(
                    tree.leaves().expect("leaves exist")[i],
                    *expected,
                    "Leaf {i} mismatch"
                );
            }
        }

        #[test]
        fn build_merkle_tree_single_nullifier() {
            let nullifiers = vec![nf![0x42]];
            let tree =
                build_merkle_tree::<Sha256>(&nullifiers).expect("Failed to build Merkle tree");

            // 1 nullifier -> 2 leaves (front + back)
            assert_eq!(tree.leaves_len(), 2);
            assert!(tree.root().is_some());

            let expected_front = Sha256::hash(&build_leaf(&MIN_NF, &nullifiers[0]));
            let expected_back = Sha256::hash(&build_leaf(&nullifiers[0], &MAX_NF));

            let leaves = tree.leaves().expect("leaves exist");
            assert_eq!(leaves[0], expected_front);
            assert_eq!(leaves[1], expected_back);
        }
    }

    mod partition_by_pool {
        use futures::stream;

        use super::*;

        #[tokio::test]
        async fn partition_by_pool_empty() {
            let items: Vec<Result<PoolNullifier, std::io::Error>> = vec![];
            let stream = stream::iter(items);

            let (sapling, orchard) = partition_by_pool(stream)
                .await
                .expect("Failed to partition");

            assert!(sapling.is_empty(), "Expected zero sapling notes.");
            assert!(orchard.is_empty(), "Expected zero orchard notes.");
        }

        #[tokio::test]
        async fn partition_by_pool_test() {
            #![allow(clippy::indexing_slicing, reason = "Test code")]

            let items: Vec<Result<PoolNullifier, std::io::Error>> = vec![
                Ok(PoolNullifier {
                    pool: Pool::Sapling,
                    nullifier: nf![1],
                }),
                Ok(PoolNullifier {
                    pool: Pool::Orchard,
                    nullifier: nf![2],
                }),
                Ok(PoolNullifier {
                    pool: Pool::Sapling,
                    nullifier: nf![3],
                }),
                Ok(PoolNullifier {
                    pool: Pool::Orchard,
                    nullifier: nf![4],
                }),
                Ok(PoolNullifier {
                    pool: Pool::Orchard,
                    nullifier: nf![5],
                }),
            ];
            let stream = stream::iter(items);

            let (sapling, orchard) = partition_by_pool(stream)
                .await
                .expect("Failed to partition");

            assert_eq!(sapling.len(), 2);
            assert_eq!(sapling[0], nf!(1));
            assert_eq!(sapling[1], nf!(3));

            assert_eq!(orchard.len(), 3);
            assert_eq!(orchard[0], nf!(2));
            assert_eq!(orchard[1], nf!(4));
            assert_eq!(orchard[2], nf!(5));
        }

        #[tokio::test]
        async fn partition_by_pool_error_propagation() {
            let items: Vec<Result<PoolNullifier, std::io::Error>> = vec![
                Ok(PoolNullifier {
                    pool: Pool::Sapling,
                    nullifier: nf![1],
                }),
                Err(std::io::Error::other("test error")),
                Ok(PoolNullifier {
                    pool: Pool::Orchard,
                    nullifier: nf![2],
                }), // Never reached
            ];
            let stream = stream::iter(items);

            let result = partition_by_pool(stream).await;

            assert!(matches!(
                result,
                Err(e) if e.to_string() == "test error"
            ));
        }
    }
}
