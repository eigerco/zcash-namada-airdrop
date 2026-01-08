//! Non-membership proofs library
//!
//! This crate provides tools for generating non-membership proofs using Merkle trees.
//! These proofs are used in the Zcash-Namada airdrop to prove that a user's nullifier
//! has NOT been spent without revealing the actual nullifier.

pub mod chain_nullifiers;
pub mod merkle;
pub mod source;
pub mod user_nullifiers;
pub mod utils;

use chain_nullifiers::PoolNullifier;
use futures::{Stream, TryStreamExt as _};
// Re-export key merkle types for convenience
pub use merkle::{
    MerklePathError, NON_MEMBERSHIP_TREE_DEPTH, NonMembershipNode, NonMembershipTree, TreePosition,
};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Buffer size for file I/O
const BUF_SIZE: usize = 1024 * 1024;

/// Size of a nullifier in bytes
const NULLIFIER_SIZE: usize = 32;

/// A representation of Nullifiers
///
/// Nullifiers in Zcash Orchard and Sapling pools are both 32 bytes long.
pub type Nullifier = [u8; NULLIFIER_SIZE];

/// Minimum nullifier (all zeros)
pub const MIN_NF: Nullifier = [0_u8; NULLIFIER_SIZE];

/// Maximum nullifier (all ones)
pub const MAX_NF: Nullifier = [0xFF_u8; NULLIFIER_SIZE];

/// Zcash pools
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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
    use test_utils::nf;
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
