//! Non-membership proofs library
//!
//! This crate provides tools for generating non-membership proofs using Merkle trees.
//! These proofs are used in the Zcash-Namada airdrop to prove that a user's nullifier
//! has NOT been spent without revealing the actual nullifier.

pub mod light_walletd;
pub mod non_membership_tree;
mod nullifier;
pub mod scanner;
pub mod user_nullifiers;
pub mod utils;
mod viewing_keys;

// Re-export key merkle types for convenience
pub use non_membership_tree::{
    MerklePathError, NonMembershipNode, NonMembershipTree, TreePosition,
};
// Re-export nullifier types
pub use nullifier::{NULLIFIER_SIZE, Nullifier, SanitiseNullifiers};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub use viewing_keys::{OrchardViewingKeys, SaplingViewingKeys, ViewingKeys};

/// Buffer size for file I/O
const BUF_SIZE: usize = 1024 * 1024;

/// Zcash pools
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Pool {
    /// Sapling pool
    Sapling,
    /// Orchard pool
    Orchard,
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
    use futures::io::Cursor;
    use rand::distr::{Distribution, StandardUniform};
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    use super::*;

    impl Distribution<Nullifier> for StandardUniform {
        fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Nullifier {
            Nullifier::new(rng.random())
        }
    }

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
                bytemuck::cast_slice::<_, u8>(&nullifiers),
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

            assert_eq!(buf, bytemuck::cast_slice::<_, u8>(&nullifiers),);
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
}
