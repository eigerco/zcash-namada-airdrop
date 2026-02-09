//! Chain scanning and lightwalletd integration.

pub mod chain_nullifiers;
pub mod light_walletd;
pub mod scanner;
pub mod user_nullifiers;
pub mod viewing_keys;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub use viewing_keys::{OrchardViewingKeys, SaplingViewingKeys, ViewingKeys};
use zair_core::base::{NULLIFIER_SIZE, Nullifier, SanitiseNullifiers};

/// 1 MiB buffer for file I/O.
const FILE_BUF_SIZE: usize = 1024 * 1024;

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
    let mut buf = Vec::with_capacity(FILE_BUF_SIZE);
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
    use tokio_util::compat::FuturesAsyncReadCompatExt as _;

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

            let nullifiers: [Nullifier; 3] =
                std::array::from_fn(|_| Nullifier::new(rand::random()));

            let cursor = Cursor::new(Vec::new());
            let mut writer = cursor.compat();
            write_nullifiers(&nullifiers, &mut writer)
                .await
                .expect("Failed to write nullifiers");

            let buf = writer.into_inner().into_inner();

            assert_eq!(buf.len(), nullifiers.len() * NULLIFIER_SIZE,);
            assert_eq!(buf, bytemuck::cast_slice::<_, u8>(&nullifiers),);
        }
    }

    #[tokio::test]
    async fn write_read_roundtrip() {
        let original: [Nullifier; 3] = std::array::from_fn(|_| Nullifier::new(rand::random()));

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
