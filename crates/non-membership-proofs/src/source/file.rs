//! Read nullifiers from local files.
//!
//! This is used for testing and local setups.
//! The expected file format is a sequence of 32-byte nullifiers with no header or separators.
//!
//! # Cancellation
//!
//! The stream can be safely cancelled by dropping it. File handles are automatically
//! closed when the stream is dropped, with no risk of resource leaks.

use std::io;
use std::ops::RangeInclusive;
use std::path::PathBuf;

use async_stream::try_stream;
use futures::Stream;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt as _, BufReader};

use crate::chain_nullifiers::{BoxedNullifierStream, ChainNullifiers, PoolNullifier};
use crate::{Nullifier, Pool};

/// Size of the buffer used to read the file, in number of nullifiers
const BUF_NULLIFIERS: usize = 1024;

/// Size of a nullifier in bytes
const NULLIFIER_SIZE: usize = 32;

/// Buffer size in bytes
const BUF_SIZE: usize = NULLIFIER_SIZE * BUF_NULLIFIERS;

/// Source for reading nullifiers from local binary files
#[allow(
    clippy::module_name_repetitions,
    reason = "Clearer name for source type"
)]
pub struct FileSource {
    sapling_path: Option<PathBuf>,
    orchard_path: Option<PathBuf>,
    buf_size: usize,
}

impl FileSource {
    /// Create a new file `Source` with the given file paths
    ///
    /// # Arguments
    /// * `sapling_path` - Path to the Sapling nullifiers binary file
    /// * `orchard_path` - Path to the Orchard nullifiers binary file
    #[must_use]
    pub const fn new(sapling_path: Option<PathBuf>, orchard_path: Option<PathBuf>) -> Self {
        Self {
            sapling_path,
            orchard_path,
            buf_size: BUF_SIZE,
        }
    }

    /// Create a new file `Source` with the given file paths and buffer size.
    /// This is intended for testing purposes only. It allows to set a smaller buffer size
    /// to test boundary conditions.
    #[cfg(test)]
    #[must_use]
    pub const fn with_buf_size(
        sapling_path: Option<PathBuf>,
        orchard_path: Option<PathBuf>,
        buf_size: usize,
    ) -> Self {
        Self {
            sapling_path,
            orchard_path,
            buf_size,
        }
    }
}

impl ChainNullifiers for FileSource {
    type Error = io::Error;
    type Stream = BoxedNullifierStream<Self::Error>;

    /// Read nullifiers from the specified files.
    /// `_range` is ignored because if a file is provided all nullifiers are considered as part of
    /// the snapshot.
    fn nullifiers_stream(&self, _range: &RangeInclusive<u64>) -> Self::Stream {
        let sapling_path = self.sapling_path.clone();
        let orchard_path = self.orchard_path.clone();
        let buf_size = self.buf_size;

        Box::pin(try_stream! {
            for (file, pool) in [
                (sapling_path.as_ref(), Pool::Sapling),
                (orchard_path.as_ref(), Pool::Orchard)
            ] {
                if let Some(path) = file {
                    let file = File::open(path).await?;
                    let reader = BufReader::new(file);
                    for await result in read_nullifiers(reader, buf_size) {
                        yield PoolNullifier { pool, nullifier: result? };
                    }
                }
            }
        })
    }
}

/// Core function to read nullifiers from an async reader.
///
/// It reads 32-byte nullifiers from the reader, handling buffer boundaries correctly.
/// The internal buffer size should be at least 32 bytes.
fn read_nullifiers<R: AsyncRead + Unpin>(
    reader: R,
    buf_size: usize,
) -> impl Stream<Item = Result<Nullifier, io::Error>> {
    try_stream! {
        // Ensure buffer can hold at least one nullifier
        let buf_size = buf_size.max(NULLIFIER_SIZE);
        let mut buf = vec![0_u8; buf_size];
        let mut reader = reader;
        let mut leftover = 0_usize;

        loop {
            // Safety: leftover is always < NULLIFIER_SIZE (32), buf_size is always >= 32
            let read_buf = buf.get_mut(leftover..).expect("leftover < NULLIFIER_SIZE < buf_size");
            let n = reader.read(read_buf).await?;
            if n == 0 {
                if leftover > 0 {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "reader has {leftover} trailing bytes (not a multiple of {NULLIFIER_SIZE})"
                        ),
                    ))?;
                }
                break;
            }

            let total = leftover.saturating_add(n);
            #[allow(clippy::integer_division, reason = "Integer division is intentional here - we want floor division")]
            let complete_count = total / NULLIFIER_SIZE;
            let complete_bytes = complete_count.saturating_mul(NULLIFIER_SIZE);

            // Safety: complete_bytes <= total <= buf.len() by construction
            let complete_slice = buf.get(..complete_bytes).expect("complete_bytes <= buf.len()");
            for chunk in complete_slice.chunks_exact(NULLIFIER_SIZE) {
                // Safety: chunks_exact(32) guarantees exactly 32 bytes per chunk
                let nullifier: Nullifier = chunk.try_into().expect("chunks_exact guarantees size");
                yield nullifier;
            }

            leftover = total.saturating_sub(complete_bytes);
            if leftover > 0 {
                buf.copy_within(complete_bytes..total, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "Test code - relax these lints for clarity"
    )]

    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures::StreamExt as _;
    use tempfile::NamedTempFile;
    use test_utils::nfs;
    use tokio::io::{AsyncWriteExt as _, BufWriter, ReadBuf};

    use super::*;
    use crate::{Nullifier, partition_by_pool, write_nullifiers};

    /// A reader that returns data in fixed-size chunks.
    /// This is used for testing buffer boundary handling.
    struct ChunkedReader {
        data: Vec<u8>,
        pos: usize,
        chunk_size: usize,
    }

    impl ChunkedReader {
        fn new(data: Vec<u8>, chunk_size: usize) -> Self {
            Self {
                data,
                pos: 0,
                chunk_size,
            }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pos >= self.data.len() {
                return Poll::Ready(Ok(()));
            }

            let remaining = self.data.len() - self.pos;
            let to_read = remaining.min(self.chunk_size).min(buf.remaining());
            buf.put_slice(&self.data[self.pos..self.pos + to_read]);
            self.pos += to_read;

            Poll::Ready(Ok(()))
        }
    }

    /// Prepare test environment
    async fn nullifiers_file(count: usize) -> NamedTempFile {
        let temp_file = NamedTempFile::new().expect("failed to create temp file");
        let file = File::create(temp_file.path())
            .await
            .expect("failed to create file");

        let nullfiers: Vec<Nullifier> = (0..count).map(|_| rand::random()).collect();
        let writer = BufWriter::new(file);
        write_nullifiers(&nullfiers, writer)
            .await
            .expect("failed to write nullifiers");

        temp_file
    }

    async fn check_read_nullifiers(sapling_count: usize, orchard_count: usize) {
        let sapling_file = nullifiers_file(sapling_count).await;
        let orchard_file = nullifiers_file(orchard_count).await;
        let file_source = FileSource::new(
            Some(sapling_file.path().to_path_buf()),
            Some(orchard_file.path().to_path_buf()),
        );

        let stream = file_source.nullifiers_stream(&(0..=0));
        let (sapling, orchard) = partition_by_pool(stream)
            .await
            .expect("failed to read nullifiers");

        assert_eq!(sapling.len(), sapling_count);
        assert_eq!(orchard.len(), orchard_count);
    }

    #[tokio::test]
    async fn test_empty() {
        let sapling_nullifiers = 0;
        let orchard_nullifiers = 0;
        check_read_nullifiers(sapling_nullifiers, orchard_nullifiers).await;
    }

    #[tokio::test]
    async fn test_single() {
        let sapling_nullifiers = 1;
        let orchard_nullifiers = 1;
        check_read_nullifiers(sapling_nullifiers, orchard_nullifiers).await;
    }

    #[tokio::test]
    async fn test_buffer_boundary() {
        let sapling_nullifiers = BUF_NULLIFIERS;
        let orchard_nullifiers = BUF_NULLIFIERS;
        check_read_nullifiers(sapling_nullifiers, orchard_nullifiers).await;
    }

    #[tokio::test]
    async fn test_over_buffer_boundary() {
        let sapling_nullifiers = BUF_NULLIFIERS + 1;
        let orchard_nullifiers = BUF_NULLIFIERS + 1;
        check_read_nullifiers(sapling_nullifiers, orchard_nullifiers).await;
    }

    #[tokio::test]
    async fn test_no_nullifiers() {
        let file_source = FileSource::new(None, None);

        let stream = file_source.nullifiers_stream(&(0..=0));
        let (sapling, orchard) = partition_by_pool(stream)
            .await
            .expect("failed to read nullifiers");

        assert!(sapling.is_empty());
        assert!(orchard.is_empty());
    }

    /// Test incomplete nullifier handling
    #[tokio::test]
    async fn test_incomplete_nullifier() {
        let temp_file = NamedTempFile::new().expect("failed to create temp file");
        let mut file = File::create(temp_file.path())
            .await
            .expect("failed to create file");

        // Write 33 bytes (1 complete nullifier + 1 extra byte)
        let data = vec![0_u8; 33];
        file.write_all(&data).await.expect("failed to write data");
        file.flush().await.expect("failed to flush data");

        let file_source = FileSource::new(Some(temp_file.path().to_path_buf()), None);
        let results: Vec<_> = file_source.nullifiers_stream(&(0..=0)).collect().await;

        // First item should be Ok (the complete nullifier)
        assert!(results[0].is_ok());

        // Second item should be an UnexpectedEof error
        assert!(matches!(
            results[1],
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[tokio::test]
    async fn missing_file() {
        let sapling_file = nullifiers_file(1).await;
        let source = FileSource::new(
            Some(sapling_file.path().to_path_buf()),
            Some("/nonexistent/orchard.bin".into()),
        );

        let results: Vec<_> = source.nullifiers_stream(&(0..=0)).collect().await;

        // First: Ok (sapling nullifier)
        assert!(results[0].is_ok());

        // Second: NotFound error (orchard file)
        assert!(matches!(
            results[1],
            Err(ref e) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    // Tests using read_nullifiers directly
    //
    // These tests use ChunkedReader to guarantee specific read patterns,
    // testing the actual production code path (read_nullifiers).

    /// Test that leftover bytes are correctly handled when reads don't align to nullifier
    /// boundaries.
    ///
    /// Uses `ChunkedReader` to return data in 50-byte chunks (not aligned to 32-byte nullifiers):
    /// - 3 nullifiers = 96 bytes total
    /// - Read 1: 50 bytes → 1 complete nullifier (32 bytes), 18 bytes leftover
    /// - Read 2: 46 bytes (remaining) → 18 + 46 = 64 → 2 complete, 0 leftover
    #[tokio::test]
    async fn test_leftover_bytes_handling() {
        #![allow(
            clippy::arithmetic_side_effects,
            reason = "nullifiers.len() * NULLIFIER_SIZE will not overflow"
        )]

        // Create 3 nullifiers
        let nullifiers = nfs![1, 2, 3];
        let data = bytemuck::cast_slice(&nullifiers).to_vec();
        assert_eq!(data.len(), { nullifiers.len() * NULLIFIER_SIZE });

        // Use 50-byte chunks to force unaligned reads
        let reader = ChunkedReader::new(data, 50);
        let stream = read_nullifiers(reader, BUF_SIZE);
        let results: Vec<_> = stream.collect().await;

        // All 3 should succeed
        assert_eq!(results.len(), 3);
        for (i, result) in results.iter().enumerate() {
            let nf = result.as_ref().expect("should be Ok");
            assert_eq!(nf, &nullifiers[i]);
        }
    }

    /// Test leftover handling with very small buffer and unaligned chunks.
    /// This stresses the leftover logic more aggressively.
    #[tokio::test]
    async fn test_leftover_with_small_buffer() {
        #![allow(
            clippy::arithmetic_side_effects,
            reason = "nullifiers.len() * NULLIFIER_SIZE will not overflow"
        )]

        // 5 nullifiers = 160 bytes
        let nullifiers = nfs![1, 2, 3, 4, 5];
        let data = bytemuck::cast_slice(&nullifiers).to_vec();
        assert_eq!(data.len(), nullifiers.len() * NULLIFIER_SIZE);

        // Small buffer (64 bytes = 2 nullifiers) with 45-byte chunks
        // This forces multiple buffer fills with leftover handling each time
        let reader = ChunkedReader::new(data, 45);
        let stream = read_nullifiers(reader, 64);
        let results: Vec<_> = stream.collect().await;

        assert_eq!(results.len(), nullifiers.len());
        for (i, result) in results.iter().enumerate() {
            let nf = result.as_ref().expect("should be Ok");
            assert_eq!(nf, &nullifiers[i]);
        }
    }

    /// Test that leftover bytes at EOF produce an error.
    #[tokio::test]
    async fn test_leftover_at_eof_error() {
        // 1 complete nullifier + 10 extra bytes = 42 bytes
        let mut data = vec![0_u8; 42];
        data[0] = 0xAB; // Mark the valid nullifier

        let reader = ChunkedReader::new(data, 100);
        let stream = read_nullifiers(reader, BUF_SIZE);
        let results: Vec<_> = stream.collect().await;

        // First should be Ok
        assert!(results[0].is_ok());
        assert_eq!(results[0].as_ref().expect("is ok")[0], 0xAB);

        // Second should be UnexpectedEof error
        assert!(matches!(
            results[1],
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    /// Test with both pools using `FileSource` but with small buffer to test boundary handling.
    #[tokio::test]
    async fn test_both_pools_with_small_buffer() {
        let sapling_file = nullifiers_file(5).await;
        let orchard_file = nullifiers_file(3).await;

        // Use small buffer (64 bytes = 2 nullifiers) to force multiple reads
        let source = FileSource::with_buf_size(
            Some(sapling_file.path().to_path_buf()),
            Some(orchard_file.path().to_path_buf()),
            64,
        );

        let stream = source.nullifiers_stream(&(0..=0));
        let (sapling, orchard) = partition_by_pool(stream)
            .await
            .expect("failed to read nullifiers");

        assert_eq!(sapling.len(), 5);
        assert_eq!(orchard.len(), 3);
    }
}
