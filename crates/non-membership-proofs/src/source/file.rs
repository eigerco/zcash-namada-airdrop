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
use std::pin::Pin;

use async_stream::try_stream;
use futures_core::Stream;
use tokio::fs::File;
use tokio::io::{AsyncReadExt as _, BufReader};

use crate::Pool;
use crate::chain_nullifiers::{ChainNullifiers, PoolNullifier};

/// Source for reading nullifiers from local binary files
#[allow(
    clippy::module_name_repetitions,
    reason = "Clearer name for source type"
)]
pub struct FileSource {
    sapling_path: Option<PathBuf>,
    orchard_path: Option<PathBuf>,
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
        }
    }
}

impl ChainNullifiers for FileSource {
    type Error = io::Error;
    type Stream = Pin<Box<dyn Stream<Item = Result<PoolNullifier, Self::Error>> + Send>>;

    /// Read nullifiers from the specified files
    /// range is ignored since files contain all nullifiers
    fn nullifiers_stream(&self, _range: &RangeInclusive<u64>) -> Self::Stream {
        let sapling_path = self.sapling_path.clone();
        let orchard_path = self.orchard_path.clone();

        Box::pin(try_stream! {
            const NULLIFIER_SIZE: usize = 32;
            const BUF_NULLIFIERS: usize = 1024;
            let mut buf = vec![0_u8; NULLIFIER_SIZE * BUF_NULLIFIERS];

            for (file, pool) in [
                (sapling_path, Pool::Sapling),
                (orchard_path, Pool::Orchard),
            ] {
                let Some(file) = file else {
                    continue;
                };
                let file = File::open(file).await?;
                let mut reader = BufReader::new(file);
                let mut leftover = 0_usize; // bytes carried over from previous read

                loop {
                    // Read into buffer after any leftover bytes
                    let read_buf = buf.get_mut(leftover..).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "leftover exceeds buffer size")
                    })?;
                    let n = reader.read(read_buf).await?;
                    if n == 0 {
                        // End of file - check for incomplete nullifier
                        if leftover > 0 {
                            Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "file has {leftover} trailing bytes (not a multiple of {NULLIFIER_SIZE})"
                                ),
                            ))?;
                        }
                        break;
                    }

                    let total = leftover.saturating_add(n);
                    #[allow(clippy::integer_division, reason = "Integer division is intentional here - we want floor division")]
                    let complete_count = total / NULLIFIER_SIZE;
                    let complete_bytes = complete_count.saturating_mul(NULLIFIER_SIZE);

                    // Process complete nullifiers
                    let complete_slice = buf.get(..complete_bytes).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "complete_bytes exceeds buffer")
                    })?;
                    for chunk in complete_slice.chunks_exact(NULLIFIER_SIZE) {
                        let nullifier: [u8; 32] = chunk.try_into().map_err(|_err| {
                            io::Error::new(io::ErrorKind::InvalidData, "chunk size mismatch")
                        })?;
                        yield PoolNullifier {
                            pool,
                            nullifier,
                        };
                    }

                    // Move leftover bytes to the start of buffer
                    leftover = total.saturating_sub(complete_bytes);
                    if leftover > 0 {
                        buf.copy_within(complete_bytes..total, 0);
                    }
                }
            }
        })
    }
}
