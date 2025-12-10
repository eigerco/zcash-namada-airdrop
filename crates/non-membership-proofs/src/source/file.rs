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
use tokio::io::{AsyncReadExt, BufReader};

use crate::Pool;
use crate::chain_nullifiers::{ChainNullifiers, PoolNullifier};

/// Read nullifiers from local files
pub struct FileSource {
    sapling_path: PathBuf,
    orchard_path: PathBuf,
}

impl FileSource {
    /// Create a new FileSource with the given file paths
    pub fn new(sapling_path: PathBuf, orchard_path: PathBuf) -> Self {
        Self {
            sapling_path,
            orchard_path,
        }
    }
}

impl ChainNullifiers for FileSource {
    type Error = io::Error;
    type Stream = Pin<Box<dyn Stream<Item = Result<PoolNullifier, Self::Error>> + Send>>;

    fn into_nullifiers_stream(&self, _range: &RangeInclusive<u64>) -> Self::Stream {
        let sapling_path = self.sapling_path.clone();
        let orchard_path = self.orchard_path.clone();

        Box::pin(try_stream! {
            const NULLIFIER_SIZE: usize = 32;
            const BUF_NULLIFIERS: usize = 1024;
            let mut buf = vec![0u8; NULLIFIER_SIZE * BUF_NULLIFIERS];

            for (file, pool) in [
                (sapling_path, Pool::Sapling),
                (orchard_path, Pool::Orchard),
            ] {
                let file = File::open(file).await?;
                let mut reader = BufReader::new(file);
                let mut leftover = 0usize; // bytes carried over from previous read

                loop {
                    // Read into buffer after any leftover bytes
                    let n = reader.read(&mut buf[leftover..]).await?;
                    if n == 0 {
                        // End of file - check for incomplete nullifier
                        if leftover > 0 {
                            Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "file has {} trailing bytes (not a multiple of {})",
                                    leftover, NULLIFIER_SIZE
                                ),
                            ))?;
                        }
                        break;
                    }

                    let total = leftover + n;
                    let complete_bytes = (total / NULLIFIER_SIZE) * NULLIFIER_SIZE;

                    // Process complete nullifiers
                    for chunk in buf[..complete_bytes].chunks_exact(NULLIFIER_SIZE) {
                        let nullifier: [u8; 32] = chunk.try_into().unwrap();
                        yield PoolNullifier {
                            pool,
                            nullifier,
                        };
                    }

                    // Move leftover bytes to the start of buffer
                    leftover = total - complete_bytes;
                    if leftover > 0 {
                        buf.copy_within(complete_bytes..total, 0);
                    }
                }
            }
        })
    }
}
