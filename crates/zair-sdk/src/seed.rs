//! Seed parsing and file utilities.

use std::path::Path;

use eyre::{Context as _, ensure};
use secrecy::SecretBox;

/// Parse a hex-encoded seed into a 64-byte array.
pub fn parse_seed_hex(seed_hex: &str) -> eyre::Result<SecretBox<[u8; 64]>> {
    // Wrap in Zeroizing immediately so it's zeroized on drop even if we return early.
    let seed_bytes = zeroize::Zeroizing::new(hex::decode(seed_hex).context("Invalid hex seed")?);

    ensure!(
        seed_bytes.len() == 64,
        "Seed must be exactly 64 bytes (128 hex characters), got {} bytes",
        seed_bytes.len()
    );

    let array: [u8; 64] = seed_bytes[..]
        .try_into()
        .map_err(|_| eyre::eyre!("Seed must be exactly 64 bytes"))?;

    Ok(SecretBox::new(Box::new(array)))
}

/// Read a seed file containing hex and parse it into a 64-byte seed.
pub async fn read_seed_file(path: &Path) -> eyre::Result<SecretBox<[u8; 64]>> {
    let seed_hex = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read seed file {}", path.display()))?;
    parse_seed_hex(seed_hex.trim())
}
