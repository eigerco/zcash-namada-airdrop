//! Helper functions to derive Orchard and Sapling Full Viewing Keys from a BIP-39 mnemonic phrase.

use bip39::Language;
use eyre::{Result, WrapErr as _};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_primitives::consensus::Network;
use zcash_primitives::zip32::AccountId;

/// Complete set of Zcash keys derived from a mnemonic
///
/// Contains both Full Viewing Keys (for finding notes) and Spending Keys (for deriving nullifiers).
pub struct ZcashKeys {
    /// Unified Spending Key (for deriving nullifiers)
    pub usk: UnifiedSpendingKey,
    /// Unified Full Viewing Key (for finding notes)
    pub ufvk: UnifiedFullViewingKey,
}

/// Reads the mnemonic from the `ZCASH_MNEMONIC` environment variable, or prompts the user to enter
/// it securely if the variable is not set.
///
/// # Errors
/// Returns an `std::io::Error` if there was an error reading the input.
///
/// # Returns
/// A `Result` containing the mnemonic as a `String` if successful, or an `std::io::Error` if
/// there was an error reading the input.
pub fn read_mnemonic_secure() -> std::io::Result<String> {
    if let Ok(mnemonic) = std::env::var("ZCASH_MNEMONIC") {
        return Ok(mnemonic);
    }

    rpassword::prompt_password("Enter mnemonic: ").map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("Failed to read mnemonic from terminal: {e}"),
        )
    })
}

/// Derives both Full Viewing Keys AND Spending Keys from a BIP-39 mnemonic phrase
///
/// Use this when you need to derive nullifiers (for spend detection).
/// For view-only operations, use `mnemonic_to_fvks()` instead.
///
/// # Arguments
/// - `phrase`: The BIP-39 mnemonic phrase as a string slice
/// - `coin_type`: The Zcash coin type (Mainnet, Testnet, Regtest)
///
/// # Returns
/// A Result containing `ZcashKeys` with both viewing and spending keys
///
/// # Errors
/// Returns an error if the mnemonic phrase is invalid or key derivation fails
///
/// # Security Warning
/// Spending keys allow spending funds. Handle with extreme care.
pub fn mnemonic_to_keys(phrase: &str, network: Network) -> Result<ZcashKeys> {
    let m = bip39::Mnemonic::parse_in_normalized(Language::English, phrase)
        .wrap_err("Failed to parse BIP-39 mnemonic phrase")?;
    let seed = m.to_seed("");

    let usk = UnifiedSpendingKey::from_seed(&network, &seed, AccountId::ZERO)?;

    let ufvk = usk.to_unified_full_viewing_key();

    Ok(ZcashKeys { usk, ufvk })
}
