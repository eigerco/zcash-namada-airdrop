//! Helper functions to derive Orchard and Sapling Full Viewing Keys from a BIP-39 mnemonic phrase.

use bip39::Language;
use clap_derive::ValueEnum;
use eyre::{Result, WrapErr as _};
use orchard::keys::{FullViewingKey as OrchardFvk, SpendingKey as OrchardSpendingKey};
use sapling_crypto::keys::FullViewingKey as SaplingFvk;
use sapling_crypto::zip32::ExtendedSpendingKey as SaplingSpendingKey;
use zcash_primitives::zip32::AccountId;

/// Complete set of Zcash keys derived from a mnemonic
///
/// Contains both Full Viewing Keys (for finding notes) and Spending Keys (for deriving nullifiers).
pub struct ZcashKeys {
    /// Orchard Full Viewing Key (for finding notes)
    pub orchard_fvk: OrchardFvk,
    /// Orchard Spending Key (for deriving nullifiers)
    pub orchard_spending_key: OrchardSpendingKey,
    /// Sapling Full Viewing Key (for finding notes)
    pub sapling_fvk: SaplingFvk,
    /// Sapling Extended Spending Key (for deriving nullifiers)
    pub sapling_spending_key: SaplingSpendingKey,
}

/// Enum representing the Zcash pool types for which Full Viewing Keys can be derived
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Pool {
    /// Sapling pool
    Sapling,
    /// Orchard pool
    Orchard,
    /// Both pools, Sapling and Orchard
    Both,
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

/// Enum representing the Zcash coin type for different networks
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum CoinType {
    /// Zcash Mainnet
    Mainnet,
    /// Zcash Testnet
    Testnet,
    /// Zcash Regtest
    Regtest,
}

impl CoinType {
    const fn to_u32(self) -> u32 {
        match self {
            Self::Mainnet => zcash_primitives::constants::mainnet::COIN_TYPE,
            Self::Testnet => zcash_primitives::constants::testnet::COIN_TYPE,
            Self::Regtest => zcash_primitives::constants::regtest::COIN_TYPE,
        }
    }
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
pub fn mnemonic_to_keys(phrase: &str, coin_type: CoinType) -> Result<ZcashKeys> {
    let m = bip39::Mnemonic::parse_in_normalized(Language::English, phrase)
        .wrap_err("Failed to parse BIP-39 mnemonic phrase")?;
    let seed = m.to_seed("");

    // Derive Orchard keys
    let orchard_spending_key = OrchardSpendingKey::from_zip32_seed(
        &seed,
        coin_type.to_u32(),
        AccountId::ZERO,
    )
    .map_err(|e| eyre::eyre!(e))
    .wrap_err_with(|| {
        format!(
            "Failed to derive Orchard spending key from ZIP-32 seed for coin type {coin_type:?}"
        )
    })?;
    let orchard_fvk = OrchardFvk::from(&orchard_spending_key);

    // Derive Sapling keys
    let sapling_spending_key = sapling_spending_key(&seed, coin_type);
    let sapling_fvk = sapling_spending_key
        .to_diversifiable_full_viewing_key()
        .fvk()
        .clone();

    Ok(ZcashKeys {
        orchard_fvk,
        orchard_spending_key,
        sapling_fvk,
        sapling_spending_key,
    })
}

fn sapling_spending_key(seed: &[u8; 64], coin_type: CoinType) -> SaplingSpendingKey {
    use sapling_crypto::zip32::ExtendedSpendingKey;
    use zip32::ChildIndex;

    let master = ExtendedSpendingKey::master(seed);
    let purpose = master.derive_child(ChildIndex::hardened(32)); // TODO: understand why 32 is used here
    let coin = purpose.derive_child(ChildIndex::hardened(coin_type.to_u32()));
    coin.derive_child(ChildIndex::hardened(0))
}
