//! Helper functions to derive Orchard and Sapling Full Viewing Keys from a BIP-39 mnemonic phrase.

use bip39::Language;
use eyre::{Result, WrapErr as _};
use secrecy::{ExposeSecret as _, SecretBox};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::Network;
use zip32::AccountId;

/// Complete set of Zcash keys derived from a mnemonic
///
/// Contains both Full Viewing Keys (for finding notes).
pub struct ZcashKeys {
    /// Unified Full Viewing Key (for finding notes)
    pub ufvk: UnifiedFullViewingKey,
}

/// Derives both Full Viewing Keys from a BIP-39 mnemonic phrase
///
/// # Arguments
/// - `phrase`: The BIP-39 mnemonic phrase as a string slice
/// - `network`: The Zcash network (Mainnet, Testnet) for key derivation
/// - `passphrase`: The optional BIP-39 passphrase (empty string if none)
///
/// # Returns
/// A Result containing `ZcashKeys` with viewing keys
///
/// # Errors
/// Returns an error if the mnemonic phrase is invalid or key derivation fails
pub fn mnemonic_to_keys(
    phrase: &SecretBox<str>,
    network: Network,
    passphrase: &SecretBox<str>,
    account_index: u32,
) -> Result<ZcashKeys> {
    let m = bip39::Mnemonic::parse_in_normalized(Language::English, phrase.expose_secret())
        .wrap_err("Failed to parse BIP-39 mnemonic phrase")?;
    let seed = m.to_seed(passphrase.expose_secret());

    let usk = UnifiedSpendingKey::from_seed(&network, &seed, AccountId::try_from(account_index)?)?;

    let ufvk = usk.to_unified_full_viewing_key();

    Ok(ZcashKeys { ufvk })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Smoke test for mnemonic_to_keys function
    #[test]
    fn valid_mnemonic_to_keys() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let phrase = SecretBox::from(mnemonic);
        let network = Network::TestNetwork;
        let passphrase = SecretBox::from("");
        let account_index = 0;

        let result = mnemonic_to_keys(&phrase, network, &passphrase, account_index);
        assert!(result.is_ok());
    }

    #[test]
    fn invalid_mnemonic_to_keys() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let phrase = SecretBox::from(mnemonic);
        let network = Network::TestNetwork;
        let passphrase = SecretBox::from("");
        let account_index = 0;

        let result = mnemonic_to_keys(&phrase, network, &passphrase, account_index);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_account_index() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let phrase = SecretBox::from(mnemonic);
        let network = Network::TestNetwork;
        let passphrase = SecretBox::from("");
        let account_index = u32::MAX; // Exceeds AccountId max (i32::MAX)

        let result = mnemonic_to_keys(&phrase, network, &passphrase, account_index);
        assert!(result.is_err());
    }
}
