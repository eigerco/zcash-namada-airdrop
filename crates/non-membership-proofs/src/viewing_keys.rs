//! Structures for viewing keys used in note decryption and nullifier derivation

use orchard::keys::{FullViewingKey as OrchardFvk, PreparedIncomingViewingKey as OrchardPivk};
use sapling::NullifierDerivingKey;
use sapling::note_encryption::PreparedIncomingViewingKey as SaplingPivk;
use sapling::zip32::DiversifiableFullViewingKey as SaplingDfvk;
use zcash_keys::keys::UnifiedFullViewingKey;
use zip32::Scope;

/// Viewing keys for decryption and nullifier derivation
///
/// Provide both external (for receiving) and internal (for change) keys
#[derive(Clone)]
pub struct SaplingViewingKeys {
    /// External viewing key for external scope (needed for note decryption)
    /// External scope is used for incoming payments.
    /// When we receive ZEC, the note is encrypted to the external ivk.
    pub external: SaplingPivk,
    /// Internal viewing key for internal scope (needed for note decryption)
    /// Internal scope is used for change outputs.
    /// When we send ZEC, any change is sent to an address derived from the internal ivk and the
    /// change output is encrypted to that ivk.
    pub internal: SaplingPivk,
    /// Nullifier deriving key for external scope (needed for nullifier derivation)
    pub nk_external: NullifierDerivingKey,
    /// Nullifier deriving key for internal scope (needed for nullifier derivation)
    pub nk_internal: NullifierDerivingKey,
    /// Reference to the `DiversifiableFullViewingKey` (needed for nullifier derivation)
    pub dfvk: SaplingDfvk,
}

/// Viewing keys for decryption and nullifier derivation for Orchard pool
#[derive(Clone)]
pub struct OrchardViewingKeys {
    /// External viewing key for external scope (needed for note decryption)
    pub external: OrchardPivk,
    /// Internal viewing key for internal scope (needed for note decryption)
    pub internal: OrchardPivk,
    /// Full viewing key (needed for nullifier derivation)
    pub fvk: OrchardFvk,
}

/// Viewing keys for both Sapling and Orchard pools
#[derive(Clone)]
pub struct ViewingKeys {
    /// Sapling viewing keys (if any)
    sapling: Option<SaplingViewingKeys>,
    /// Orchard viewing keys (if any)
    orchard: Option<OrchardViewingKeys>,
}

impl ViewingKeys {
    /// Generate viewing keys from Sapling and Orchard pools
    pub fn new(ufvk: &UnifiedFullViewingKey) -> Self {
        let sapling = ufvk.sapling().map(SaplingViewingKeys::from_dfvk);
        let orchard = ufvk.orchard().map(OrchardViewingKeys::from_fvk);

        Self { sapling, orchard }
    }

    /// Get Sapling viewing key
    #[must_use]
    pub const fn sapling(&self) -> Option<&SaplingViewingKeys> {
        self.sapling.as_ref()
    }

    /// Get Orchard viewing key
    #[must_use]
    pub const fn orchard(&self) -> Option<&OrchardViewingKeys> {
        self.orchard.as_ref()
    }
}

impl SaplingViewingKeys {
    /// Create from a Sapling `DiversifiableFullViewingKey`
    #[must_use]
    pub fn from_dfvk(dfvk: &SaplingDfvk) -> Self {
        Self {
            external: SaplingPivk::new(&dfvk.to_ivk(Scope::External)),
            internal: SaplingPivk::new(&dfvk.to_ivk(Scope::Internal)),
            nk_external: dfvk.to_nk(Scope::External),
            nk_internal: dfvk.to_nk(Scope::Internal),
            dfvk: dfvk.clone(),
        }
    }

    /// Get the appropriate nullifier deriving key based on scope
    #[must_use]
    pub const fn nk(&self, scope: Scope) -> &NullifierDerivingKey {
        match scope {
            Scope::External => &self.nk_external,
            Scope::Internal => &self.nk_internal,
        }
    }
}

impl OrchardViewingKeys {
    /// Create from an Orchard `FullViewingKey`
    #[must_use]
    pub fn from_fvk(fvk: &OrchardFvk) -> Self {
        use orchard::keys::Scope;
        Self {
            external: OrchardPivk::new(&fvk.to_ivk(Scope::External)),
            internal: OrchardPivk::new(&fvk.to_ivk(Scope::Internal)),
            fvk: fvk.clone(),
        }
    }
}
