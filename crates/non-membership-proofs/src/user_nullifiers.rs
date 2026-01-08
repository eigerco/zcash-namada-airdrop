//! This module provides functionality for handling user nullifiers. Scans the remote chain,
//! identifies user nullifiers and returns them.

use std::fmt::Debug;
use std::ops::RangeInclusive;
use std::pin::Pin;

use futures::Stream;
use orchard::Note as OrchardNote;
use zcash_protocol::TxId;
use zcash_protocol::consensus::Parameters;

use crate::{Nullifier, Pool};

pub(crate) mod decrypt_notes;

/// A boxed stream of found notes with the given error type.
pub type BoxedNoteStream<E> = Pin<Box<dyn Stream<Item = Result<AnyFoundNote, E>> + Send>>;

// Re-export viewing keys for external use
pub use decrypt_notes::{OrchardViewingKeys, SaplingViewingKeys, ViewingKeys};
pub use zip32::Scope;

/// Metadata common to all found notes (Sapling and Orchard)
#[derive(Debug, Clone)]
pub struct NoteMetadata {
    /// Block height where the note was found
    pub height: u64,
    /// Transaction ID containing the note
    pub txid: TxId,
    /// The scope (External for received payments, Internal for change)
    pub scope: Scope,
}

/// Error type for nullifier derivation
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NullifierError {
    /// Sapling personalization exceeds maximum length
    #[error(
        "Sapling hiding nullifier personalization too long: got {length} bytes, max {max} bytes"
    )]
    PersonalizationTooLong {
        /// Actual length provided
        length: usize,
        /// Maximum allowed length
        max: usize,
    },
}

/// Trait for note types that can derive nullifiers.
pub trait NoteNullifier: Sized {
    /// The hiding factor type for this note
    type HidingFactor<'a>;
    /// The viewing keys type for this note
    type ViewingKeys;

    /// Derive the standard nullifier
    fn nullifier(&self, keys: &Self::ViewingKeys) -> Nullifier;

    /// Derive the hiding nullifier
    ///
    /// # Errors
    ///
    /// Returns an error if the hiding factor parameters are invalid.
    fn hiding_nullifier(
        &self,
        keys: &Self::ViewingKeys,
        hiding: &Self::HidingFactor<'_>,
    ) -> Result<Nullifier, NullifierError>;
}

/// Sapling hiding factor
#[derive(Debug)]
pub struct SaplingHidingFactor<'a> {
    /// Personalization bytes, are used to derive the hiding sapling nullifier
    pub personalization: &'a [u8],
}

/// Orchard hiding factor
#[derive(Debug)]
pub struct OrchardHidingFactor<'a> {
    /// Domain separator for the hiding orchard nullifier
    pub domain: &'a str,
    /// Tag bytes, are used to derive the hiding orchard nullifier
    pub tag: &'a [u8],
}

/// A Sapling note with its required position
#[derive(Debug, Clone)]
pub struct SaplingNote {
    /// Sapling note
    pub note: sapling::Note,
    /// Note position in the commitment tree
    pub position: u64,
    /// Note scope (internal or external)
    pub scope: Scope,
}

impl NoteNullifier for SaplingNote {
    type HidingFactor<'a> = SaplingHidingFactor<'a>;
    type ViewingKeys = SaplingViewingKeys;

    fn nullifier(&self, keys: &Self::ViewingKeys) -> Nullifier {
        let nk = keys.nk(self.scope);
        self.note.nf(nk, self.position).0
    }

    fn hiding_nullifier(
        &self,
        keys: &Self::ViewingKeys,
        hiding: &Self::HidingFactor<'_>,
    ) -> Result<Nullifier, NullifierError> {
        if hiding.personalization.len() > blake2s_simd::PERSONALBYTES {
            return Err(NullifierError::PersonalizationTooLong {
                length: hiding.personalization.len(),
                max: blake2s_simd::PERSONALBYTES,
            });
        }
        let nk = keys.nk(self.scope);
        Ok(self
            .note
            .nf_hiding(nk, self.position, hiding.personalization)
            .0)
    }
}

impl NoteNullifier for OrchardNote {
    type HidingFactor<'a> = OrchardHidingFactor<'a>;
    type ViewingKeys = OrchardViewingKeys;

    fn nullifier(&self, keys: &Self::ViewingKeys) -> Nullifier {
        self.nullifier(&keys.fvk).to_bytes()
    }

    fn hiding_nullifier(
        &self,
        keys: &Self::ViewingKeys,
        hiding: &Self::HidingFactor<'_>,
    ) -> Result<Nullifier, NullifierError> {
        Ok(self
            .hiding_nullifier(&keys.fvk, hiding.domain, hiding.tag)
            .to_bytes())
    }
}

/// A note found for the user, with metadata
#[derive(Debug, Clone)]
pub struct FoundNote<N: NoteNullifier + Debug> {
    /// The note
    pub note: N,
    /// Common metadata
    pub metadata: NoteMetadata,
}

impl<N: NoteNullifier + Debug> FoundNote<N> {
    /// Note block height
    pub const fn height(&self) -> u64 {
        self.metadata.height
    }

    /// Note scope, internal or external
    pub const fn scope(&self) -> Scope {
        self.metadata.scope
    }
}

impl<N: NoteNullifier + Debug> NoteNullifier for FoundNote<N> {
    type HidingFactor<'a> = N::HidingFactor<'a>;
    type ViewingKeys = N::ViewingKeys;

    fn nullifier(&self, keys: &Self::ViewingKeys) -> Nullifier {
        self.note.nullifier(keys)
    }

    fn hiding_nullifier(
        &self,
        keys: &Self::ViewingKeys,
        hiding: &Self::HidingFactor<'_>,
    ) -> Result<Nullifier, NullifierError> {
        self.note.hiding_nullifier(keys, hiding)
    }
}

/// A found note that can be either Sapling or Orchard (for mixed streams)
#[derive(Debug)]
pub enum AnyFoundNote {
    /// Sapling note
    Sapling(FoundNote<SaplingNote>),
    /// Orchard note
    Orchard(FoundNote<OrchardNote>),
}

impl AnyFoundNote {
    /// Note block height
    #[must_use]
    pub const fn height(&self) -> u64 {
        match self {
            Self::Sapling(n) => n.height(),
            Self::Orchard(n) => n.height(),
        }
    }

    /// Note scope, internal or external
    #[must_use]
    pub const fn scope(&self) -> Scope {
        match self {
            Self::Sapling(n) => n.scope(),
            Self::Orchard(n) => n.scope(),
        }
    }

    /// Derive the nullifier for this note
    #[must_use]
    pub fn nullifier(&self, keys: &ViewingKeys) -> Option<Nullifier> {
        match self {
            Self::Sapling(n) => keys.sapling.as_ref().map(|key| n.nullifier(key)),
            Self::Orchard(n) => keys.orchard.as_ref().map(|key| n.nullifier(key)),
        }
    }

    /// Returns the pool (Sapling or Orchard) this note belongs to.
    #[must_use]
    pub const fn pool(&self) -> Pool {
        match self {
            Self::Sapling(_) => Pool::Sapling,
            Self::Orchard(_) => Pool::Orchard,
        }
    }
}

/// A trait for sources that can provide user nullifiers
pub trait UserNullifiers: Sized {
    /// The error type for this source
    type Error: std::error::Error + Send + 'static;

    /// The concrete stream type returned by this source
    type Stream: Stream<Item = Result<AnyFoundNote, Self::Error>> + Send;

    /// Consume self and return a stream of all nullifiers (both Sapling and Orchard)
    fn user_nullifiers<P: Parameters + Clone + Send + 'static>(
        &self,
        network: &P,
        range: RangeInclusive<u64>,
        keys: ViewingKeys,
    ) -> Self::Stream;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "Tests")]

    use orchard::keys::{
        FullViewingKey as OrchardFvk, Scope as OrchardScope, SpendingKey as OrchardSpendingKey,
    };
    use orchard::value::NoteValue as OrchardNoteValue;
    use sapling::zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey};
    use zcash_protocol::TxId;
    use zip32::{AccountId, Scope};

    use super::*;
    use crate::user_nullifiers::decrypt_notes::{OrchardViewingKeys, SaplingViewingKeys};

    /// Creates a test Orchard note with matching FVK.
    /// We create the note by deriving an address from the FVK and creating a note to that address.
    fn orchard_note_and_fvk() -> (OrchardNote, OrchardFvk) {
        let seed = [42_u8; 32];
        let sk =
            OrchardSpendingKey::from_zip32_seed(&seed, 0, AccountId::ZERO).expect("valid seed");
        let fvk = OrchardFvk::from(&sk);

        // Get a valid address from the FVK
        let address = fvk.address_at(0_u32, OrchardScope::External);

        // Create a valid rho from a nullifier
        let rho = orchard::note::Rho::from_bytes(&[1_u8; 32]).expect("valid rho");

        // Create random seed - we need a valid one
        let rseed = orchard::note::RandomSeed::from_bytes([2_u8; 32], &rho).expect("valid rseed");

        // Create the note
        let note = OrchardNote::from_parts(address, OrchardNoteValue::from_raw(1000), rho, rseed)
            .expect("valid note");

        (note, fvk)
    }

    fn sapling_dfvk() -> DiversifiableFullViewingKey {
        let seed = [0_u8; 32];
        let extsk = ExtendedSpendingKey::master(&seed);
        extsk.to_diversifiable_full_viewing_key()
    }

    fn txid() -> TxId {
        TxId::from_bytes([1_u8; 32])
    }

    /// Creates a test Sapling note with matching viewing keys.
    fn sapling_note_and_keys() -> (SaplingNote, SaplingViewingKeys) {
        let dfvk = sapling_dfvk();
        let keys = SaplingViewingKeys::from_dfvk(&dfvk);

        // Create a note to ourselves using AfterZip212 which takes raw bytes
        let address = dfvk.default_address().1;
        let note = sapling::Note::from_parts(
            address,
            sapling::value::NoteValue::from_raw(1000),
            sapling::Rseed::AfterZip212([0_u8; 32]),
        );

        let sapling_note = SaplingNote {
            note,
            position: 42,
            scope: Scope::External,
        };

        (sapling_note, keys)
    }

    mod orchard_nullifier {
        use super::*;

        #[test]
        fn nullifier_derivation() {
            let (note, fvk) = orchard_note_and_fvk();
            let keys = OrchardViewingKeys::from_fvk(&fvk);
            let hiding = OrchardHidingFactor {
                domain: "test.domain",
                tag: b"test_tag",
            };

            let nf1 = NoteNullifier::nullifier(&note, &keys);
            let hiding_nf = NoteNullifier::hiding_nullifier(&note, &keys, &hiding).unwrap();
            assert_ne!(nf1, hiding_nf);

            let nf_domain_1 = NoteNullifier::hiding_nullifier(
                &note,
                &keys,
                &OrchardHidingFactor {
                    domain: "d1",
                    tag: b"t",
                },
            );
            let nf_domain_2 = NoteNullifier::hiding_nullifier(
                &note,
                &keys,
                &OrchardHidingFactor {
                    domain: "d2",
                    tag: b"t",
                },
            );
            assert_ne!(nf_domain_1, nf_domain_2);

            let nf_tag_1 = NoteNullifier::hiding_nullifier(
                &note,
                &keys,
                &OrchardHidingFactor {
                    domain: "d",
                    tag: b"t1",
                },
            );
            let nf_tag_2 = NoteNullifier::hiding_nullifier(
                &note,
                &keys,
                &OrchardHidingFactor {
                    domain: "d",
                    tag: b"t2",
                },
            );
            assert_ne!(nf_tag_1, nf_tag_2);
        }
    }

    mod sapling_nullifier {
        use super::*;

        #[test]
        fn nullifier_derivation() {
            let (note, keys) = sapling_note_and_keys();
            let hiding = SaplingHidingFactor {
                personalization: b"testpers",
            };

            let nf1 = note.nullifier(&keys);
            let hiding_nf = note.hiding_nullifier(&keys, &hiding).unwrap();
            assert_ne!(nf1, hiding_nf);

            // Different personalization produces different nullifiers
            let nf_p1 = note.hiding_nullifier(
                &keys,
                &SaplingHidingFactor {
                    personalization: b"persone1",
                },
            );
            let nf_p2 = note.hiding_nullifier(
                &keys,
                &SaplingHidingFactor {
                    personalization: b"perstwo2",
                },
            );
            assert_ne!(nf_p1, nf_p2);
        }

        #[test]
        fn hiding_nullifier_rejects_long_personalization() {
            let (note, keys) = sapling_note_and_keys();
            let hiding = SaplingHidingFactor {
                personalization: b"this_is_longer_than_8_bytes",
            };
            let result = note.hiding_nullifier(&keys, &hiding);
            assert!(matches!(
                result,
                Err(NullifierError::PersonalizationTooLong { length: 27, max: 8 })
            ));
        }

        #[test]
        fn nullifier_changes_with_position_and_scope() {
            let (original_note, keys) = sapling_note_and_keys();

            // Different position
            let mut note_pos2 = original_note.clone();
            note_pos2.position += 1;
            assert_ne!(original_note.nullifier(&keys), note_pos2.nullifier(&keys));

            // Different scope
            let mut internal_note = original_note.clone();
            internal_note.scope = Scope::Internal;
            assert_ne!(
                original_note.nullifier(&keys),
                internal_note.nullifier(&keys),
            );
        }
    }

    fn sapling_found_note(
        scope: Scope,
        height: u64,
    ) -> (FoundNote<SaplingNote>, SaplingViewingKeys) {
        let (note, keys) = sapling_note_and_keys();
        let found = FoundNote {
            note,
            metadata: NoteMetadata {
                height,
                txid: txid(),
                scope,
            },
        };
        (found, keys)
    }

    fn orchard_found_note(
        scope: Scope,
        height: u64,
    ) -> (FoundNote<OrchardNote>, OrchardViewingKeys) {
        let (note, fvk) = orchard_note_and_fvk();
        let keys = OrchardViewingKeys::from_fvk(&fvk);
        let found = FoundNote {
            note,
            metadata: NoteMetadata {
                height,
                txid: txid(),
                scope,
            },
        };
        (found, keys)
    }

    mod found_note {
        use super::*;

        #[test]
        fn wrapping_behavior_sanity_check() {
            // Sapling
            let height = 12345_u64;
            let (sapling, keys) = sapling_found_note(Scope::External, height);
            assert_eq!(sapling.height(), height);
            assert_eq!(sapling.scope(), Scope::External);
            let hiding = SaplingHidingFactor {
                personalization: b"testpers",
            };
            assert_eq!(
                sapling.hiding_nullifier(&keys, &hiding),
                sapling.note.hiding_nullifier(&keys, &hiding)
            );

            // Orchard
            let (orchard, keys) = orchard_found_note(Scope::Internal, height);
            assert_eq!(orchard.height(), height);
            assert_eq!(orchard.scope(), Scope::Internal);
            let hiding = OrchardHidingFactor {
                domain: "test",
                tag: b"tag",
            };
            assert_eq!(
                orchard.hiding_nullifier(&keys, &hiding),
                NoteNullifier::hiding_nullifier(&orchard.note, &keys, &hiding)
            );
        }
    }

    mod any_found_note {
        use super::*;
        use crate::user_nullifiers::decrypt_notes::ViewingKeys;

        fn sapling_any_found_note(scope: Scope, height: u64) -> (AnyFoundNote, SaplingViewingKeys) {
            let (sapling_note, keys) = sapling_found_note(scope, height);
            let any = AnyFoundNote::Sapling(sapling_note);
            (any, keys)
        }

        fn orchard_any_found_note(scope: Scope, height: u64) -> (AnyFoundNote, OrchardViewingKeys) {
            let (orchard_note, keys) = orchard_found_note(scope, height);
            let any = AnyFoundNote::Orchard(orchard_note);
            (any, keys)
        }

        #[test]
        fn height_scope_and_pool() {
            let scope = Scope::External;
            let height = 12345_u64;
            let (sapling, _) = sapling_any_found_note(scope, height);
            assert_eq!(sapling.height(), height);
            assert_eq!(sapling.scope(), scope);
            assert_eq!(sapling.pool(), Pool::Sapling);

            let (orchard, _) = orchard_any_found_note(scope, height);
            assert_eq!(orchard.height(), height);
            assert_eq!(orchard.scope(), scope);
            assert_eq!(orchard.pool(), Pool::Orchard);
        }

        #[test]
        fn nullifier_returns_none_without_keys() {
            let scope = Scope::External;
            let height = 12345_u64;
            let (sapling_note, _) = sapling_any_found_note(scope, height);
            let (orchard_note, _) = orchard_any_found_note(scope, height);

            let keys = ViewingKeys {
                sapling: None,
                orchard: None,
            };

            assert!(sapling_note.nullifier(&keys).is_none());
            assert!(orchard_note.nullifier(&keys).is_none());
        }

        #[test]
        fn nullifier_returns_some_with_correct_keys() {
            // Sapling
            let scope = Scope::External;
            let height = 12345_u64;
            let (note, sapling_keys) = sapling_any_found_note(scope, height);
            let keys = ViewingKeys {
                sapling: Some(sapling_keys),
                orchard: None,
            };
            assert!(note.nullifier(&keys).is_some());

            // Orchard
            let (note, orchard_keys) = orchard_any_found_note(scope, height);
            let keys = ViewingKeys {
                sapling: None,
                orchard: Some(orchard_keys),
            };
            assert!(note.nullifier(&keys).is_some());
        }

        #[test]
        fn nullifier_returns_none_with_wrong_pool_keys() {
            // Sapling note with only Orchard keys
            let scope = Scope::External;
            let height = 12345_u64;

            let (sapling_note, _) = sapling_any_found_note(scope, height);
            let (_, orchard_keys) = orchard_any_found_note(scope, height);
            let keys = ViewingKeys {
                sapling: None,
                orchard: Some(orchard_keys),
            };
            assert!(sapling_note.nullifier(&keys).is_none());

            // Orchard note with only Sapling keys
            let (orchard_note, _) = orchard_any_found_note(scope, height);
            let (_, sapling_keys) = sapling_any_found_note(scope, height);
            let keys = ViewingKeys {
                sapling: Some(sapling_keys),
                orchard: None,
            };
            assert!(orchard_note.nullifier(&keys).is_none());
        }
    }
}
