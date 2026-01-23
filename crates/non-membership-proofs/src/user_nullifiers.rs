//! This module provides functionality for handling user nullifiers. Scans the remote chain,
//! identifies user nullifiers and returns them.

use std::fmt::Debug;

use ff::PrimeField as _;
use group::GroupEncoding as _;
use orchard::Note as OrchardNote;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zcash_protocol::TxId;
// Re-export viewing keys for external use
pub use zip32::Scope;

use crate::{Nullifier, OrchardViewingKeys, SaplingViewingKeys};

/// Metadata common to all found notes (Sapling and Orchard)
#[derive(Debug, Clone)]
pub struct NoteMetadata {
    /// Block height where the note was found
    pub height: u64,
    /// Transaction ID containing the note
    pub txid: TxId,
    /// The scope (External for received payments, Internal for change)
    pub scope: Scope,
    /// Note position in the commitment tree
    pub position: u64,
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
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
pub struct SaplingHidingFactor<'a> {
    /// Personalization bytes, are used to derive the hiding sapling nullifier
    pub personalization: &'a [u8],
}

/// Orchard hiding factor
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
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

impl SaplingNote {
    /// Returns the diversified generator bytes (Sapling only).
    ///
    /// # Panics
    /// Panics if the diversifier is invalid, but this should never happen
    #[must_use]
    pub fn g_d(&self) -> [u8; 32] {
        // g_d is guaranteed to be valid since PaymentAddress checks this at construction
        let g_d = self
            .note
            .recipient()
            .diversifier()
            .g_d()
            .expect("valid diversifier");
        g_d.to_bytes()
    }

    /// Returns the diversified transmission key bytes (Sapling only).
    #[must_use]
    pub fn pk_d(&self) -> [u8; 32] {
        self.note.recipient().pk_d().inner().to_bytes()
    }

    /// Returns the note value.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }

    /// Returns the commitment randomness bytes (Sapling only).
    #[must_use]
    pub fn rcm(&self) -> [u8; 32] {
        self.note.rcm().to_repr()
    }
}

impl NoteNullifier for SaplingNote {
    type HidingFactor<'a> = SaplingHidingFactor<'a>;
    type ViewingKeys = SaplingViewingKeys;

    fn nullifier(&self, keys: &Self::ViewingKeys) -> Nullifier {
        self.note.cmu();
        let nk = keys.nk(self.scope);
        self.note.nf(nk, self.position).0.into()
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
        Ok(Nullifier::new(
            self.note
                .nf_hiding(nk, self.position, hiding.personalization)
                .0,
        ))
    }
}

impl NoteNullifier for OrchardNote {
    type HidingFactor<'a> = OrchardHidingFactor<'a>;
    type ViewingKeys = OrchardViewingKeys;

    fn nullifier(&self, keys: &Self::ViewingKeys) -> Nullifier {
        Nullifier::new(self.nullifier(&keys.fvk).to_bytes())
    }

    fn hiding_nullifier(
        &self,
        keys: &Self::ViewingKeys,
        hiding: &Self::HidingFactor<'_>,
    ) -> Result<Nullifier, NullifierError> {
        Ok(Nullifier::new(
            self.hiding_nullifier(&keys.fvk, hiding.domain, hiding.tag)
                .to_bytes(),
        ))
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

impl FoundNote<OrchardNote> {
    /// Returns the note commitment bytes.
    #[must_use]
    pub fn note_commitment(&self) -> [u8; 32] {
        let extracted: orchard::note::ExtractedNoteCommitment = self.note.commitment().into();
        extracted.to_bytes()
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

#[cfg(test)]
mod tests {
    use orchard::keys::{
        FullViewingKey as OrchardFvk, Scope as OrchardScope, SpendingKey as OrchardSpendingKey,
    };
    use orchard::value::NoteValue as OrchardNoteValue;
    use sapling::zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey};
    use zip32::{AccountId, Scope};

    use super::*;

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
            let hiding_nf = NoteNullifier::hiding_nullifier(&note, &keys, &hiding)
                .expect("Failed to derive hiding nullifier");
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
            let hiding_nf = note
                .hiding_nullifier(&keys, &hiding)
                .expect("Failed to derive hiding nullifier");
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
}
