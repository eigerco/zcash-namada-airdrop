//! This module provides functionality for handling user nullifiers. Scans the remote chain,
//! identifies user nullifiers and returns them.

use std::fmt::Debug;

use futures_core::Stream;
use orchard::keys::FullViewingKey as OrchardFvk;
use sapling::zip32::DiversifiableFullViewingKey;
use zcash_primitives::consensus::Parameters;

use crate::user_nullifiers::decrypt_notes::{derive_orchard_nullifier, derive_sapling_nullifier};

pub(crate) mod decrypt_notes;

// Re-export viewing keys for external use
pub use decrypt_notes::{OrchardViewingKeys, SaplingViewingKeys, ViewingKeys};
pub use zip32::Scope;

/// Metadata common to all found notes (Sapling and Orchard)
#[derive(Debug, Clone)]
pub struct NoteMetadata {
    /// Block height where the note was found
    pub height: u64,
    /// Transaction ID containing the note
    pub txid: Vec<u8>,
    /// The scope (External for received payments, Internal for change)
    pub scope: Scope,
}

/// Trait for note types that can derive nullifiers.
pub trait NoteNullifier: Sized {
    /// The hiding factor type for this note
    type HidingFactor<'a>;
    /// The viewing keys type for this note
    type ViewingKeys;

    // TODO: review if the metadata parameter is necessary

    /// Derive the standard nullifier
    fn nullifier(&self, keys: &Self::ViewingKeys, metadata: &NoteMetadata) -> [u8; 32];

    /// Derive the hiding nullifier
    fn hiding_nullifier(
        &self,
        keys: &Self::ViewingKeys,
        metadata: &NoteMetadata,
        hiding: &Self::HidingFactor<'_>,
    ) -> [u8; 32];
}

/// Sapling hiding factor
#[allow(missing_docs)]
#[derive(Debug)]
pub struct SaplingHidingFactor<'a> {
    pub personalization: &'a [u8],
}

/// Orchard hiding factor
#[allow(missing_docs)]
#[derive(Debug)]
pub struct OrchardHidingFactor<'a> {
    pub domain: &'a str,
    pub tag: &'a [u8],
}

/// A Sapling note with its required position
#[allow(missing_docs)]
#[derive(Debug)]
pub struct SaplingNote {
    pub note: sapling::Note,
    pub position: u64,
}

impl NoteNullifier for SaplingNote {
    type HidingFactor<'a> = SaplingHidingFactor<'a>;
    type ViewingKeys = SaplingViewingKeys;

    fn nullifier(&self, keys: &Self::ViewingKeys, metadata: &NoteMetadata) -> [u8; 32] {
        let nk = keys.nk(metadata.scope);
        derive_sapling_nullifier(&self.note, &nk, self.position)
    }

    fn hiding_nullifier(
        &self,
        keys: &Self::ViewingKeys,
        metadata: &NoteMetadata,
        hiding: &Self::HidingFactor<'_>,
    ) -> [u8; 32] {
        let nk = keys.nk(metadata.scope);
        self.note
            .nf_hiding(&nk, self.position, hiding.personalization)
            .0
    }
}

impl NoteNullifier for orchard::Note {
    type HidingFactor<'a> = OrchardHidingFactor<'a>;
    type ViewingKeys = OrchardViewingKeys;

    fn nullifier(&self, keys: &Self::ViewingKeys, _metadata: &NoteMetadata) -> [u8; 32] {
        derive_orchard_nullifier(self, &keys.fvk)
    }

    fn hiding_nullifier(
        &self,
        keys: &Self::ViewingKeys,
        _metadata: &NoteMetadata,
        hiding: &Self::HidingFactor<'_>,
    ) -> [u8; 32] {
        self.hiding_nullifier(&keys.fvk, hiding.domain, hiding.tag)
            .to_bytes()
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
    pub fn height(&self) -> u64 {
        self.metadata.height
    }

    /// Note scope, internal or external
    pub fn scope(&self) -> Scope {
        self.metadata.scope
    }

    /// Derive the nullifier for this note
    pub fn nullifier(&self, keys: &N::ViewingKeys) -> [u8; 32] {
        self.note.nullifier(keys, &self.metadata)
    }

    /// Derive the hiding nullifier for this note
    pub fn hiding_nullifier(
        &self,
        keys: &N::ViewingKeys,
        hiding: &N::HidingFactor<'_>,
    ) -> [u8; 32] {
        self.note.hiding_nullifier(keys, &self.metadata, hiding)
    }
}

/// A found note that can be either Sapling or Orchard (for mixed streams)
#[derive(Debug)]
pub enum AnyFoundNote {
    /// Sapling note
    Sapling(FoundNote<SaplingNote>),
    /// Orchard note
    Orchard(FoundNote<orchard::Note>),
}

impl AnyFoundNote {
    /// Note block height
    pub fn height(&self) -> u64 {
        match self {
            AnyFoundNote::Sapling(n) => n.height(),
            AnyFoundNote::Orchard(n) => n.height(),
        }
    }

    /// Note scope, internal or external
    pub fn scope(&self) -> Scope {
        match self {
            AnyFoundNote::Sapling(n) => n.scope(),
            AnyFoundNote::Orchard(n) => n.scope(),
        }
    }

    /// Derive the nullifier for this note
    pub fn nullifier(&self, keys: &ViewingKeys) -> Option<[u8; 32]> {
        match self {
            AnyFoundNote::Sapling(n) => keys.sapling.as_ref().map(|key| n.nullifier(key)),
            AnyFoundNote::Orchard(n) => keys.orchard.as_ref().map(|key| n.nullifier(key)),
        }
    }

    /// Derive the hiding nullifier for this note
    pub fn pool(&self) -> &'static str {
        match self {
            AnyFoundNote::Sapling(_) => "sapling",
            AnyFoundNote::Orchard(_) => "orchard",
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
    ///
    /// TODO: handle cancellation
    fn user_nullifiers<P: Parameters + Clone + Send + 'static>(
        &self,
        network: &P,
        start_height: u64,
        end_height: u64,
        orchard_fvk: &OrchardFvk,
        sapling_fvk: &DiversifiableFullViewingKey,
    ) -> Self::Stream;
}
